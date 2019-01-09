#!/usr/bin/python
# @lint-avoid-python-3-compatibility-imports
#
# nsoop     Trace syscalls related to namespace execution.
#           For Linux, uses BCC, eBPF. Embedded C.
#
# USAGE: nsoop [-h] [-t] [-x] [-n NAME]
#
# This currently will print up to a maximum of 19 arguments, plus the process
# name, so 20 fields in total (MAXARG).
#
# This won't catch all new processes: an application may fork() but not exec().
#
# Copyright 2016-2018 Netflix, Inc.
# Copyright 2018-2019 Covalent IO
# Licensed under the Apache License, Version 2.0 (the "License")
#
# 07-Feb-2016   Brendan Gregg   Created this.
# 05-Dec-2018   Joe Stringer    Extended to snoop clone,setns,cgroups

from __future__ import print_function
from bcc import BPF
from bcc.utils import ArgString, printb
import bcc.utils as utils
import argparse
import ctypes as ct
import re
import time
import threading
from collections import defaultdict

# arguments
examples = """examples:
    ./nsoop           # trace all exec(),clone(),setns(),cgroup open syscalls
    ./nsoop -x        # include failed exec()s
    ./nsoop -t        # print timestamp column (offset from start)
    ./nsoop -T        # print time column
    ./nsoop -q        # add "quotemarks" around arguments
    ./nsoop -n main   # only print command lines containing "main"
    ./nsoop -l tpkg   # only print command where arguments contains "tpkg"
"""
parser = argparse.ArgumentParser(
    description="Trace exec() syscalls",
    formatter_class=argparse.RawDescriptionHelpFormatter,
    epilog=examples)
parser.add_argument("-t", "--timestamp", action="store_true",
                    help="print timestamp column (offset from start)")
parser.add_argument("-T", "--time", action="store_true",
                    help="print time column")
parser.add_argument("-x", "--fails", action="store_true",
                    help="include failed exec()s")
parser.add_argument("-q", "--quote", action="store_true",
                    help="Add quotemarks (\") around arguments.")
parser.add_argument("-n", "--name",
                    type=ArgString,
                    help="only print commands matching this name (regex), any arg")
parser.add_argument("-l", "--line",
                    type=ArgString,
                    help="only print commands where arg contains this line (regex)")
parser.add_argument("--max-args", default="20",
                    help="maximum number of arguments parsed and displayed, defaults to 20")
parser.add_argument("--ebpf", action="store_true",
                    help=argparse.SUPPRESS)
kernel_filter = parser.add_mutually_exclusive_group()
kernel_filter.add_argument("-p", "--pid",
                           help="trace this PID only")
kernel_filter.add_argument("--tid",
                           help="trace this TID only")
args = parser.parse_args()

# define BPF program
bpf_text = """
#include <uapi/linux/ptrace.h>
#include <linux/sched.h>
#include <linux/fs.h>

#define ARGSIZE  128

enum event_type {
    EVENT_EXEC_ARG, // 0
    EVENT_EXEC_RET, // 1
    EVENT_WRITE,    // 2
    EVENT_OPEN,     // 3
};

struct data_t {
    // PID as in userspace term (i.e. task->tgid in kernel)
    u32 pid;
    // Parent PID as in userspace term (i.e task->real_parent->tgid in kernel)
    u32 ppid;
    u64 ts;
    enum event_type type;
    int retval;
    char fname[NAME_MAX];
    char comm[TASK_COMM_LEN];
    char argv[ARGSIZE];
};

BPF_PERF_OUTPUT(events);

static int __submit_arg(struct pt_regs *ctx, void *ptr, struct data_t *data)
{
    bpf_probe_read(data->argv, sizeof(data->argv), ptr);
    events.perf_submit(ctx, data, sizeof(struct data_t));
    return 1;
}

static int submit_arg(struct pt_regs *ctx, void *ptr, struct data_t *data)
{
    const char *argp = NULL;
    bpf_probe_read(&argp, sizeof(argp), ptr);
    if (argp) {
        return __submit_arg(ctx, (void *)(argp), data);
    }
    return 0;
}

static u32 get_ppid(void)
{
    struct task_struct *task;

    task = (struct task_struct *)bpf_get_current_task();
    // Some kernels, like Ubuntu 4.13.0-generic, return 0
    // as the real_parent->tgid.
    // We use the get_ppid function as a fallback in those cases. (#1883)
    return task->real_parent->tgid;
}

int syscall__execve(struct pt_regs *ctx,
    const char __user *filename,
    const char __user *const __user *__argv,
    const char __user *const __user *__envp)
{
    // create data here and pass to submit_arg to save stack space (#555)
    struct data_t data = {};
    struct task_struct *task;

    data.pid = bpf_get_current_pid_tgid() >> 32;
    data.ppid = get_ppid();

    bpf_get_current_comm(&data.comm, sizeof(data.comm));
    data.type = EVENT_EXEC_ARG;

    __submit_arg(ctx, (void *)filename, &data);

    // skip first arg, as we submitted filename
    #pragma unroll
    for (int i = 1; i < MAXARG; i++) {
        if (submit_arg(ctx, (void *)&__argv[i], &data) == 0)
             goto out;
    }

    // handle truncated argument list
    char ellipsis[] = "...";
    __submit_arg(ctx, (void *)ellipsis, &data);
out:
    return 0;
}

int do_ret_sys_execve(struct pt_regs *ctx)
{
    struct data_t data = {};

    data.pid = bpf_get_current_pid_tgid() >> 32;
    data.ppid = get_ppid();

    bpf_get_current_comm(&data.comm, sizeof(data.comm));
    data.type = EVENT_EXEC_RET;
    data.retval = PT_REGS_RC(ctx);
    events.perf_submit(ctx, &data, sizeof(data));

    return 0;
}

struct val_t {
    u64 id;
    u64 ts;
    char comm[TASK_COMM_LEN];
    const char *fname;
};

BPF_HASH(infotmp, u64, struct val_t);
BPF_HASH(openfds, u64, struct val_t);

int trace_open(struct pt_regs *ctx, int dfd, const char __user *filename)
{
    struct val_t val = {};
    u64 id = bpf_get_current_pid_tgid();
    u32 pid = id >> 32; // PID is higher part
    u32 tid = id;       // Cast and get the lower part
    const char *prefix = "/sys/fs/cgroup/";

    if (pid == TGID) { return 0; }

    FILTER
    if (bpf_get_current_comm(&val.comm, sizeof(val.comm)) == 0) {
        val.id = id;
        val.ts = bpf_ktime_get_ns();
        val.fname = filename;
        infotmp.update(&id, &val);
    }

    return 0;
};

int trace_ret_open(struct pt_regs *ctx)
{
    u64 id = bpf_get_current_pid_tgid();
    struct val_t *valp;
    struct data_t data = {};

    u64 tsp = bpf_ktime_get_ns();

    valp = infotmp.lookup(&id);
    if (valp == 0) {
        // missed entry
        return 0;
    }
    bpf_probe_read(&data.comm, sizeof(data.comm), valp->comm);
    bpf_probe_read(&data.fname, sizeof(data.fname), (void *)valp->fname);
    data.pid = OPEN_GET_PID;
    data.ts = tsp / 1000;
    data.retval = PT_REGS_RC(ctx);
    data.type = EVENT_OPEN;

    //events.perf_submit(ctx, &data, sizeof(data));
    infotmp.delete(&id);

    if (data.retval > 0) {
        u64 fdkey = data.pid;
        fdkey <<= 32;
        fdkey |= data.retval;

        openfds.update(&fdkey, valp);
    }

    return 0;
}

static u64 get_fdkey(u64 pid_tgid, int fd)
{
    u64 fdkey = pid_tgid >> 32;
    fdkey <<= 32;
    fdkey |= fd;
    return fdkey;
}

int trace_write(struct pt_regs *ctx, int fd)
{
    u64 id = bpf_get_current_pid_tgid();
    struct val_t *valp;
    struct data_t data = {};
    u64 tsp = bpf_ktime_get_ns();
    u64 fdkey = get_fdkey(id, fd);

    valp = infotmp.lookup(&fdkey);
    if (valp == 0) {
        // missed entry
        return 0;
    }
    bpf_probe_read(&data.comm, sizeof(data.comm), valp->comm);
    bpf_probe_read(&data.fname, sizeof(data.fname), (void *)valp->fname);
    data.pid = OPEN_GET_PID;
    data.ts = tsp / 1000;
    data.retval = PT_REGS_RC(ctx);
    data.type = EVENT_WRITE;

    events.perf_submit(ctx, &data, sizeof(data));
    infotmp.delete(&id);

    if (data.retval > 0) {
        u64 fdkey = data.pid;
        fdkey <<= 32;
        fdkey |= data.retval;

        openfds.update(&fdkey, valp);
    }

    return 0;
}

int trace_close(struct pt_regs *ctx, int fd)
{
    u64 pid = bpf_get_current_pid_tgid() >> 32; /* XXX: Broken for --tid */
    u64 fdkey = get_fdkey(pid, fd);

    infotmp.delete(&fdkey);

    return 0;
}

"""

CUSTOM_SYSCALLS = ["execve", "open"]
GEN_SYSCALLS = ["setns", "clone"]
ALL_SYSCALLS = CUSTOM_SYSCALLS + GEN_SYSCALLS
NEXT_EVENT = len(CUSTOM_SYSCALLS)*2
for i, syscall in enumerate(GEN_SYSCALLS):
    kprobe_type = i*2+NEXT_EVENT
    kretprobe_type = i*2+NEXT_EVENT+1
    print("Generating syscall handler for %s: event %d, ret %d" %
          (syscall, kprobe_type, kretprobe_type))
    bpf_text = bpf_text + """
int syscall__%s(struct pt_regs *ctx)
{
    struct data_t data = {};
    u32 pid = bpf_get_current_pid_tgid() >> 32;

    if (pid == TGID) { return 0; }

    data.pid = pid;
    data.ppid = get_ppid();
    data.type = %d;
    bpf_get_current_comm(&data.comm, sizeof(data.comm));

    events.perf_submit(ctx, &data, sizeof(data));
    return 0;
}

int do_ret_sys_%s(struct pt_regs *ctx)
{
    struct data_t data = {};
    u32 pid = bpf_get_current_pid_tgid() >> 32;

    if (pid == TGID) { return 0; }

    data.pid = pid;
    data.ppid = get_ppid();

    bpf_get_current_comm(&data.comm, sizeof(data.comm));
    data.type = %d;
    data.retval = PT_REGS_RC(ctx);
    events.perf_submit(ctx, &data, sizeof(data));

    return 0;
}
""" % (syscall, kprobe_type, syscall, kretprobe_type)

bpf_text = bpf_text.replace("MAXARG", args.max_args)
libc = ct.cdll.LoadLibrary('libc.so.6')
SYS_gettgid = 186
bpf_text = bpf_text.replace("TGID", "%d" % libc.syscall(SYS_gettgid))
if args.tid:  # TID trumps PID
    bpf_text = bpf_text.replace('FILTER',
                                'if (tid != %s) { return 0; }' % args.tid)
elif args.pid:
    bpf_text = bpf_text.replace('FILTER',
                                'if (pid != %s) { return 0; }' % args.pid)
else:
    bpf_text = bpf_text.replace('FILTER', '')
if args.tid:  # TID trumps PID
    bpf_text = bpf_text.replace('OPEN_GET_PID', 'valp->id & 0xFFFFFFFF')
else:
    bpf_text = bpf_text.replace('OPEN_GET_PID', 'valp->id >> 32')
if args.ebpf:
    print(bpf_text)
    exit()

# initialize BPF
b = BPF(text=bpf_text)
print("Attaching to %s (%s)..." % ("open", "do_sys_open"))
b.attach_kprobe(event="do_sys_open", fn_name="trace_open")
b.attach_kretprobe(event="do_sys_open", fn_name="trace_ret_open")
for syscall in ["close", "write"]:
    fnname = b.get_syscall_fnname(syscall)
    print("Attaching to %s (%s)..." % (syscall, fnname))
    b.attach_kprobe(event=fnname, fn_name="trace_%s" % syscall)
for syscall in [syscall for syscall in ALL_SYSCALLS if syscall != "open"]:
    fnname = b.get_syscall_fnname(syscall)
    print("Attaching to %s (%s)..." % (syscall, fnname))
    b.attach_kprobe(event=fnname, fn_name="syscall__%s" % syscall)
    b.attach_kretprobe(event=fnname, fn_name="do_ret_sys_%s" % syscall)

# header
if args.timestamp or args.time:
    print("%-8s " % ("TIME(s)"), end="")
COLUMNS = b"%-10s %-16s %-6s %-6s %4s %5s %s"
print(COLUMNS % ("EVENT", "PCOMM", "PID", "PPID", "FD", "RET", "ARGS"))

TASK_COMM_LEN = 16      # linux/sched.h
ARGSIZE = 128           # should match #define in C above
NAME_MAX = 255          # linux/limits.h


class Data(ct.Structure):
    _fields_ = [
        ("pid", ct.c_uint),
        ("ppid", ct.c_uint),
        ("ts", ct.c_ulonglong),
        ("type", ct.c_int),
        ("retval", ct.c_int),
        ("fname", ct.c_char * NAME_MAX),
        ("comm", ct.c_char * TASK_COMM_LEN),
        ("argv", ct.c_char * ARGSIZE),
    ]


class EventType(object):
    EVENT_EXEC_ARG = 0
    EVENT_EXEC_RET = 1
    EVENT_WRITE = 3
    EVENT_OPEN = 3


EventTypeStrings = {
    0: "exec_arg",
    1: "exec",
    2: "write",
    3: "open",
}
for i, v in enumerate(GEN_SYSCALLS):
    EventTypeStrings[i*2+NEXT_EVENT] = "sys_%s" % v
    EventTypeStrings[i*2+NEXT_EVENT+1] = v


def ret_event(ret):
    return ret % 2 == 1


start_ts = time.time()
argv = defaultdict(list)


# This is best-effort PPID matching. Short-lived processes may exit
# before we get a chance to read the PPID.
# This is a fallback for when fetching the PPID from task->real_parent->tgip
# returns 0, which happens in some kernel versions.
def get_ppid(pid):
    try:
        with open("/proc/%d/status" % pid) as status:
            for line in status:
                if line.startswith("PPid:"):
                    return int(line.split()[1])
    except IOError:
        pass
    return 0


# process event
def print_event(cpu, data, size):
    event = ct.cast(data, ct.POINTER(Data)).contents

    skip = False

    if event.type == EventType.EVENT_EXEC_ARG:
        argv[event.pid].append(event.argv)
    elif event.type == EventType.EVENT_OPEN or event.type == EventType.EVENT_WRITE:
        # split return value into FD and errno columns
        if event.retval >= 0:
            fd_s = event.retval
            err = 0
        else:
            fd_s = -1
            err = - event.retval

        if event.retval == -1 and not args.fails:
            return

        if args.name and bytes(args.name) not in event.comm:
            return

        if args.timestamp or args.time:
            ts = time.strftime("%H:%M:%S") if not args.timestamp else \
                   "%-8.3f" % (event.ts - start_ts)
            print("%-8s " % ts[:8], end="")

        ppid = event.ppid if event.ppid > 0 else get_ppid(event.pid)
        ppid = b"%d" % ppid if ppid > 0 else b"?"
        printb(COLUMNS % (EventTypeStrings[event.type], event.comm.decode(),
                          event.pid, ppid, fd_s, err, event.fname.decode()))

    elif ret_event(event.type):
        if event.retval == -1 and not args.fails:
            skip = True
        if args.name and not re.search(bytes(args.name), event.comm):
            skip = True
        if args.line and not re.search(bytes(args.line),
                                       b' '.join(argv[event.pid])):
            skip = True

        if not skip:
            if args.quote:
                argv[event.pid] = [
                    "\"" + arg.replace("\"", "\\\"") + "\""
                    for arg in argv[event.pid]
                ]
            if args.timestamp or args.time:
                ts = time.strftime("%H:%M:%S") if not args.timestamp else \
                       "%-8.3f" % (time.time() - start_ts)
                print("%-8s " % ts[:8], end="")
            ppid = event.ppid if event.ppid > 0 else get_ppid(event.pid)
            ppid = b"%d" % ppid if ppid > 0 else b"?"
            argv_text = b' '.join(argv[event.pid]).replace(b'\n', b'\\n')
            printb(COLUMNS % (EventTypeStrings[event.type], event.comm.decode(),
                              event.pid, ppid, 0, event.retval, argv_text))

        try:
            del(argv[event.pid])
        except Exception:
            pass


# loop with callback to print_event
b["events"].open_perf_buffer(print_event, page_cnt=64)
while 1:
    b.perf_buffer_poll()
