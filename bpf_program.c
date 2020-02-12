/* 3000sigsnoop: Snooping all signals sent to a pid/comm
   Copyright (C) 2020  William Findlay

   This program is free software: you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation, either version 3 of the License, or
   (at your option) any later version.

   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.

   You should have received a copy of the GNU General Public License
   along with this program.  If not, see <https://www.gnu.org/licenses/>.

   The BPF program used here is based on memleak.py from bcc tools:
   https://github.com/iovisor/bcc/blob/master/tools/memleak.py */

#include "bpf_program.h"

/* Helper to initialize sigsnoopstack structs */
BPF_ARRAY(__sigsnoopstack_init, struct sigsnoopstack, 1);

/* An LRU hash of SIGSNOOP_MAX_PROCESSES signal stacks */
BPF_F_TABLE("lru_hash", u32, struct sigsnoopstack, signal_stacks, SIGSNOOP_MAX_PROCESSES, 0);

/* Intermediate helper array, stores memory address of ksignal pointer */
BPF_PERCPU_ARRAY(addrs, struct addr_struct, 1);

/* Perf buffers for returning information to userspace */
BPF_PERF_OUTPUT(sig_enter_events);
BPF_PERF_OUTPUT(sig_return_events);

/* Helpers below this line --------------------------------------------- */

static inline u32 bpf_strlen(char *s)
{
    u32 i;
    for (i = 0; s[i] != '\0' && i < (1 << (32 - 1)); i++);
    return i;
}

static inline int bpf_strncmp(char *s1, char *s2, u32 n)
{
    int mismatch = 0;
    for (int i = 0; i < n && i < sizeof(s1) && i < sizeof(s2); i++)
    {
        if (s1[i] != s2[i])
            return s1[i] - s2[i];

        if (s1[i] == s2[i] == '\0')
            return 0;
    }

    return 0;
}

static inline int bpf_strcmp(char *s1, char *s2)
{
    u32 s1_size = sizeof(s1);
    u32 s2_size = sizeof(s2);

    return bpf_strncmp(s1, s2, s1_size < s2_size ? s1_size : s2_size);
}

/* Keep userland pid and ignore tid */
static u32 bpf_get_pid()
{
    return (u32)(bpf_get_current_pid_tgid() >> 32);
}

/* Keep userland tid and ignore pid */
static u32 bpf_get_tid()
{
    return (u32)(bpf_get_current_pid_tgid());
}

/* Return 0 if the filter is OK */
static int filter()
{
#ifdef SIGSNOOP_PID
    return bpf_get_pid() == SIGSNOOP_PID ? 0 : -1;
#elif defined(SIGSNOOP_COMM)
    char comm[TASK_COMM_LEN];
    bpf_get_current_comm(&comm, sizeof(comm));
    return (bpf_strncmp(comm, SIGSNOOP_COMM, TASK_COMM_LEN));
#else
    return 0;
#endif
}

static int push(struct sigsnoopstack *stack)
{
    if (stack->top < SIGSNOOP_STACK_SIZE - 1)
        stack->top++;
    else
        return -1;

    struct sigsnoopinfo *info = stacktop(stack);
    if (!info)
        return -2;

    info->signal = 0;
    info->code = 0;
    info->errno = 0;
    info->overhead = 0;

    return 0;
}

static int pop(struct sigsnoopstack *stack)
{
    /* We allow -1 for an empty stack */
    if (stack->top > -1)
        stack->top--;
    else
        return -1;

    return 0;
}

/* Get the top of a signal stack */
static struct sigsnoopinfo *stacktop(struct sigsnoopstack *stack)
{
    if (!stack)
        return NULL;

    /* Soothe the verifier */
#pragma unroll
    for (int i = 0; i < SIGSNOOP_STACK_SIZE; i++)
    {
        if (stack->top == i)
            return &stack->info[i];
    }

    return NULL;
}

/* BPF programs below this line ------------------------------ */

/* Signal handler setup and entry */
int kprobe__do_signal(struct pt_regs *ctx)
{
    if (filter())
        return 0;

    int zero = 0;
    u32 tid = bpf_get_tid();

    /* Try to initialize an entry in signal_stacks */
    struct sigsnoopstack *stack = __sigsnoopstack_init.lookup(&zero);
    if (!stack)
        return -1;
    /* Set top to -1 to indicate empty stack */
    stack->top = -1;
    stack = signal_stacks.lookup_or_init(&tid, stack);
    if (!stack)
        return -2;

    /* Set comm and pid */
    bpf_get_current_comm(stack->comm, sizeof(stack->comm));
    stack->pid = bpf_get_pid();

    push(stack);
    struct sigsnoopinfo *info = stacktop(stack);
    if (!info)
        return -3;
    info->overhead = bpf_ktime_get_ns();

    return 0;
}

/* Hack to populate ksignal */
int kprobe__get_signal(struct pt_regs *ctx, struct ksignal *ksig)
{
    if (filter())
        return 0;

    int zero = 0;
    struct addr_struct addr = {};

    addr.addr = (void *)ksig;
    addrs.update(&zero, &addr);

    return 0;
}

/* Hack to populate ksignal */
int kretprobe__get_signal(struct pt_regs *ctx)
{
    if (filter())
        return 0;

    int zero = 0;
    u32 tid = bpf_get_tid();

    struct addr_struct *addr = addrs.lookup(&zero);
    if (!addr)
        return -1;

    struct ksignal *ksig = (struct ksignal *)addr->addr;
    if (!ksig)
        return -2;

    struct sigsnoopstack *stack = signal_stacks.lookup(&tid);
    if (!stack)
        return -3;

    struct sigsnoopinfo *info = stacktop(stack);
    if (!info)
        return -4;

    /* Populate signal information */
    info->signal = ksig->info.si_signo;
    info->code   = ksig->info.si_code;
    info->errno  = ksig->info.si_errno;

    /* Cleanup addr struct */
    addrs.delete(&zero);

    return 0;
}

/* Pop sigsnoopinfo struct from the stack and return data to userspace */
TRACEPOINT_PROBE(syscalls, sys_enter_rt_sigreturn)
{
    if (filter())
        return 0;

    int zero = 0;
    u32 tid = bpf_get_tid();

    struct sigsnoopstack *stack = signal_stacks.lookup(&tid);
    if (!stack)
        return -3;

    struct sigsnoopinfo *info = stacktop(stack);
    if (!info)
        return -4;

    /* Calculate overhead */
    info->overhead = bpf_ktime_get_ns() - info->overhead;

    struct __event event = {};
    event.signal = info->signal;
    event.code = info->code;
    event.errno = info->errno;
    event.overhead = info->overhead;
    event.pid = stack->pid;
    bpf_probe_read_str(event.comm, sizeof(stack->comm), stack->comm);

    sig_return_events.perf_submit((struct pt_regs *)args, &event, sizeof(event));

    pop(stack);

    return 0;
}

/* Reap signal stack when a process or thread exits */
TRACEPOINT_PROBE(sched, sched_process_exit)
{
    u32 tid = bpf_get_tid();
    signal_stacks.delete(&tid);

    return 0;
}
