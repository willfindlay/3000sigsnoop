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

BPF_PERCPU_ARRAY(intermediate, struct sigsnoopinfo, 1);
BPF_PERCPU_ARRAY(addrs, struct addr_struct, 1);
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

/* BPF programs below this line ------------------------------ */

/* Signal handler setup and entry */
int kprobe__do_signal(struct pt_regs *ctx)
{
    if (filter())
        return 0;

    int zero = 0;

    struct sigsnoopinfo data = {};

    bpf_get_current_comm(data.comm, sizeof(data.comm));
    data.pid = bpf_get_pid();
    data.overhead = bpf_ktime_get_ns();

    intermediate.update(&zero, &data);

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

    struct addr_struct *addr = addrs.lookup(&zero);
    if (!addr)
        return -1;

    struct ksignal *ksig = (struct ksignal *)addr->addr;
    if (!ksig)
        return -2;

    struct sigsnoopinfo *data = intermediate.lookup(&zero);
    if (!data)
        return -3;

    /* Populate signal information */
    data->signal = ksig->info.si_signo;
    data->code   = ksig->info.si_code;
    data->errno  = ksig->info.si_errno;

    /* Cleanup */
    addrs.delete(&zero);

    return 0;
}

TRACEPOINT_PROBE(syscalls, sys_enter_rt_sigreturn)
{
    if (filter())
        return 0;

    int zero = 0;

    struct sigsnoopinfo *data = intermediate.lookup(&zero);
    if (!data)
        return -3;

    /* Calculate overhead */
    data->overhead = bpf_ktime_get_ns() - data->overhead;

    sig_return_events.perf_submit((struct pt_regs *)args, data, sizeof(*data));

    intermediate.delete(&zero);

    return 0;
}

