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

#ifndef BPF_PROGRAM_H
#define BPF_PROGRAM_H

#include <linux/sched.h>
#include <linux/signal.h>

#define SIGSNOOP_STACK_SIZE 5
#define SIGSNOOP_MAX_PROCESSES 1000

struct sigsnoopinfo
{
    int signal;
    int code;
    int errno;
    u64 overhead;
};

struct sigsnoopstack
{
    int top;
    struct sigsnoopinfo info[SIGSNOOP_STACK_SIZE];
    u32 pid;
    char comm[TASK_COMM_LEN];
};

struct __event
{
    int signal;
    int code;
    int errno;
    u64 overhead;
    u32 pid;
    char comm[TASK_COMM_LEN];
};

struct addr_struct
{
    void *addr;
};

static struct sigsnoopinfo *stacktop(struct sigsnoopstack *stack);
static int push(struct sigsnoopstack *stack);
static int pop(struct sigsnoopstack *stack);

static inline u32 bpf_strlen(char *s);
static inline int bpf_strncmp(char *s1, char *s2, u32 n);
static inline int bpf_strcmp(char *s1, char *s2);
static u32 bpf_get_pid();
static u32 bpf_get_tid();
static int filter();

#endif /* BPF_PROGRAM_H */
