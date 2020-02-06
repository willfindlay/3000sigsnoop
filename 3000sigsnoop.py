#! /usr/bin/env python3

# 3000sigsnoop: Snooping all signals sent to a pid/comm
# Copyright (C) 2020  William Findlay
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <https://www.gnu.org/licenses/>.

# The BPF program used here is based on memleak.py from bcc tools:
# https://github.com/iovisor/bcc/blob/master/tools/memleak.py

import os, sys
import argparse
import time
import signal
import atexit

from bcc import BPF

# Path to the BPF program source file
PROJECT_PATH = os.path.dirname(os.path.realpath(__file__))
BPF_PROGRAM_PATH = os.path.realpath(os.path.join(PROJECT_PATH, 'bpf_program.c'))

DESCRIPTION = """
Snooping all signals sent to a pid/comm.
Created by William Findlay for teaching purposes.
"""
EPILOG = """
Example usage:
    sudo ./3000sigsnoop.py --comm ls   # Trace all signals sent to ls
    sudo ./3000sigsnoop.py --pid 12374 # Trace all signals sent to pid 12374
"""

def print_formatted_items(*args, header=0):
    """
    Print items according to the specified row format.
    """
    row_format = "{:<16}  {:>10}  {:>10}  {:>5}  {:>5}  {:>16}"
    s = row_format.format(*args)
    print(s)
    if header:
        print('-' * len(s))

def on_exit(bpf):
    """
    Run exit hooks.
    Register this with atexit below.
    """
    print("All done!", file=sys.stderr)

def trace_print(bpf):
    """
    A non-blocking version of bcc's trace_print.
    """
    while True:
        fields = bpf.trace_fields(nonblocking=True)
        msg = fields[-1]
        if msg == None:
            return
        print(msg.decode('utf-8'), file=sys.stderr)

def register_perf_buffers(bpf):
    """
    Register perf buffers with BPF program.
    """
    def sig_enter_events(cpu, data, size):
        # Read event data from perf buffer
        v = bpf["sig_enter_events"].event(data)

    bpf["sig_enter_events"].open_perf_buffer(sig_enter_events, page_cnt=2**5)

    def sig_return_events(cpu, data, size):
        # Read event data from perf buffer
        v = bpf["sig_return_events"].event(data)

        comm = v.comm.decode('utf-8')

        # Print information
        print_formatted_items(comm, v.pid, signal.Signals(v.signal).name, v.code, v.errno, v.overhead / (10 ** 9))
    bpf["sig_return_events"].open_perf_buffer(sig_return_events, page_cnt=2**5)

if __name__ == '__main__':
    # Parse arguments
    parser = argparse.ArgumentParser(description=DESCRIPTION, epilog=EPILOG, formatter_class=argparse.RawDescriptionHelpFormatter)
    filters = parser.add_mutually_exclusive_group()
    filters.add_argument('--pid', type=int,
            help='trace a specific pid')
    filters.add_argument('--comm', type=str,
            help='trace a specific comm')
    args = parser.parse_args()

    # Check for root
    if not (os.geteuid() == 0):
        parser.error("This script must be run with root privileges! Exiting.")

    # Register signal handlers that invoke sys.exit
    signal.signal(signal.SIGTERM, lambda x, y: sys.exit(0))
    signal.signal(signal.SIGINT, lambda x, y: sys.exit(0))

    # Read bpf program
    with open(BPF_PROGRAM_PATH, 'r') as f:
        text = f.read()

    # Set flags
    flags = []
    flags.append(f"-I{PROJECT_PATH}")
    if args.pid:
        flags.append(f"-DSIGSNOOP_PID={args.pid}")
    if args.comm:
        flags.append(f"-DSIGSNOOP_COMM=\"{args.comm}\"")

    # Load bpf program
    bpf = BPF(text=text, cflags=flags)
    pid = -1 if not args.pid else args.pid
    register_perf_buffers(bpf)
    atexit.register(on_exit, bpf)

    print("Tracing signals, ctrl-c to quit...", file=sys.stderr)
    print_formatted_items("COMM (RECV)", "PID (RECV)", "SIGNAL", "CODE", "ERRNO", "OVERHEAD (S)", header=1)
    while True:
        trace_print(bpf)
        bpf.perf_buffer_poll()
        time.sleep(1)
