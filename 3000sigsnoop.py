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

# Get page size from sysconf
PAGE_SIZE = os.sysconf("SC_PAGE_SIZE")
# Get page shift from page size
PAGE_SHIFT = int(math.log(PAGE_SIZE, 2))

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
    row_format = "{:>8} {:>16} {:>16}"
    if not header:
        row_format += " -> "
    else:
        row_format += "    "
    row_format += "{:<16} {:>8}"
    print(row_format.format(*args))

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
    def sigreturn(cpu, data, size):
        # Read event data from perf buffer
        v = bpf["sigreturn"].event(data)

        # Print information
        #print_formatted_items(v.pid, v.comm.decode('utf-8'))
    bpf["sigreturn"].open_perf_buffer(sigreturn, page_cnt=2**5)

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
        flags.append(f"-DHEAPSNOOP_PID={args.pid}")
    if args.comm:
        flags.append(f"-DHEAPSNOOP_COMM=\"{args.comm}\"")
    if args.debug:
        flags.append(f"-DHEAPSNOOP_DEBUG")

    # Load bpf program
    bpf = BPF(text=text, cflags=flags)
    pid = -1 if not args.pid else args.pid
    attach_uprobes(bpf, "malloc", pid)
    attach_uprobes(bpf, "calloc", pid)
    register_perf_buffers(bpf)
    atexit.register(on_exit, bpf)

    print("Tracing process memory, ctrl-c to quit...", file=sys.stderr)
    print_formatted_items("PID", "COMM", "VIRT ADDR", "PHYS ADDR", "SIZE", header=1)
    while True:
        if args.debug:
            trace_print(bpf)
        bpf.perf_buffer_poll()
        time.sleep(1)
