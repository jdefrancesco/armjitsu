#!/usr/bin/env python

# WARNING: Because I was informed of dead line so suddenly, the code needs major refactoring.
# A lot of this code is axcting just as PoC to meet the deadline. It is functional but not well tested.
# Next revision, with additional funding, I plan to implement the rest of the code-base as I had originally envisioned.

__author__ = "Joey DeFrancesco"
__version__ = "0.1"

# pylint: skip-file

import sys
import argparse
import string
import logging
import unicorn
import time
from binascii import hexlify

from cmd2 import Cmd, make_option, options

import colorful

import armcpu

import armcpu_const
import armjit_const

from ui import *
from utils import *

# Setup logging
LOG_FORMAT = "%(asctime)s:line number %(lineno)s:%(levelname)s - %(message)s"
logging.basicConfig(filename="armjitsu.log", filemode="w", level=logging.DEBUG, format=LOG_FORMAT)
logger = logging.getLogger(armjit_const.LOGGER_NAME)


# Scratch globals for the time being...
ADDRESS = 0x10000

# THUMB_CODE = "\x70\x47\x00\xf0\x10\xe8\xeb\x46\x83\xb0\xc9\x68\x1f\xb1\x30\xbf\xaf\xf3\x20\x84\x52\xf8\x23\xf0"
# ARM_CODE3 = b"\x37\x00\xa0\xe3\x03\x10\x42\xe0"
# ARM_CODE4   = b"\x37\x00\xa0\xe3\x03\x10\x42\xe0" # mov r0, #0x37; sub r1, r2, r3

# Pure ARM code
# ARM_CODE1 = "\xf1\x02\x03\x0e\x00\x00\xa0\xe3\x02\x30\xc1\xe7\x00\x00\x53\xe3"

# All Thumb code
# THUMB_CODE = "\x70\x47\x00\xf0\x10\xe8\xeb\x46\x83\xb0\xc9\x68\x1f\xb1\x30\xbf\xaf\xf3\x20\x84"

# ARM and Thumb instructions mixed
# ARM_MIXED = "\xd1\xe8\x00\xf0\xf0\x24\x04\x07\x1f\x3c\xf2\xc0\x00\x00\x4f\xf0\x00\x01\x46\x6c"

colorful.use_style('solarized')


class ArmjitsuCmd(Cmd):
    """Command dispatch loop"""

    prompt = colorful.bold_green("(armjitsu) ")
    ruler = "-"
    debug = True

    def __init__(self):
        Cmd.__init__(self)

        self.bin_loaded = False
        self.bin_running = False

        self.arm_dbg = None

        if DEBUG_MODE:
            import ipdb; ipdb.set_trace()


    @options([make_option('-l', '--list', action="store_true", help="Show supported binary formats."),
              make_option('-r', '--raw', action="store_true", help="Load ARM RAW/Shellcode from file."),
              make_option('-e', '--elf', action="store_true", help="Load ARM ELF binary from file.")
             ])
    def do_file(self, args, opts=None):
        """
        Load an ARM binary file for emulation and debugging.
        To list ARMjitsu supported binary formats invoke:

        (armjitsu) file --list
        """
        BIN_TYPE = armcpu_const.RAW_BIN
        if opts.raw:
            BIN_TYPE = armcpu_const.RAW_BIN
        elif opts.elf:
            BIN_TYPE = armcpu_const.ELF_BIN

        line = args
        if not line:
            print colorful.yellow("Supply the filename of the binary you wish to load please.")
            return None

        file_name = line if is_file(line) else None
        if not file_name or not BIN_TYPE:
            print colorful.yellow("Error with supplied filename.")
            return False

        self.arm_dbg = armcpu.ArmCPU(file_name, BIN_TYPE)
        self.bin_loaded = True

        print colorful.base1("Loaded binary file: {}".format(file_name))

    # Synonyms for do_file
    do_load = do_file

    # REMOVE AFTER DEV
    def do_testing(self, line):
        self.arm_dbg = armcpu.ArmCPU("armraw.bin", armcpu_const.RAW_BIN)
        self.bin_loaded = True
        print colorful.bold_red("Developer testing mode! armraw.bin loaded!")

        print colorful.base1("Loaded binary file: {}".format(file_name))

    # Synonyms for do_file
    do_load = do_file

    # REMOVE AFTER DEV
    def do_testing(self, line):
        self.arm_dbg = armcpu.ArmCPU("armraw.bin", armcpu_const.RAW_BIN)
        self.bin_loaded = True
        print colorful.bold_red("Developer testing mode! armraw.bin loaded!")

    do_t = do_testing

    def do_run(self, line):
        """Begins execution of ARM binary."""
        if not self.bin_running:
            self.bin_running = True
        else:
            print colorful.yellow("Process is already running.")
            return None

        self.arm_dbg.start_execution()

    do_start = do_run
    do_r = do_run

    def do_continue(self, line):
        """Continue execution from a paused state."""
        self.arm_dbg.continue_execution()

    do_c = do_continue
    do_con = do_continue

    def do_registers(self, line):
        """Display registers."""
        self.arm_dbg.context_registers()

    do_regs = do_registers

    def do_step(self, line):
        self.arm_dbg.stop_next_instruction = False
        self.arm_dbg.use_step_mode = True
        self.arm_dbg.step_execution()

    # TODO: RF - check for error conditions
    def do_x(self, line):
        """Examine memory similar to GDB x/? command"""
        l = line.split()
        byte_count = l[0]
        address = int(l[1], 16)

        # Read memory as byte, half-word, word
        if byte_count == "b":
            size = 1
        elif byte_count == "h":
            size = 2
        elif byte_count == "w":
            size = 4

        # Print our data
        data = self.arm_dbg.read_mem(address, size)
        data_list = []

        for i in data:
            data_list.append("0x{:02x} ".format(i))

        print " ".join(data_list)

    @options([make_option('-l', '--list', action="store_false", help="List all set breakpoints.")])
    def do_break(self, line):
        pass

    def do_snapshot(self, line):
        """ Load/Save a snapshot """
        l = line.split()
        usage = "snapshot load|save ini|file"
        if len(l) != 3:
            print usage
            return

        if l[0] == "load":
            if l[1] == "ini":
                bin_type = armcpu_const.INI_BIN
            elif l[1] == "file":
                bin_type = armcpu_const.SNAPSHOT_BIN
            else:
                print usage
                return
        else:
            print usage
            return

        self.arm_dbg = armcpu.ArmCPU(l[2], bin_type)
        print colorful.bold_green("Loaded snapshot: {}".format(l[2]))

    def do_info(self, line):
        pass

    def do_exit(self, line):
        print "Exiting..."
        return True


class FuzzingFramework(object):
    def __init__(self, snapshot_file, is_ini_file=False):
        self.snapshot_file = snapshot_file
        self.is_ini_file = is_ini_file

        self.timed_out = False
        self.got_exception = False
        self.error_message = None
        self.error_register_state = None

        self._load_snapshot()

    def _load_snapshot(self):
        if self.is_ini_file:
            bin_type = armcpu_const.INI_BIN
        else:
            bin_type = armcpu_const.SNAPSHOT_BIN
            print "Snapshot file not supported yet"
            raise NotImplementedError

        self.arm_dbg = armcpu.ArmCPU(self.snapshot_file, bin_type)

    def reload(self):
        self.timed_out = False
        self.got_exception = False
        self.error_message = None
        self.error_register_state = None
        self._load_snapshot()

    def write(self, addr, data):
        """ Write data to memory location """
        try:
            self.arm_dbg.write_mem(addr, data)
        except unicorn.UcError as e:
            print "Error writing data to 0x{:X}".format(addr)
            print "Unicorn returned: {}".format(e)
            return False

        return True

    def write_exit_bp(self, addr):
        """ End emulation if target address is hit """
        self.arm_dbg.set_breakpoint_address(addr)

    def run(self, timeout):
        try:
            delay = 0.001
            tm = timeout * delay

            self.arm_dbg.start_execution_no_catch()
            while not self.arm_dbg.breakpoint_hit and tm > 0:
                time.sleep(delay)
                tm -= delay

            if tm <= 0:
                self.timed_out = True

        except unicorn.UcError as e:
            self.got_exception = True
            self.error_message = e
            self.error_register_state = self.arm_dbg.context_registers_str()

        self.arm_dbg.stop()

if __name__ == "__main__":

    show_logo()

    DEBUG_MODE = False

    parser = argparse.ArgumentParser(description="ARMulator - ARM 32-bit emulator for instropection into arcane binaries")
    parser.add_argument("-t", "--tui", action="store_true", dest="tui_switch",
                        default=False, help="Launch ARMjitsu with ncurses Textual User Interface")
    parser.add_argument("-l", "--load", type=str, dest="",
                        help="Specify name of ARM binary file to load for emulation.")
    parser.add_argument("-m", "--machine", dest="machine_code", help="Provide raw ARM32 machine code to emulator")
    parser.add_argument("-e", "--emutest", help="For developer use. ARMjitsu will emulate machine code embedded in source.")
    parser.add_argument("-v", "--version", action="version", version="")
    parser.add_argument("-s", "--snapshot", dest="snapshot_file", help="")
    parser.add_argument("-d", "--debug", action="store_true", help="Starts ARMjitsu in debugging mode. For developers only.")
    args = parser.parse_args()

    if args.debug:
        DEBUG_MODE = True

    # Command dispatch loop
    a = ArmjitsuCmd()
    a.cmdloop()


