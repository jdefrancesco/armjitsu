#!/usr/bin/env python

__author__ = "Joey DeFrancesco"
__version__ = "0.1"

# pylint: skip-file

import sys
import argparse
import string
import logging
from binascii import hexlify
from cmd2 import Cmd, make_option, options

import colorful

import armcpu
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



ARM_CODE4 = ("\x01\x60\x8f\xe2"
"\x16\xff\x2f\xe1"
"\x40\x40"
"\x78\x44"
"\x0c\x30"
"\x49\x40"
"\x52\x40"
"\x0b\x27"
"\x01\xdf"
"\x01\x27"
"\x01\xdf"
"\x2f\x2f"
"\x62\x69\x6e\x2f"
"\x2f\x73"
"\x68")




class ArmjitsuCmd(Cmd):
    """Command dispatch loop"""

    prompt = colorful.bold_white("(armjitsu) ")
    ruler = "-"

    # Init with code in source for development etc...
    # Eventually this will be where we read in code from file
    def __init__(self):
        Cmd.__init__(self)

        self.arm_dbg = None
        self.code = None


    def do_EOF(self, line):
        return True


    # --- Implement supported commands

    def do_file(self, line):
        if not line:
            print "Supply a file name please!"
            return

        file_name = line
        try:
            self.code = read_bin_file(file_name)
        except IOError as e:
            print "[-] Error reading code from file!"

        self.arm_dbg = armcpu.ArmCPU(self.code)
        print colorful.bold_green("Loaded binary file: {}".format(file_name))


    def do_run(self, line):
        banner("Running")
        self.arm_dbg.use_step_mode = False
        self.arm_dbg.stop_now = False
        self.arm_dbg.run()


    def do_continue(self, line):
        self.arm_dbg.use_step_mode = False
        self.arm_dbg.stop_now = False
        self.arm_dbg.run()


    def do_regs(self, line):
        """Display registers."""
        banner("Registers")
        self.arm_dbg.dump_regs()


    def do_step(self, line):
        self.arm_dbg.use_step_mode = True
        self.arm_dbg.stop_now = False
        self.arm_dbg.run()


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


    # TODO: Fix up
    def do_break(self, line):
        break_input = int(line, 16)
        logger.debug("".format(self.arm_dbg.break_points))
        self.arm_dbg.set_breakpoint_address(break_input)


    def do_blist(self, line):
        print colorful.bold_orange(self.arm_dbg.list_breakpoints())


    def do_info(self, line):
        pass


    def do_exit(self, line):
        print "Exiting..."
        return True

if __name__ == "__main__":


    show_logo()

    parser = argparse.ArgumentParser(description="ARMulator - ARM 32-bit emulator for instropection into arcane binaries")
    parser.add_argument("-t", "--tui", action="store_true", dest="tui_switch",
                        default=False, help="Launch ARMjitsu with ncurses Textual User Interface")
    parser.add_argument("-l", "--load", type=str, dest="",
                        help="Specify name of ARM binary file to load for emulation.")
    parser.add_argument("-m", "--machine", dest="machine_code", help="Provide raw ARM32 machine code to emulator")
    parser.add_argument("-e", "--emutest", help="For developer use. ARMjitsu will emulate machine code embedded in source.")
    parser.add_argument("-v", "--version", action="version", version="")
    parser.add_argument("-s", "--snapshot", dest="snapshot_file", help="")

    results = parser.parse_args()

    # Command dispatch loop
    a = ArmjitsuCmd()
    a.cmdloop()


