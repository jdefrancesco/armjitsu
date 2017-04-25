#!/usr/bin/env python

__author__ = "Joey DeFrancesco"
__version__ = "0.1"

# pylint: skip-file

import sys
import argparse
import string
import logging
from cmd2 import Cmd, make_option, options

import colorful

# Move these modules all to ui.py eventually
from fabulous import image, utils, text

import armcpu
import armjit_const
from ui import *

# Setup logging
LOG_FORMAT = "%(asctime)s:line number %(lineno)s:%(levelname)s - %(message)s"
logging.basicConfig(filename="armjitsu.log", filemode="w", level=logging.DEBUG, format=LOG_FORMAT)
logger = logging.getLogger(armjit_const.LOGGER_NAME)


# Scratch globals for the time being...
ADDRESS = 0x10000

#
# THUMB_CODE = "\x70\x47\x00\xf0\x10\xe8\xeb\x46\x83\xb0\xc9\x68\x1f\xb1\x30\xbf\xaf\xf3\x20\x84\x52\xf8\x23\xf0"
#
# THUMB_CODE2 = ("\x4f\xf0\x00\x01\xbd\xe8\x00\x88\xd1\xe8\x00\xf0\x18\xbf\xad\xbf\xf3\xff\x0b\x0C"
# "\x86\xf3\x00\x89\x80\xf3\x00\x8c\x4f\xfa\x99\xf6\xd0\xff\xa2\x01")
# ARM_CODE3 = b"\x37\x00\xa0\xe3\x03\x10\x42\xe0"
# ARM_CODE4   = b"\x37\x00\xa0\xe3\x03\x10\x42\xe0" # mov r0, #0x37; sub r1, r2, r3

# Pure ARM code
# ARM_CODE1 = "\xED\xFF\xFF\xEB\x04\xe0\x2d\xe5\x00\x00\x00\x00\xe0\x83\x22\xe5\xf1\x02\x03\x0e\x00\x00\xa0\xe3\x02\x30\xc1\xe7\x00\x00\x53\xe3\x00\x02\x01\xf1\x05\x40\xd0\xe8\xf4\x80\x00\x00"
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



# TODO: Move this to ui.py
def show_banner():
    """Show the armjitsu banner logo."""
    print image.Image("../images/armjit-logo.png", width=150)


class ArmjitsuCmd(Cmd):
    """Command dispatch loop"""

    prompt = "(armjitsu) "
    ruler = "-"

    def __init__(self):
        Cmd.__init__(self)
        self.arm_dbg = armcpu.ArmCPU(0x10000, ARM_CODE4)


    def do_EOF(self, line):
        return True


    # --- Implement supported commands

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
        banner("Registers")
        self.arm_dbg.dump_regs()

    def do_step(self, line):
        if self.arm_dbg.finished_exec:
            print ""
        self.arm_dbg.use_step_mode = True
        self.arm_dbg.stop_now = False
        self.arm_dbg.run()


    def do_break(self, line):
        # break_input = int(line, 16)
        # self.arm_dbg.run()
        # self.arm_dbg.set_breakpoint_address(break_input)
        pass

    def do_info(self, line):
        pass

    def do_exit(self, line):
        print "Exiting..."
        # TODO: Gracefully clean up and destruct ArmCPU Emulation instance
        sys.exit(0)


if __name__ == "__main__":


    show_banner()

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


