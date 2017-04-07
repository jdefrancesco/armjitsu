#!/usr/bin/env python

__author__ = "Joey DeFrancesco"
__version__ = "0.1"

# pylint: skip-file

import sys
import argparse
import string
import logging
from cmd2 import Cmd, make_option, options

from clint.textui import puts, indent, colored
from fabulous import image

import armcpu
import armjit_const
from misc_utils import *

# Setup logging
LOG_FORMAT = "%(asctime)s:line number %(lineno)s:%(levelname)s - %(message)s"
logging.basicConfig(filename="armjitsu.log", filemode="w", level=logging.INFO, format=LOG_FORMAT)
logger = logging.getLogger(armjit_const.LOGGER_NAME)

# Scratch globals for the time being...
ADDRESS = 0x10000

ARM_CODE2 = ("\x01\x60\x8f\xe2"
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


def show_banner():
    """Show the armjitsu banner logo."""
    print image.Image("../images/armjit-logo.png")


class ArmjitsuCmd(Cmd):
    """Command dispatch loop"""

    # cmd2 properties
    prompt = colored.green("(armjitsu) ")
    ruler = "-"


    def __init__(self):
        Cmd.__init__(self)


    def do_EOF(self, line):
        return True

    # Will remove when I provide loading file, this is just to test
    def do_init(self, line):
        self.arm_dbg = armcpu.ArmCPU(0x10000, ARM_CODE2)


    # --- Implement supported commands

    def do_run(self, line):
        new_line()
        self.arm_dbg.use_step_mode = False
        self.arm_dbg.stop_now = False
        self.arm_dbg.run()

    def do_continue(self, line):
        self.arm_dbg.run()

    def do_regs(self, line):
        self.arm_dbg.dump_regs()

    def do_step(self, line):
        self.arm_dbg.use_step_mode = True
        self.arm_dbg.stop_now = False
        self.arm_dbg.run()


    def do_break(self, line):
        pass

    def do_info(self, line):
        pass

    def do_exit(self, line):
        print "Exiting..."
        return True


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


