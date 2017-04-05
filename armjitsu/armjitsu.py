#!/usr/bin/env python

__author__ = "Joey DeFrancesco"
__version__ = "0.1"

import sys
import argparse
import string
from cmd2 import Cmd, make_option, options

import armcpu
from misc_utils import *


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




class ArmjitsuCmd(Cmd):
    """Command dispatch loop"""

    # cmd2 properties
    prompt = "(armjitsu) "
    ruler = "-"

    def do_EOF(self, line):
        return True

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

    print "Welcome to ARMjitsu - The simple ARM emulator!\n"

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


