#!/usr/bin/env python

import sys
import argparse
import string

from cmd2 import Cmd, make_option, options

import armcpu


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
    """
    Command loop when ran without args

    """

    # cmd2 properties
    prompt = "(armjitsu) "
    ruler = "-"

    def do_EOF(self, line):
        return True

    def do_init(self, line):
        self.arm_dbg = armcpu.ArmCPU(0x10000, ARM_CODE2)

    # --- Implement supported commands

    def do_exit(self, line):
        print "Exiting..."
        return True

    def do_run(self, line):
        self.arm_dbg.use_step_mode = False
        self.arm_dbg.stop_now = False
        self.arm_dbg.run()

    def do_continue(self, line):
        self.arm_dbg.contiue_exec()

    def do_stop(self, line):
        pass

    def do_regs(self, line):
        self.arm_dbg.dumpregs()

    def do_break(self, line):
        pass

    def do_info(self, line):
        print self.arm_dbg.is_running
        print hex(self.arm_dbg.saved_pc)



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


