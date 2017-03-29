#!/usr/bin/env python

import sys
import argparse
import string

from cmd2 import Cmd, make_option, options

from capstone import *
from unicorn import *
from unicorn.arm_const import *

from misc_utils import *

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


BREAK_HIT = False
EMULATION_STOPPED = False


class ArmCPU(object):
    """ArmCPU class provides abstraction to unicorn emulation object.

    Args:
        address (int): Base address code will be loaded into and subsequently executed from.
        code (byte array): Actual code to run in emulator.

    Attributes:
        code (str): Human readable string describing the exception.
        pc (int): Exception error code.
        break_points(dict):
        sys_calls(list):

    """


    def __init__(self, address, code):

        self.code = code

        # Where our code execution will begin
        self.pc = address

        self.break_points = {}
        self.sys_calls = []

        self.running = False

        # Are we currently on breakpoint?
        self.on_breakpoint = False
        self.set_bp_hook = False

        # Jump tracking state
        self._prev = None
        self._prevsize = None
        self._curr = None

        try:

            # Init our ARM emulator with code at given address
            self.emu = Uc(UC_ARCH_ARM, UC_MODE_ARM)
            self.emu.mem_map(self.address, 2 * 1024 * 1024)
            self.emu.mem_write(self.address, self.code)

            self.emu.reg_write(UC_ARM_REG_APSR, 0x000000) #All application flags turned on

        except UcError as e:
            print "ERROR: %s", e

        # Set up hooks
        self.hook_add(UC_HOOK_CODE, hook_code_trace, user_data=self.break_points)

    def start(self, *args, **kwargs):
        if not self.running:
            self.running = True
            try:
                return self.emu.emu_start(*args, **kwargs)
            except UcError as e:
                print "[-] Error: %s" % e


    def stop(self, *args, **kwargs):
        if self.running:
            self.running = False
            try:
                return self.emu.emu_stop(*args, **kwargs)
            except UcError as e:
                print "[-] Error: %s" % e


    def update_pc(self, pc=None):
        if pc is None:
            self.pc = self.emu.reg_read(UC_ARM_REG_PC)

    def dump_state(self):
        self.__dump_regs()

    def single_step(self, pc=None):
        self._singlestep = (None, None)

        pc = pc or self.pc

        try:
            self.emu.hook_add(UC_HOOK_CODE, self.single_step_hook_code)
        except UcError as e:
            self._singlestep = (None, None)

        return self._singlestep

    def single_step_iter(self, pc=None):
        s = self.single_step(pc)
        while s:
            yield s
            s = self.single_step(pc)

    def single_step_hook_code(self, uc, address, size, user_data):
        self._singlestep = (address, size)


    def set_bp(self, address=None):
        """set_bp

        set break point by address.
        """

        if not address:
            print "[*] Specify address where break point should be set"
            return

        if address not in self.break_points.values():
            self.break_points[self.id] = address
            self.id += 1
            print "Setting breakpoint {} = {}".format(self.id, address)

    # -- Methods to add and remove hooks

    def hook_add(self, *a, **kw):
        return self.emu.hook_add(*a, **kw)

    def hook_del(self, *a, **kw):
        return self.emu.hook_del(*a, **kw)


    # -- Our "private" methods

    def __dump_regs(self):
        """dump_regs method

        Dump state of ARM registers to stdout
        """

        # Dump our special named registers first
        print "[*] SL = 0x{:08x}".format(self.emu.reg_read(UC_ARM_REG_SL))
        print "[*] FP = 0x{:08x}".format(self.emu.reg_read(UC_ARM_REG_FP))
        print "[*] IP = 0x{:08x}".format(self.emu.reg_read(UC_ARM_REG_IP))
        print "[*] SP = 0x{:08x}".format(self.emu.reg_read(UC_ARM_REG_SP))
        print "[*] LR = 0x{:08x}".format(self.emu.reg_read(UC_ARM_REG_LR))
        print "[*] PC = 0x{:08x}".format(self.emu.reg_read(UC_ARM_REG_PC))
        print "[*] CPSR = 0x{:08x}".format(self.emu.reg_read(UC_ARM_REG_CPSR))

        print ""

        # Dump R based registers
        for reg in xrange(UC_ARM_REG_R0, UC_ARM_REG_R0 + 14):
            print_string = "[*] R{:<3d} = 0x{:08x}".format((reg-UC_ARM_REG_R0), self.emu.reg_read(reg))
            print print_string

        print ""





class ArmjitsuCmd(Cmd):
    """
    Command loop dispatching, this is how user interacts with out emulator

    """

    # cmd2 properties
    prompt = "(armjitsu) "
    ruler = "-"

    # Our instance of ArmDBG
    arm_dbg = ArmCPU(address=0x10000, ARM_CODE2)


    def do_EOF(self, line):
        return True

    # --- Implement supported commands

    def do_exit(self, line):
        print "Exiting..."
        return True

    def do_run(self, line):
        ArmjitsuCmd.arm_dbg.start()

    def do_stop(self, line):
        pass

    def do_continue(self, line):
        pass

    def do_break(self, line):
        address = int(line, 16)
        ArmjitsuCmd.arm_dbg.set_bp(address)

    def do_info(self, line):
        pass

    def do_regs(self, line):
        ArmjitsuCmd.arm_dbg.regs()



def hook_code_trace(uc, address, size, user_data):

    # Handle breakpoints
    if address in user_data.values():
        try:
            print "BREAK POINT HIT @ 0x{:08x}".format(address)
            mem_tmp = uc.mem_read(address, size)
            print "*** PC = %x *** :" %(address),
            for i in mem_tmp:
                print " %02x" %i
            print("")
        except UcError as e:
            print "ERROR: %s", e


    return True


def hook_code_dbg_step(uc, address, size, user_data):
    pass

def main(args):

    # argument parsing

    print "Welcome to ARMjitsu - The simple ARM emulator!\n"

    parser = argparse.ArgumentParser(description="ARMulator - ARM 32-bit emulator for instropection into arcane binaries")

    parser.add_argument("-t", "--tui", action="store_true", dest="tui_switch",
                        default=False, help="Launch ARMjitsu with ncurses Textual User Interface")
    parser.add_argument("-l", "--load", type=str, dest="",
                        help="Specify name of ARM binary file to load for emulation.")
    parser.add_argument("-m", "--machine", dest="machine_code", help="Provide raw ARM32 machine code to emulator")
    parser.add_argument("-e", "--emutest", help="For developer use. ARMjitsu will emulate machine code embedded in source.")
    parser.add_argument("-v", "--version", action="version", version="")
    parser.add_arguments("-s", "--snapshot", dest="snapshot_file", help="")

    results = parser.parse_args()


    # Command dispatch loop
    a = ArmjitsuCmd()
    a.cmdloop()


if __name__ == "__main__":

    main(sys.argv)
