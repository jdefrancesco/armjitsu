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

        # Store code
        self.code = code
        # Where our code execution will begin
        self.pc = address
        # Where execution ends...
        self.end_addr = self.pc + len(self.code)

        self.break_points = {}
        self.sys_calls = []

        self.strop_now = False
        self.is_running = False
        self.registers = {}

        # Jump tracking state
        self._prev = None
        self._prevsize = None
        self._curr = None


        try:

            # Init our ARM emulator with code at given address
            self.emu = Uc(UC_ARCH_ARM, UC_MODE_ARM)
            self.emu.mem_map(self.pc, 2 * 1024 * 1024)
            self.emu.mem_write(self.pc, self.code)

            self.emu.reg_write(UC_ARM_REG_APSR, 0x000000) #All application flags turned on

            self.emu.hook_add(UC_HOOK_CODE, self.trace_hook)
            self.emu.hook_add(UC_HOOK_BLOCK, self.hook_block)
            self.emu.hook_add(UC_HOOK_INTR, self.hook_interrupt)
            self.emu.hook_add(UC_HOOK_MEM_WRITE, self.hook_mem_access)
            self.emu.hook_add(UC_HOOK_MEM_READ, self.hook_mem_access)

        except UcError as e:
            print "ERROR: %s", e


    def cmd_run(self):
        try:
            self.emu.emu_start(self.start_addr, self.end_addr)
        except UcError as e:
            self.emu.emu_stop()
            return

        if self.get_pc() == self.end_addr:
            print "Ending execution..."
        return

    def cmd_stop(self):

        del self.emu
        self.emu = None
        self.is_running = False

    def cmd_dumpregs(self):
        print self._dump_regs()

    def cmd_set_bp(self, address=None):
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

    def cmd_get_regs(self):
        pass


    def get_pc(self):
        return self.emu.reg_read(UC_ARM_REG_PC)

    def get_sp(self):
        return self.emu.reg_read(UC_ARM_REG_SP)

    def update_pc(self, pc=None):
        """"update_pc() updates PC register with a value supplied as an argument.

        Args:
            pc(int): Address to update PC with.

        Returns:
            Current value of PC register

        Side Effects:
            PC of emulator is updated, thus execution flow may change.

        """
        if pc is None:
            pc = self.emu.reg_read(UC_ARM_REG_PC)
        self.emu.reg_write(UC_ARM_REG_PC, pc)

        return self.emu.reg_read(UC_ARM_REG_PC)

    def dump_state(self):
        """dump_state() dumps state of emulation machine.

        This method should dump the context of the emulator. Register values, backtrace, and current instructions executed
        should all be printed to screen output.


        Side Effects:
            Dumps emulator context to screen.

        Example:
            >>> inst.dump_state()
            ... REG VALUES, BACKTRACE, INSTRUCTIONS

        """
        self._dump_regs()


#     def single_step(self, pc=None):
#         self._singlestep = (None, None)

#         pc = pc or self.pc

#         try:
#             self.emu.hook_add(UC_HOOK_CODE, self.single_step_hook_code)
#         except UcError as e:
#             self._singlestep = (None, None)

#         return self._singlestep


#     def single_step_iter(self, pc=None):
#         s = self.single_step(pc)
#         while s:
#             yield s
#             s = self.single_step(pc)


#     def single_step_hook_code(self, uc, address, size, user_data):
#         print "Single stepping: 0x{:08}".format(address)
#         self._singlestep = (address, size)


    def trace_hook(self, uc, address, size, user_data):
        try:
            # Tell user we have hit entry

            # Ask for  - Continue,
            print "TRACE @ 0x{:08x}".format(address)
            mem_tmp = uc.mem_read(address, size)
            print "*** PC = %x *** :" %(address),
            for i in mem_tmp:
                print " %02x" %i
            print("")
        except UcError as e:
            print "ERROR: %s", e

        return True


    def _dump_regs(self):
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



class ArmjitsuCmd(Cmd):
    """
    Command loop when ran without args

    """

    # cmd2 properties
    prompt = "(armjitsu) "
    ruler = "-"

    global ARM_CODE2
    # Our instance of ArmDBG
    arm_dbg = ArmCPU(0x10000, ARM_CODE2)


    def do_EOF(self, line):
        return True

    # --- Implement supported commands

    def do_exit(self, line):
        print "Exiting..."
        Armjitsu.arm_dbg.cmd_stop()
        return True

    def do_run(self, line):
        if not ArmjitsuCmd.arm_dbg.is_running:
            ArmjitsuCmd.arm_dbg.is_running = True

        ArmjitsuCmd.arm_dbg.cmd_run()

    def do_stop(self, line):
        if not ArmjitsuCmd.arm_dbg.is_running:
            return
        ArmjitsuCmd.arm_dbg.cmd_stop()


    def do_dumpregs(self, line):
        ArmjitsuCmd.arm_dbg.cmd_dumpregs()

    def do_continue(self, line):
        pass

    def do_break(self, line):
        address = int(line, 16)
        ArmjitsuCmd.arm_dbg.set_bp(address)

    def do_info(self, line):
        pass

    def do_regs(self, line):
        ArmjitsuCmd.arm_dbg.regs()





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


