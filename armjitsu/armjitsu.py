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
ARM_CODE1 = b"\x37\x00\xa0\xe3\x03\x10\x42\xe0" # mov r0, #0x37; sub r1, r2, r3


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
    """ArmCPU Class acts as primary emulator for ARM code.

    """
    def __init__(self, address, code):

        self.code = code
        self.base_address = address
        self.break_points = {}
        self.sys_calls = []

        self.running = False
        self.on_breakpoint = False
        self.set_bp_hook = False

        try:

            # Init our ARM emulator with code at given address
            self.emu = Uc(UC_ARCH_ARM, UC_MODE_ARM)
            self.emu.mem_map(self.address, 2 * 1024 * 1024)
            self.emu.mem_write(self.address,self.code)

            # initialize machine registers
            # self.emu.reg_write(UC_ARM_REG_R0, 0x0)
            # self.emu.reg_write(UC_ARM_REG_R2, 0x0)
            # self.emu.reg_write(UC_ARM_REG_R3, 0x0)
            self.emu.reg_write(UC_ARM_REG_APSR, 0x000000) #All application flags turned on

            # Set up hooks
            self.emu.hook_add(UC_HOOK_CODE, hook_code_dbg_break, user_data=self.break_points)

        except UcError as e:
            print "ERROR: %s", e


    def dump_state(self):
        self.__dump_regs()

    def run(self):
        # Begin execution
        if not self.running:
            self.running = True
            self.emu.emu_start(self.address, self.address + len(self.code))

    def stop(self):

        try:
            self.emu.emu_stop()
        except UcError as e:
            print "[-] Error: %s" % e


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
    maxrepeats = 3
    Cmd.settable.append('maxrepeats')
    prompt = "(armjitsu) "
    ruler = "-"

    # Our instance of ArmDBG
    arm_dbg = ArmCPU(address=0x10000, ARM_CODE2)

    global BREAK_HIT

    def do_EOF(self, line):
        return True

    # --- Implement supported commands

    def do_exit(self, line):
        print "Exiting..."
        if ArmjitsuCmd.arm_dbg.cpu.emu_running:
            ArmjitsuCmd.arm_dbg.stop()
        return True

    def do_run(self, line):
        if BREAK_HIT:
            arm_dbg.cpu.context_restore()
            arm_dbg.cpu.emu_start()

        arm_dbg.run()

    def do_stop(self, line):
        if arm_dbg.emu_running:
           arm_dbg.stop()
        else:
            print "[*] Emulation already halted..."

    def do_continue(self, line):
        pass

    def do_break(self, line):
        address = int(line, 16)
        arm_dbg.set_bp(address)


    def do_info(self, line):
        pass

    def do_regs(self, line):
        ArmjitsuCmd.arm_dbg.regs()



# -- Hooks
def hook_code(uc, address, size, user_data):
    print(">>> Tracing instruction at 0x%x, instruction size = 0x%x" %(address, size))
    # read this instruction code from memory
    tmp = uc.mem_read(address, size)
    print "*** EIP = %x *** :" %(address),
    for i in tmp:
        print " %02x" %i
    print("")


def hook_code_syscall(uc, addresas, size, user_data):
    pass

def hook_code_dbg_break(uc, address, size, user_data):

    global BREAK_HIT

    if address in user_data.values():

        BREAK_HIT = True
        try:
            print "BREAK POINT HIT @ filler"
            tmp = uc.mem_read(address, size)
            print "*** PC = %x *** :" %(address),
            for i in tmp:
                print " %02x" %i
            print("")
            user_in = raw_input("Continue? ")
            BREAK_HIT = True
        except UcError as e:
            print "ERROR: %s", e
    return True


def hook_code_dbg_step(uc, address, size, user_data):
    pass

def main(args):

    # Obviously all will be refactored heavily

    global ARM_CODE1
    if len(args) > 1:
        print "[*] Reading ARM code from file..."
        fd = open(args[1], "rb")
        ARM_CODE1 = fd.read()
        fd.close()

    print "Welcome to ARMjitsu - The simple ARM emulator!\n"

    # Command dispatch loop
    a = ArmjitsuCmd()
    a.cmdloop()


if __name__ == "__main__":

    main(sys.argv)
