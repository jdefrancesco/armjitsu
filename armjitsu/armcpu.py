"""armcpu.py moodule

Supplies ArmCPU() class which wraps a unicorn emulator object for more fine grain control
over a possible emulation session.
"""
# pylint: skip-file
__author__ = "Joey DeFrancesco"

import logging
import binascii

from unicorn import *
from unicorn.arm_const import *
import capstone

import armjit_const
from ui import *

# pylint: disable-

logger = logging.getLogger(armjit_const.LOGGER_NAME)



class AddressOutOfRange(Exception):
    """AddressOutOfRange Exception for Addresses not valid in code space"""

    def __init__(self, message):
        super(AddressOutOfRange, self).__init__(message)
        self.message = message



class ArmCPU(object):
    """ArmCPU class provides abstraction to unicorn emulation object.

    Args:
        address (int): Base address code will be loaded into and subsequently executed from.
        code (byte array): Actual code to run in emulator.
    """

    # pylint: disable=too-many-instance-attributes
    # Large class will have quite a few control attributes...


    def __init__(self, address, code):


        # Breakpoint related variables
        self.break_points = {}
        self.break_hit = False
        self.break_addr = False


        # Eventually we will implement system calls to emulate usermode
        self.sys_calls = []

        self.unique_bp_id = 0

        # Our emulator object from unicorn
        self.emu = None

        self.thumb_mode = False

        # Set code and address variables
        self.code = code
        self.start_addr = address
        self.end_addr = self.start_addr + len(self.code)

        # self.start_addr will chance is we pause and resume,
        # we should keep the original entry address around.
        self.saved_start = address

        # Variables to control stopping and resuming
        self.is_running = False
        self.use_step_mode = False
        self.stop_now = False

        self.finished_exec = False
        # Dictionary of registers and memory areas
        self.registers = {}
        self.areas = {}

        # Original start address

        # Disassembled code listing
        self.disassembly = {}

        self.emu_init()


    def emu_init(self):
        """emu_init() - called by constructor to setup
        our emulation object.

        Args:
            address(int):
            code(byte array):

        """
        try:
            self.emu = Uc(UC_ARCH_ARM, UC_MODE_ARM)
            self.emu_init_memory()
            self.emu_init_registers()
        except UcError as err:
            print "[-] Error setting up!"
            return False

        self._disassemble_code()
        logger.debug("Finished disassembling code")
        return True


    def emu_init_memory(self):
        """emu_init_memory()"""
        # Map memory sections
        self.emu.mem_map(self.start_addr, 2 * 1024 * 1024)
        self.emu.mem_write(self.start_addr, self.code)

        # Primary UC_HOOK_CODE hook is invoked for ALL instructions.
        # This hook is where most of the emulation control happens!
        self.emu.hook_add(UC_HOOK_CODE, self.main_code_hook)


    def emu_init_registers(self):
        """emu_init_registers() set registers to initial values"""
        self.emu.reg_write(UC_ARM_REG_APSR, 0x00000000)


    def emu_map_code(self):
        """emu_map_code()"""
        pass


    def run(self):
        """run() - start emulation.  calling this method."""
        try:
            self.is_running = True
            if self.thumb_mode: self.start_addr |= 1
            logger.debug("start {}    end {}".format(self.start_addr, self.end_addr))
            self.emu.emu_start(self.start_addr | 1, self.end_addr)
        except UcError as err:
            self.emu.emu_stop()
            return

        if self.get_pc() == self.end_addr:
            print "[+] Ending execution..."
        return


    def stop(self):
        """stop() - stops emulation, unmaps any memory, and destroys emulation object.
        This method could be thought of as a deconstructor usually called before exiting
        armjitsu.
        """
        print "STOPPING"
        self.emu.emu_stop()
        del self.emu
        self.emu = None
        self.is_running = False



    def get_arm_register(self, reg):
        return "UC_ARM_REG_{}".format(reg.upper())


    def update_register_dict(self):
        pass


    def dump_regs(self):
        """dump_regs() - shows user the content of ARM registers."""
        # Dump registers R0 to R9
        for reg in xrange(UC_ARM_REG_R0, UC_ARM_REG_R0 + 10):

            reg_string = "[*] R{:<3d} = 0x{:08x}".format((reg-UC_ARM_REG_R0),
                                                         self.emu.reg_read(reg))
            print reg_string

        # Dump registers with alias
        print ""
        print "[*] SL   = 0x{:08x}".format(self.emu.reg_read(UC_ARM_REG_SL))
        print "[*] FP   = 0x{:08x}".format(self.emu.reg_read(UC_ARM_REG_FP))
        print "[*] IP   = 0x{:08x}".format(self.emu.reg_read(UC_ARM_REG_IP))
        print "[*] SP   = 0x{:08x}".format(self.emu.reg_read(UC_ARM_REG_SP))
        print "[*] LR   = 0x{:08x}".format(self.emu.reg_read(UC_ARM_REG_LR))
        print "[*] PC   = 0x{:08x}".format(self.emu.reg_read(UC_ARM_REG_PC))
        print "[*] CPSR = 0x{:08x}".format(self.emu.reg_read(UC_ARM_REG_CPSR))
        print ""


    def get_pc(self):
        """get_pc() - returns Program Counter register (PC)."""
        return self.emu.reg_read(UC_ARM_REG_PC)


    def get_sp(self):
        """get_sp() - returns Stack Pointer register (SP)."""
        return self.emu.reg_read(UC_ARM_REG_SP)


    def set_breakpoint_address(self, break_addr):
        """Set a breakpoint by address."""
        if  not self.start_addr <= break_addr <= self.end_addr:
            raise AddressOutOfRange("Address is out of .text memory range!")
        else:
            if break_addr not in self.break_points.values():
                bp_id = self._next_bp_id()
                self.break_points[bp_id] = break_addr


    def list_breakpoints(self):
        """List breakpoints."""
        print "Break points:"
        if self.break_points:
            for bp_id, break_addr in self.break_points:
                print "{}: 0x{:08x}".format(bp_id, break_addr)
        else:
            puts(colored.red("No breakpoints currently set."))


    def remove_breakpoint(self):
        pass


    def main_code_hook(self, uc, address, size, user_data):
        """Hooks every instruction. This hook handles pausing and resuming
        any emulation event that takes place. Stopping, starting, breakpoint handling, etc
        """
        if self.finished_exec:
            uc.emu_stop()

        try:
            code = self.emu.mem_read(address, size)
        except UcError as err:
            print "ERROR: %s", err


        if self.stop_now:
            self.start_addr = self.get_pc()
            # When we pause execution with a thumb inst, we need to resume it in that mode
            self.thumb_mode = True if size == 2 else False
            uc.emu_stop()
            return


        logger.debug("address = 0x{:08x}, size = {}".format(address, size))
        (inst_mnemonic, inst_op_str, inst_size) = self.disassembly[address]
        print "0x{:08x}: {:s} {:s}".format(address, inst_mnemonic, inst_op_str)

        # If we are stepping, we set stop_now, so next hook call we pause emulator.
        if self.use_step_mode:
            self.stop_now = True

        if address == self.end_addr:
            self.finished_exec = True

        return


    # -- Instruction disassembly

    def display_disassembly(self):
        """Display the disassembly of N number of instructions."""
        pass


    def full_disassembly(self):
        """Disassemble entire ARM binary."""
        pass

    # TODO: TESTING DISASSEMBLY as GENERATOR!
    def _disassemble_code(self, address=0x10000):
        """Disassembles ARM machine code provided to our emulator."""
        # code = self.code
        # address = self.saved_start
        # md = capstone.Cs(capstone.CS_ARCH_ARM, capstone.CS_MODE_ARM)
        # self.disassembly = { inst.address: (inst.mnemonic, inst.op_str, inst.size)  for inst in md.disasm(code, self.saved_start) }

    # -- End disassembly


    # -- Context methods

    def display_context(self):
        pass


    def context_registers(self):
        pass


    def context_code(self):
        pass


    def context_stack(self):
        pass


    def context_backtrace(self):
        pass


    # -- End Context

    def _next_bp_id(self):
        """Returns a unique integer. Allows us to give IDs to breakpoints."""
        self.unique_bp_id += 1
        return self.unique_bp_id


