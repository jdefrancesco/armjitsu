"""armcpu.py moodule

Supplies ArmCPU() class which wraps a unicorn emulator object for more fine grain control
over a possible emulation session.
"""
# pylint: skip-file
__author__ = "Joey DeFrancesco"

import logging

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


#TODO: For next time I code. Add disassembly of instructions via capstone. Also we may need to store emulation mode
# so it can be updated every instruction. ARM can switch from big endian to little and vice-versa. Also for proper disassembly
# we may need to keep close track of working in ARM or THUMB mode. Not sure if unicorn/capstone can handle the dynamic properties ARM can take on

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

        self.was_thumb = False

        # Set code and address variables
        self.code = code
        self.start_addr = address
        self.end_addr = self.start_addr + len(self.code)

        # Variables to control stopping and resuming
        self.is_running = False
        self.use_step_mode = False
        self.stop_now = False

        # Dictionary of registers and memory areas
        self.registers = {}
        self.areas = {}

        # Original start address
        self.saved_start = address

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

        return True


    def emu_init_memory(self):
        """emu_init_memory()"""
        # Map memory sections
        self.emu.mem_map(self.start_addr, 2 * 1024 * 1024)
        self.emu.mem_write(self.start_addr, self.code)

        # Add our hooks..
        self.emu.hook_add(UC_HOOK_CODE, self.main_code_hook)


    def emu_init_registers(self):
        """emu_init_registers() set registers to initial values"""
        self.emu.reg_write(UC_ARM_REG_APSR, 0x00000000) #All application flags turned on


    def emu_map_code(self):
        """emu_map_code()"""
        pass


    def run(self):
        """run() - start emulation.  calling this method."""
        try:
            self.is_running = True
            # if self.was_thumb: self.start_addr |= 1
            self.emu.emu_start(self.start_addr, self.end_addr)
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
        print_header("Register Dump")

        # Dump registers R0 to R9
        for reg in xrange(UC_ARM_REG_R0, UC_ARM_REG_R0 + 10):

            reg_string = "[*] R{:<3d} = 0x{:08x}".format((reg-UC_ARM_REG_R0),
                                                         self.emu.reg_read(reg))

            print reg_string

        print ""

        # Dump registers with alias
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


    def dump_state(self):
        """dump_state() - dumps state of emulation machine.

        This method should dump the context of the emulator. Register values, backtrace,
        and current instructions executed should all be printed to stdout.

        Example:
            >>> inst.dump_state()
            ... REG VALUES, BACKTRACE, INSTRUCTIONS

        """
        pass


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


    def remove_breakpoint(self):
        pass


    def main_code_hook(self, uc, address, size, user_data):
        """Hooks every instruction. This hook handles pausing and resuming
        any emulation event that takes place. Stopping, starting, breakpoint handling, etc
        """

        logger.debug("In main_hook_code. address = 0x{:08x}, size = {}".format(address, size))
        # Read the instruction that is about to execute
        try:
            code = self.emu.mem_read(address, size)
            insn = self.disassemble_instruction(code, address)
        except UcError as err:
            print "ERROR: %s", err


        logger.debug("stop_now = {}".format(self.stop_now))

        if self.stop_now:
            logger.debug("stop_now: {}".format(self.stop_now))
            self.start_addr = self.get_pc()
            # When we pause execution with a thumb inst, we need to resume it in that mode
            # self.was_thumb = True if size == 2 else False
            uc.emu_stop()
            return

        # print out_string
        print "0x{:x}: {:s} {:s}".format(insn.address, insn.mnemonic, insn.op_str)

        # If we are stepping, we set stop_now, so next hook call we pause emulator.
        if self.use_step_mode:
            logger.debug("hit use_step_mode=True!")
            self.stop_now = True

        logger.debug("end of function stop_now = {}".format(self.stop_now))
        return


    # -- Instruction disassembly

    def display_disassembly(self):
        """Display the disassembly of N number of instructions."""
        pass

    def disassemble_instruction(self, code, addr):
        """Disassemble one instruction. The instruction contained at a given address."""
        arch, mode, endian = capstone.CS_ARCH_ARM, capstone.CS_MODE_ARM, capstone.CS_MODE_LITTLE_ENDIAN
        md = capstone.Cs(arch, mode | endian)
        for i in md.disasm(bytes(code), addr):
            return i

    def full_disassembly(self):
        """Disassemble entire ARM binary."""
        pass


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



    # -- Private methods...

    def _next_bp_id(self):
        self.unique_bp_id += 1
        return self.unique_bp_id
