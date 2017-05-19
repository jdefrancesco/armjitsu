"""armcpu.py moodule
Supplies ArmCPU() class which wraps a unicorn emulator object for more fine grain control
over a possible emulation session.
"""

# WARNING: Because I was informed of dead line so suddenly, the code needs major refactoring.
# A lot of this code is axcting just as PoC to meet the deadline. It is functional but not well tested.
# Next revision, with additional funding, I plan to implement the rest of the code-base as I had originally envisioned.

# pylint: skip-file
__author__ = "Joey DeFrancesco"

import logging
import binascii

from unicorn import *
from unicorn.arm_const import *
import capstone

# import armjit_const
import armjit_const
from ui import *
from utils import *

# pylint: disable-

logger = logging.getLogger(armjit_const.LOGGER_NAME)

class AddressOutOfRange(Exception):
    """AddressOutOfRange Exception for Addresses not valid in code space."""

    def __init__(self, message):
        super(AddressOutOfRange, self).__init__(message)
        self.message = message



class ArmCPU(object):
    """ArmCPU class provides abstraction to unicorn emulation object."""

    # pylint: disable=too-many-instance-attributes
    # Large class will have quite a few control attributes...

    def __init__(self, file_name, bin_type=armjit_const.RAW_BIN):

        self.file_name = file_name
        self.bin_type = bin_type

        # Our emulator object from unicorn
        self.emu = None

        self.code = None
        self.start_addr = 0
        self.end_addr = 0
        self.continue_addr = 0

        self.is_init = False
        self.use_step_mode = False
        self.stop_next_instruction = False

        # Breakpoint related variables
        self.break_points = {}
        self.break_points_enabled = False
        self.unique_bp_id = 0

        # Dictionary of registers and memory areas
        self.registers = {}
        self.thumb_mode = False

        self.mem_regions = []

        self.full_disassembly = {}
        self.show_asm = False

        self.is_init = False

        self.emu_init()


    def emu_init(self):
        """emu_init() - called by constructor to setup
        our emulation object.
        """

        try:

            self.emu = Uc(UC_ARCH_ARM, UC_MODE_ARM)
        except UcError as err:
            print colorful.bold_red("Error creating emulator: {}".format(err))
            return False

        try:
            self.emu_init_memory(self.bin_type)
        except UcError as err:
            print colorful.red("Error initializing memory: {}".format(err))
            return False

        try:
            self.emu_init_hooks()
        except UcError as err:
            print colorful.bold_red("".format(err))
            return False

        # Hook all instructions in order to debug emulation session.
        # self.emu.hook_add(UC_HOOK_CODE, self.main_code_hook)

        self.is_init = True

        return True


    def emu_init_memory(self, bin_type="RAW"):
        """emu_init_memory()"""

        # Map memory sections
        if bin_type == "RAW":

            self.code = read_bin_file(self.file_name)
            self.end_addr = self.start_addr + len(self.code)

           # Map ourselves 2MB for emulation starting at 0x10000
            self.emu.mem_map(self.start_addr, 2 * 1024 * 1024)
            self.emu.mem_write(self.start_addr, self.code)

            # Set our stack 4KB shy of end of address space
            self.emu.reg_write(UC_ARM_REG_SP, 0x20F000)

            return True


        elif bin_type == "ELF":

            # Get needed ELF data to map into memory (needs total rewrite obviously)
            self.mem_map = read_elf_bin_file_segments(self.file_name)
            entry_addr = read_elf_entry(self.file_name)
            self.code = read_elf_text_section(self.file_name)


            is_mapped = False
            # Read ELF segments but only map PT_LOAD (.text, .bss, .data is all we want for now)
            for seg_type, vaddr, size, data in self.mem_map:
                if seg_type != "PT_LOAD":
                    continue

                print colorful.bold_green("Mapping ELF Segment of type {} at address 0x{:08x} with size {}".format(seg_type, vaddr, size))
                if not is_mapped:
                    self.emu.mem_map(vaddr, 4 * 1024 * 1024)
                    is_mapped = True

                self.emu.mem_write(vaddr, data)

            # SET STACK
            self.emu.mem_map(0xBEDA4000, 1 * 1024 * 1024)

            self.start_addr = entry_addr
            self.end_addr = self.start_addr + len(self.code)

            print colorful.bold_white("Entry is 0x{:08x}, size of .text section is 0x{:08x}".format(self.start_addr, len(self.code)))

            self.emu.reg_write(UC_ARM_REG_PC, self.start_addr)


            self.emu.reg_write(UC_ARM_REG_SP, 0xBEDA4000)
            self.emu.reg_write(UC_ARM_REG_CPSR, 0x30)

            return True


    def emu_init_hooks(self):
        """Set emulator hooks."""
        self.emu.hook_add(UC_HOOK_CODE, self.main_code_hook)



    def emu_init_registers(self):
        """emu_init_registers() set registers to initial values"""
        pass


    def read_mem(self, address, size):
        read_address = address
        read_size = size
        return self.emu.mem_read(read_address, read_size)


    def run(self):
        """run() - start emulation.  calling this method."""
        try:
            if self.thumb_mode:
                self.start_addr |= 1
                print "Starting in THUMB mode..."

            self.emu.emu_start(self.start_addr, self.end_addr)
        except UcError as err:
            self.emu.emu_stop()
            return

        if self.get_pc() == self.end_addr:
            self.finished_exec = True
            logger.debug("Finished execution")

        return


    def stop(self):
        """stop() - stops emulation, unmaps any memory, and destroys emulation object.
        This method could be thought of as a deconstructor usually called before exiting
        armjitsu.
        """
        self.emu.emu_stop()

        del self.emu

        self.emu = None
        self.is_init = False


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
            print "No breakpoints currently set."


    def remove_breakpoint(self):
        pass


    def main_code_hook(self, uc, address, size, user_data):
        """Hooks every instruction. This hook handles pausing and resuming
        any emulation event that takes place. Stopping, starting, breakpoint handling, etc

        Detailed description
        """

        # Check for THUMB Mode is needed for capstone and unicorn engines.
        # Passing it this information it vital to having correct emulation resuls
        if size == 2:
            self.thumb_mode = True
        else:
            self.thumb_mode = False

        code = self.emu.mem_read(address, size)
        print "code = {}, type = {}".format(code, type(code))
        insn = self._disassemble_one_instruction(code, address)

        # Check for breakpoint hit
        if address in self.break_points.values():
            self.break_hit = True

        if self.stop_now:
            self.start_addr = self.get_pc()
            if self.break_hit:
                print "Breakpoint hit!"
            uc.emu_stop()
            return

        if insn:
            print "0x{:08x}: {:s} {:s}".format(insn.address, insn.mnemonic, insn.op_str)

        if self.break_hit:
            self.stop_now = True


        # If we are stepping we set stop_now, so next hook call we 'pause' emulator.
        if self.use_step_mode:
            self.stop_now = True

        return


    # -- Instruction disassembly

    def _full_disassembly(self):
        """Disassemble entire ARM binary at once and displays results in list dict self.disassembly."""
        code = self.code
        address = self.saved_start
        md = capstone.Cs(capstone.CS_ARCH_ARM, capstone.CS_MODE_ARM)
        self.disassembly = { inst.address: (inst.mnemonic, inst.op_str, inst.size)  for inst in md.disasm(code, self.saved_start) }


    def _disassemble_one_instruction(self, code, addr):
        md = capstone.Cs(capstone.CS_ARCH_ARM, capstone.CS_MODE_ARM)
        if self.thumb_mode:
            md.mode = capstone.CS_MODE_THUMB
        print "{}".format(binascii.hexlify(code))
        for i in md.disasm(bytes(code), addr):
            return i

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


