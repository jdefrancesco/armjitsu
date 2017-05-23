"""armcpu.py moodule supplies ArmCPU() object, an emulation instance we have debugger like control over."""

# pylint: skip-file

__author__ = "Joey DeFrancesco"

import logging
import binascii

from unicorn import *
from unicorn.arm_const import *
import capstone

import armcpu_const
import armjit_const

from ui import *
from utils import *

import hooks

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

    def __init__(self, file_name, bin_type=armcpu_const.RAW_BIN):

        self.file_name = file_name
        self.bin_type = bin_type

        # Our emulator object from unicorn
        self.emu = None
        self.is_init = False

        self.code = dict()
        self.start_addr = 0x0
        self.end_addr = 0x0
        self.continue_addr = 0x0

        # Attributes for handling breakpoints
        self.use_step_mode = False
        self.stop_next_instruction = False

        # Breakpoint related variables
        self.instruction_breakpoints = dict()
        self.instruction_breakpoints_enabled = True
        self.breakpoint_hit = False
        self.unique_bp_id = 0

        # Dictionary of registers and memory areas
        self.registers = dict()
        self.thumb_mode = False

        self.mem_regions = []

        self.full_disassembly = dict()
        self.show_asm = False

        # Prepare ARM emulator for execution and debugging
        self._emu_init()

    def _emu_init(self):
        """Create emulation object. Map/initialize memory, add needed hooks"""

        try:
            self.emu = Uc(UC_ARCH_ARM, UC_MODE_ARM)
            self._emu_init_memory()
            self._emu_init_registers()
            self._emu_init_hooks()
        except UcError as err:
            print colorful.bold_red("Error initializing emulator: {}".format(err))
            return False

        self.is_init = True
        return True

    def _emu_init_memory(self, bin_type=armcpu_const.RAW_BIN):
        if bin_type == armcpu_const.RAW_BIN:
            self._load_raw_arm_binary_img()

    def _emu_init_registers(self):
        """Set registers to initial values."""
        pass

    def _emu_init_hooks(self):
        """Set emulator hooks."""
        self.emu.hook_add(UC_HOOK_CODE, hooks.main_code_hook, self)

    def _emu_mem_map(self, segment_name, addr, code, size):
        """Map memory into emulator, ensuring we load data with correct alignment."""
        PAGE_SIZE = armcpu_const.PAGE_SIZE
        alignment = addr % PAGE_SIZE
        base_addr = addr - alignment

        page_size = (int(size / PAGE_SIZE) * PAGE_SIZE) + PAGE_SIZE

        if segment_name == ".text":
            self.start_addr = base_addr
            self.end_addr = base_addr + len(code)

        self.emu.mem_map(base_addr, page_size)
        self.emu.mem_write(base_addr, code)

    def read_reg(self, reg="R0"):
        r_reg = "UC_ARM_REG_{}".format(reg.upper())
        return self.emu.reg_read(r_reg)

    def write_reg(self, val, reg="R0"):
        w_reg = "UC_ARM_REG_{}".format(reg.upper())
        return self.emu.reg_write(w_reg)

    def write_mem(self, addr, val):
        """Write size bytes of memory to addr."""
        self.emu.mem_write(addr, val)

    def read_mem(self, address, size):
        """Read size bytes of memory from addr."""
        return self.emu.mem_read(address, size)

    def emu_memory_insert(self, addr, val):
        for o, b in enumerate(val):
            current_addr = addr + offset
            self.memory[current_addr] = byte

    def start_execution(self):
        """Starts execution."""
        try:
            if self.thumb_mode:
                self.start_addr |= 1

            self.stop_next_instruction = False
            self.emu.emu_start(self.start_addr, self.end_addr)
        except UcError as err:
            logger.critical("Error starting emulator. Shutting down...!")
            self.emu.emu_stop()
            return False

        return True

    def stop_execution(self, last_pc):
        """Stop execution of emulator."""
        self.continue_addr = last_pc
        self.emu.emu_stop()

    def continue_execution(self):
        """Continue emulation after a pause possibly caused by a breakpoint or inturrupt."""
        self.use_step_mode = False
        self.stop_next_instruction = False
        self.start_addr = self.continue_addr
        self.start_execution()

    def step_execution(self):
        """Enable stepping through binary."""
        self.use_step_mode = True
        self.stop_next_instruction = False
        self.start_execution()

    def mem_map(self, addr, code, size):
        """Map memory into emulator, ensuring we load data with correct alignment."""
        alignment = addr % PAGE_SIZE
        base_addr = addr - alignment

        page_size = (int(size / PAGE_SIZE) * PAGE_SIZE) + PAGE_SIZE

        self.emu.mem_map(base_addr, page_size)
        self.emu.write(base_addr, code)

    def get_pc(self):
        """Return ARM program counter register (PC)."""
        return self.emu.reg_read(UC_ARM_REG_PC)

    def get_sp(self):
        """Return ARM stack pointer register (SP)."""
        return self.emu.reg_read(UC_ARM_REG_SP)

    def set_breakpoint_address(self, break_addr):
        """Set a breakpoint by address."""
        break_addr = int(break_addr, 16)
        if  not self.start_addr <= break_addr <= self.end_addr:
            raise AddressOutOfRange("Address is out of .text memory range!")
        else:
            bp_id = self._next_bp_id()
            self.instruction_breakpoints[break_addr] = bp_id

    def remove_breakpoint_address(self, break_id):
        pass

    def disable_instruction_breakpoints():
        self.instruction_break_points_enabled = False

    def list_breakpoints(self):
        """List breakpoints."""
        print "Breakpoints:"
        if self.instruction_breakpoints:
            for break_addr, bp_id in self.instruction_break_points:
                print "{}: 0x{:08x}".format(bp_id, break_addr)
        else:
            print "No breakpoints currently set."

    def remove_breakpoint(self):
        pass

    def full_disassembly(self):
        """Disassemble entire ARM binary at once and displays results in list dict self.disassembly."""
        code = self.code
        address = self.saved_start
        md = capstone.Cs(capstone.CS_ARCH_ARM, capstone.CS_MODE_ARM)
        self.disassembly = { inst.address: (inst.mnemonic, inst.op_str, inst.size)  for inst in md.disasm(code, self.saved_start) }


    def disassemble_one_instruction(self, code, addr):
        md = capstone.Cs(capstone.CS_ARCH_ARM, capstone.CS_MODE_ARM)
        if self.thumb_mode:
            md.mode = capstone.CS_MODE_THUMB
        print "{}".format(binascii.hexlify(code))
        for i in md.disasm(bytes(code), addr):
            return i

    def display_context(self):
        pass

    def context_registers(self):
        """Show contents of ARM registers."""

        # Dump registers R0 to R9
        for reg in xrange(UC_ARM_REG_R0, UC_ARM_REG_R0 + 10):
            reg_string = "R{:<3d} = 0x{:08x}".format((reg-UC_ARM_REG_R0),
                                                         self.emu.reg_read(reg))
            print reg_string

        # Dump registers with alias
        print ""
        print "SL   = 0x{:08x}".format(self.emu.reg_read(UC_ARM_REG_SL))
        print "FP   = 0x{:08x}".format(self.emu.reg_read(UC_ARM_REG_FP))
        print "IP   = 0x{:08x}".format(self.emu.reg_read(UC_ARM_REG_IP))
        print "SP   = 0x{:08x}".format(self.emu.reg_read(UC_ARM_REG_SP))
        print "LR   = 0x{:08x}".format(self.emu.reg_read(UC_ARM_REG_LR))
        print "PC   = 0x{:08x}".format(self.emu.reg_read(UC_ARM_REG_PC))
        print "CPSR = 0x{:08x}".format(self.emu.reg_read(UC_ARM_REG_CPSR))
        print ""


    def context_code(self):
        pass


    def context_stack(self):
        pass


    def context_backtrace(self):
        pass


    def _load_raw_arm_binary_img(self):
        """Load raw ARM code or shellcode into emulator."""
        raw_code = read_raw_arm_code(self.file_name)

        #TODO: Allow user to set sefment_size
        segment_size = 1 * 1024 * 1024
        base_addr = 0x1000000
        segment_name = ".text"
        self.code[segment_name] = [raw_code, base_addr, segment_size]
        self._emu_mem_map(segment_name, base_addr, raw_code, segment_size)

        logging.debug("{} loaded at 0x{:08x}, size = {}".format(segment_name, base_addr, segment_size))

    def _load_elf_binary_img(self):
        pass

    def _next_bp_id(self):
        """Returns a unique integer. Allows us to give IDs to breakpoints."""
        self.unique_bp_id += 1
        return self.unique_bp_id

    def stop(self):
        """Completely stop all emulation, and destroy ArmCPU object."""
        self.emu.emu_stop()

        del self.emu

        self.emu = None
        self.is_init = False
