"""armcpu.py moodule

Supplies ArmCPU() class which wraps a unicorn emulator object for more fine grain control
over a possible emulation session.
"""

__author__ = "Joey DeFrancesco"

from unicorn import *
from unicorn.arm_const import *
from capstone import *

from misc_utils import *

class AddressOutOfRange(Exception):

    def __init__(self, message, errors):
        super(AddressOutOfRange, self).__init__(message)

        self.message = message
        self.errors = errors


class ArmCPU(object):
    """ArmCPU class provides abstraction to unicorn emulation object.

    Args:
        address (int): Base address code will be loaded into and subsequently executed from.
        code (byte array): Actual code to run in emulator.
    """


    def __init__(self, address, code):
        self.break_points = {}
        self.sys_calls = []

        self.unique_bp_id = 0

        self.emu = None
        self.was_thumb = False

        self.saved_start = address
        self.emu_init(address, code)


    def emu_init(self, address, code):
        """emu_init() - called by constructor to setup
        our emulation object.

        Args:
            address(int):
            code(byte array):

        """

        self.code = code
        self.start_addr = address
        self.end_addr = self.start_addr + len(self.code)

        self.is_running = False
        self.use_step_mode = False
        self.stop_now = False

        self.registers = {}
        self.areas = {}


        try:
            self.emu = Uc(UC_ARCH_ARM, UC_MODE_ARM)
            self.emu_init_memory()
            self.emu_init_registers()
        except UcError as e:
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
        self.emu.reg_write(UC_ARM_REG_APSR, 0x000000) #All application flags turned on


    def emu_map_code(self):
        """emu_map_code()"""
        pass


    def run(self):
        """run() - start emulation. Ensure the emulation object is properly initalized before
        calling this method.
        """
        try:
            self.is_running = True
            if self.was_thumb: self.start_addr |= 1
            self.emu.emu_start(self.start_addr, self.end_addr)
        except UcError as e:
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
        self.emu.mem_unmap(self.start_addr)
        self.emu.emu_stop()
        del self.emu
        self.emu = None
        self.is_running = False


    def dump_regs(self):
        """dump_regs() - shows user the content of ARM registers."""
        print_header("Register Dump")

        # Dump registers R0 to R9
        for reg in xrange(UC_ARM_REG_R0, UC_ARM_REG_R0 + 10):
            reg_string = "[*] R{:<3d} = 0x{:08x}".format((reg-UC_ARM_REG_R0), self.emu.reg_read(reg))
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

        This method should dump the context of the emulator. Register values, backtrace, and current instructions executed
        should all be printed to stdout.

        Example:
            >>> inst.dump_state()
            ... REG VALUES, BACKTRACE, INSTRUCTIONS

        """
        pass


    def set_breakpoint_address(self, break_addr):
        if  not (self.start_addr <= break_addr <= self.end_addr):
            raise AddressOutOfRange("Address is out of current range!")
        else:
            if break_addr not in self.break_points.values():
                bp_id = self._next_bp_id()
                self.break_points[bp_id] = break_addr


    def list_breakpoints(self):
        print "Break points:"
        if self.break_points:
            for bp_id, break_addr in self.break_points:
                print "{}: 0x{:08x}".format(bp_id, break_addr)


    def remove_breakpoint(self):
        pass


    def main_code_hook(self, uc, address, size, user_data):
        """ main_code_hook()"""

        # Read the current instruction to execute
        try:
            mem_tmp = self.emu.mem_read(address, size)
            inst = ["0x{:02x}".format(i) for i in mem_tmp]
            inst_string = "  ".join(inst)

            out_string = "0x{:08x}: {}\n".format(address, inst_string)

        except UcError as e:
            print "ERROR: %s", e


        if self.stop_now:
             self.start_addr = self.get_pc()
             # When we pause execution with a thumb inst, we need to resume it in that mode
             if size == 2: self.was_thumb = True
             if size == 4: self.was_thumb = False
             uc.emu_stop()
             return

        print out_string

        # If we are stepping, we set stop_now, so next hook call we pause emulator
        if self.use_step_mode:
             self.stop_now = True


        # Check for break points
        return


    def _next_bp_id(self):
        self.unique_bp_id += 1
        return self.unique_bp_id

