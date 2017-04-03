
from unicorn import *
from unicorn.arm_const import *

from capstone import *

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
        # Where execution ends...

        self.break_points = {}
        self.sys_calls = []


        self.saved_pc = None
        # Jump tracking state
        self._prev = None
        self._prevsize = None
        self._curr = None
        self.emu = None

        self.emu_init(address, code)


    def emu_init(self, address, code):

        self.is_setup = False
        self.code = code
        self.start_addr = address
        self.end_addr = self.start_addr + len(self.code)

        self.is_running = False
        self.stop_now = False

        self.registers = {}
        self.areas = {}

        try:
            self.emu = Uc(UC_ARCH_ARM, UC_MODE_ARM)
            self.emu_init_memory()
            self.emu_init_registers()
        except UcError as e:
            print "[-] Error setting up!"
            return

        print "[+] Emulator initialized..."

    def emu_init_memory(self):


        # Map memory sections
        self.emu.mem_map(self.start_addr, 2 * 1024 * 1024)
        self.emu.mem_write(self.start_addr, self.code)

        # Add our hooks..
        self.emu.hook_add(UC_HOOK_CODE, self.trace_hook)


    def emu_init_registers(self):

        self.emu.reg_write(UC_ARM_REG_APSR, 0x000000) #All application flags turned on


    def emu_map_code(self):
        pass


    def run(self):
        print "[+] Beginning execution..."
        try:
            self.is_running = True
            self.emu.emu_start(self.start_addr, self.end_addr)
        except UcError as e:
            self.emu.emu_stop()
            return

        if self.get_pc() == self.end_addr:
            print "[+] Ending execution..."
        return


    def pause(self):
        if self.is_running:
            self.emu.emu_stop()
            self.is_running = False


    def resume(self):
        if not self.is_running:
            self.is_running = True
            self.emu.emu_start(self.saved_pc, self.end_addr)

    def stop(self):

        self.emu.mem_unmap(self.start_addr)
        self.emu.emu_stop()
        del self.emu
        self.emu = None
        self.is_running = False


    def dumpregs(self):
        print self._dump_regs()



    def get_pc(self):
        return self.emu.reg_read(UC_ARM_REG_PC)

    def get_sp(self):
        return self.emu.reg_read(UC_ARM_REG_SP)


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

        usr_input = raw_input("Pause? ")
        if usr_input == "y":
            print "[+] Pausing..."
            self.pause()
            print "RETURNED FROM PAUSE"
            self.dumpregs()
            self.saved_pc = uc.reg_read(UC_ARM_REG_PC)
            return True
        else:
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


