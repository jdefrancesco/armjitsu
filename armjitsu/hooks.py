"""This module contains all the hooks that may be used by unicorn. main_code_hook() is of great importance; it supplies the debugging like capabilities."""
import logging

from unicorn import *

import armjit_const

logger = logging.getLogger(armjit_const.LOGGER_NAME)


def main_code_hook(uc, address, size, emu):

    # Check for THUMB Mode
    if size == 2:
        emu.thumb_mode = True
    else:
        emu.thumb_mode = False

    code = emu.mem_read(address, size)
    print "code = {}, type = {}".format(code, type(code))
    insn = emu.disassemble_one_instruction(code, address)


    if emu.stop_next_instruction:
        emu.stop_execution()


    if emu.instruction_breakpoints_enabled and address in emu.instruction_breakpoints:
        emu.emu_stop()


    if emu.stop_next_instruction:
        emu.start_addr = emu.get_pc()
        emu.emu_stop()
        return

    if insn:
        print "0x{:08x}: {:s} {:s}".format(insn.address, insn.mnemonic, insn.op_str)


    # If we are stepping we set stop_now, so next hook call we 'pause' emulator.
    if emu.use_step_mode:
        emu.stop_next_instruction = True

    return


def hook_code(uc, address, size, emu):
    opcode = str(emu.mem_read(address, size))

    if emu.stop_next_instruction:
        emu.stop_execution()

    if address == emu.final_instruction:
        emu.stop_next_instruction = True
        for op in emu.arch.jumps.union(emu.arch.conditional_jumps):
            if opcode.encode("hex").startswith(op):
                emu.stop_execution()
                return False

    if emu.verbosity_level > 1:
        print "0x{:x};{}".format(address, opcode.encode("hex"))

    # handle breakpoint
    if emu.instruction_breakpoints_enabled and address in emu.instruction_breakpoints:
        cb = emu.instruction_breakpoints[address][0]
        args = emu.instruction_breakpoints[address][1]
        call = cb(emu, *args)

        # bp handler returns False
        if not call:
            emu.stop_execution()
            return False

    if emu.instruction_trace:
        emu.code_tracer.add_instruction_trace(address, opcode, size)

    if emu.force_path:
        if not emu.enforced_path:
            emu.stop_execution()
            return False

        path_addr, path_instr_size = emu.enforced_path.popleft()

        if path_addr != address:
            emu.stop_execution()
            emu.enforced_path.appendleft((path_addr, size))
            return False

    return True
