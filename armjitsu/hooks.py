"""This module contains all the hooks that may be used by unicorn. main_code_hook() is of great importance; it supplies the debugging like capabilities."""
import logging

from unicorn import *

import ui
import armjit_const

logger = logging.getLogger(armjit_const.LOGGER_NAME)


def main_code_hook(uc, address, size, emu):

    # Check for THUMB Mode
    emu.thumb_mode = True if size == 2 else False

    code = uc.mem_read(address, size)
    insn = emu.disassemble_one_instruction(code, address)

    if emu.stop_next_instruction:
        emu.stop_execution()
        return

    # Check for breakpoints
    if emu.instruction_breakpoints_enabled and address in emu.instruction_breakpoints:
        emu.breakpoint_hit = True
        emu.stop_next_instruction = True
        ui.show_breakpoint_hit_msg(address)

    if insn:
        print "0x{:08x}: {:s} {:s}".format(insn.address, insn.mnemonic, insn.op_str)

    # If we are stepping we set stop_now, so next hook call we 'pause' emulator.
    if emu.use_step_mode:
        emu.stop_next_instruction = True

    return True


