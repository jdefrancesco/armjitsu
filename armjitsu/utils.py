#!/usr/bin/env python

import string
import struct

import unicorn
import capstone


def format_address(addr, mode):
    memalign_size = mode.get_memory_alignment()

    if memalign_size == 16:
        return "0x{:04x}".format(addr & 0xFFFF)
    elif memalign_size == 32:
        return "0x{:08x}".format(addr & 0xFFFFFFFF)
    elif memalign_size == 64:
        return "0x{:16x}".format(addr & 0xFFFFFFFFFFFFFFFF)

i
