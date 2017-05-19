"""utils.py contains utility/helper functions to core armjitsu python code."""

# WARNING: Because I was informed of dead line so suddenly, the code needs major refactoring.
# A lot of this code is axcting just as PoC to meet the deadline. It is functional but not well tested.
# Next revision, with additional funding, I plan to implement the rest of the code-base as I had originally envisioned.

import os
import os.path

from elftools.elf.elffile import ELFFile


def read_bin_file(target_file):
    """Read binary contents of file that contains executable code to emulate"""

    if not target_file:
        return False


    # At least check if file exists in some matter at all at some point.
    if not os.path.isfile(target_file) and os.access(target_file, os.R_OK):
        raise IOError("Error obtaining file")

    with open(target_file, "rb") as bin_file:
        bin_code = bin_file.read()

    return bin_code


def read_elf_entry(target_file):
    if not target_file:
        return False

    # At least check if file exists in some matter at all at some point.
    if not os.path.isfile(target_file) and os.access(target_file, os.R_OK):
        raise IOError("Error obtaining file")

    with open(target_file, "rb") as bin_file:
        elf_bin = ELFFile(bin_file)
        entry_addr = elf_bin.header['e_entry']

    return entry_addr

def read_elf_text_section(target_file):
    if not target_file:
        return False

    # At least check if file exists in some matter at all at some point.
    if not os.path.isfile(target_file) and os.access(target_file, os.R_OK):
        raise IOError("Error obtaining file")

    with open(target_file, "rb") as bin_file:
        elf_bin = ELFFile(bin_file)
        for section in elf_bin.iter_sections():
            if section.name.startswith(".text"):
                text_data = bytes(section.data())

    return text_data


def read_elf_bin_file_segments(target_file):
    """Will ingest a simple statically linked ELF binary and return its relevant
    segments in a tuple for use by emulator.
    """
    if not target_file:
        return False

    # At least check if file exists in some matter at all at some point.
    if not os.path.isfile(target_file) and os.access(target_file, os.R_OK):
        raise IOError("Error obtaining file")

    elf_segments = []
    with open(target_file, "rb") as bin_file:
        elf_bin = ELFFile(bin_file)
        # Will store section name, offset, and size as a 3-tuple
        for seg in elf_bin.iter_segments():
            elf_segments.append((seg.header['p_type'], seg.header['p_vaddr'],
                                 seg.header['p_memsz'], seg.data()))

    return elf_segments
