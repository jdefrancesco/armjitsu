"""utils.py contains utility/helper functions to core armjitsu python code."""

# WARNING: Because I was informed of dead line so suddenly, the code needs major refactoring.
# A lot of this code is axcting just as PoC to meet the deadline. It is functional but not well tested.
# Next revision, with additional funding, I plan to implement the rest of the code-base as I had originally envisioned.

import os
import os.path

from elftools.elf.elffile import ELFFile


def is_file(target_file):
    """Simple check if target_file is valid for usage."""

    if not target_file:
        return False

    # At least check if file exists in some matter at all at some point.
    if not os.path.isfile(target_file) and os.access(target_file, os.R_OK):
        return False

    return True


def read_raw_arm_code(target_file):
    """Read binary contents of file that contains executable code to emulate"""

    if not is_file(target_file):
        return False

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

    text_data = None

    with open(target_file, "rb") as bin_file:
        elf_bin = ELFFile(bin_file)
        for section in elf_bin.iter_sections():
            if section.name == ".text":
                text_data = bytes(section.data())
                break

    if text_data is None:
        print "Unable to find .text section in ELF"
        return False

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


def elf_ingest(target_file):

    file_name = target_file

    elf_entry = read_elf_entry(file_name)

    elf_segs = read_elf_bin_file_segments(file_name)
    loadable_segs = []
    for p_type, p_vaddr, p_memsz, seg_data in elf_segs:
        if p_type == "PT_LOAD":
            loadable_segs.append((p_type, p_vaddr, p_memsz, seg_data))

    return elf_entry, loadable_segs
