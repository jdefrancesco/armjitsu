"""
File: misc_utils.py
Description: Contains misc. utility functions possibly needed by other modules
in the armjitsu codebase. Use this file to add any functions that provide general
support for other parts of the application. For example, print_header() is a function
that simply prints a header banner (for text) to stdout.
"""

import fcntl
import termios
import sys
import struct

from fabulous import image, utils, text

import colorful
colorful.use_style('solarized')
from terminaltables import *


BANNER_SEPERATOR = '-'

def show_logo():
    """Show the armjitsu banner logo."""
    print image.Image("../images/armjit-logo.png", width=130)


def new_line(count=1):
    """Print new line 'count' number of times (count=1 by default)."""
    out_str = "\n" * count
    print out_str,


def banner(header):
    """Prints banner. Red line accross screen with text in the middle."""
    print ""
    header = header.upper()
    try:
        _, width = struct.unpack('hh', fcntl.ioctl(sys.stdin.fileno(), termios.TIOCGWINSZ, '1234'))
    except struct.error:
        width = 80

    width -= 2
    print colorful.red(("[{:%s^%ss}]" % (BANNER_SEPERATOR, width)).format(header))

    return


def show_breakpoint_hit_msg(addr):
    print colorful.red("Breakpoint @ 0x{:08x}".format(addr))


def table_show_registers(regs_list):
    """Show registers in a table."""
    table_data = [
            [r for r in regs_list[:4]   ],
            [r for r in regs_list[4:8]  ],
            [r for r in regs_list[8:12] ],
            [r for r in regs_list[12:16]]
    ]

    table_title = colorful.bold_green("ARM Registers")
    table_instance = SingleTable(table_data, table_title)
    table_instance.inner_heading_row_border = False
    table_instance.inner_row_border = True
    table_instance.justify_columns = {0: 'center', 1: 'center', 2: 'center', 3 : 'center'}

    print ""
    print table_instance.table
    print ""
