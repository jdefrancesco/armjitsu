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

from clint.textui import colored, puts


BANNER_SEPERATOR = "-"

def new_line(count=1):
    """Print new line 'count' number of times (count=1 by default)."""
    out_str = "\n" * count
    print out_str,


# Banner idea taken from pwndbg
def banner(header):
    """Prints banner. Red line accross screen with text in the middle."""

    header = header.upper()
    try:
        _, width = struct.unpack('hh', fcntl.ioctl(sys.stdin.fileno(), termios.TIOCGWINSZ, '1234'))
    except struct.error:
        width = 80

    width -= 2
    puts(colored.red(("[{:%s^%ss}]" % (BANNER_SEPERATOR, width)).format(header)))

    return
