#!/usr/bin/env python

# File: misc_utils.py
# Description: Contains misc. utility functions possibly needed by other modules
# in the armjitsu codebase. Use this file to add any functions that provide general
# support for other parts of the application. For example, print_header() is a function
# that simply prints a header banner (for text) to stdout.

def print_header(header_text):
    """Print header between four equal signs."""
    print "\n==== {} ====".format(header_text)

def new_line(count=1):
    """Print new line 'count' number of times (count=1 by default)."""
    out_str = "\n" * count
    print out_str,
