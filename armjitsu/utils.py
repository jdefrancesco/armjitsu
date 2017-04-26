"""utils.py contains utility/helper functions to core armjitsu python code."""
import os
import os.path



def read_bin_file(target_file):
    """Read binary contents of file that contains executable code to emulate"""

    if not target_file:
        return False

    if not os.path.isfile(target_file) and os.access(target_file, os.R_OK):
        raise IOError("Error obtaining file")

    with open(target_file, "rb") as bin_file:
        bin_code = bin_file.read()

    return bin_code
