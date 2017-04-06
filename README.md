# Getting started:

ARMjitsu is an ARM emulator based on the Unicorn emulation engine. The project is written in Python, it essentially provides a front-end for the core emulation
services offered by unicorn.

In order to use the python bindings for unicorn-engine as well as capstone (disassembly engine), you need to download the core C based dependencies.

## macOS:
Open terminal:
`brew install unicorn && brew install capstone`

## Ubuntu Linux
Open terminal:
`sudo apt install unicorn`

## Other

If no instructions for installing unicorn on your system appear in this document simply navigate to http://www.unicorn-engine.org/docs/ for further
assistance.

------------

Once you have the core Unicorn dependencies installed, you are ready to create your development environment!

It is recommended you work in a virtual environment (virtualenv) for the project.
Once you have obtained the source for ARMjitsu you can easily setup your development environment like so:


- $ git clone git://repo
- $ cd armjitsu/
- $ virtualenv venv
- $ source venv/bin/activate
- $ pip install -r requirments.txt

*NOTE: Be sure you have virtualenv installed on your system. If not, you can easily install it via your systems native package management system.*

With your virtual environment active you are all ready to develop!


# Source files:
The core armjitsu.py file is in "armjitsu" directory. This directory is structured like any python package module.
A break down of each file is as follows.

- `__init__.py` - Empty, this is needed for creation of a package
- `armjitsu.py` - Main exec file of armjitsu, it contains dispatch command dispatch loop. 
- `armcpu.py`   - Contains ArmCPU class. This is the core emulation class, it allows you to create and manipulate a unicorn emulator instance.
- `misc_utils.py` - Add any helper functions here. For example `print_header()` can be found here.


# Conventions:

The code conventions used in armjitsu code are outlined formally in PEP8 document. Please adhere to this document to the best of your ability.
If there is a specific break from convention, be sure to comment why.


## Documentation:

Documentation of the project is very important. Luckily python makes documentation easy by including ways to document source code directly in the source itself via doc strings. 
If you are not familiar with docstrings seek on online reference for the basics of setting and viewing a docstring.


# Git Workflow

ARMjitsu will be hosted centrally in a GIT repository. As the development team of ARMjitsu is currently only a small number of developers we are going to use a GIT workflow Scott Chacon describes in Pro Git.

