#Getting started:

ARMjitsu is an ARM emulator based on the Unicorn emulation engine. The project is written in Python, it essentially provides a front-end for the core emulation
services offered by unicorn.

In order to use the python bindings for unicorn-engine as well as capstone (disassembly engine), you need to download the core C based dependencies.

##macOS:

Open terminal:

`brew install unicorn && brew install capstone`


##Ubuntu Linux

Open terminal:

`sudo apt install unicorn`

##Other

If no instructions for installing unicorn on your system appear in this document simply navigate to http://www.unicorn-engine.org/docs/ for further
assistance.

------------

Once you have the core Unicorn dependencies installed, you are ready to create your development environment!

It is recommended you work in a virtual environment (virtualenv) for the project.
Once you have obtained the source for ARMjitsu you can easily setup your development environment like so:


    `
    $ git clone git://repo           # Grab source code
    $ cd armjitsu/                   # Change to directory where source is located
    $ virtualenv venv                # Setup python virtualenv for ease of development
    $ source venv/bin/activate       # Activate virtual environment
    $ pip install -r requirments.txt # Fetch dependencies needed to run armjitsu!
    `

*NOTE: Be sure you have virtualenv installed on your system. If not, you can easily install it via your systems native package management system.*

With your virtual environment active you are all ready to develop!


#Source files:
The core armjitsu.py file is in "armjitsu" directory. This directory is structured like any python package module.
A break down of each file is as follows.

    * `__init__.py` - Empty, this is needed for creation of a package
    * `armjitsu.py` - Contains the crux of armjitsu code. This is where  most early development will take place.
    * `misc_utils.py` - Add any helper functions here. For example `print_header()` can be found here.


#Conventions:

The code conventions used in armjitsu code are outlined formally in PEP8 document. Please adhere to this document to the best of your ability.
If there is a specific break from convention, be sure to comment why.

##Documentation:

Documentation of the project is very important. Luckily python makes documentation easy by providing docstrings. When a new function or method is developed be sure
that the docstring is filled out appropriately. This project will use reStructuredText Docstring format. PEP287 outlines this convention well, it is wise to have that document'
open and ready to reference. Be sure that documentation exists for any new code BEFORE you push your changes upstream!


#Git Workflow
