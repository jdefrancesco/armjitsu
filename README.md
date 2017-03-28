# Getting started:

    It is recommended you work in a virtual environment (virtualenv) for the project.
    Once you have obtained the repo (if you're reading this it means you probably already have), you can setup your development environment like so

    $ virtualenv venv
    $ source venv/bin/activate
    $ pip install -r requirments.txt

With your virtual environment active you are all ready to develop!

The core armjitsu.py file is in "armjitsu" directory. This directory is structured like any python package module.
A break down of each file is as follows.

    * `__init__.py` - Empty, this is needed for creation of a package
    * `armjitsu.py` - Contains the crux of armjitsu code. This is where  most early development will take place.
    * `misc_utils.py` - Add any helper functions here. For example print_header() can be found here.


#Conventions:

The code conventions used in armjitsu code are outlined formally in PEP8 document. Please adhere to this document to the best of your ability.
If there is a specific break from convention, be sure to comment why.

##Documentation:

Documentation of the project is very important. Luckily python makes documentation easy by providing docstrings. When a new function or method is developed be sure
that the docstring is filled out appropriately. This project will use reStructuredText Docstring format. PEP287 outlines this convention well, it is wise to have that document'
open and ready to reference. Be sure that documentation exists for any new code BEFORE you push your changes upstream!
