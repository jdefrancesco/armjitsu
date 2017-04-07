"""
setup.py

Installer file for ARMjitsu. After installation ARMjitsu should be available
by invoking from command line:

    bash$ armjitsu

Enjoy :-)
"""
try:
    from setuptools import setup
except ImportError:
    from distutils.core import setup

CONFIG = {
    'description' : 'ARMjitsu: An ARM emulator and debugger for Reverse Engineers!',
    'author' : 'Joey DeFrancesco',
    'author_email': 'jdefranc@harris.com',
    'version': '0.1',
    'install_requires': ['nose',
                         'appdirs',
                         'capstone',
                         'cmd2',
                         'fabulous',
                         'packaging',
                         'pyparsing',
                         'six',
                         'unicorn'],
    'packages': ['armjitsu'],
    'name': 'ARMjitsu',
    'entry_points': {
        'console_scripts': ['armjitsu = armjitsu.armjitsu.armjitsu:__main__']
    },
}

setup(**CONFIG)
