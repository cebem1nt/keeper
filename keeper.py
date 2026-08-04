#!/usr/bin/env python3
from argparse import ArgumentParser
from sys import exit as sys_exit
from os import system as os_system
from importlib import import_module

from src.backend import Keeper
from src.frontend import Frontend

import params

# This password manager is built using layered like architecture, from the bottom where
# files are manipulated, the medium where Keeper class provides some kind of API,
# to the frontend level. Beauty of it is that you do not have to modify the base.
# You can modify frontend functionality without any need to modify the file system or API. 

# Brief tour:
# src/      -- Source directory. Frontend, backend and extensions are there
# src/core  -- Two files with basic functionality for a password manager: cryptography and a file system
# params.py -- You can tweak some parameters of keeper's behaviour inside of it

def init_extensions(keeper: Keeper, extensions_list: list[str]):
    module = import_module('src.extensions')
    instances = []

    for extension in extensions_list:
        extension_class = getattr(module, extension)
        instance = extension_class(keeper=keeper)
        instance.subscribe()
        instances.append(instance)

    return instances

if __name__ == '__main__':
    p = ArgumentParser(description="Keeper is a Python password manager. Locker is a .lk file where passwords are stored, triplet is tag/login/password. More detailed info about each command can be seen by adding -h to the command, for example \"keeper add -h\"")

    subparsers = p.add_subparsers(dest='command', help='Available commands')

    add_parser = subparsers.add_parser('add', aliases=['a'], help='Add a new triplet with provided tag or tags.')
    add_parser.add_argument('tag', metavar='TAG(S)', type=str, nargs='+', help='Tag(s) for the new triplet(s).')
    add_parser.add_argument('-s', '--show-password', action='store_true', help='Show password when adding triplet')
    add_parser.set_defaults(command='add')

    get_parser = subparsers.add_parser('get', aliases=['g'], help='Retrieve login or password based on tag.')
    get_parser.add_argument('tag', metavar='TAG', type=str,              help='Tag of the triplet to get.')
    get_parser.add_argument('-l',  '--login', action='store_true',       help='Return the login to the clipboard instead of password.')
    get_parser.add_argument('-P',  '--print', action='store_true',       help='Instead of copying to the clipboard, print to the stdout.')
    get_parser.set_defaults(command='get')

    remove_parser = subparsers.add_parser('remove', aliases=['r', 'rm'], help='Remove a triplet based on tag or tags.')
    remove_parser.add_argument('tag', metavar='TAG(S)', type=str, nargs='+', help='Tag(s) of the triplet(s) to remove.')
    remove_parser.add_argument('-nc', '--no-confirm', action='store_true',   help='Do not confirm deleting of a triplet')
    remove_parser.set_defaults(command='remove')

    edit_parser = subparsers.add_parser('edit', aliases=['e', 'ed'], help='Interactively edit parameters of a triplet.')
    edit_parser.add_argument('tag', metavar='TAG(S)', type=str, nargs='+', help='Tag(s) of the triplet(s) to edit.')
    edit_parser.set_defaults(command='edit')

    list_parser = subparsers.add_parser('list', aliases=['l', 'ls'], help='List all stored triplets.')
    list_parser.add_argument('-s', '--show', action='store_true',    help='Include passwords in the listing.')
    list_parser.add_argument('-n', '--num', action='store_true',     help='Output number of passwords instead of printing each one.')
    list_parser.set_defaults(command='list')

    find_parser = subparsers.add_parser('find', aliases=['f', 'fn'], help='Search for triplets with similar tag.')
    find_parser.add_argument('tag', metavar='TAG', type=str,         help='Similar tag to search for.')
    find_parser.add_argument('-s', '--show', action='store_true',    help='Show passwords for every found triplet')
    find_parser.set_defaults(command='find')

    generate_parser = subparsers.add_parser('generate', aliases=['gen'], help="Generates a password, prints it or stores if -S provided")
    generate_parser.add_argument('-l',  '--length', type=int, default=16,       help='Length of the generated password, default value is 16.')
    generate_parser.add_argument('-ns', '--no-symbols', action='store_true',    help='generates a password without any special symbols.')
    generate_parser.add_argument('-nl', '--no-letters', action='store_true',    help='generates a password without any letters.')
    generate_parser.add_argument('-np', '--no-paste',   action='store_true',    help='Do not paste generated password to the clipboard')
    generate_parser.add_argument('-S',  '--store',    type=str, metavar="TAG",  help='Store generated password with given tag')
    generate_parser.set_defaults(command='generate')

    change_parser = subparsers.add_parser('change', aliases=['ch'],     help='Changes current locker file to provided.')
    change_parser.add_argument('dir', metavar='DIR', type=str,          help='Directory to the new locker file.')
    change_parser.add_argument('-a', '--absolute', action='store_true', help='Open a file out of the storage directory')
    change_parser.set_defaults(command='change')

    copy_parser = subparsers.add_parser('copy', aliases=['cp'], help='Copy current .lk or token file to the provided directory.')
    copy_parser.add_argument('dir', metavar='[DIR]', type=str, nargs='?', help='Directory to copy to. If no directory provided, copy to the current directory.')
    copy_parser.add_argument('-t', '--token', action='store_true',        help='Instead of copying current locker file, copy token to the provided directory.')
    copy_parser.set_defaults(command='copy')

    current_parser = subparsers.add_parser('current', aliases=['cr'], help='Prints directory of the current locker in use.')
    current_parser.add_argument('-f', '--full', action='store_true',  help='Print absolute path, include root passwords storage directory')
    current_parser.set_defaults(command='current')

    shred_parser = subparsers.add_parser('shred-locker', help='Shreds current locker.')
    generate_token_parser = subparsers.add_parser('generate-token', help="Generates a new token.")

    args = p.parse_args()

    keeper = Keeper(
        params.token_size, params.salt_size, params.iterations, params.is_portable, params.backend
    )

    # Initializing extensions
    extensions = init_extensions(keeper, params.active_extensions)

    # - Frontend is a variable set in frontend.py that refers to a class that implements user interface functionality
    # - Frontend itself should manage registration / authentification handling when needed
    # - Frontend's main() function should implement proper arguments handling
    # - For an interactive cli: 
    #   - keeper.py will pass None and parser instance if no arguments.

    frontend = Frontend(keeper=keeper)
    
    if any(vars(args).values()):
        frontend.main(args)
    else:
        frontend.main(None, p)