from argparse import ArgumentParser
from sys import exit as sys_exit
from os import system as os_system

from func.backend import Keeper
from func.frontend import CLI

# This is a project code for a minimalistic and at the same time 
# functional python password manager. The following project 
# For sequrity reasons, the following python code should be compiled.
# You can use pyinstaller for it

# This password manager built as a layered project, from the bottom where
# files are getting manipulated, the medium where class provides some kind of API,
# to the frontend level. Beauty of it is that you do not have to modify the base.
# You can add some frontend functionality as a new abstract layer without any need
# to modify file system or API. 

def main(args: ArgumentParser, keeper: Keeper, cli: CLI):    
    try:
        if args.command == 'change':
            cli.change_locker(args.dir, keeper, args.absolute)

        elif args.command == 'current':
            cli.print_locker(keeper.get_current_locker_dir(args.full))

        elif args.command == 'copy':
            dest = args.dir if args.dir else '.'
            if args.token:
                cli.copy_token(dest, keeper)
            else:
                cli.copy(dest, keeper)

        elif args.command == 'add':
            for t in args.tag:
                cli.add_triplet(t, keeper, args.show_password)

        elif args.command == 'remove':
            for t in args.tag:
                cli.remove_by_tag(t, keeper, args.no_confirm)

        elif args.command == 'get':
            tag = args.tag
            if args.login:
                cli.get_login(tag, keeper, args.print_stdout)
            else:
                cli.get_password(tag, keeper, args.print_stdout)

        elif args.command == 'edit':
            for t in args.tag:
                cli.edit(t, keeper)

        elif args.command == 'list':
            items = keeper.list_triplets()
            if args.num:
                print(len(items))
            else:
                cli.print_triplets(items, not args.show)
            del items

        elif args.command == 'search':
            cli.search(args.tag, args.show, keeper)

        elif args.command == 'shred-locker':
            cli.delete_locker(keeper)

        elif args.command == 'generate':
            tag = args.tag
            cli.generate_password_and_store(tag, args.length, args.no_symbols, args.no_letters, keeper, args.no_paste)


    except KeyboardInterrupt:
        return print('\nAborting...')

if __name__ == '__main__':
    p = ArgumentParser(description="Keeper is a Python password manager. Locker is a .lk file where passwords are stored, triplet is tag/login/password. More detailed info about each command can be seen by adding -h to the command.")

    subparsers = p.add_subparsers(dest='command', help='Available commands')

    add_parser = subparsers.add_parser('add', help='Add a new triplet with provided tag or tags.')
    add_parser.add_argument('tag', metavar='TAG(S)', type=str, nargs='+', help='Tag(s) for the new triplet(s).')
    add_parser.add_argument('-s', '--show-password', action='store_true', help='Show password when adding triplet')

    remove_parser = subparsers.add_parser('remove', help='Remove a triplet based on tag or tags.')
    remove_parser.add_argument('tag', metavar='TAG(S)', type=str, nargs='+', help='Tag(s) of the triplet(s) to remove.')
    remove_parser.add_argument('-nc', '--no-confirm', action='store_true', help='Do not confirm deleting of a triplet')

    get_parser = subparsers.add_parser('get', help='Retrieve login or password based on tag.')
    get_parser.add_argument('tag', metavar='TAG', type=str, help='Tag of the triplet to get.')
    get_parser.add_argument('-l', '--login', action='store_true', help='Return the login to the clipboard instead of password.')
    get_parser.add_argument('-ps', '--print-stdout', action='store_true',help='Instead of copying to the clipboard, print to the stdout.')

    edit_parser = subparsers.add_parser('edit', help='Interactively edit parameters of a triplet.')
    edit_parser.add_argument('tag', metavar='TAG(S)', type=str, nargs='+', help='Tag(s) of the triplet(s) to edit.')

    list_parser = subparsers.add_parser('list', help='List all stored triplets.')
    list_parser.add_argument('-s', '--show', action='store_true', help='Include passwords in the listing.')
    list_parser.add_argument('-n', '--num', action='store_true', help='Output number of passwords instead of printing each one.')

    search_parser = subparsers.add_parser('search', help='Search for a triplets with similar tag.')
    search_parser.add_argument('tag', metavar='TAG', type=str, help='Similar tag to search for.')
    search_parser.add_argument('-s', '--show', action='store_true', help='Show passwords for every found triplet')

    generate_parser = subparsers.add_parser('generate', help="Generates a password and stores it with provided tag")
    generate_parser.add_argument('tag', metavar='TAG', type=str, help='Tag for the new triplet.')
    generate_parser.add_argument('-l', '--length', type=int, default=16, help='Length of the generated password, default value is 16.')
    generate_parser.add_argument('-ns', '--no-symbols', action='store_true', help='generates a password without any special symbols.')
    generate_parser.add_argument('-nl', '--no-letters', action='store_true', help='generates a password without any letters.')
    generate_parser.add_argument('-np', '--no-paste', action='store_true', help='Do not paste generated password to the clipboard')

    change_parser = subparsers.add_parser('change', help='Changes current locker file to provided.')
    change_parser.add_argument('dir', metavar='DIR', type=str, help='Directory to the new locker file.')
    change_parser.add_argument('-a', '--absolute', action='store_true', help='Open a file out of the storage directory')

    copy_parser = subparsers.add_parser('copy', help='Copy current .lk or token file to the provided directory.')
    copy_parser.add_argument('dir', metavar='[DIR]', type=str, nargs='?', help='Directory to copy to. If no directory provided, copy to the current directory.')
    copy_parser.add_argument('-t', '--token', action='store_true', help='Instead of copying current locker file, copy token to the provided directory.')

    current_parser = subparsers.add_parser('current', help='Prints directory of the current locker in use.')
    current_parser.add_argument('-f', '--full', action='store_true', help='Print absolute path, include root passwords storage directory')

    shred_parser = subparsers.add_parser('shred-locker', help='Shreds current locker.')

    args = p.parse_args()

    keeper = Keeper()
    cli = CLI()

    try:
        if not keeper.is_locker_salted():
            cli.console_registrate(keeper)

        else:
            cli.console_auth(keeper)

    except KeyboardInterrupt:
        sys_exit(1)

    if any(vars(args).values()):
        main(args, keeper, cli)

    else:
        current_locker = keeper.get_current_locker_dir()
        while True:
            try:
                if current_locker != keeper.get_current_locker_dir() or not keeper.is_locker_salted():
                    if not keeper.is_locker_salted():
                        cli.console_registrate(keeper)
                    else:
                        cli.console_auth(keeper)
                    current_locker = keeper.get_current_locker_dir()

                command = input(">> ").strip()

                if command.lower() in ("quit", "exit"):
                    print("Exiting...")
                    break

                elif command.lower() == 'help':
                    p.print_help()
                    continue

                elif command.lower() == 'clear':
                    command = 'cls' if keeper.platform == 'Windows' else 'clear'
                    os_system(command)
                    continue

                args = p.parse_args(command.split())

                if any(vars(args).values()):
                    main(args, keeper, cli)
                else:
                    continue

            except KeyboardInterrupt:
                print("\nExiting...")
                break

            except SystemExit:
                continue