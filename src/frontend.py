import pyperclip

from getpass import getpass
from subprocess import run as sub_run
from os import environ, name as os_name, system as os_system

from src.backend import Keeper
from sys import exit as sys_exit

def add_to_clipboard(content: str):
    try:
        pyperclip.copy(content)

    except Exception as e:
        if 'TERMUX_VERSION' in environ:
            sub_run(["termux-clipboard-set", content])
        else:
            raise e

class CLI:
    def __init__(self, keeper: Keeper):
        self.keeper = keeper
        
    def message(self, do_message: bool, token_dir: str):
        if do_message:
            print("""\n
              \033[36m/\\ /\\___  \033[35m___ _ __   ___ _ __     
             \033[36m/ //_/ _ \\\033[35m/ _ \\ '_ \\ / _ \\ '__|   
            \033[36m/ __ \\  __/\033[35m  __/ |_) |  __/ |   
            \033[36m\\/  \\/\\___|\033[35m\\___| .__/ \\___|_|   
                          \033[35m |_|              
                \033[0m\n""")

            print("Keeper is a password manager designed to securely store your passwords locally.")
            print('Each password file is referred to as a \033[33m"locker"\033[0m and has a .lk extension.')
            print("You can manage multiple lockers, each containing different sets of passwords.")
            print("Passwords are stored in a triplet format: \033[33mtag/login/password\033[0m.") 
            print("Use the tag to retrieve detailed information about each triplet.")
            print("Lockers are encrypted with a passphrase and your unique token.")
            print("If you want to use your lockers on multiple devices, you need the same token.")

            print(f"\033[33m[WARNING!]\033[0m You don't have a token yet. Generate it by 'keeper generate-token'")
            print(f"or insert your existing token to {token_dir}")
            print(f'You can get your token with "copy --token" command, then move it to {token_dir}\n')
            print("\033[33m[WARNING!]\033[0m Make sure to remember this passphrase! as losing it")
            print("means you will not be able to recover your encrypted passwords.\n")
            
            # Fix infinity loop on token creation
            sys_exit(3)

    def auth(self) -> int:
        if not self.keeper.is_locker_salted():
            self.registrate()
        else:
            self.login()

    def registrate(self):
        self.message(not self.keeper.token_exists(), self.keeper.token_file)
        print("Current locker: ", self.keeper.get_current_locker_dir())

        while True:
            passphrase = getpass("Create passphrase for the locker: ")

            if len(passphrase) < 3:
                print("Passphrase is too short")
                continue

            repeated = getpass("Repeat passphrase: ")

            if passphrase == repeated:
                print("Passphrase created")
                return self.keeper.verify_key(passphrase)
            else:
                print("Passphrases don't match")

    def login(self):
        current_locker = f"[{self.keeper.get_current_locker_dir(is_full=False)}] "

        while True:
            passphrase = getpass(f"Passphrase: {current_locker}")

            try:
                if self.keeper.verify_key(passphrase):
                    return
            
                else:
                    print("Incorrect passphrase, try again")
            except ValueError:
                print(f"You haven't a token yet. Generate it by 'keeper generate-token' or set it manually to {self.keeper.token_file}")
                sys_exit(1)

    def print_locker(self, locker: str):
        print(f"Current locker: {locker}")

    def print_triplet(self, triplet: tuple, hidden_password=True):
        print('\nTag:', triplet[0])
        print('Login:', triplet[1])

        if not hidden_password:
            print('Password:', triplet[2])

    def print_triplets(self, triplets: list[tuple], is_hidden=True):
        for triplet in triplets:
            self.print_triplet(triplet, is_hidden)
        print('')    

    def delete_locker(self):
        choice = input("Are you sure you want to delete all the data from the current locker? [y/N] ")

        if 'y' == choice.lower():
            self.keeper.reset()
            return print("Data reseted")

        else:
            print("Aboarting..")

    def change_locker(self, new_locker: str, is_abs = False):
        try:
            self.keeper.change_locker_dir(new_locker, is_relative=is_abs)
            print(f'\nSuccesfuly changed current locker to : {new_locker}\n')

        except FileNotFoundError:
            print(f"\nCould not find: {new_locker}\n")

        except ValueError:
            print(f"\n{new_locker} should be a .lk file\n")

        except AssertionError:
            print(f"\n{new_locker} is current locker\n")

    def add_triplet(self, tag: str, do_show_password=False, password=None):
        if self.keeper.get_triplet(tag):
            print(f"Triplet with tag '{tag}' already exists.\n")
            return 0

        print(f'\nCreating new triplet with tag "{tag}"\n')

        try:
            while True:
                login = input("Enter the login: ")

                if len(login):
                    break

                print("Login can not be empty!")

            if not password:
                while True:
                    if do_show_password:
                        password = input("Enter the password [*] : ")

                    else:
                        password = getpass("Enter the password: ")

                    if len(password):            
                        break

                    print("Password can not be empty!")

        except KeyboardInterrupt as e:
            raise e

        self.keeper.store_triplet(tag, login, password)
        print(f"Triplet successfully stored with the tag: {tag}")


    def get_password(self, tag: str, no_clipboard=False):
        triplet = self.keeper.get_triplet(tag)

        if triplet is None:
            print(f'Could not find triplet with tag: {tag}')
            return

        if no_clipboard:
            print(triplet[2])

        else:
            add_to_clipboard(triplet[2])
            print("Password added to the clipboard!")


    def get_login(self, tag: str, no_clipboard=False):
        triplet = self.keeper.get_triplet(tag)

        if triplet is None:
            print(f'Could not find triplet with tag: {tag}')
            return

        if no_clipboard:
            print(triplet[1])

        else:
            add_to_clipboard(triplet[1])
            print("Login added to the clipboard!")

    def search(self, tag: str, do_show: bool):
        found = self.keeper.search_for_triplet(tag)
        self.print_triplets(found, not do_show)
        del found

    def remove_by_tag(self, tag: str, no_confirm=False):
        triplet = self.keeper.get_triplet(tag)

        if triplet is None:
            return print(f"Could not find triplet with tag: {tag}")

        self.print_triplet(triplet)
        print('')

        if not no_confirm:
            remove = input("Delete this triplet? [y/N] ")

            if 'y' != remove.lower():
                print("Aboarting..")
                return

        self.keeper.remove_triplet(tag)
        print("Triplet deleted")

    def edit(self, tag: str):
        triplet = self.keeper.get_triplet(tag)

        if triplet is None:
            print(f"Could not find triplet with tag: {tag}")
            return

        print(f'\nEditing triplet with tag "{tag}"')
        print("\nParameters that can be edited: \n\t0 - tag \n\t1 - login \n\t2 - password\n")

        while True:
            try:
                param = int(input("Enter the parameter to edit (0-2): "))

            except:
                param = -1

            if param in (0, 1, 2):
                break

            else:
                print("Incorrect parameter")

        while True:
            value = input(f'Enter new value for \"{("tag", "login", "password")[param]}\": ')

            try:
                self.keeper.edit_triplet_property(tag, param, value)
                break

            except ValueError:
                print(f'Triplet with tag "{value}" already exist')

        print(f'Succesfully edited triplet with tag: "{tag}"')

    def copy(self, dest: str):
        try:
            self.keeper.copy_locker(dest)
            print(f'Succesfuly copied current locker to "{dest}"')

        except:
            print(f"Could not find destination dir: {dest}")
        
    def copy_token(self, dest: str):
        try:
            self.keeper.copy_token(dest)
            print(f'Succesfuly copied token to "{dest}"')

        except:
            print(f"Could not find destination dir: {dest}")

    def generate_password_and_store(self, tag: str, length: int, 
        no_syms: bool, no_letters: bool, do_not_paste=False):
        generated_password = self.keeper.generate_password(length, no_syms, no_letters)
        
        if self.add_triplet(tag, password=generated_password) == 0:
            return

        if not do_not_paste:
            add_to_clipboard(generated_password)
            print("Generated password added to the clipboard!")
        else:
            print(f"Password is generated and stored with the tag: {tag}")

    def generate_token(self):
        print("Generating token...")

        try:
            self.keeper.generate_token()
            print("Token was generated")

        except AssertionError:
            print(f"Token already exists at {self.keeper.token_file}")

    def clear_screen(self):
        if os_name == 'nt':
            os_system('cls')
        else: 
            os_system('clear')

    def interactive_cli(self, parser: any):
        current_locker = self.keeper.get_current_locker_dir()

        while True:
            try:
                if current_locker != self.keeper.get_current_locker_dir() or not self.keeper.is_locker_salted():
                    self.auth()
                    current_locker = self.keeper.get_current_locker_dir()

                command = input(">> ").strip()

                if command.lower() in ("quit", "exit"):
                    print("Exiting...")
                    break

                elif command.lower() == 'help':
                    parser.print_help()
                    continue

                elif command.lower() == 'clear':
                    self.clear_screen()
                    continue

                args = parser.parse_args(command.split())

                if any(vars(args).values()):
                    # If there were some interrupt, lets exit
                    if self.handle_args(args) == 1: raise KeyboardInterrupt
                else:
                    continue

            except KeyboardInterrupt:
                print("\nExiting...")
                break

            # The point of this part of this except is that when argparse successfully 
            # parses arguments and the command gets executed, it raises SystemExit. 
            # Though we don't want it. Well keep call argaprse as much as user wants
            # Although we raise SystemExit to :). It should be prevented here 

            except SystemExit as e:
                if e.code == 3:
                    return
                continue

    def handle_args(self, args):
        try:
            if not self.keeper.has_cipher():
                self.auth()

            if args.command == 'change':
                self.change_locker(args.dir, args.absolute)

            elif args.command == 'current':
                self.print_locker(self.keeper.get_current_locker_dir(args.full))

            elif args.command == 'copy':
                dest = args.dir if args.dir else '.'
                if args.token:
                    self.copy_token(dest)
                else:
                    self.copy(dest)

            elif args.command == 'add':
                for t in args.tag:
                    self.add_triplet(t, args.show_password)

            elif args.command == 'remove':
                for t in args.tag:
                    self.remove_by_tag(t, args.no_confirm)

            elif args.command == 'get':
                tag = args.tag
                if args.login:
                    self.get_login(tag, args.print_stdout)
                else:
                    self.get_password(tag, args.print_stdout)

            elif args.command == 'edit':
                for t in args.tag:
                    self.edit(t)

            elif args.command == 'list':
                items = self.keeper.list_triplets()
                if args.num:
                    print(len(items))
                else:
                    self.print_triplets(items, not args.show)
                del items

            elif args.command == 'search':
                self.search(args.tag, args.show)

            elif args.command == 'shred-locker':
                self.delete_locker()

            elif args.command == 'generate':
                tag = args.tag
                self.generate_password_and_store(tag, args.length, args.no_symbols, args.no_letters, args.no_paste)

            elif args.command == 'generate-token':
                print('No.')

        except KeyboardInterrupt:
            return print('\nAborting...')

    def main(self, args: any, parser: any = None):
        """
        Main entry function, used to start frontend functionality.  
        """

        # Given: args or None and parser. 
        # Objective: Proper handling, of authentification, interactive cli if no args

        # Operations that can be executed without password entering

        no_auth_commands = ('generate-token', 'change', 'current')
        self.keeper.trigger_event("init")

        if args:
            if args.command in no_auth_commands:
                # Can be executed without any registration, because 
                # these operations don't involve cryptography  

                if args.command == 'generate-token':
                    self.generate_token()
                elif args.command == 'change':
                    self.change_locker(args.dir, args.absolute)
                else:
                    self.print_locker(self.keeper.get_current_locker_dir(args.full))

            else:                            
                self.handle_args(args)
        else:
            self.interactive_cli(parser)

        self.keeper.trigger_event('exit')

Frontend = CLI