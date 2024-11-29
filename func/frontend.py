import pyperclip

from getpass import getpass
from subprocess import run as sub_run
from os import environ

from func.backend import Keeper

def add_to_clipboard(content: str):
    try:
        pyperclip.copy(content)

    except Exception as e:
        if 'TERMUX_VERSION' in environ:
            sub_run(["termux-clipboard-set", content])
        else:
            raise e

class CLI:
    def __init__(self):
        pass
        
    def message(self, do_message: bool):
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
            print('You can get your token with "copy --token" command, then move it to ~/.local/share/keeper\n')

            print("[WARNING!] Make sure to remember this passphrase! as losing it")
            print("means you will not be able to recover your encrypted passwords.\n")

    def console_registrate(self, keeper: Keeper):
        self.message(not keeper.token_exists())
        print("Current locker: ", keeper.get_current_locker_dir())

        while True:
            passphrase = getpass("Create passphrase for the locker: ")

            if len(passphrase) < 3:
                print("Passphrase is too short")
                continue

            repeated = getpass("Repeat passphrase: ")

            if passphrase == repeated:
                print("Passphrase created")
                return keeper.verify_key(passphrase)
            else:
                print("Passphrases don't match")

    def console_auth(self, keeper: Keeper):
        current_locker = f"[{keeper.get_current_locker_dir(is_full=False)}] "

        while True:
            passphrase = getpass(f"Passphrase: {current_locker}")

            if keeper.verify_key(passphrase):
                return
            
            else:
                print("Incorrect passphrase, try again")

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

    def delete_locker(self, keeper: Keeper):
        choice = input("Are you sure you want to delete all the data from the current locker? [y/N] ")

        if 'y' == choice.lower():
            keeper.reset()
            return print("Data reseted")

        else:
            print("Aboarting..")

    def change_locker(self, new_locker: str, keeper: Keeper, is_abs = False):
        try:
            keeper.change_locker_dir(new_locker, is_relative=is_abs)
            print(f'\nSuccesfuly changed current locker to : {new_locker}\n')

        except FileNotFoundError:
            print(f"\nCould not find: {new_locker}\n")

        except ValueError:
            print(f"\n{new_locker} should be a .lk file\n")

        except AssertionError:
            print(f"\n{new_locker} is current locker\n")

    def add_triplet(self, tag: str, keeper: Keeper, do_show_password=False, password=None):
        if keeper.get_triplet(tag):
            print(f"Triplet with tag '{tag}' already exists.\n")
            return 0

        print(f'\nCreating new triplet with tag "{tag}"\n')

        while True:
            login = input("Enter the login: ")

            if len(login):
                break

            print("Login can not be empty!")

        if not password:
            while True:
                if do_show_password:
                    password = input("Enter the password [󰈈] : ")

                else:
                    password = getpass("Enter the password: ")

                if len(password):            
                    break

                print("Password can not be empty!")

        keeper.store_triplet(tag, login, password)
        print(f"Triplet successfully stored with the tag: {tag}")


    def get_password(self, tag: str, keeper: Keeper, no_clipboard=False):
        triplet = keeper.get_triplet(tag)

        if triplet is None:
            print(f'Could not find triplet with tag: {tag}')
            return

        if no_clipboard:
            print(triplet[2])

        else:
            add_to_clipboard(triplet[2])
            print("Password added to the clipboard!")


    def get_login(self, tag: str,  keeper: Keeper, no_clipboard=False):
        triplet = keeper.get_triplet(tag)

        if triplet is None:
            print(f'Could not find triplet with tag: {tag}')
            return

        if no_clipboard:
            print(triplet[1])

        else:
            add_to_clipboard(triplet[1])
            print("Login added to the clipboard!")

    def search(self, tag: str, do_show: bool, keeper: Keeper):
        found = keeper.search_for_triplet(tag)
        self.print_triplets(found, not do_show)
        del found

    def remove_by_tag(self, tag: str, keeper: Keeper, no_confirm=False):
        triplet = keeper.get_triplet(tag)

        if triplet is None:
            return print(f"Could not find triplet with tag: {tag}")

        self.print_triplet(triplet)
        print('')

        if not no_confirm:
            remove = input("Delete this triplet? [y/N] ")

            if 'y' != remove.lower():
                print("Aboarting..")
                return

        keeper.remove_triplet(tag)
        print("Triplet deleted")

    def edit(self, tag: str, keeper: Keeper):
        triplet = keeper.get_triplet(tag)

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
                keeper.edit_triplet_property(tag, param, value)
                break

            except ValueError:
                print(f'Triplet with tag "{value}" already exist')

        print(f'Succesfully edited triplet with tag: "{tag}"')

    def copy(self, dest: str, keeper: Keeper):
        try:
            keeper.copy_locker(dest)
            print(f'Succesfuly copied current locker to "{dest}"')

        except:
            print(f"Could not find destination dir: {dest}")
        
    def copy_token(self, dest: str, keeper: Keeper):
        try:
            keeper.copy_token(dest)
            print(f'Succesfuly copied token to "{dest}"')

        except:
            print(f"Could not find destination dir: {dest}")

    def generate_password_and_store(self, tag: str, length: int, 
        no_syms: bool, no_letters: bool, keeper: Keeper, do_not_paste=False):
        generated_password = keeper.generate_password(length, no_syms, no_letters)
        
        if self.add_triplet(tag, keeper, password=generated_password) == 0:
            return

        if not do_not_paste:
            add_to_clipboard(generated_password)
            print("Generated password added to the clipboard!")
        else:
            print(f"Password is generated and stored with the tag: {tag}")
