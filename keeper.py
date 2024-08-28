from argparse import ArgumentParser
from getpass import getpass
from cryptography.fernet import Fernet, InvalidToken
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
from shutil import copy
from platform import system
from hashlib import sha256
from sys import exit as sys_exit
from subprocess import run as sub_run

import re, base64, pyperclip, os, random, string

def add_to_clipboard(content: str):
    try:
        pyperclip.copy(content)

    except Exception as e:
        if 'TERMUX_VERSION' in os.environ:
            sub_run(["termux-clipboard-set", content])
        else:
            raise e

class FileSystem:
    """
    Class for file manipulatoions with password manager file system
    """

    def __init__(self, salt_size=16, header_size=64) -> None:
        self.root_dir = self._determine_root_dir()
        self.current_locker_file = os.path.join(self.root_dir, '.current_locker') 
        # file with current selected locker directory

        self._salt_size=salt_size
        self._header_size=header_size # size as symbols

        self.init_locker()

    def _determine_root_dir(self) -> str:
        """
        Determine working root dir based on operating system, and create the leaf directory
        """
        platform = system()

        dirs = {
            'Linux' : os.path.expanduser('~/.local/share/keeper'),   
            'Darwin': os.path.expanduser('~/.local/share/keeper'),  # macOS
            'Windows' : os.path.join(os.environ.get('LOCALAPPDATA', os.path.expanduser('~')), 'keeper')
        }

        if platform in dirs:
            dir = dirs[platform]
            os.makedirs(dir, exist_ok=True)
            return dir
        
        else:
            raise OSError(f"Unsuported os: {platform}")

    def init_locker(self) -> None:
        """
        Ensure that required directories and files exist. Initializing locker file
        """

        if not os.path.exists(self.current_locker_file):
            with open(self.current_locker_file, 'w'):
                pass

        self.locker = self.get_current_locker() 

        if not self.locker or not os.path.exists(self.locker):
            # if it is empty, or previous locker doesnt exist anymore we set default one and make it 
            self.locker = os.path.join(self.root_dir, 'default.lk')
            
            if not os.path.exists(self.locker):
                with open(self.locker, 'w'):
                    pass

            self.change_locker(self.locker)

    def salt_exists(self) -> bool:
        """
        Check if the salt exists.
        """
        try:
            return bool(self.get_salt())
            
        except:
            return False

    def get_salt(self) -> bytes:
        """
        Returns salt of the file
        """
        with open(self.locker, 'rb') as f:
            return f.read(self._salt_size)
        
    def get_line_from_storage(self, header: bytes) -> bytes| None:
        """
        Returns a line based on the header
        """

        with open(self.locker, 'rb') as locker:
            locker.read(self._salt_size)

            for line in locker:
                line_header = line[:self._header_size]

                if line_header == header:
                    return line[self._header_size:]

    def get_all_lines_from_storage(self) -> list[bytes]:
        """
        Reuturns all lines from the storage
        """
        lines = []

        with open(self.locker, 'rb') as locker:
            locker.read(self._salt_size)

            for line in locker:
                lines.append(line[self._header_size:])
        
        return lines

    def set_to_locker(self, value: bytes, set_salt=True) -> None :
        """
        Sets/Appends content to the locker based on param. 
        """

        if not set_salt and not self.salt_exists():
            raise Warning("Salt doesn't exist!")

        mode = 'wb' if set_salt else 'ab'

        with open(self.locker, mode) as f:
            f.write(value)

    def remove_from_storage(self, header: bytes) -> None:
        """
        Remove a line with the same header from the locker file.
        """

        temp_file = self.locker + '.tmp'

        try:
            with open(self.locker, 'rb') as original, open(temp_file, 'wb') as tmp:
                tmp.write(original.read(self._salt_size))

                for line in original:
                    line_header = line[:self._header_size]

                    if header != line_header:
                        tmp.write(line)

        except KeyboardInterrupt:
            return os.remove(temp_file)

        os.replace(temp_file, self.locker)


    def change_locker(self, dest: str) -> None:
        """
        A function to change current locker to provided dir. 
        """

        dest = os.path.abspath(os.path.expanduser(dest))
        
        if os.path.isdir(dest):
            raise ValueError("Argument is a directory")

        elif not os.path.exists(dest):
            raise FileNotFoundError("Could not find locker file")

        elif dest == self.get_current_locker():
            raise IndentationError("Same file")

        with open(self.current_locker_file, 'w') as f:
            f.write(dest)

        self.init_locker() # Reset locker file to the new locker

    def copy_locker(self, dir: str) -> None:
        """
        Recieves destination dir and copies current locker there
        """

        dir = os.path.abspath(os.path.expanduser(dir))

        copy(self.locker, dir)

    def get_current_locker(self, is_last_two=False):
        """
        Returns current locker directory
        """
        with open(self.current_locker_file) as f:
            content = f.read().strip()

            if is_last_two:
                last_dir = os.path.basename(os.path.dirname(content))
                file = os.path.basename(content)
                return os.path.join(last_dir, file)

            return content

    def suicide(self):
        """
        Shreds current locker and removes it
        """
        try:
            with open(self.locker, 'r+b') as f:
                file_size = os.path.getsize(self.locker)
                
                for _ in range(2):
                    f.seek(0)
                    f.write(bytearray(random.getrandbits(8) for _ in range(file_size)))
                
                f.truncate()
            
            os.remove(self.locker)
    
        except Exception as e:
            raise e

def derive_key(passphrase: bytes, salt: bytes):
    """
    Gets passphrase and salt, returns a unique key
    """

    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=1000,
        backend=default_backend()
    )

    return base64.urlsafe_b64encode(kdf.derive(passphrase))

class CryptoSystem:
    """
    Cryptography class for encrypting / decrypting passwords, hashing 
    """

    def get_cipher(self, key: bytes):
        """
        Gets key as bytes and returns Fernet instance for
        future decryption and encryption
        """
        return Fernet(key)

    def encrypt(self, cipher: Fernet, data: str):
        """
        Gets data and Fernet instance.
        returns encrypted data
        """
        return cipher.encrypt(data.encode()).decode()

    def decrypt(self, cipher: Fernet, encrypted_data: bytes):
        """
        Gets encrypted data and a Fernet instance. 
        returns decrypted data
        """
        return cipher.decrypt(encrypted_data).decode()

    def generate_salt(self, size=16):
        """
        Generates a random salt of given size.
        """
        return os.urandom(size)
    
    def hash(self, content: str) -> bytes:
        """
        Returns hashed content as bytes
        """
        return sha256(content.encode()).hexdigest().encode()

    def generate_password(self, length: int, is_no_special_symbols: bool, is_no_letters: bool):

        """
        Based on options, generates random password
        """

        letters = string.ascii_letters
        digits = string.digits
        special_symbols = string.punctuation
        
        # Determine the character set to use
        if is_no_special_symbols and is_no_letters:
            chars = digits

        elif is_no_special_symbols:
            chars = letters + digits

        elif is_no_letters:
            chars = digits + special_symbols

        else:
            chars = letters + digits + special_symbols
        
        if not chars:
            raise ValueError("Character set is empty. Cannot generate a password.")

        password = ''.join(random.choice(chars) for _ in range(length))
        
        return password

def red(string: str) -> str:
    return "\033[31m" + string + "\033[0m"

def green(string: str) -> str:
    return "\033[32m" + string + "\033[0m"

def blue(string: str) -> str:
    return "\033[34m" + string + "\033[0m"

class Keeper:
    """
    Class for manipulations of both FileSystem and CryptoSystem
    Provides functionality for a password manager
    """

    def __init__(self, fs: FileSystem, cs: CryptoSystem):
        self.cipher = None
        self.fs = fs
        self.cs = cs

    def __escape_brackets(self, text: str) -> str:
        return text.replace("]", "/]").replace("[", "/[")

    def __restore_brackets(self, text: str) -> str:
        return text.replace("/]", "]").replace("/[", "[")

    def _decrypt_triplet(self, line: bytes):
        decrypted_line = self.__restore_brackets(self.cs.decrypt(self.cipher, line).rstrip('\n'))
        matches: list[str] = re.findall(r'\[\s*([^\]]+?)\s*\]', decrypted_line)
        
        if len(matches) == 3:
            return (matches[0], matches[1], matches[2])

        else:
            raise ValueError(f"Unexpected Matching error")

    def _set_cipher(self, passphrase: str):
        """
        Sets Keeper's cipher based on passphrase. 
        Required before recieving triplets
        """
        passphrase_bytes = passphrase.encode()

        if not self.fs.salt_exists():
            salt = self.cs.generate_salt()
            self.fs.set_to_locker(salt)

        else:
            salt = self.fs.get_salt()

        key = derive_key(passphrase_bytes, salt)
        self.cipher = self.cs.get_cipher(key)

    def init_keeper(self, passphrase: str):
        """
        Basic function that is used before any decrypting / encrypting methods. 
        Use to check the correctness of given password
        """
        try:
            self._set_cipher(passphrase)
            listed = self.list_triplets()
            del listed
            return True
        
        except InvalidToken:
            return False
        
        except Exception as e:
            raise e

    def list_triplets(self):
        encrypted_lines = self.fs.get_all_lines_from_storage()
        decrypted_triplets = []

        for line in encrypted_lines:
            decrypted_triplets.append(self._decrypt_triplet(line))

        return decrypted_triplets

    def search_for_triplet(self, part_tag: str):
        encrypted_lines = self.fs.get_all_lines_from_storage()
        found = []

        for line in encrypted_lines:
            decrypted_triplet = self._decrypt_triplet(line)

            if part_tag.lower() in decrypted_triplet[0].lower():
                found.append(decrypted_triplet)

        return found

    def get_triplet(self, tag: str):
        """
        Returns a triplet with the same tag
        """
        hash_tag = self.cs.hash(tag)

        found = self.fs.get_line_from_storage(hash_tag)

        if found:
            return self._decrypt_triplet(found)

        return None 

    def store_triplet(self, tag: str, login: str, password: str):
        """
        Stores a formatted triplet (nametag, login, password) in the storage after encryption.
        """

        tag = self.__escape_brackets(tag).strip()
        login = self.__escape_brackets(login).strip()
        password = self.__escape_brackets(password).strip()

        formatted_line = f"[ {tag} ] [ {login} ] [ {password} ]"

        hash_tag = self.cs.hash(tag)

        encrypted_line = self.cs.encrypt(self.cipher, formatted_line) + '\n'
        self.fs.set_to_locker(hash_tag + encrypted_line.encode(), set_salt=False)

    
    def remove_triplet(self, tag: str):
        """
        Removes triplet
        """
        hash_tag = self.cs.hash(tag)

        self.fs.remove_from_storage(hash_tag)

    def edit_triplet_property(self, tag: str, property: int, value: str):
        """
        Gets list of triplets, triplet and a property to edit as index.
            0: Tag
            1: Login
            2: Password
        """
        triplet = list(self.get_triplet(tag))
        triplet[property] = value
        new_tag, new_login, new_password = triplet

        if property == 0 and self.get_triplet(new_tag):
            raise ValueError("Triplet already exist")

        self.remove_triplet(tag)
        self.store_triplet(new_tag, new_login, new_password)

    def copy_locker(self, destination: str):
        """
        Copies current locker to the specified dir
        """
        self.fs.copy_locker(destination)

    def change_locker(self, locker_dir: str):
        """
        Changes current locker to provided directory
        """
        self.fs.change_locker(locker_dir)

    def get_current_locker(self, is_last_two=False):
        """
        Returns locker currently working with
        """
        return self.fs.get_current_locker(is_last_two)

    def generate_password(self, length: int, is_no_special_symbols=False, is_no_letters=False):
        """
        Generates a password based on the params
        """
        return self.cs.generate_password(length, is_no_special_symbols, is_no_letters)
    
    def reset(self):
        """
        Resets all the data from current locker
        """
        self.fs.suicide()

    def passphrase_exist(self):
        """
        Checks is passphrase already exists
        """
        return self.fs.salt_exists()

    # Interface functions

    def console_auth(self):
        """
        Default funciton for console password prompt auth
        """

        current_locker = f"[{self.get_current_locker(True)}] "

        if current_locker == '[keeper/default.lk] ' or current_locker == '[keeper\\default.lk] ':
            current_locker = ''

        current_locker = blue(current_locker)

        while True:
            passphrase = getpass(f"\033[95mPassphrase: {current_locker}\033[0m")

            if self.init_keeper(passphrase):
                return
            
            else:
                print(red("Incorrect passphrase, try again"))

    def console_registrate(self):
        """
        Default function for registration, creating passphrase
        """

        print("""
          \033[36m/\\ /\\___  \033[35m___ _ __   ___ _ __ 
         \033[36m/ //_/ _ \\\033[35m/ _ \\ '_ \\ / _ \\ '__|
        \033[36m/ __ \\  __/\033[35m  __/ |_) |  __/ |   
        \033[36m\\/  \\/\\___|\033[35m\\___| .__/ \\___|_|   
                      \033[35m |_|              
    """)
    # Print the welcome message with colors directly
        print(green("Welcome to Keeper!\n"))
        print("\n\033[33m[Info]\033[34m Keeper is a password manager designed to securely store your passwords locally on your machine.\033[0m")
        print("\033[33m[Info]\033[34m Each password file is referred to as a \033[33m'locker'\033[34m and has a .lk extension.\033[0m")
        print("\033[33m[Info]\033[34m You can manage multiple lockers, each containing different sets of passwords.\033[0m")
        print("\033[33m[Info]\033[34m Passwords are stored in a triplet format: \033[33mtag/login/password\033[34m. Use the tag to retrieve detailed information about each triplet.\033[0m")
        print("\033[33m[Info]\033[34m Lockers are encrypted with a passphrase.\n")

        print(red("[WARNING!] Make sure to remember this passphrase, as losing it means you will not be able to recover your encrypted passwords.\n"))

        print("\033[35mCurrent locker: ", self.get_current_locker() + '\033[0m\n')

        while True:
            passphrase = getpass(green("Create passphrase for the locker: "))

            if len(passphrase) < 3:
                print(red("Passphrase is too short"))
                continue

            repeated = getpass(green("Repeat passphrase: "))

            if passphrase == repeated:
                print(green("Passphrase created"))
                self.init_keeper(passphrase)
                return
            
            else:
                print(red("Passwords don't match"))


def print_locker(locker: str):
    print(f"\n\033[32mCurrent locker: \033[36m{locker}\n\033[0m")

def print_triplet(triplet: tuple, hidden_password=True):
    print('\n\033[34mTag:', triplet[0] + '\033[0m')
    print('\033[36mLogin:', triplet[1] + '\033[0m')

    if not hidden_password:
        print('\033[35mPassword:', triplet[2] + '\033[0m')

def print_triplets(triplets: list[tuple], is_hidden=True):
    for triplet in triplets:
        print_triplet(triplet, is_hidden)
    print('')    

def delete_locker(keeper: Keeper):
    choice = input(red("Are you sure you want to delete all the data from the current locker? [y/N] "))

    if 'y' == choice.lower():
        keeper.reset()
        print(green("Data reseted"))
        return

    else:
        print(green("Aboarting.."))

def change_locker(new_locker: str, keeper: Keeper):
    try:
        keeper.change_locker(new_locker)
        print(green(f'\nSuccesfuly changed current locker to : {new_locker}\n'))

    except FileNotFoundError:
        print(red(f"\nCould not find: {new_locker}\n"))

    except ValueError:
        print(red(f"\n{new_locker} should be a .lk file\n"))

    except IndentationError:
        print(red(f"\n{new_locker} is current locker\n"))

def add_triplet(tag: str, keeper: Keeper, do_show_password=False, password=None):
    if keeper.get_triplet(tag):
        print(red(f"Triplet with tag '{tag}' already exists.\n"))
        return 2

    print(blue(f'\nCreating new triplet with tag "{tag}"\n'))

    while True:
        login = input("\033[36mEnter the login: ")

        if len(login):
            break

        print(red("Login can not be empty!"))


    if not password:
        while True:
            if do_show_password:
                password = input("\033[35mEnter the password [󰈈] : ")

            else:
                password = getpass("\033[35mEnter the password: ")

            if len(password):            
                break

            print(red("Password can not be empty!"))

    keeper.store_triplet(tag, login, password)
    print(green(f"Triplet successfully stored with the tag: {tag}"))


def get_password(tag: str, keeper: Keeper, no_clipboard=False):
    triplet = keeper.get_triplet(tag)

    if triplet is None:
        print(red(f'Could not find triplet with tag: {tag}'))
        return

    if no_clipboard:
        print(triplet[2])

    else:
        add_to_clipboard(triplet[2])
        print(green("Password added to the clipboard!"))


def get_login(tag: str,  keeper: Keeper, no_clipboard=False):
    triplet = keeper.get_triplet(tag)

    if triplet is None:
        print(red(f'Could not find triplet with tag: {tag}'))
        return

    if no_clipboard:
        print(triplet[1])

    else:
        add_to_clipboard(triplet[1])
        print(green("Login added to the clipboard!"))

def search(tag: str, do_show: bool, keeper: Keeper):
    found = keeper.search_for_triplet(tag)
    print_triplets(found, do_show)
    del found

def remove_by_tag(tag: str, keeper: Keeper, no_confirm=False):
    triplet = keeper.get_triplet(tag)

    if triplet is None:
        print(red(f"Could not find triplet with tag: {tag}"))
        return

    print_triplet(triplet)
    print('')

    if not no_confirm:
        remove = input(red("Delete this triplet? [y/N] "))

        if 'y' != remove.lower():
            print(green("Aboarting.."))
            return

    keeper.remove_triplet(tag)
    print(green("Triplet deleted"))


def edit(tag: str, keeper: Keeper):
    triplet = keeper.get_triplet(tag)

    if triplet is None:
        print(red(f"Could not find triplet with tag: {tag}"))
        return

    print(green(f'\nEditing triplet with tag "{tag}"'))
    print(blue("\nParameters that can be edited: \n\t0 - tag \n\t1 - login \n\t2 - password\n"))

    while True:
        try:
            param = int(input(green("Enter the parameter to edit (0-2): ")))

        except:
            param = -1

        if param in (0, 1, 2):
            break

        else:
            print(red("Incorrect parameter"))

    while True:
        value = input(f'\033[32mEnter new value for \"{("tag", "login", "password")[param]}\": \033[0m')

        try:
            keeper.edit_triplet_property(tag, param, value)
            break

        except ValueError:
            print(red(f'Triplet with tag "{value}" already exist'))

    print(green(f'Succesfully edited triplet with tag: "{tag}"'))

def dump(dest: str, keeper: Keeper):

    try:
        keeper.copy_locker(dest)
        print(f'\033[32mSuccesfuly copied current locker to "{dest}"\033[0m')

    except:
        print(red(f"Could not find destination dir: {dest}"))
    
def generate_password_and_store(tag: str, length: int, syms: bool, letters: bool, keeper: Keeper, do_not_paste=False):
    
    generated_password = keeper.generate_password(length, syms, letters)
    print(green("Password is generated."))

    if not do_not_paste and add_triplet(tag, keeper, password=generated_password) != 2:
        add_to_clipboard(generated_password)
        print(green("Generated password added to the clipboard!"))

def main(args: ArgumentParser, keeper: Keeper):    
    try:

        if args.command == 'change':
            change_locker(args.dir, keeper)
        
        elif args.command == 'current':
            print_locker(keeper.get_current_locker())
        
        elif args.command == 'dump':
            dest = args.dir if args.dir else '.'
            dump(dest, keeper)

        if args.command == 'add':
            for t in args.tag:
                add_triplet(t, keeper, args.show_password)

        elif args.command == 'remove':
            for t in args.tag:
                remove_by_tag(t, keeper, args.no_ask)

        elif args.command == 'get':
            tag = args.tag

            if args.login:
                get_login(tag, keeper, args.no_clipboard)

            elif args.password:
                get_password(tag, keeper, args.no_clipboard)

        elif args.command == 'edit':
            for t in args.tag:
                edit(t, keeper)

        elif args.command == 'list':
            items = keeper.list_triplets()

            if args.num:
                print(len(items))
            else:
                print_triplets(items, not args.all)

            del items

        elif args.command == 'search':
            search(args.tag, not args.all, keeper)

        elif args.command == 'shred-locker':
            delete_locker(keeper)

        elif args.command == 'generate':
            tag = args.tag

            generate_password_and_store(tag, args.length, args.no_symbols, args.no_letters, keeper, args.no_paste)

    except KeyboardInterrupt:
        return print(green('\nAborting...'))

if __name__ == '__main__':
    p = ArgumentParser(description="Keeper is a Python password manager. Locker is a .lk file where passwords are stored, triplet is tag/login/password. More detailed info about each command can be seen by adding -h to the command.")

    subparsers = p.add_subparsers(dest='command', help='Available commands')

    add_parser = subparsers.add_parser('add', help='Add a new triplet with provided tag or tags.')
    add_parser.add_argument('tag', metavar='TAG(S)', type=str, nargs='+',
                            help='Tag(s) for the new triplet(s).')
    
    add_parser.add_argument('-s', '--show-password', action='store_true',
                            help='Show password when adding triplet')


    remove_parser = subparsers.add_parser('remove', help='Remove a triplet based on tag or tags.')
    remove_parser.add_argument('tag', metavar='TAG(S)', type=str, nargs='+',
                            help='Tag(s) of the triplet(s) to remove.')

    remove_parser.add_argument('-na', '--no-ask', action='store_true',
                               help='Do not confrm deleting of a triplet')

    get_parser = subparsers.add_parser('get', help='Retrieve login or password based on tag.')
    get_parser.add_argument('tag', metavar='TAG', type=str, help='Tag of the triplet to get.')

    group = get_parser.add_mutually_exclusive_group(required=True)
    group.add_argument('-l', '--login', action='store_true', 
                       help='Return the login to the clipboard.')
    
    group.add_argument('-p', '--password', action='store_true', 
                       help='Return the password to the clipboard.')

    get_parser.add_argument('-nc', '--no-clipboard', action='store_true',
                        help='Instead of copying to the clipboard, will print to the terminal.')


    edit_parser = subparsers.add_parser('edit', help='Interactively edit parameters of a triplet.')
    edit_parser.add_argument('tag', metavar='TAG(S)', type=str, nargs='+',
                            help='Tag(s) of the triplet(s) to edit.')


    list_parser = subparsers.add_parser('list', help='List all stored triplets.')
    list_parser.add_argument('-a', '--all', action='store_true', 
                             help='Include passwords in the listing.')

    list_parser.add_argument('-n', '--num', action='store_true', 
                             help='Output number of passwords instead of printing each one.')

    search_parser = subparsers.add_parser('search', help='Search for a triplets with similar tag.')
    search_parser.add_argument('tag', metavar='TAG', type=str,
                               help='Similar tag to search for.')
    
    search_parser.add_argument('-a', '--all', action='store_true',
                               help='Show passwords for every found triplet')


    generate_parser = subparsers.add_parser('generate', help="Generates a password and stores it with provided tag")

    generate_parser.add_argument('tag', metavar='TAG', type=str,
                                help='Tag for the new triplet.')

    generate_parser.add_argument('-l', '--length', type=int, default=16,
                                 help='Length of the generated password, default value is 16.')

    generate_parser.add_argument('-ns', '--no-symbols', action='store_true',
                                 help='generates a password without any special symbols.')
    
    generate_parser.add_argument('-nl', '--no-letters', action='store_true',
                                 help='generates a password without any letters.')

    generate_parser.add_argument('-np', '--no-paste', action='store_true',
                                 help='Do not paste generated password to the clipboard')

    change_parser = subparsers.add_parser('change', help='Changes current locker file to provided. Default locker file dir: ~/.local/share/.keeper/default.lk')
    change_parser.add_argument('dir', metavar='DIR', type=str,
                               help='Directory to the new locker file.')


    dump_parser = subparsers.add_parser('dump', help='Copy current .lk file to the provided directory.')
    dump_parser.add_argument('dir', metavar='[DIR]', type=str, nargs='?',
                             help='Directory to copy to. If no directory provided, copy to the current directory.')


    current_parser = subparsers.add_parser('current', help='Prints directory of the current locker in use.')

    shred_parser = subparsers.add_parser('shred-locker', help='Shreds current locker.')

    args = p.parse_args()

    keeper = Keeper(FileSystem(), CryptoSystem())


    try:
        if args.command == 'change':
            change_locker(args.dir, keeper)
            sys_exit(0)
        
        elif args.command == 'current':
            print_locker(keeper.get_current_locker())
            sys_exit(0)

        # A weird part of handling, just not to stuck if you forgot password and want to change locker

        if not keeper.passphrase_exist():
            keeper.console_registrate()

        else:
            keeper.console_auth()

    except KeyboardInterrupt:
        sys_exit(1)

    if any(vars(args).values()):
        main(args, keeper)

    else: # Entering loop
        current_locker = keeper.get_current_locker()
        while True:
            try:
                if not keeper.passphrase_exist():
                    keeper.console_registrate()

                elif current_locker != keeper.get_current_locker():
                    # In case locker was changed
                    keeper.console_auth()
                    current_locker = keeper.get_current_locker()

                command = input(">> ").strip()

                if command.lower() in ("quit", "exit"):
                    print(green("Exiting..."))
                    break
                
                elif command.lower() == 'help':
                    p.print_help()
                    continue

                elif command.lower() == 'clear':
                    os.system('clear')
                    continue

                args = p.parse_args(command.split())

                if any(vars(args).values()):
                    main(args, keeper)

                else:
                    continue

            except KeyboardInterrupt:
                print(green("\nExiting..."))
                break

            except SystemExit:
                continue