from argparse import ArgumentParser
from getpass import getpass
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
from shutil import copy
from platform import system

import re, pyperclip, base64, os, random, string

class FileSystem:
    """
    Class for file manipulatoions with password manager file system
    """

    def __init__(self, salt_size=16) -> None:
        self.root_dir = self.determine_root_dir()
        self.current_locker_file = os.path.join(self.root_dir, '.current_locker') 
        # file with current selected locker directory

        self._salt_size=salt_size
        self.init_locker()

    def determine_root_dir(self) -> str:
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
            raise OSError("Unsuported os.")

    def init_locker(self) -> None:
        """
        Ensure that required directories and files exist. Initializing locker file
        """

        if not os.path.exists(self.current_locker_file):
            with open(self.current_locker_file, 'w'):
                pass

        self.locker = self.get_current_locker() 

        if not self.locker or not os.path.exists(self.locker):
            # if it is empty, or previous setted locker doesnt exist anymore we set default one and make it 
            self.locker = os.path.join(self.root_dir, 'default.lk')
            
            if not os.path.exists(self.locker):
                with open(self.locker, 'w'):
                    pass

            self.change_locker(self.locker)

    def salt_exists(self) -> bool:
        """
        Check if the salt exists. Used to identify is the first run
        """
        try:
            return bool(self.get_from_locker())
            
        except:
            return False

    def get_from_locker(self, get_salt=True) -> bytes :
        """
        Reads content based on param from current locker.
        """
        
        with open(self.locker, 'rb') as f:
            salt = f.read(self._salt_size)
            storage = f.read()

        if get_salt:
            return salt

        return storage

    def set_to_locker(self, value: bytes, set_salt=True) -> None :
        """
        Sets content based on param from current locker. 
        """

        mode = 'wb' if set_salt else 'ab'

        with open(self.locker, mode) as f:
            f.write(value)

    def remove_from_storage(self, index: int) -> None:
        """
        Remove a line at specified index from the locker file.
        """

        temp_file = self.locker + '.tmp'

        try:
            with open(self.locker, 'rb') as original, open(temp_file, 'wb') as tmp:
                tmp.write(original.read(self._salt_size))
                current_index = 0

                for line in original:

                    if current_index != index:
                        tmp.write(line)

                    current_index += 1

        except KeyboardInterrupt:
            return os.remove(temp_file)

        os.replace(temp_file, self.locker)

    def change_locker(self, dest: str) -> None:
        """
        A function to change current locker to provided dir. 
        locker file is a file with .lk extention
        """
        dest = os.path.abspath(os.path.expanduser(dest))
        
        if not os.path.exists(dest):
            raise FileNotFoundError(f"Could not find locker in {dest}")

        with open(self.current_locker_file, 'w') as f:
            f.write(dest)

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
    and other cryptography manipulations 
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
    
    def generate_password(self, length: int, is_no_special_symbols: bool, 
                          is_no_letters: bool):

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
        self.triplets = None
        self.fs = fs
        self.cs = cs

    def init_keeper(self, passphrase: str):
        """
        Inits all necessary stuff and returns True if a succes and False otherwise
        """
        try:
            self.set_cipher(passphrase)
            self.triplets = self.get_triplets()
            return True
        
        except :
            return False

    def set_cipher(self, passphrase: str):
        """
        Sets Keeper's cipher based on passphrase. 
        Required before recieving triplets
        """
        passphrase_bytes = passphrase.encode()

        salt = self.fs.get_from_locker()

        if not salt:
            salt = self.cs.generate_salt()
            self.fs.set_to_locker(salt)

        key = derive_key(passphrase_bytes, salt)

        self.cipher = self.cs.get_cipher(key)

    def set_salt(self):
        """
        Sets salt
        """
        self.fs.set_to_locker(self.cs.generate_salt())

    def passphrase_exist(self):
        """
        Checks is passphrase already exists
        """
        return self.fs.salt_exists()

    def __escape_brackets(self, text: str) -> str:
        """
        Escapes brackets in the text to avoid formatting issues.
        """
        return text.replace("]", "/]").replace("[", "/[")

    def get_triplets(self):
        """
        Returns a list of tuples containing nametag, login, and password triplets.
        """
        encrypted_storage_lines = self.fs.get_from_locker(False).decode().splitlines()
        
        pattern = r'\[\s*([^\]]+?)\s*\]'
        triplets = []

        for line in encrypted_storage_lines:
            decrypted_line = self.cs.decrypt(self.cipher, line.encode()).rstrip('\n')
            decrypted_line = decrypted_line.replace("/]", "]").replace("/[", "[")
            
            matches = re.findall(pattern, decrypted_line)
            
            if len(matches) == 3:
                triplets.append((matches[0], matches[1], matches[2]))

            else:
                raise ValueError(f"Unexpected Matching error")

        return triplets

    def store_triplet(self, tag: str, login: str, password: str):
        """
        Stores a formatted triplet (nametag, login, password) in the storage after encryption.
        """

        tag = self.__escape_brackets(tag).strip()
        login = self.__escape_brackets(login).strip()
        password = self.__escape_brackets(password).strip()

        formatted_line = f"[ {tag} ] [ {login} ] [ {password} ]"

        encrypted_line = self.cs.encrypt(self.cipher, formatted_line) + '\n'
        self.fs.set_to_locker(encrypted_line.encode(), set_salt=False)
        self.triplets = self.get_triplets()

    def get_triplets_by_tag(self, tag: str, strict=True):
        """
        Gets a tag. If strict, returns only exact match.
        If not strict, returns all indexes of triplets which contain a tag
        """
        matches = []

        for triplet in self.triplets:

            if strict and tag == triplet[0]:
                matches.append(triplet)
                break
                
            elif not strict and tag in triplet[0]:
                matches.append(triplet)

        return matches
    
    def remove_triplet(self, triplet: tuple):
        """
        Removes triplet
        """
        triplet_index = self.triplets.index(triplet)

        self.fs.remove_from_storage(triplet_index)
        self.triplets = self.get_triplets()

    def reset(self):
        """
        Resets all the data from current locker
        """
        self.fs.suicide()

    def edit_triplet_property(self, triplet: tuple, property: int, value: str):
        """
        Gets list of triplets, triplet and a property to edit as index.
            0: Tag
            1: Login
            2: Password
        """
        edited_triplet = list(triplet)
        edited_triplet[property] = value
        t, l, p = edited_triplet

        if len(self.get_triplets_by_tag(t)):
            raise ValueError("Triplet already exist")

        self.remove_triplet(triplet)
        self.store_triplet(t, l, p)

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


def auth(keeper: Keeper) -> str:
    """
    Default funciton for console password prompt auth
    """

    current_locker = f"[{keeper.get_current_locker(True)}] "

    if current_locker == '[keeper/default.lk] ' or current_locker == '[keeper\\default.lk] ':
        current_locker = ''

    current_locker = blue(current_locker)

    while True:
        passphrase = getpass(f"\033[95mPassphrase: {current_locker}\033[0m")

        if keeper.init_keeper(passphrase):
            return
        
        else:
            print(red("Incorrect passphrase, try again"))
    

def registrate(keeper: Keeper):
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

    print("\033[35mCurrent locker: ", keeper.get_current_locker() + '\033[0m\n')

    while True:
        passphrase = getpass(green("Create passphrase for the locker: "))

        if len(passphrase) < 3:
            print(red("Passphrase is too short"))
            continue

        repeated = getpass(green("Repeat passphrase: "))

        if passphrase == repeated:
            print(green("Passphrase created"))
            keeper.init_keeper(passphrase)
            return

def print_triplet(triplet: tuple, hidden_password=True):
    print('\n\033[34mTag:', triplet[0] + '\033[0m')
    print('\033[36mLogin:', triplet[1] + '\033[0m')

    if not hidden_password:
        print('\033[35mPassword:', triplet[2] + '\033[0m')

def list_triplets(triplets: list[tuple], is_hidden=True):
    for triplet in triplets:
        print_triplet(triplet, is_hidden)
    print('')    

def print_locker(keeper: Keeper):
    print(f"\n\033[32mCurrent locker: \033[36m{keeper.get_current_locker()}\n\033[0m")

def delete_locker(keeper: Keeper):
    choice = input(red("Are you sure you want to delete all the data? [y/N] "))

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

    except:
        print(red(f"\nCould not find locker dir: {new_locker}\n"))


def add_triplet(tag: str, keeper: Keeper, do_show=False, password=''):
    if len(keeper.get_triplets_by_tag(tag)):
        print(red(f"Triplet with tag '{tag}' already exists.\n"))
        return

    print(blue(f'Creating new triplet with tag "{tag}"'))
    while True:
        login = input("\033[36mEnter the login: ")

        if len(login):
            break

        print(red("Login can not be empty!"))


    if not password:
        while True:
            if do_show:
                password = input("\033[35mEnter the password [󰈈] : ")

            else:
                password = getpass("\033[35mEnter the password: ")

            if len(password):            
                break

            print(red("Password can not be empty!"))

    keeper.store_triplet(tag, login, password)
    print(green(f"Triplet successfully stored with the tag: {tag}"))


def get(tag: str, keeper: Keeper):
    matches = keeper.get_triplets_by_tag(tag)
    list_triplets(matches, False)

def get_password(tag: str, keeper: Keeper, no_clipboard=False):
    matches = keeper.get_triplets_by_tag(tag)

    if not len(matches):
        print(red(f'Could not find triplet with tag: {tag}'))
        return

    triplet = matches[0]
    
    if no_clipboard:
        print(triplet[2])
    else:
        print(green("Password added to the clipboard!"))
        pyperclip.copy(triplet[2])

def get_login(tag: str,  keeper: Keeper, no_clipboard=False):
    matches = keeper.get_triplets_by_tag(tag)

    if not len(matches):
        print(red(f'Could not find triplet with tag: {tag}'))
        return

    triplet = matches[0]

    if no_clipboard:
        print(triplet[1])
    else:
        print(green("Login added to the clipboard!"))
        pyperclip.copy(triplet[1])

def search(tag: str, do_show: bool, keeper: Keeper):
    matches = keeper.get_triplets_by_tag(tag, False)
    list_triplets(matches, do_show)

def remove_by_tag(tag: str, keeper: Keeper, no_confirm=False):
    match = keeper.get_triplets_by_tag(tag)

    if not len(match):
        print(red(f"Could not find triplet with tag: {tag}"))
        return

    print_triplet(match[0])
    print('')

    if not no_confirm:
        remove = input(red("Delete this triplet? [y/N] "))

        if 'y' != remove.lower():
            print(green("Aboarting.."))
            return

    keeper.remove_triplet(match[0])
    print(green("Triplet deleted"))


def edit(tag: str, keeper: Keeper):
    triplets = keeper.get_triplets_by_tag(tag)

    if not len(triplets):
        print(red(f"Could not find triplet with tag: {tag}"))
        return

    triplet = triplets[0]
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
            keeper.edit_triplet_property(triplet, param, value)
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
    
def generate_password_and_store(tag: str, length: int, syms: bool, letters: bool, 
                                keeper: Keeper, do_not_paste=False):
    
    generated_password = keeper.generate_password(length, syms, letters)
    print(green("Password is generated."))

    add_triplet(tag, keeper, password=generated_password)

    if not do_not_paste:
        pyperclip.copy(generated_password)
        print(green("Generated password added to the clipboard!"))

def main(args: ArgumentParser):
    keeper = Keeper(FileSystem(), CryptoSystem())
    
    try:

        if args.command == 'change':
            change_locker(args.dir, keeper)
            return 
        
        elif args.command == 'current':
            print_locker(keeper)
            return
        
        elif args.command == 'dump':
            dest = args.dir if args.dir else '.'
            dump(dest, keeper)
            return

        if not keeper.passphrase_exist():
            registrate(keeper)

        else:
            auth(keeper)

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
            list_triplets(keeper.triplets, not args.all)

        elif args.command == 'search':
            search(args.tag, not args.all, keeper)

        elif args.command == 'shred-locker':
            delete_locker(keeper)

        elif args.command == 'generate':
            tag = args.tag

            generate_password_and_store(tag, args.length, args.no_symbols, args.no_letters, keeper, args.no_paste)

    except KeyboardInterrupt:
        print(green('\nAboarting...'))
        return

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


    search_parser = subparsers.add_parser('search', help='Search for a triplets with similar tag.')
    search_parser.add_argument('tag', metavar='TAG', type=str,
                               help='Similar tag to search for.')
    
    search_parser.add_argument('-a', '--all', action='store_true',
                               help='Show passwords for every found triplet')


    generate_parser = subparsers.add_parser('generate', help="Generates a password and stores it with provided tag")

    generate_parser.add_argument('tag', metavar='TAG', type=str,
                                help='Tag for the new triplet.')

    generate_parser.add_argument('-l', '--length', type=int, default=15,
                                 help='Length of the generated password, default value is 12.')

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

    if any(vars(args).values()):
        main(args)

    else:
       p.print_help()