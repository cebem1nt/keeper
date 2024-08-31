import re, base64, pyperclip, random, string, os, stat, subprocess

from argparse import ArgumentParser
from getpass import getpass
from cryptography.fernet import Fernet, InvalidToken
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
from hashlib import sha256

from sys import exit as sys_exit
from shutil import copy as sh_copy
from platform import system as pl_system

# This is a project code for a minimalistic and at the same time 
# very functional python password manager. The following project 
# is located at one file to make compilation to the .c code easy.
# For sequrity reasons, the following code should be compiled.

# This password manager built as a layered project, from the bottom where
# files are getting manipulated, the medium where class provides some kind of API,
# to the frontend level. Beauty of it is that you do not have to modify the base.
# You can add some frontend functionality as a new abstract layer without any need
# to modify file system or API. 

## Lib functions

def own(file: str):
    os.chmod(file, stat.S_IRUSR | stat.S_IWUSR)

def escape_brackets(text: str):
    return text.replace("]", "/]").replace("[", "/[")

def restore_brackets(text: str):
    return text.replace("/]", "]").replace("/[", "[")

def red(string: str):
    return "\033[31m" + string + "\033[0m"

def green(string: str):
    return "\033[32m" + string + "\033[0m"

def blue(string: str):
    return "\033[34m" + string + "\033[0m"

def add_to_clipboard(content: str):
    try:
        pyperclip.copy(content)

    except Exception as e:
        if 'TERMUX_VERSION' in os.environ:
            subprocess.run(["termux-clipboard-set", content])
        else:
            raise e

def derive_key(passphrase: bytes, salt: bytes, token: bytes, itr: int):
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=token+salt,
        iterations=itr,
        backend=default_backend()
    )

    return base64.urlsafe_b64encode(kdf.derive(passphrase))

## Base classes and functionality

class SaltManager:
    def __init__(self, size: int, dir: str) -> None:
        self._size = size
        self.dir = dir

    def exists(self):
        try:
            with open(self.dir, 'rb') as f:
                return bool(f.read(self._size)) 

        except:
            return False
    
    def get(self):
        if not self.exists():
            salt = os.urandom(self._size)

            with open(self.dir, 'wb') as f:
                f.write(salt)

            own(self.dir)
            return salt

        else:
            with open(self.dir, 'rb') as f:
                return f.read(self._size)

class CrossPlatform:
    def __init__(self):
        self.__init_dirs()

    def __init_dirs(self):
        platform = pl_system()

        def win(dir):
            return lambda : os.path.join(os.environ.get('LOCALAPPDATA', os.path.expanduser('~')), dir)
        
        def linux(dir):
            return lambda : os.path.expanduser(dir)

        dirs = {
            'Linux'  : ( linux('~/.local/share/keeper'), linux('~/.keeper_storage')),    
            'Darwin' : ( linux('~/.local/share/keeper'), linux('~/.keeper_storage')),
            'Windows': ( win('keeper'), win('keeper_storage')),
        }

        if platform in dirs:
            self.root_dir = dirs[platform][0]()
            self.storage_dir = dirs[platform][1]()
            os.makedirs(self.root_dir, exist_ok=True)
            os.makedirs(self.storage_dir, exist_ok=True)

        else:
            raise OSError(f"Unsuported os: {platform}")

class FileSystem(CrossPlatform):
    """
    A base layer class for the password's manager file system manipulations.
    """

    # Token is a randomly generated N bytes salt, which will be used 
    # as unique key part of the passphrase for every user. 
    # It's necessary because default salt is located in the locker file.
    # So to decrypt a locker, you need a locker file and the same generated token 

    def __init__(self, header_size=64, salt_size=16):
        super().__init__()
        self.token_file = os.path.join(self.root_dir, 'token') 
        self.current_locker_file = os.path.join(self.root_dir, '.current_locker') 
        self._header_size=header_size
        self._salt_size=salt_size
        self.__init_root()
        self.__sync_locker()

    def __init_root(self):
        if not os.path.exists(self.current_locker_file):
            open(self.current_locker_file, 'w').close()

    def __sync_locker(self):
        current_locker =  self.get_current_locker()
        self.locker = os.path.join(self.storage_dir, current_locker)

        if not current_locker or not os.path.exists(self.locker):
            self.locker = os.path.join(self.storage_dir, 'default.lk')

            if not os.path.exists(self.locker):
                open(self.locker, 'w').close()

            self.change_locker('default.lk', same_ok=True)

    def open_tmp_locker(self, tmp_locker: str):
        if os.path.exists(tmp_locker):
            self.locker = tmp_locker
        else:
            raise FileExistsError("Tmp locker doesn't exist")

    def get_line_from_storage(self, header: bytes) -> bytes | None:
        with open(self.locker, 'rb') as locker:
            locker.read(self._salt_size)
            for line in locker:
                line_header = line[:self._header_size]
                if line_header == header:
                    return line[self._header_size:]

    def get_all_lines_from_storage(self) -> list[bytes]:
        lines = []
        with open(self.locker, 'rb') as locker:
            locker.read(self._salt_size)
            for line in locker:
                lines.append(line[self._header_size:])
        return lines

    def append_line_to_storage(self, header: bytes, line: bytes):
        with open(self.locker, 'ab') as f:
            f.write(header+line)

    def remove_line_from_storage(self, header: bytes):
        temp_file = self.locker + '.tmp'
        try:
            with open(self.locker, 'rb') as original, open(temp_file, 'wb') as tmp:
                tmp.write(original.read(self._salt_size))
                for line in original:
                    if header != line[:self._header_size]:
                        tmp.write(line)
        except IOError as e:
            os.remove(temp_file)
            raise e
        except KeyboardInterrupt:
            return os.remove(temp_file)
        os.replace(temp_file, self.locker)

    def get_current_locker(self):
        with open(self.current_locker_file) as f:
            return f.read().strip()

    def change_locker(self, dest: str, same_ok=False) -> None:
        if os.path.isdir(dest):
            raise ValueError("Argument is a directory")
        
        tmpdest = os.path.join(self.storage_dir, dest)

        if not os.path.exists(tmpdest):
            default_locker = os.path.join(self.storage_dir, 'default.lk')
            if tmpdest == default_locker:
                open(self.locker, 'w').close()
            else:
                raise FileNotFoundError("Could not find locker file")
        
        elif dest == self.get_current_locker() and not same_ok:
            raise AssertionError("Same file")
        
        with open(self.current_locker_file, 'w') as f:
            f.write(dest) # File keeps directories relative to the storage dir

        self.__sync_locker() # Sync locker file to the new locker

    def copy_locker(self, dir: str):
        sh_copy(self.locker, os.path.abspath(os.path.expanduser(dir)))

    def copy_token(self, dir: str):
        sh_copy(self.token_file, os.path.abspath(os.path.expanduser(dir)))

    def suicide(self, passes=3):
        try:
            file_size = os.path.getsize(self.locker)
            with open(self.locker, 'r+b') as f:
                for _ in range(passes):
                    f.seek(0)
                    f.write(bytearray(random.getrandbits(8) for _ in range(file_size)))
                    f.flush()
            os.remove(self.locker)
            self.change_locker('default.lk', same_ok=True)
        except Exception as e:
            raise e

class Keeper:
    """
    Class for high level manipulations for a keeper password manager.
    """

    def __init__(self, token_size=32, salt_size=16, iterations=340000):
        self.fs = FileSystem(salt_size=salt_size)
        self._cipher = None
        self._salt_size = salt_size
        self._token_size = token_size
        self._iterations = iterations
     
    def __encrypt(self, data: str):
        return self._cipher.encrypt(data.encode()).decode()

    def __decrypt(self, encrypted_data: bytes):
        return self._cipher.decrypt(encrypted_data).decode()
    
    def __hash(self, content: str):
        return sha256(content.encode()).hexdigest().encode()

    def _decrypt_triplet(self, line: bytes):
        decrypted_line = restore_brackets(self.__decrypt(line).rstrip('\n'))
        matches: list[str] = re.findall(r'\[\s*([^\]]+?)\s*\]', decrypted_line)
        
        if len(matches) == 3:
            return (matches[0], matches[1], matches[2])

        else:
            raise ValueError(f"File seems to be corrupted")

    def _set_cipher(self, passphrase: str):
        passphrase_bytes = passphrase.encode()
        locker_salt = SaltManager(self._salt_size, self.fs.locker).get()
        token = SaltManager(self._token_size, self.fs.token_file).get()

        self.cipher = self._cipher = Fernet(derive_key(passphrase_bytes, locker_salt, token, self._iterations))

    def verify_key(self, passphrase: str):
        """
        Basic function that is used before any decrypting / encrypting methods.
        Use to check the correctness of given password and initialize all the variables.
        Returns true if a success, false otherwise
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
        """Returns a list of stored triplets"""
        encrypted_lines = self.fs.get_all_lines_from_storage()
        decrypted_triplets = []

        for line in encrypted_lines:
            decrypted_triplets.append(self._decrypt_triplet(line))

        return decrypted_triplets

    def search_for_triplet(self, part_tag: str):
        """Searches for a triplet with the provided part of the tag"""
        encrypted_lines = self.fs.get_all_lines_from_storage()
        found = []

        for line in encrypted_lines:
            decrypted_triplet = self._decrypt_triplet(line)

            if part_tag.lower() in decrypted_triplet[0].lower():
                found.append(decrypted_triplet)

        return found

    def get_triplet(self, tag: str):
        """Returns a triplet with the same tag"""
        hash_tag = self.__hash(tag)

        found = self.fs.get_line_from_storage(hash_tag)

        if found:
            return self._decrypt_triplet(found)

        return None 

    def store_triplet(self, tag: str, login: str, password: str):
        """ Stores a formatted triplet (nametag, login, password) in the storage after encryption."""

        tag = escape_brackets(tag).strip()
        login = escape_brackets(login).strip()
        password = escape_brackets(password).strip()

        formatted_line = f"[ {tag} ] [ {login} ] [ {password} ]"
        encrypted_line = self.__encrypt(formatted_line) + '\n'
        self.fs.append_line_to_storage(self.__hash(tag), encrypted_line.encode())

    def generate_password(self, length: int, no_special_symbols=False, no_letters=False):
        """Generates a password based on the params"""
        letters, digits, special_symbols = (string.ascii_letters, string.digits, string.punctuation)
        
        if no_special_symbols and no_letters:
            chars = list(digits)

        elif no_special_symbols:
            chars = list(letters + digits)

        elif no_letters:
            chars = list(digits + special_symbols)

        else:
            chars = list(letters + digits + special_symbols)
        
        if not len(chars):
            raise ValueError("Character set is empty. Cannot generate a password.")

        random.shuffle(chars)

        password = ''.join(random.choice(chars) for _ in range(length))
        
        return password

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
        """ Copies current locker to the specified dir """
        self.fs.copy_locker(destination)

    def copy_token(self, destination: str):
        """ Copies token to the specified dir """
        self.fs.copy_token(destination)

    def change_locker(self, locker_dir: str):
        """ Changes current locker to provided directory """
        self.fs.change_locker(locker_dir)

    def get_current_locker(self):
        """ Returns locker currently working with """
        return self.fs.get_current_locker()

    def reset(self):
        """ Resets all the data from current locker """
        self.fs.suicide()
    
    def remove_triplet(self, tag: str):
        """ Removes triplet based on the tag """
        self.fs.remove_line_from_storage(self.__hash(tag))

    def is_salted(self):
        """ Checks is locker already salted """
        return SaltManager(self._salt_size, self.fs.locker).exists()

    def token_exists(self):
        """Checks is token exist"""
        return SaltManager(self._token_size, self.fs.token_file).exists()

## CLI Interface functions & high level addons

def message(do_message: bool):
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

        print(red("[WARNING!] Make sure to remember this passphrase! as losing it"))
        print(red("means you will not be able to recover your encrypted passwords.\n"))

def console_registrate(keeper: Keeper):
    message(not keeper.token_exists())

    print("\033[35mCurrent locker: ", keeper.get_current_locker() + '\033[0m\n')

    while True:
        passphrase = getpass(green("Create passphrase for the locker: "))

        if len(passphrase) < 3:
            print(red("Passphrase is too short"))
            continue

        repeated = getpass(green("Repeat passphrase: "))

        if passphrase == repeated:
            print(green("Passphrase created"))
            keeper.verify_key(passphrase)
            return
        
        else:
            print(red("Passwords don't match"))

def console_auth(keeper: Keeper):
    current_locker = blue(f"[{keeper.get_current_locker()}] ")

    while True:
        passphrase = getpass(f"\033[95mPassphrase: {current_locker}\033[0m")

        if keeper.verify_key(passphrase):
            return
        
        else:
            print(red("Incorrect passphrase, try again"))

def print_locker(locker: str):
    print(f"\n\033[32mCurrent locker: \033[36m{locker}\n\033[0m")

def print_triplet(triplet: tuple, hidden_password=True):
    print('\nTag:', triplet[0])
    print('Login:', triplet[1])

    if not hidden_password:
        print('Password:', triplet[2])

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

    except AssertionError:
        print(red(f"\n{new_locker} is current locker\n"))

def add_triplet(tag: str, keeper: Keeper, do_show_password=False, password=None):
    if keeper.get_triplet(tag):
        print(red(f"Triplet with tag '{tag}' already exists.\n"))
        return

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
        value = input(green(f'Enter new value for \"{("tag", "login", "password")[param]}\": '))

        try:
            keeper.edit_triplet_property(tag, param, value)
            break

        except ValueError:
            print(red(f'Triplet with tag "{value}" already exist'))

    print(green(f'Succesfully edited triplet with tag: "{tag}"'))

def copy(dest: str, keeper: Keeper):
    try:
        keeper.copy_locker(dest)
        print(green(f'Succesfuly copied current locker to "{dest}"'))

    except:
        print(red(f"Could not find destination dir: {dest}"))
    
def copy_token(dest: str, keeper: Keeper):
    try:
        keeper.copy_token(dest)
        print(green(f'Succesfuly copied token to "{dest}"'))

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
        
        elif args.command == 'copy':
            dest = args.dir if args.dir else '.'
            if args.token:
                copy_token(dest, keeper)
            else:
                copy(dest, keeper)

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

            else:
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
    add_parser.add_argument('tag', metavar='TAG(S)', type=str, nargs='+', help='Tag(s) for the new triplet(s).')
    add_parser.add_argument('-s', '--show-password', action='store_true', help='Show password when adding triplet')

    remove_parser = subparsers.add_parser('remove', help='Remove a triplet based on tag or tags.')
    remove_parser.add_argument('tag', metavar='TAG(S)', type=str, nargs='+', help='Tag(s) of the triplet(s) to remove.')
    remove_parser.add_argument('-na', '--no-ask', action='store_true', help='Do not confirm deleting of a triplet')

    get_parser = subparsers.add_parser('get', help='Retrieve login or password based on tag.')
    get_parser.add_argument('tag', metavar='TAG', type=str, help='Tag of the triplet to get.')
    get_parser.add_argument('-nc', '--no-clipboard', action='store_true',help='Instead of copying to the clipboard, will print to the terminal.')

    get_parser.add_argument('-l', '--login', action='store_true', help='Return the login to the clipboard instead of password.')

    edit_parser = subparsers.add_parser('edit', help='Interactively edit parameters of a triplet.')
    edit_parser.add_argument('tag', metavar='TAG(S)', type=str, nargs='+', help='Tag(s) of the triplet(s) to edit.')

    list_parser = subparsers.add_parser('list', help='List all stored triplets.')
    list_parser.add_argument('-a', '--all', action='store_true', help='Include passwords in the listing.')
    list_parser.add_argument('-n', '--num', action='store_true', help='Output number of passwords instead of printing each one.')

    search_parser = subparsers.add_parser('search', help='Search for a triplets with similar tag.')
    search_parser.add_argument('tag', metavar='TAG', type=str, help='Similar tag to search for.')
    search_parser.add_argument('-a', '--all', action='store_true', help='Show passwords for every found triplet')

    generate_parser = subparsers.add_parser('generate', help="Generates a password and stores it with provided tag")
    generate_parser.add_argument('tag', metavar='TAG', type=str, help='Tag for the new triplet.')
    generate_parser.add_argument('-l', '--length', type=int, default=16, help='Length of the generated password, default value is 16.')
    generate_parser.add_argument('-ns', '--no-symbols', action='store_true', help='generates a password without any special symbols.')
    generate_parser.add_argument('-nl', '--no-letters', action='store_true', help='generates a password without any letters.')
    generate_parser.add_argument('-np', '--no-paste', action='store_true', help='Do not paste generated password to the clipboard')

    change_parser = subparsers.add_parser('change', help='Changes current locker file to provided.')
    change_parser.add_argument('dir', metavar='DIR', type=str, help='Directory to the new locker file.')

    copy_parser = subparsers.add_parser('copy', help='Copy current .lk or token file to the provided directory.')
    copy_parser.add_argument('dir', metavar='[DIR]', type=str, nargs='?', help='Directory to copy to. If no directory provided, copy to the current directory.')
    copy_parser.add_argument('-t', '--token', action='store_true', help='Instead of copying current locker file, copy token to the provided directory.')

    current_parser = subparsers.add_parser('current', help='Prints directory of the current locker in use.')

    shred_parser = subparsers.add_parser('shred-locker', help='Shreds current locker.')

    args = p.parse_args()

    keeper = Keeper()

    try:
        if args.command == 'change':
            change_locker(args.dir, keeper)
            sys_exit(0)
        
        elif args.command == 'current':
            print_locker(keeper.get_current_locker())
            sys_exit(0)

        # A weird part of handling, just not to stuck if you forgot password and want to change locker

        if not keeper.is_salted():
            console_registrate(keeper)

        else:
            console_auth(keeper)

    except KeyboardInterrupt:
        sys_exit(1)

    if any(vars(args).values()):
        main(args, keeper)

    else: # Entering loop
        current_locker = keeper.get_current_locker()
        while True:
            try:
                if not keeper.is_salted():
                    console_registrate(keeper)
                    current_locker = keeper.get_current_locker()

                elif current_locker != keeper.get_current_locker():
                    # In case locker was changed
                    console_auth(keeper)
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