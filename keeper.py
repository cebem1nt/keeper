from modules.crypt import CryptoSystem, derive_key
from modules.files import FileSystem
from argparse import ArgumentParser
import re
from getpass import getpass

class Keeper:
    """
    Class for manipulations of both FileSystem and CryptoSystem
    Provides functionality for a password manager
    """
    def __init__(self, fs: FileSystem, cs: CryptoSystem):
        self.cipher = None
        self.fs = fs
        self.cs = cs

    def set_cipher(self, passphrase: str):
        """
        Sets Keeper's cipher based on passphrase. 
        Required before recieving triplets
        """
        passphrase_bytes = passphrase.encode()

        salt = self.fs.get_from_locker('salt')

        if not salt:
            self.fs.set_to_locker(self.cs.generate_salt())

        key = derive_key(passphrase_bytes, salt)

        self.cipher = self.cs.get_cipher(key)

    def set_salt(self):
        self.fs.set_to_locker(self.cs.generate_salt())

    def passphrase_exist(self):
        """
        Checks is passphrase already exists
        """
        return self.fs.salt_exists()

    def verify_passphrase(self, passphrase: str):
        """
        Verifies correctness of given passphrase
        """
        try:
            self.set_cipher(passphrase)
            self.get_triplets()
            return True
        except Exception as e:
            raise e

    def __escape_brackets(self, text: str) -> str:
        """
        Escapes brackets in the text to avoid formatting issues.
        """
        return text.replace("]", "/]").replace("[", "/[")

    def get_triplets(self):
        """
        Returns a list of tuples containing nametag, login, and password triplets.
        """
        encrypted_storage_lines = self.fs.get_from_locker('storage').decode().splitlines()
        
        pattern = r'\[\s*([^\]]+?)\s*\]'
        triplets = []

        if self.cipher is None:
            raise ValueError("No cipher found.")

        for line in encrypted_storage_lines:
            decrypted_line = self.cs.decrypt(self.cipher, line).rstrip('\n')
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
        if self.cipher is None:
            raise ValueError("No cipher found.")

        tag = self.__escape_brackets(tag)
        login = self.__escape_brackets(login)
        password = self.__escape_brackets(password)

        formatted_line = f"[ {tag} ] [ {login} ] [ {password} ]"

        encrypted_line = self.cs.encrypt(self.cipher, formatted_line) + '\n'
        self.fs.set_to_locker(encrypted_line.encode(), set_salt=False)

    def get_triplet_by_tag(self, triplets_list: list[tuple], tag: str, strict=True):
        """
        Gets a list of triplets and a tag. If strict, returns only exact match.
        If not strict, returns all indexes of triplets which contain a tag
        """
        matches = []

        for triplet in triplets_list:

            if strict and tag == triplet[0]:
                matches.append(triplet)
                break
                
            elif not strict and tag in triplet[0]:
                matches.append(triplet)

        return matches
    
    def remove_triplet(self, triplet_index: int):
        """
        Removes triplet by index
        """
        self.fs.remove_from_storage(triplet_index)

    def reset(self):
        """
        Resets all the data from password manager
        """
        self.fs.suicide()

    def edit_triplet_property(self, triplets_list: list[tuple], triplet: tuple, 
                              property: int, value: str):
        """
        Gets list of triplets, triplet and a property to edit as index.
            0: Tag
            1: Login
            2: Password
        """
        edited_triplet = list(triplet)
        edited_triplet[property] = value
        t, l, p = edited_triplet
        self.remove_triplet(triplets_list.index(triplet))
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

    def get_current_locker(self):
        """
        Returns locker currently working with
        """

        return self.fs.get_current_locker()

def auth(keeper: Keeper) -> str:
    """
    Default funciton for console password prompt auth
    """
    while True:
        passphrase = getpass("\033[95mPassphrase: \033[0m")

        if keeper.verify_passphrase(passphrase):
            return passphrase
        else:
            print('\033[31mIncorrect passphrase, try again\033[0m')
    

def registrate(current_locker: str) -> str:
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

    print("Current locker: ", current_locker + '\n')

    while True:
        passphrase = getpass("\033[32mCreate passphrase: \033[0m")

        if len(passphrase) < 3:
            print("\033[31mPassphrase is too short\033[0m")
            continue

        repeated = getpass("\033[32mRepeat passphrase: \033[0m")

        if passphrase == repeated:
            print("\033[32mPassphrase created\033[0m")
            return passphrase

def print_triplet(triplet: tuple, hidden_password=True):
    print('\n\033[34mTag:', triplet[0] + '\033[0m')
    print('\033[36mLogin:', triplet[1] + '\033[0m')

    if not hidden_password:
        print('\033[35mPassword:', triplet[2] + '\033[0m')

def main(args: ArgumentParser):
    # Initialize the Keeper instance
    keeper = Keeper(FileSystem(), CryptoSystem())
    
    try:
        if args.print_locker:
            print(f"\n\033[32mCurrent locker: \033[36m{keeper.get_current_locker()}\n\033[0m")
            return

        if args.change_locker:
            locker_dir = args.change_locker
            try:
                keeper.change_locker(locker_dir)
                print(f'\n\033[32mSuccesfuly changed current locker to : {locker_dir}\033[0m\n')
            except:
                print(f"\n\033[31mCould not find locker dir: {locker_dir}\033[0m\n")
                
            return

        if not keeper.passphrase_exist():
            passphrase = registrate(keeper.get_current_locker())
            keeper.set_salt()

        else:
            passphrase = auth(keeper)

        keeper.set_cipher(passphrase)
        triplets = keeper.get_triplets()

        if args.add:
            print("\033[34mA tag is a label used to identify your password in the storage system. When you need to find a specific password and login, you can search by its tag.")
            tag = input("\033[34mEnter the tag: ")
            login = input("\033[36mEnter the login: ")
            password = input("\033[35mEnter the password: ")

            keeper.store_triplet(tag, login, password)
            print(f"\033[32mTriplet successfully stored with the tag: {tag}\033[0m")

        if args.list:
            for triplet in triplets:
                print_triplet(triplet)
            print('')        

        if args.list_shown:
            for triplet in triplets:
                print_triplet(triplet, hidden_password=False)
            print('')

        if args.reset_locker:
            choice = input("\033[31mAre you sure you want to reset all the data? [y/N] \033[0m")

            if 'y' == choice.lower():
                keeper.reset()
                print('\033[32mData reseted\033[0m')
                return

            else:
                print('\033[32mAboarting..\033[0m')

        if args.get_strict:
            tag = ' '.join(args.get_strict)
            matches = keeper.get_triplet_by_tag(triplets, tag)

            for triplet in matches:
                print_triplet(triplet, hidden_password=False)
            print('')

        if args.get_password:
            tag = ' '.join(args.get_password)
            matches = keeper.get_triplet_by_tag(triplets, tag)

            if not len(matches):
                print(f"\033[31mCould not find triplet with tag: {tag}\033[0m")
                return

            for triplet in matches:
                print(triplet[2])

        if args.get_login:
            tag = ' '.join(args.get_login)
            matches = keeper.get_triplet_by_tag(triplets, tag)

            if not len(matches):
                print(f"\033[31mCould not find triplet with tag: {tag}\033[0m")
                return

            for triplet in matches:
                print(triplet[1])

        if args.get_easy:
            tag = ' '.join(args.get_easy)

            matches = keeper.get_triplet_by_tag(triplets, tag, False)

            for triplet in matches:
                print_triplet(triplet, hidden_password=False) 
            print('')

        if args.remove_by_tag:
            tag = ' '.join(args.remove_by_tag)

            match = keeper.get_triplet_by_tag(triplets, tag)

            if not len(match):
                print(f"\033[31mCould not find triplet with tag: {tag}\033[0m")
                return

            print('\033[31m')
            print_triplet(match[0], hidden_password=False) 

            remove = input("\033[31mDelete this triplet? [y/N] \033[0m")

            if 'y' == remove.lower():
                keeper.remove_triplet(triplets.index(match[0]))
                print('\033[32mTriplet deleted\033[0m')
            else:
                print('\033[32mAboarting..\033[0m')

        if args.edit:
            for triplet in triplets:
                print_triplet(triplet)
            print('')  
            
            while True:
                tag = input("Enter the tag: ")
                triplet = keeper.get_triplet_by_tag(triplets, tag)

                if not len(triplet):
                    print(f"\033[31mCould not find triplet with tag: {tag}\033[0m")
                    cont = input("\033[32mWould you like to try again? [y/N]\033[0m")

                    if 'y' == cont.lower():
                        continue
                    else:
                        print('\033[32mAboarting..\033[0m')

                triplet = triplet[0]

                print("\033[32mParameters that can be edited: \n 0 - tag \n 1 - login \n 2 - password\033[0m")

                while True:
                    try:
                        param = int(input("\033[32mEnter the parameter to edit (0-2): \033[0m"))

                    except:
                        param = -1

                    if param in (0, 1, 2):
                        break

                    else:
                        print("\033[31mIncorrect parameter\033[0m")

                names = ('tag', 'login', 'password')
                value = input(f'\033[32mEnter new value for "{names[param]}": \033[0m')

                keeper.edit_triplet_property(triplets, triplet, param, value)
                print(f"\033[32mSuccesfully edited triplet with tag: {tag}\033[0m")
                break

        if args.dump:
            dest = args.dump

            try:
                keeper.dump(dest)
                print(f'\033[32mSuccesfuly dumped current locker to : {dest}\033[0m')

            except:
                print(f"\033[31mCould not find destination dir: {dest}\033[0m")
        
    except KeyboardInterrupt:
        return

if __name__ == '__main__':
    p = ArgumentParser(description="Keeper is a Python password manager. Locker is a directory where passwords are stored, triplet is tag/login/password")

    p.add_argument('-a', '--add', action='store_true',
                    help='Interactively adds tag/login/password')
    
    p.add_argument('-r', '--remove-by-tag', metavar=('<tag>'), type=str, nargs='+',
                help='Removes a tag/password/login triplet based on tag')

    p.add_argument('-e', '--edit', action='store_true',
                    help='Interactively edits param of triplet')

    p.add_argument('-l', '--list', action='store_true',
                   help='Lists all stored triplets without showing password')
    
    p.add_argument('-ls', '--list-shown', action='store_true',
                    help='Lists all stored triplets showing password for each one!')

    p.add_argument('-g', '--get-strict', metavar=('<tag>'), type=str, nargs='+',
                   help='Gets a tag/password/login triplet based on tag')
    
    p.add_argument('-gp', '--get-password', metavar=('<tag>'), type=str, nargs='+',
                   help='Gets a password based on tag')
    
    p.add_argument('-gl', '--get-login', metavar=('<tag>'), type=str, nargs='+',
                   help='Gets a login based on tag')

    p.add_argument('-ge', '--get-easy', metavar=('<tag>'), type=str, nargs='+',
                   help='Based on tag, gets all tag/password/login triplets with similar tags')
        
    p.add_argument('-du', '--dump', type=str, metavar=('<dir>'),
                   help='Dumps current keeper storage to specified dir')

    p.add_argument('-cl', '--change-locker', type=str, metavar=('<dir>'),
                   help='Sets another directory with triplets (locker) to manipulate them. Default locker dir: ~/.keeper/default_locker.')

    p.add_argument('-pl', '--print-locker', action='store_true',
                   help='Prints directory of the current locker in use')

    p.add_argument('-reset-locker', '--reset-locker', action='store_true',
                   help='Resets all data of the current locker')

    args = p.parse_args()

    if any(vars(args).values()):
        main(args)
    else:
        p.print_help()