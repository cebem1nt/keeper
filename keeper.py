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

        salt = self.fs.get_content('salt')

        if not salt:
            salt = self.cs.generate_salt()
            self.fs.set_content('salt', salt)

        key = derive_key(passphrase_bytes, salt)

        self.cipher = self.cs.get_cipher(key)

    def passphrase_exist(self):
        """
        Checks is passphrase already exists
        """
        return self.fs.hash_exists()
    
    def set_passphrase(self, passphrase: str):
        """
        Hashes password and writes it to hash.txt
        """
        passphrase_hash = self.cs.hash_data(passphrase)
        self.fs.set_content('hash', passphrase_hash)

    def verify_passphrase(self, passphrase: str):
        """
        Verifies correctness of stored passphrase with given
        """
        original_hash = self.fs.get_content('hash').strip()
        return self.cs.verify_hash(original_hash, passphrase)

    def get_triplets(self):
        """
        Returns a list of tuples with nametag, login, password  triplets
        """
        encrypted_storage = self.fs.get_content('storage').splitlines()
        pattern = r'\[\s*([^\]]+?)\s*\]'
        triplets = []

        if self.cipher is None:
            raise ValueError("No cipher found.")

        for line in encrypted_storage:
            decrypted_line = self.cs.decrypt(self.cipher, line).rstrip('\n')
            mathces = re.findall(pattern, decrypted_line)
            triplets.append((mathces[0], mathces[1], mathces[2]))

        return triplets 

    def store_triplet(self, p_nametag: str, p_login: str, p_password: str):
        """
        Gets nametag, login and password. Creates a formated line, 
        encrypts it and stores in storage
        """

        if self.cipher is None:
            raise ValueError("No cipher found.")

        password_line = f"[ {p_nametag} ] [ {p_login} ] [ {p_password} ]"

        encrypted_password_line = self.cs.encrypt(self.cipher, password_line)
        self.fs.set_content('storage', encrypted_password_line)

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
        n, l, p = edited_triplet
        self.remove_triplet(triplets_list.index(triplet))
        self.store_triplet(n, l, p)

    def dump(self, destination: str):
        """
        Dumps current locker to the specified dir
        """
        self.fs.dump_locker(destination)

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
    Default funciton for console password prompt
    """
    while True:
        passphrase = getpass("Passphrase: ")

        if keeper.verify_passphrase(passphrase):
            return passphrase
        else:
            print('Incorrect passphrase, try again')
    

def registrate() -> str:
    """
    Default function for registration, creating passphrase
    """
    while True:
        passphrase = getpass("Create passphrase: ")

        if len(passphrase) < 3:
            print("Passphrase is too short")
            continue

        repeated = getpass("Repeat passphrase: ")

        if passphrase == repeated:
            print("Passphrase created")
            return passphrase

def print_triplet(triplet: tuple, hidden_password=True):
    print('')
    print('Tag:', triplet[0])
    print('Login:', triplet[1])

    if not hidden_password:
        print('Password:', triplet[2])

def main(args: ArgumentParser):
    # Initialize the Keeper instance
    keeper = Keeper(FileSystem(), CryptoSystem())
    
    try:
        if not keeper.passphrase_exist():
            passphrase = registrate()
            keeper.set_passphrase(passphrase)

        else:
            passphrase = auth(keeper)

    except KeyboardInterrupt:
        return

    keeper.set_cipher(passphrase)
    triplets = keeper.get_triplets()

    if args.add:
        print("A tag is a label used to identify your password in the storage system. When you need to find a specific password and login, you can search by its tag.")
        tag = input("Enter the tag: ")
        login = input("Enter the login: ")
        password = input("Enter the password: ")

        keeper.store_triplet(tag, login, password)
        print(f"Triplet successfully stored with the tag: {tag}")

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
            print('Data reseted')
            return

        else:
            print('Aboarting..')

    if args.get_strict:
        tag = ' '.join(args.get_strict)
        matches = keeper.get_triplet_by_tag(triplets, tag)

        for triplet in matches:
            print_triplet(triplet, hidden_password=False)
        print('')

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
            print(f"Could not find triplet with tag: {tag}")
            return

        print('\033[31m')
        print_triplet(match[0], hidden_password=False) 
        print('\033[0m')

        remove = input("Delete this triplet? [y/N] ")

        if 'y' == remove.lower():
            keeper.remove_triplet(triplets.index(match[0]))
            print('Triplet deleted')
        else:
            print('Aboarting..')

    if args.edit:
        for triplet in triplets:
            print_triplet(triplet)
        print('')  
        
        while True:
            tag = input("Enter the tag: ")
            triplet = keeper.get_triplet_by_tag(triplets, tag)

            if not len(triplet):
                print(f"Could not find triplet with tag: {tag}")
                cont = input("Would you like to try again? [y/N] ")

                if 'y' == cont.lower():
                    continue
                else:
                    print('Aboarting..')

            triplet = triplet[0]

            print("Parameters that can be edited: \n 0 - tag \n 1 - login \n 2 - password")

            while True:
                try:
                    param = int(input("Enter the parameter to edit (0-2): "))

                except:
                    param = -1

                if param in (0, 1, 2):
                    break
                else:
                    print("Incorrect parameter")

            value = input("Enter new value: ")

            keeper.edit_triplet_property(triplets, triplet, int(param), value)
            
            print(f"Succesfully edited triplet with tag: {tag}")

    if args.dump:
        dest = args.dump

        try:
            keeper.dump(dest)
            print(f'Succesfuly dumped current locker to : {dest}')

        except:
            print(f"Could not find destination dir: {dest}")

    if args.print_locker:
        print(f"\nCurrent locker: {keeper.get_current_locker()}\n")

    if args.change_locker:
        locker_dir = args.change_locker
        try:
            keeper.change_locker(locker_dir)
            print(f'Succesfuly changed current locker to : {locker_dir}')
        except:
            print(f"Could not find locker dir: {locker_dir}")
            
        return

if __name__ == '__main__':
    p = ArgumentParser(description="Keeper is a Python password manager")

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