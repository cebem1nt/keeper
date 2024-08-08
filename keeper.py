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
        Sets passphrase hash to hash.txt file
        """
        passphrase_hash = self.cs.hash_data(passphrase)
        self.fs.set_content('hash', passphrase_hash)

    def verify_passphrase(self, passphrase: str):
        """
        Verifies correctness of stored passphrase with given
        """
        original_hash = self.fs.get_content('hash')
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

        for i, triplet in enumerate(triplets_list):

            if strict and tag == triplet[0]:
                matches.append(triplet)
                break
                
            elif not strict and tag in triplet[0]:
                matches.append(triplet)

        return matches
    
    def get_triplet_by_index(self, triplets_list: list[tuple], index: int):

        if 0 <= index < len(triplets_list):
            return triplets_list[index]
        
        return None

    def remove_triplet(self, triplet_index: int):
        self.fs.remove_from_storage(triplet_index)

    def reset(self):
        self.fs.suicide()

def auth(keeper: Keeper) -> str:
    while True:
        passphrase = getpass("Passphrase: ")

        if keeper.verify_passphrase(passphrase):
            return passphrase
        else:
            print('Incorrect passphrase, try again')
    

def registrate() -> str:
    while True:
        passphrase = getpass("Create passphrase: ")

        if len(passphrase) < 3:
            print("Passphrase is too short")
            continue

        repeated = getpass("Repeat passphrase: ")

        if passphrase == repeated:
            print("Passphrase created")
            return passphrase

def print_triplet(triplet: tuple, index: int, hidden_password=True):
    print('')
    if index > -1:
        print('Index:', index)
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

        else:
            passphrase = auth(keeper)

    except KeyboardInterrupt:
        return

    keeper.set_cipher(passphrase)
    triplets = keeper.get_triplets()

    if args.add:
        tag, login, password = args.add

        keeper.store_triplet(tag, login, password)
        print(f"Succesfully stored with tag: {tag}")

    if args.list:
        for i, triplet in enumerate(triplets):
            print_triplet(triplet, i)
        print('')        

    if args.list_unhiden:
        for i, triplet in enumerate(triplets):
            print_triplet(triplet, i, hidden_password=False)
        print('')

    if args.reset:
        print('\033[31m')
        choice = input("Are you sure you want to reset all the data? [y/N] ")
        print('\033[0m')

        if 'y' == choice.lower():
            keeper.reset()
            print('Data reseted')
            return

        else:
            print('Aboarting')

    if args.get_strict:
        tag = args.get_strict 
        matches = keeper.get_triplet_by_tag(triplets, tag)

        for i, triplet in enumerate(matches):
            print_triplet(triplet, i, hidden_password=False)

    if args.get_easy:
        tag = args.get_easy 
        matches = keeper.get_triplet_by_tag(triplets, tag, False)

        for i, triplet in enumerate(matches):
            print_triplet(triplet, i, hidden_password=False) 
        print('')

    if args.get_by_index:
        index = args.get_by_index
        triplet = keeper.get_triplet_by_index(triplets, index)
        if triplet:
            print_triplet(triplet, index, hidden_password=False)
        else:
            print(f'Could not find triplet with index {index}')
            
    if args.remove_by_tag:
        tag = args.remove_by_tag
        match = keeper.get_triplet_by_tag(triplets, tag)

        if not len(match):
            print(f"Could not find triplet with tag: {tag}")
            return

        print('\033[31m')
        print_triplet(match[0], -1, hidden_password=False) 
        print('\033[0m')

        remove = input("Delete this triplet? [y/N] ")

        if 'y' == remove.lower():
            keeper.remove_triplet(triplets.index(match[0]))
            print('Triplet deleted')
        else:
            print('Aboarting')

    if args.remove_by_index:
        index = args.remove_by_index
        triplet = keeper.get_triplet_by_index(triplets, index)

        if not triplet:
            print(f'Could not find triplet with index: {index}')
            return

        print('\033[31m')
        print_triplet(triplet, -1, hidden_password=False) 
        print('\033[0m')

        remove = input("Delete this triplet? [y/N] ")

        if 'y' == remove.lower():
            keeper.remove_triplet(index)
            print('Triplet deleted')
        else:
            print('Aboarting')
        
if __name__ == '__main__':
    p = ArgumentParser(description="Keeper is a Python password manager")

    p.add_argument('-a', '--add', nargs=3, metavar=('TAG', 'LOGIN', 'PASSWORD'),
                    help='Adds a tag/password/login triplet based on params')
    
    p.add_argument('-g', '--get-strict', type=str,
                   help='Gets a tag/password/login triplet based on tag')
    
    p.add_argument('-ge', '--get-easy', type=str,
                   help='Based on tag, gets all tag/password/login triplets with similar tags')

    p.add_argument('-gi', '--get-by-index', type=int,
                   help='Gets a tag/password/login triplet based on index')
    
    p.add_argument('-r', '--remove-by-tag', type=str,
                    help='Removes a tag/password/login triplet based on tag')
            
    p.add_argument('-ri', '--remove-by-index', type=int,
                        help='Removes a tag/password/login triplet based on index')

    p.add_argument('-l', '--list', action='store_true',
                   help='Lists all stored triplets without showing password')
    
    p.add_argument('-lu', '--list-unhiden', action='store_true',
                    help='Lists all stored triplets with showing password')

    p.add_argument('-reset', '--reset', action='store_true',
                   help='Resets all data')

    args = p.parse_args()

    if any(vars(args).values()):
        main(args)
    else:
        p.print_help()