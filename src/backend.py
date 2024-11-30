import random, string

from core.cryptography import CryptoSystem
from core.file_system import FileSystem

class EventManager:
    _events = {}

    def subscribe(self, event: str, function: object):    
        if not event in self._events:
            self._events[event] = [function]
            return
        self._events[event].append(function)

    def trigger_event(self, *events: str):
        for event in events:
            if not event in self._events:
                continue
            for fn in self._events[event]:
                fn()

class Keeper(FileSystem, CryptoSystem, EventManager):
    """
    Class for high level manipulations for a keeper password manager.
    By default keeper produces the following events:
        - "init" : On succesfull cipher initialization
        - "store" : On storing new triplet
        - "remove" : On triplet deleting
    """

    def __init__(self, token_size=32, salt_size=16, iterations=340000):
        FileSystem.__init__(self, salt_size=salt_size, token_size=token_size)
        CryptoSystem.__init__(self, iterations=iterations)
        self._cipher = None

    def verify_key(self, passphrase: str):
        """
        Basic function that is used before any decrypting / encrypting methods.
        Use to check the correctness of given password and initialize all the variables.
        Returns true if a success, false otherwise
        """
        try:
            token = self.get_token()
            if token:
                self.init_cipher(passphrase.encode(), token, self.get_salt())
                listed = self.list_triplets()
                self.trigger_event("init")
                return True
            raise ValueError("Token wasn't generated!")
            
        except AssertionError:
            return False

    def list_triplets(self):
        """Returns a list of stored triplets"""
        encrypted_lines = self._get_all_lines_from_storage()
        decrypted_triplets = []

        for line in encrypted_lines:
            decrypted_triplets.append(self.decrypt_triplet(line))

        return decrypted_triplets

    def search_for_triplet(self, part_tag: str):
        """Searches for a triplet with the provided part of the tag"""
        encrypted_lines = self._get_all_lines_from_storage()
        found = []

        for line in encrypted_lines:
            decrypted_triplet = self.decrypt_triplet(line)

            if part_tag.lower() in decrypted_triplet[0].lower():
                found.append(decrypted_triplet)

        return found

    def get_triplet(self, tag: str):
        """Returns a triplet with the same tag"""
        hash_tag = self.hash(tag)

        found = self._get_line_from_storage(hash_tag)

        if found:
            return self.decrypt_triplet(found)

        return None 

    def store_triplet(self, tag: str, login: str, password: str):
        """ Stores a formatted triplet (nametag, login, password) in the storage after encryption."""

        encrypted_line = self.encrypt_triplet(tag, login, password)
        self._append_line_to_storage(self.hash(tag), encrypted_line)
        self.trigger_event("store")

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

    def remove_triplet(self, tag: str):
        """ Removes triplet based on the tag """
        self._remove_line_from_storage(self.hash(tag))
        self.trigger_event("remove")