import base64, os, random, string
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend

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

    def generate_salt(self):
        """
        Generates a random 16-byte salt.
        """
        return os.urandom(16)
    
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