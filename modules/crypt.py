import hashlib, base64, os
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend

class CryptoSystem:
    """
    Cryptography class for encrypting / decrypting passwords, hashing 
    and other cryptography manipulations 
    """
    def __init__(self) -> None:
        pass

    def get_cipher(self, key: bytes):
        """
        Gets key as bytes and returns Fernet instance for
        future decryption and encryption
        """
        return Fernet(key)

    def hash_data(self, data: str):
        """
        Recieves data and returns it's hash
        """
        sha256 = hashlib.sha256()
        sha256.update(data.encode())
        return sha256.hexdigest()

    def verify_hash(self, original_hash: str, new_data: str):
        """
        Gets hashed string, and normal string. Hashes
        data and verifies are they equal
        """
        return original_hash == self.hash_data(new_data)

    def encrypt(self, cipher: Fernet, data: str):
        """
        Gets data and Fernet instance.
        returns encrypted data
        """
        return cipher.encrypt(data.encode()).decode()

    def decrypt(self, cipher: Fernet, encrypted_data: str):
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