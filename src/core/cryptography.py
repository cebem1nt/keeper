from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend

from cryptography.fernet import Fernet, InvalidToken
from hashlib import sha256

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding

from base64 import urlsafe_b64encode, urlsafe_b64decode
import re, os

# Main module for all cryptography stuff

def derive_key(passphrase: bytes, salt: bytes, token: bytes, itr: int) -> bytes:
    # The main key derivation function.
    # Length of derived key should be 32 bytes!
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=token+salt,
        iterations=itr,
        backend=default_backend()
    )
    # urlsafe_b64encode actually increases key length...
    # Now it returns raw key
    return kdf.derive(passphrase) 


class AESBackend:
    def __init__(self, iterations: int):
        self.iterations = iterations
        self.cipher = None
        self._key = None

    def init_cipher(self, passphrase: bytes, salt: bytes, token: bytes):
        derivated_key = derive_key(passphrase, salt, token, self.iterations)
        self._key = derivated_key
        self.cipher = True # Simplify verification later on

    def encrypt(self, data: str) -> bytes:
        iv = os.urandom(16)
        cipher = Cipher(algorithms.AES(self._key), modes.CBC(iv), backend=default_backend())
        encryptor = cipher.encryptor()
        
        # Pad the given data
        padder = padding.PKCS7(algorithms.AES.block_size).padder()
        padded_plaintext = padder.update(data.encode('utf-8')) + padder.finalize()
        
        ciphertext = encryptor.update(padded_plaintext) + encryptor.finalize()
        return urlsafe_b64encode(iv + ciphertext)

    def decrypt(self, encrypted_data: bytes) -> str:
        encrypted_data = urlsafe_b64decode(encrypted_data)
        iv = encrypted_data[:16]  # Extract the initial vector from the beginning
        actual_data = encrypted_data[16:]

        cipher = Cipher(algorithms.AES(self._key), modes.CBC(iv), backend=default_backend())
        decryptor = cipher.decryptor()
        
        # Decrypt the data
        decrypted_padded_text = decryptor.update(actual_data) + decryptor.finalize()
        
        # Unpad the decrypted data
        unpadder = padding.PKCS7(algorithms.AES.block_size).unpadder()
        unpadded_text = unpadder.update(decrypted_padded_text) + unpadder.finalize()

        return unpadded_text.decode('utf-8')


class FernetBackend:
    def __init__(self, iterations: int):
        self.iterations = iterations
        self.cipher = None

    def init_cipher(self, passphrase: bytes, salt: bytes, token: bytes):
        derivated_key = derive_key(passphrase, salt, token, self.iterations)
        self.cipher = Fernet(urlsafe_b64encode(derivated_key)) 

    def encrypt(self, data: str) -> bytes:
        if self.cipher is None:
            raise ValueError("Cipher wasn't initialized")

        return self.cipher.encrypt(data.encode())

    def decrypt(self, encrypted_data: bytes) -> str:
        if self.cipher is None:
            raise ValueError("Cipher wasn't initialized")

        try:
            return self.cipher.decrypt(encrypted_data).decode()

        except InvalidToken:
            raise AssertionError("Token doesn't match")


class CryptoSystem:
    """Base cryptography class"""

    def __init__(self, iterations: int, backend: str = "fernet"):
        self.__backend = None

        if backend.lower() == "aes": 
            self.__backend = AESBackend(iterations)
        else:
            # Fallback to fernet silently
            self.__backend = FernetBackend(iterations)

    def init_cipher(self, passphrase: bytes, salt: bytes, token: bytes):
        self.__backend.init_cipher(passphrase, salt, token)

    def encrypt(self, data: str) -> bytes:
        return self.__backend.encrypt(data)

    def decrypt(self, encrypted_data: bytes) -> str:
        return self.__backend.decrypt(encrypted_data)

    def has_cipher(self) -> bool:
        return self.__backend.cipher != None
    
    def hash(self, content: str):
        return sha256(content.encode()).hexdigest().encode()

    def encrypt_triplet(self, tag: str, login: str, password: str):
        # Replace brackets to avoid formating issues
        escape_brackets = lambda text: text.replace("]", "/]").replace("[", "/[").strip()
            
        tag = escape_brackets(tag)
        login = escape_brackets(login)
        password = escape_brackets(password)

        formatted_line = f"[ {tag} ] [ {login} ] [ {password} ]"
        encrypted_line = self.encrypt(formatted_line)
        return encrypted_line

    def decrypt_triplet(self, line: bytes):
        # Restoring brackets back
        restore_brackets = lambda text: text.replace("/]", "]").replace("/[", "[")
        decrypted_line = restore_brackets(self.decrypt(line))
        matches: list[str] = re.findall(r'\[\s*([^\]]+?)\s*\]', decrypted_line)
        
        if len(matches) == 3:
            return (matches[0], matches[1], matches[2])
        else:
            raise ValueError(f"File seems to be corrupted")