from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes, padding
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

from cryptography.fernet import Fernet, InvalidToken
from hashlib import sha256

from base64 import urlsafe_b64encode as b64_encode, b64decode
import re, os

# Main module for all cryptography stuff
# TODO maybe try some AES backend instead of fernet

def derive_key(passphrase: bytes, salt: bytes, token: bytes, itr: int):
    # The main key derivation function. You can customize it however you want.
    # Length of derived key should be 32 bytes!
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=token+salt,
        iterations=itr,
        backend=default_backend()
    )
    return b64_encode(kdf.derive(passphrase))


class AESBackend:
    def __init__(self, iterations: int):
        self.iterations = iterations
        self.cipher = None
        self._key = None

    def init_cipher(self, passphrase: bytes, salt: bytes, token: bytes):
        derivated_key = derive_key(passphrase, salt, token, self.iterations)
        self._key = derivated_key
        self.cipher = True  # to verify initialization

    def __get_iv(self, data: bytes) -> bytes:
        return data[:16]

    def encrypt(self, data: str) -> bytes:
        padder = padding.PKCS7(128).padder()
        padded_data = padder.update(data.encode())
        padded_data += padder.finalize()

        iv = os.urandom(16)
        cipher = Cipher(algorithms.AES(self._key[:32]), modes.CBC(iv), backend=default_backend())
        encryptor = cipher.encryptor()

        cipher_text = encryptor.update(padded_data) + encryptor.finalize()
        return cipher_text

    def decrypt(self, encrypted_data: bytes) -> str:
        iv = encrypted_data[:16]
        decryptor = Cipher(algorithms.AES(self._key[:32]), modes.CBC(iv), backend=default_backend()).decryptor()
        decrypted_data = decryptor.update(encrypted_data[16:]) + decryptor.finalize()

        unpadder = padding.PKCS7(128).unpadder()
        unpadded_data = unpadder.update(decrypted_data)
        unpadded_data += unpadder.finalize()

        return unpadded_data.decode()


class FernetBackend:
    def __init__(self, iterations: int):
        self.iterations = iterations
        self.cipher = None

    def init_cipher(self, passphrase: bytes, salt: bytes, token: bytes):
        derivated_key = derive_key(passphrase, salt, token, self.iterations)
        self.cipher = Fernet(derivated_key) 

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
        self.backend = None

        if backend.lower() == "aes": 
            self.backend = AESBackend(iterations)
        else:
            # Fallback to fernet silently in case if backend was incorrect
            self.backend = FernetBackend(iterations)

    def init_cipher(self, passphrase: bytes, salt: bytes, token: bytes):
        self.backend.init_cipher(passphrase, salt, token)

    def encrypt(self, data: str) -> bytes:
        return self.backend.encrypt(data)

    def decrypt(self, encrypted_data: bytes) -> str:
        return self.backend.decrypt(encrypted_data)

    def has_cipher(self) -> bool:
        return self.backend.cipher != None
    
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