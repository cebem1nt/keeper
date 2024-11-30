from cryptography.fernet import Fernet, InvalidToken
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
from hashlib import sha256

from base64 import urlsafe_b64encode as b64_encode
import re

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


class CryptoSystem:
    """Base cryptography class"""

    def __init__(self, iterations: int):
        self._iterations = iterations

    def init_cipher(self, passphrase_bytes: bytes, token: bytes, salt: bytes ):
        """Impprtant function to initialize a Fernet instance for class."""
        self._cipher = Fernet(derive_key(passphrase_bytes, salt, token, self._iterations)) 

    def __encrypt(self, data: str) -> bytes:
        if self._cipher is None:
            raise ValueError("Cipher wasn't initialized")
        return self._cipher.encrypt(data.encode())

    def __decrypt(self, encrypted_data: bytes) -> str:
        if self._cipher is None:
            raise ValueError("Cipher wasn't initialized")
        try:
            return self._cipher.decrypt(encrypted_data).decode()
        except InvalidToken:
            raise AssertionError("Token doesn't match")
    
    def hash(self, content: str):
        return sha256(content.encode()).hexdigest().encode()

    def encrypt_triplet(self, tag: str, login: str, password: str):
        # Replace brackets to avoid formating issues
        escape_brackets = lambda text: text.replace("]", "/]").replace("[", "/[").strip()
            
        tag = escape_brackets(tag)
        login = escape_brackets(login)
        password = escape_brackets(password)

        formatted_line = f"[ {tag} ] [ {login} ] [ {password} ]"
        encrypted_line = self.__encrypt(formatted_line)
        return encrypted_line

    def decrypt_triplet(self, line: bytes):
        # Restoring brackets back
        restore_brackets = lambda text: text.replace("/]", "]").replace("/[", "[")
        decrypted_line = restore_brackets(self.__decrypt(line))
        matches: list[str] = re.findall(r'\[\s*([^\]]+?)\s*\]', decrypted_line)
        
        if len(matches) == 3:
            return (matches[0], matches[1], matches[2])
        else:
            raise ValueError(f"File seems to be corrupted")