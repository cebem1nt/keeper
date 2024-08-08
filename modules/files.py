import os

class FileSystem:
    """
    Class for file manipulations related to password management.
    """
    def __init__(self, dir='~/.keeper') -> None:
        self.dir = os.path.expanduser(dir)
        self.storage = os.path.join(self.dir, 'storage.txt')
        self.hash = os.path.join(self.dir, 'hash.txt')
        self.salt = os.path.join(self.dir, '.salt')
        self.ensure_dirs_exist()

    def hash_exists(self) -> bool:
        """
        Check if the hash of passphrase exists
        """
        try:
            with open(self.hash) as f:
                return bool(f.read().strip())
            
        except:
            return False

    def ensure_dirs_exist(self) -> None:
        """Ensure that required directories and files exist."""
        os.makedirs(self.dir, exist_ok=True)

        for file_path in [self.storage, self.hash, self.salt]:
            if not os.path.exists(file_path):
                with open(file_path, 'w'):
                    pass

    def get_content(self, key: str) -> str | bytes:
        """
        Get content from a specified file.
        """
        methods = {
            'hash': lambda: open(self.hash, 'r'),
            'storage': lambda: open(self.storage, 'r'),
            'salt': lambda: open(self.salt, 'rb'),
        }

        if key in methods:
            with methods[key]() as f:
                return f.read()
        else:
            raise KeyError(f"Key: {key} not found")

    def set_content(self, key: str, content: str | bytes) -> None:
        """
        Set content to a specified file.
        """

        methods = {
            'hash': lambda: open(self.hash, 'w'),
            'storage': lambda: open(self.storage, 'a'),
            'salt': lambda: open(self.salt, 'wb')
        }

        if key in methods:
            with methods[key]() as f:
                f.write(content + '\n')

        else:
            raise KeyError(f"Key: {key} not found")

    def remove_from_storage(self, index: int) -> None:
        """
        Remove a line from the storage file at a specified index.
        """

        try:
            with open(self.storage, 'r') as f:
                lines = f.readlines()
            
            if 0 <= index < len(lines):
                lines.pop(index)

                with open(self.storage, 'w') as f:
                    f.writelines(lines)

            else:
                raise IndexError("Index out of range")
            
        except:
            raise FileNotFoundError(f"File not found: {self.storage}")
        
    def suicide(self):
        os.remove(self.hash)
        os.remove(self.storage)
        os.remove(self.salt)