import os
from shutil import copy

class FileSystem:
    """
    Class for file manipulatoions with password manager file system
    """

    def __init__(self, dir='~/.keeper') -> None:
        self.root_dir = os.path.expanduser(dir)
        self.current_locker = os.path.join(self.root_dir, '.current_locker') # file with selected locker path

        self.init_locker()

        self.storage = os.path.join(self.locker_dir, 'storage')
        self.hash = os.path.join(self.locker_dir, '.hash')
        self.salt = os.path.join(self.locker_dir, '.salt')

        for file_path in [self.storage, self.hash, self.salt]:
            if not os.path.exists(file_path):
                with open(file_path, 'w'):
                    pass

    def init_locker(self) -> None:
        """
        Ensure that required directories and files exist.
        """
        # making all the basic dirs
        os.makedirs(self.root_dir, exist_ok=True)

        if not os.path.exists(self.current_locker):
            with open(self.current_locker, 'w'):
                pass

        with open(self.current_locker) as f:
            # Reading a directory to the current locker
            self.locker_dir = f.read().strip() 

        if not self.locker_dir or not os.path.exists(self.locker_dir):
            # if its empty, or previous setted locker doesnt exist anymore we set default one and make it 
            self.locker_dir = os.path.join(self.root_dir, 'default_locker')
            os.makedirs(self.locker_dir, exist_ok=True)

            self.change_locker(self.locker_dir)

    def dump_locker(self, dir: str) -> None:
        """
        Recieves destination dir and dumps current locker there
        """
        dir = os.path.expanduser(dir)

        if dir == '.':
            dir = os.getcwd()

        for file in [self.hash, self.salt, self.storage]:
            copy(file, dir)

    def hash_exists(self) -> bool:
        """
        Check if the hash of passphrase exists
        """
        try:
            with open(self.hash) as f:
                return bool(f.read().strip())
            
        except:
            return False


    def get_content(self, key: str) -> str | bytes:
        """
        Get content from a specified file.
        """
        methods = {
            'hash': lambda: open(self.hash),
            'storage': lambda: open(self.storage),
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
            'salt': lambda: open(self.salt, 'wb'),
        }

        if key in methods:
            with methods[key]() as f:
                if isinstance(content, bytes):
                    f.write(content)
                else:
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
        
    def change_locker(self, dest: str) -> None:
        """
        A function to change current locker
        """
        dest = os.path.expanduser(dest)
        cwd = os.getcwd()
        
        if not os.path.exists(dest):
            local = os.path.join(self.root_dir, dest)

            if os.path.exists(local):
                with open(self.current_locker, 'w') as f:
                    f.write(local)
                return
            else:
                raise FileNotFoundError(f"Could not find locker in {dest}")

        if dest == '.':
            dest == cwd
            
        else:
            dest = os.path.join(cwd, dest)
        

        with open(self.current_locker, 'w') as f:
            f.write(dest)

    def get_current_locker(self):
        with open(self.current_locker) as f:
            return f.read()

    def suicide(self):
        os.remove(self.hash)
        os.remove(self.storage)
        os.remove(self.salt)