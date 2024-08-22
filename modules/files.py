import os, random
from shutil import copy

class FileSystem:
    """
    Class for file manipulatoions with password manager file system
    """

    def __init__(self, dir='~/.local/share/keeper') -> None:
        self.root_dir = os.path.expanduser(dir)
        os.makedirs(self.root_dir, exist_ok=True)

        self.current_locker = os.path.join(self.root_dir, '.current_locker') # file with selected locker path

        self.init_locker()

    def init_locker(self) -> None:
        """
        Ensure that required directories and files exist.
        """
        # making the basic locker if it doesn't exist

        if not os.path.exists(self.current_locker):
            with open(self.current_locker, 'w'):
                pass

        self.locker = self.get_current_locker() 

        if not self.locker or not os.path.exists(self.locker):
            # if its empty, or previous setted locker doesnt exist anymore we set default one and make it 
            self.locker = os.path.join(self.root_dir, 'default.lk')
            
            if not os.path.exists(self.locker):
                with open(self.locker, 'w') as f:
                    pass

            self.change_locker(self.locker)

    def salt_exists(self) -> bool:
        """
        Check if the salt exists. Used to identify is the first run
        """
        try:
            return bool(self.get_from_locker())
            
        except:
            return False

    def get_from_locker(self, get_salt=True) -> bytes :
        """
        Reads content based on param from current locker.
        """
        
        with open(self.locker, 'rb') as f:
            salt = f.read(16)
            storage = f.read()

        if get_salt:
            return salt

        return storage

    def set_to_locker(self, value: bytes, set_salt=True) -> None :
        """
        Sets content based on param from current locker. 
        """

        if set_salt:
            with open(self.locker, 'wb') as f:
                f.write(value)

        else:
            with open(self.locker, 'ab') as f:
                f.write(value)

    def remove_from_storage(self, index: int) -> None:
        """
        Remove a line at specified index from the locker file.
        """

        storage_lines = self.get_from_locker(False).decode().split('\n')

        if 0 <= index < len(storage_lines):
            storage_lines.pop(index)

        else:
            raise IndexError("Index out of range")

        edited_lines = '\n'.join(storage_lines).lstrip('\n').encode()
        salt = self.get_from_locker()

        with open(self.locker, 'wb') as f:
            f.write(salt + edited_lines)

    def change_locker(self, dest: str) -> None:
        """
        A function to change current locker to provided dir. 
        locker file is a file with .lk extention
        """
        dest = os.path.abspath(os.path.expanduser(dest))
        
        if not os.path.exists(dest):
            raise FileNotFoundError(f"Could not find locker in {dest}")

        with open(self.current_locker, 'w') as f:
            f.write(dest)

    def copy_locker(self, dir: str) -> None:
        """
        Recieves destination dir and copies current locker there
        """
        dir = os.path.abspath(os.path.expanduser(dir))

        copy(self.locker, dir)

    def get_current_locker(self):
        """
        Returns current locker directory
        """
        with open(self.current_locker) as f:
            return f.read().strip()

    def suicide(self):
        """
        Shreds current locker and removes it
        """
        try:
            with open(self.locker, 'r+b') as f:
                file_size = os.path.getsize(self.locker)
                
                for _ in range(2):
                    f.seek(0)
                    f.write(bytearray(random.getrandbits(8) for _ in range(file_size)))
                
                f.truncate()
            
            os.remove(self.locker)
    
        except Exception as e:
            raise e