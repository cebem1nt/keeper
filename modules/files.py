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

    def init_locker(self) -> None:
        """
        Ensure that required directories and files exist.
        """
        # making all the basic dirs
        os.makedirs(self.root_dir, exist_ok=True)

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
            return bool(self.get_from_locker('salt'))
            
        except:
            return False

    def get_from_locker(self, param: str) -> bytes | tuple[bytes] :
        """
        Reads content based on param from current locker. 
          Params: 
          - 'salt' : returns salt
          - 'storage' : returns storage lines
          - 'all' : returns both (salt, storage)
        """
        
        with open(self.locker, 'rb') as f:
            salt = f.read(16)
            storage = f.read()

        res = {
            'salt' : salt,
            'storage' : storage,
            'all': (salt, storage)
        }

        return res[param]

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
        Remove a triplet line at specified index from the locker file.
        """

        storage_lines = self.get_from_locker('storage').decode().split('\n')

        if 0 <= index < len(storage_lines):
            storage_lines.pop(index)

        else:
            raise IndexError("Index out of range")

        edited_lines = '\n'.join(storage_lines).lstrip('\n').encode()
        salt = self.get_from_locker('salt')

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
        Removes current locker
        """
        os.remove(self.locker)