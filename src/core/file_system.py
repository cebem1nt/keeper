import os, random, sys

from stat import S_IRUSR, S_IWUSR
from shutil import copy as sh_copy
from platform import system as pl_system

class SaltManager:
    def __init__(self, size: int, dir: str) -> None:
        self._size = size
        self.dir = dir

    def exists(self):
        try:
            with open(self.dir, 'rb') as f:
                return bool(f.read(self._size)) 
        except:
            return False
    
    def generate(self):
        salt = os.urandom(self._size)

        with open(self.dir, 'wb') as f:
            f.write(salt)

        os.chmod(self.dir, S_IRUSR | S_IWUSR)
        return salt

    def get(self, auto_generate=True) -> bytes | None:
        if not self.exists():
            if auto_generate:
                return self.generate()
            return None
        else:
            with open(self.dir, 'rb') as f:
                return f.read(self._size)

class CrossPlatform:
    """Base class to determine all directories for the file system on any system"""
    
    def __init__(self, is_portable=False):
        self.platform = pl_system()

        user_root = os.path.expanduser('~')
        script_dir = os.path.dirname(sys.argv[0])

        # Load custom user directory to store passwords, if it is not set
        # or if this directory doesnt exist, fallback to default one
        
        default_sd = os.path.join(user_root, '.keeper_storage')
        storage_dir = os.getenv("KEEPER_STORAGE_DIR", default_sd)

        if is_portable:
            # If this is portable build, then everything should be located
            # in the same directory where the script is. 
            storage_dir = os.path.join(script_dir, 'storage')
            self.platform = 'Portable'

        elif not os.path.exists(storage_dir):
            storage_dir = default_sd

        # Root dir is a directory where all stuff for password manager to work will be stored
        root_dirs = {
            'Windows' : os.path.join(os.getenv('LOCALAPPDATA', user_root), 'keeper'),
            'Linux'   : os.path.expanduser('~/.local/share/keeper'), 
            'Darwin'  : os.path.expanduser('~/.local/share/keeper'),
            'Portable': os.path.join(script_dir, 'data'),
        }

        if self.platform in root_dirs:
            self.storage_dir = storage_dir
            self.root_dir = root_dirs[self.platform]
            os.makedirs(self.root_dir, exist_ok=True)
            os.makedirs(self.storage_dir, exist_ok=True)

        else:
            raise OSError(f"Unsuported os: {self.platform}")

class FileSystem(CrossPlatform):
    """
    A base layer class for the password's manager file system manipulations.
    """    
    # Locker file is a file where all the data is stored

    # Token is a randomly generated N bytes salt, used as pepper 
    # It's necessary because default salt is located in the locker file.
    # So to decrypt a locker, you need a locker file and the same generated token 

    # Header is 64 chars sha256 string, which is an id fo each line
    _header_size = 64

    def __init__(self, salt_size, token_size, is_portable=False):
        super().__init__(is_portable)
        self._salt_size=salt_size
        self._token_size=token_size
        self.locker_file = None
        self.token_file = os.path.join(self.root_dir, 'token') 
        self.current_locker_file = os.path.join(self.root_dir, 'current_locker') 

        if not os.path.exists(self.current_locker_file):
            # If there is no file with current locker directory, we create empty one
            open(self.current_locker_file, 'w').close()

        # Sets locker_file variable based on context
        self.__sync_locker()

    def __sync_locker(self):
        # Getting current locker directory
        self.locker_file = self.get_current_locker_dir() 

        if not self.locker_file or not os.path.exists(self.locker_file):
            # If there is no directory in the file or, the directory in the 
            # file doesn't exists, falls back to default locker file
            self.locker_file = os.path.join(self.storage_dir, 'default.lk')

            if not os.path.exists(self.locker_file):
                # If default locker file doesnt exist, create it
                open(self.locker_file, 'w').close()

            # Change locker dir to default one
            self.change_locker_dir('default.lk', same_ok=True)

    def get_current_locker_dir(self, is_full=True):
        with open(self.current_locker_file) as f:                
            cur_locker = f.read().strip()
            if not is_full and cur_locker.startswith(self.storage_dir):
                return os.path.relpath(cur_locker, self.storage_dir)
            return cur_locker
        
    def change_locker_dir(self, dest: str, same_ok=False, is_relative=False) -> None:
        if is_relative:
            # Destination is not a sub directory of storage_dir
            dest = os.path.abspath(os.path.expanduser(dest))
        else:
            dest = os.path.join(self.storage_dir, dest)
        
        if not os.path.exists(dest):
            if dest == os.path.join(self.storage_dir, 'default.lk'):
                open(self.locker_file, 'w').close()
            else:
                raise FileNotFoundError("Could not find locker file")

        elif os.path.isdir(dest):
            raise ValueError("Argument is a directory")

        elif dest == self.get_current_locker_dir() and not same_ok:
            raise AssertionError("Same file")
        
        with open(self.current_locker_file, 'w') as f:
            f.write(dest) # Current locker file keeps absolute directories to the locker files !

        self.__sync_locker() # Sync locker file to the new locker

    def _get_all_lines_from_storage(self) -> list[bytes]:
        lines = []
        with open(self.locker_file, 'rb') as locker:
            locker.read(self._salt_size)
            for line in locker:
                lines.append(line[self._header_size:])
        return lines

    def _append_line_to_storage(self, header: bytes, line: bytes):
        with open(self.locker_file, 'ab') as f:
            # Every line starts from a header which is used as an identifier for the line
            f.write(header+line+b'\n')

    def _get_line_from_storage(self, header: bytes) -> bytes | None:
        with open(self.locker_file, 'rb') as locker:
            locker.read(self._salt_size) # Removing salt
            for line in locker:
                line_header = line[:self._header_size] # Getting header of the line
                if line_header == header:
                    # If the header is that one we need, return content of the line
                    return line[self._header_size:].rstrip(b'\n')

    def _remove_line_from_storage(self, header: bytes):
        temp_file = self.locker_file + '.tmp'
        # Creating a temporary file to write content from the original file
        try:
            with open(self.locker_file, 'rb') as original, open(temp_file, 'wb') as tmp:
                tmp.write(original.read(self._salt_size))
                # Writing salt from the original file to the temporary one
                for line in original:
                    # Reading line by line
                    if line[:self._header_size] != header:
                        # If the line has the header we look for, dont write this line to a temporary file
                        # otherwise write this line to a temporary file 
                        tmp.write(line)
        # If something went wrong, we delete temporary file where we were making all the changes 
        # and leave the file that was before
        except IOError as e:
            os.remove(temp_file)
            raise e
        except KeyboardInterrupt:
            return os.remove(temp_file)
        # If all right, we replace original file with temporary file
        os.replace(temp_file, self.locker_file)

    def copy_locker(self, dir: str):
        sh_copy(self.locker_file, os.path.abspath(os.path.expanduser(dir)))

    def copy_token(self, dir: str):
        sh_copy(self.token_file, os.path.abspath(os.path.expanduser(dir)))

    def is_locker_salted(self):
        """Checks is locker already salted"""
        return SaltManager(self._salt_size, self.locker_file).exists()

    def token_exists(self):
        """Checks is token exist"""
        return SaltManager(self._token_size, self.token_file).exists()

    def get_token(self) -> bytes | None:
        return SaltManager(self._token_size, self.token_file).get(auto_generate=False)

    def generate_token(self):
        if not os.path.exists(self.token_file) or os.path.getsize(self.token_file) == 0: 
            return SaltManager(self._token_size, self.token_file).generate()
        raise AssertionError("Token already exists")
    
    def get_salt(self) -> bytes :
        return SaltManager(self._salt_size, self.locker_file).get()


    def reset(self, passes=3):
        """Shreding encrypted file before deletion :)"""
        try:
            file_size = os.path.getsize(self.locker_file)
            with open(self.locker_file, 'r+b') as f:
                for _ in range(passes):
                    # Moving cursor to the begining
                    f.seek(0)
                    # Replaces every byte of the file with random one
                    f.write(bytearray(random.getrandbits(8) for _ in range(file_size)))
                    # Writes changes
                    f.flush()
                    # Sync changes
                    os.fsync(f.fileno())
            # Removes the file
            os.remove(self.locker_file)
            # Fall back to default locker
            self.change_locker_dir('default.lk', same_ok=True)
        except Exception as e:
            raise e