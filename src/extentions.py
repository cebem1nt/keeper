from src.backend import Keeper
from datetime import datetime, timezone
from shutil import rmtree
import os, subprocess, socket

# This is a default extention example. Each extention must do the following:
# - Take a keeper instance in init method (for events subscribing & interactions)
# - Have a subscribe method: Here functions will be binded on special events

# TODO : Make extentions to also extend cli interface and argparse
# TODO : Async.

class GitManager:
    """
    Git managing extention, to store passwords in a remote repo
    """
    def __init__(self, keeper: Keeper):
        self._keeper = keeper
        self.storage_dir = self._keeper.storage_dir
        self._is_valid_dir = os.path.exists(os.path.join(self.storage_dir, '.git'))

    def has_internet(self):
        try:
            # Try to connect to Cloudflare's DNS server
            socket.create_connection(('1.1.1.1', 53), timeout=5)
            return True
        except (socket.timeout, socket.gaierror):
            return False

    def _git_run(self, *args, capture_output=False, check=False, text=True):
        return subprocess.run(['git', '-C', self.storage_dir] + list(args), 
                                capture_output=capture_output, check=check, text=text)

    def subscribe(self):
        if self.has_internet():
            if self._is_valid_dir:
                self._keeper.subscribe('init', self.check_remote_changes)
                self._keeper.subscribe('exit', self.push)
            else:
                create_repo = input("No repo in storage dir found, would you like to create one? [Y/n] ")
                if 'n' == create_repo.lower():
                    return
                self._init_repo()

    def _init_repo(self):
        try:
            self._git_run('init')
            self._git_run('add', '-A')
            self._git_run('commit', '-m', 'init')
            self._git_run('branch', '-M', 'main')

            while True:
                remote_origin = input("Enter remote origin: ")
                if remote_origin.startswith('http') and remote_origin.endswith('.git'):
                    print("Remote origin added...")
                    self._git_run('remote', 'add', 'origin', remote_origin)
                    break
                else:
                    print("Origin seems to be incorrect, try again")
            

            self._git_run('push', '-u', 'origin', 'main',)
        except:
            print("Aboarting repo creation...")
            rmtree(os.path.join(self.storage_dir, '.git'))

    def pull(self):
        self._git_run('pull')
    
    def push(self):
        has_changes = self._git_run('status', '--porcelain', capture_output=True)
        if has_changes.stdout:
            self._git_run('add', '-A')
            self._git_run('commit', '-m', f'sync {datetime.now(timezone.utc)}')
            self._git_run('push')

    def check_remote_changes(self):
        try:
            self._git_run('fetch', check=True)

            result = self._git_run('status', '-uno', capture_output=True)

            if 'Your branch is behind' in result.stdout:
                print("Starting synchronization.... ")
                self.pull()
            else:
                print("Up to date") 
        except subprocess.CalledProcessError as e:
            print(e)