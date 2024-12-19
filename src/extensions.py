from src.backend import Keeper
from datetime import datetime, timezone
from shutil import rmtree

import os, subprocess, sys, threading

# This is a default extension example. Each extension must do the following:
# - Take a keeper instance in init method (for events subscribing & interactions)
# - Have a subscribe method: Here functions will be binded on special events

# TODO : Make extensions to also extend cli interface and argparse

class Extension():
    def __init__(self, keeper: Keeper):
        self._keeper = keeper

    def subscribe(self):
        raise NotImplementedError()

class GitManager(Extension):
    """
    Git managing extension, to store passwords in a remote repo
    """
    def __init__(self, keeper: Keeper):
        super().__init__(keeper)
        self.storage_dir = self._keeper.storage_dir
        self._git_dir = os.path.join(self.storage_dir, '.git')

    def _git_run(self, *args, capture_output=False, check=False, text=True):
        return subprocess.run(['git', '-C', self.storage_dir] + list(args), 
                                capture_output=capture_output, check=check, text=text)

    def _git_popen(self, *args):
            return subprocess.Popen(
                ['git', '-C', self.storage_dir] + list(args),
                stdout=subprocess.PIPE, 
                stderr=subprocess.PIPE
            )

    def subscribe(self):
        if os.path.exists(self._git_dir):
            self._keeper.subscribe('init', self.check_remote_changes)
            self._keeper.subscribe('exit', self.check_and_push)
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

            self._git_run('push', '-u', 'origin', 'main')
        except:
            print("Aboarting repo creation...")
            rmtree(os.path.join(self.storage_dir, '.git'))
    
    def check_and_push(self):
        has_changes = self._git_run('status', '--porcelain', capture_output=True)
        if has_changes.stdout:
            self._git_run('add', '-A')
            self._git_run('commit', '-m', f'sync {datetime.now(timezone.utc)}')
            self._git_popen('push')

    def check_remote_changes(self):
        try:
            fetch = self._git_popen('fetch')
            fetch.wait()
            result = self._git_run('status', '-uno', capture_output=True)

            if 'Your branch is behind' in result.stdout:
                print("Remote changes detected, starting synchronization... ")
                self._git_run('pull')
        except subprocess.CalledProcessError as e:
            print(e)