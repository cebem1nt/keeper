# Keeper

Keeper is a local cli password manager writen in python. Keeper is oriented to extensibility and simplicity in code changing, while at the same time offering a good level of sequrity by default. 

## Tweaking

Before installation, you can tweak your build by modifying ```params.py```

```py
# Number of iterations used to generate unique key.
# Key generated with '320000' iterations wont match a 
# key generated with '244444' iterations. 
# More iterations, more time it takes to unlock the locker.
# Optimal number of iterations is from 300000 to 400000
iterations = 333000 

# Same with token size, but it will affect only new generated token. In case 
# if actual token is longer than it's size, will use first amount of bytes
# Optimal size: 32 to 64 
token_size = 32

# Same but size of the salt that's added at the beginning of each locker.
# Warning! In case if locker's salt is less than number passed, will lead to
# unexpected and fatal errors.
# Optimal size: 16 to 32 
salt_size = 16

# Extensions that are included in build. Leave list empty to disable any
active_extensions = ['GitManager']

# Portable build. Will look for token, lokers in the directory
# where the script is located.
# Data like token should be located in keepr_dir/data/
# .lk files should be located in keeper_dir/storage
# Where keper_dir is the location where executable is located

# Warning! Better compile it if using this param

is_portable = False
```

## Installation 

Just clone the repo:

```sh
git clone https://github.com/cebem1nt/keeper.git
cd keeper
```

And run the setup script:

```python setup.py```

This will compile python code using pyinstaller and move compiled file to /usr/bin/ or leave compiled file in /dist/keeper.exe

*Alternatively you can run it directly:*

```python keeper.py```

## Usage
```$ keeper --help
usage: keeper [-h] {add,remove,get,edit,list,search,generate,change,copy,current,shred-locker,generate-token} ...

Keeper is a Python password manager. Locker is a .lk file where passwords are stored, triplet is tag/login/password. More detailed info about each command can be seen
by adding -h to the command.

positional arguments:
  {add,remove,get,edit,list,search,generate,change,copy,current,shred-locker,generate-token}
                        Available commands
    add                 Add a new triplet with provided tag or tags.
    remove              Remove a triplet based on tag or tags.
    get                 Retrieve login or password based on tag.
    edit                Interactively edit parameters of a triplet.
    list                List all stored triplets.
    search              Search for a triplets with similar tag.
    generate            Generates a password and stores it with provided tag
    change              Changes current locker file to provided.
    copy                Copy current .lk or token file to the provided directory.
    current             Prints directory of the current locker in use.
    shred-locker        Shreds current locker.
    generate-token      Generates a new token.

options:
  -h, --help            show this help message and exit
```

## lil' notes

This project is more like an attempt on doing a good password manager, and a fetus of my paranoia:)
Keeper stores passwords in separate files with .lk extension, which is actually kinda useless, better way of it, is how it realized in pass. Anyways. 

You can setup syncronization between devices by adding repository to the directory where passwords are stored, and enabling GitManager as extension. This will just push and pull changes from remote. 

__You can find your files with passwords in:__
> ~/.keeper_storage (on linux, mac, termux)

> C:\Users\<Username>\.keeper_storage (windows)

Or alternatively you can set custom directory by setting __$KEEPER_STORAGE_DIR__ environment variable, for example:
```sh
export KEEPER_STORAGE_DIR="$XDG_STATE_HOME/keeper_storage"
```

Token is unique for each user and used like kind of salt or pepper for your encrypted passwords. If you want to use it between multiple devices, token must be equal on each device.

__You can find your generated token in:__
> ~/.local/share/keeper (on linux, mac, termux)

> C:\Users\<Username>\AppData\Local\keeper (windows)

Inside, project seems to be commented well.

## Todo

Stuff i will do: 

- [x]  Normal Readme
- [x]  One .py setup script
- [x]  Git integration for remote usage
- [x]  Improve extensibility of the code
- [x]  Event system for extensibility
- [x]  Opening an .lk file out of working directory
- [x]  Portable build for keeper, accessing and managing passwords on flashdrive
- [x]  AES encryption backend
- [ ]  Option for temporary key storing, so you dont have to enter master password every time
- [x]  Improve git manager (seems fine for now)

May be:

- Visual interface
## What is done

- All the main functionality: Searching, adding, editting, getting, removing passwords 
- Additional functionality: Generating passwords, coppying passwords files, changing between files
- Basic comments / architecture for extensibility
