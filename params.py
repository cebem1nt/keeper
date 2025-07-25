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

# Encryption backend to use
backend = 'fernet' # 'AES' 