from platform import system
from shutil import which
import os, sys, subprocess, params

operating_sys = system()
termux = False

def install_reqs(is_termux):
    if is_termux:
        subprocess.run('pkg update && pkg upgrade', shell=True)
        subprocess.run(['pkg', 'install', 'termux-api'])

    try:
        subprocess.run(['pip', 'install', '-r', 'requirements.txt'])

    except:
        if operating_sys != 'Linux':
            print("Could not install required python packages.")
            sys.exit(1)
        else:
            with open('requirements.txt', 'r') as f:
                print('')
                for line in f:
                    print(line.strip())
            print("\nYou probably have to install these python libraries")
            print("according to your distribution package manager.")
            print("If you have already installed these packages, continue.")
            cont = input("Continue? [Y/n] ")
            if cont.lower() == 'n':
                return
try:
    match operating_sys:
        case 'Windows':
            script = 'setup_win.bat'

        case 'Darwin' | 'Linux':
            script = 'bash setup_linux.sh'

        case _ :
            if 'TERMUX_VERSION' in os.environ:
                script = 'bash setup_linux.sh -t'
                termux = True
            else:
                print("Ooops, your os is unsupported!")
                sys.exit(1)    

    install_reqs(termux)
    subprocess.run(script, shell=True)

except KeyboardInterrupt:
        sys.exit(1)

except Exception as e:
    raise e