#!/bin/bash

while getopts "t" flag; do
    case "${flag}" in
        t) TERMUX=true ;;
        *) echo "Usage: $0 [-t]"; exit 1 ;;
    esac
done

pyinstaller --onefile --hidden-import=src.extensions keeper.py

if [ -f "dist/keeper" ]; then
    echo "Compilation successful"
    
    if [ "$TERMUX" = true ]; then
        mv dist/keeper $PATH
        echo "Executable added to $PATH."
    else
        sudo mv dist/keeper /usr/bin/keeper
        echo "Executable added to /usr/bin."
    fi
else
    echo "Compilation failed"
    exit 1
fi

echo "Setup complete."