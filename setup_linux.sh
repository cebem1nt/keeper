#!/bin/bash

pyinstaller --onefile keeper.py

if [ -f "dist/keeper" ]; then
    echo "Compilation successful"
    sudo mv dist/keeper /usr/bin/keeper
    echo "Executable added to /usr/bin."
else
    echo "Compilation failed"
    exit 1
fi

echo "Setup complete."