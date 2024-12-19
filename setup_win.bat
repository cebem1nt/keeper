@echo off

pyinstaller --onefile --hidden-import=src.extensions keeper.py

if exist "dist\keeper.exe" (
    echo Compilation successful
) else (
    echo Compilation failed
    exit /b 1
)

echo Setup complete.