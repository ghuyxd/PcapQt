@echo off
setlocal

:: Check if .venv exists
if not exist ".venv" (
    echo [ERROR] Virtual environment not found.
    echo Please run 'install.bat' first to set up the environment.
    pause
    exit /b 1
)

:: Activate virtual environment
call .venv\Scripts\activate.bat

:: Run the application
echo Starting PcapQt...
python -m pcapqt.main

:: Keep window open if it crashes immediately
if errorlevel 1 pause
