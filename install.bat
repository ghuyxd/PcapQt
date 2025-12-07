@echo off
setlocal

:: Define URLs and filenames
:: Python 3.11.9 is the last 3.11 release with a binary installer.
set "PYTHON_URL=https://www.python.org/ftp/python/3.11.9/python-3.11.9-amd64.exe"
set "PYTHON_INSTALLER=python-3.11.9-amd64.exe"
set "NPCAP_URL=https://nmap.org/npcap/dist/npcap-1.85.exe"
set "NPCAP_INSTALLER=npcap-1.85.exe"

echo ----------------------------------------------------------------------
echo Starting automated setup...
echo ----------------------------------------------------------------------

:: 1. Download Python
if exist "%PYTHON_INSTALLER%" (
    echo %PYTHON_INSTALLER% already exists. Skipping download.
) else (
    echo Downloading Python 3.11.9...
    powershell -Command "Invoke-WebRequest -Uri '%PYTHON_URL%' -OutFile '%PYTHON_INSTALLER%'"
    if not exist "%PYTHON_INSTALLER%" (
        echo [ERROR] Failed to download Python installer.
        pause
        exit /b 1
    )
)

:: 2. Download Npcap
if exist "%NPCAP_INSTALLER%" (
    echo %NPCAP_INSTALLER% already exists. Skipping download.
) else (
    echo Downloading Npcap 1.85...
    powershell -Command "Invoke-WebRequest -Uri '%NPCAP_URL%' -OutFile '%NPCAP_INSTALLER%'"
    if not exist "%NPCAP_INSTALLER%" (
        echo [ERROR] Failed to download Npcap installer.
        pause
        exit /b 1
    )
)

echo.
echo ----------------------------------------------------------------------
echo Installing software...
echo ----------------------------------------------------------------------

:: 3. Install Python
echo Installing Python 3.11...
:: /passive displays progress bar but requires no user interaction.
:: PrependPath=1 adds Python to environment variables.
start /wait "" "%PYTHON_INSTALLER%" /passive PrependPath=1 ALLUSERS=1

:: 4. Install Npcap
echo Installing Npcap...
:: Silent mode (/S) is removed as it is not supported in the free version.
:: The installer GUI will appear.
start /wait "" "%NPCAP_INSTALLER%"

echo.
echo ----------------------------------------------------------------------
echo Setting up Python Environment...
echo ----------------------------------------------------------------------

:: 5. Create Virtual Environment
if not exist ".venv" (
    echo Creating virtual environment...
    :: Try standard python command first, then fallback to default install path
    python -m venv .venv 2>nul
    if errorlevel 1 (
        echo "python" command not found, trying default Windows install path...
        "%LOCALAPPDATA%\Programs\Python\Python311\python.exe" -m venv .venv
    )
) else (
    echo Virtual environment already exists.
)

:: 6. Install Dependencies
if exist ".venv\Scripts\activate.bat" (
    echo Activating virtual environment...
    call .venv\Scripts\activate.bat
    
    echo Installing dependencies...
    pip install .
    
    if errorlevel 1 (
        echo [ERROR] Failed to install dependencies.
        pause
        exit /b 1
    )
    
    echo Dependencies installed successfully.
    call deactivate
) else (
    echo [ERROR] Virtual environment creation failed.
    pause
    exit /b 1
)

echo.
echo ----------------------------------------------------------------------
echo Setup completed successfully!
echo You may need to restart your computer or restart your terminal.
echo ----------------------------------------------------------------------
pause
