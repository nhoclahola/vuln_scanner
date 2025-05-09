@echo off
echo === Web Vulnerability Scanner - Installation ===

:: Check Python
python --version >nul 2>&1
if %ERRORLEVEL% NEQ 0 (
    echo Python not found. Please install Python 3.9 or later.
    echo https://www.python.org/downloads/
    exit /b 1
)

:: Set PYTHONIOENCODING environment variable
setx PYTHONIOENCODING utf-8
echo Set environment variable PYTHONIOENCODING=utf-8

:: Create virtual environment
echo Creating virtual environment...
python -m venv venv
if %ERRORLEVEL% NEQ 0 (
    echo Error creating virtual environment.
    exit /b 1
)

:: Activate virtual environment
echo Activating virtual environment...
call venv\Scripts\activate.bat
if %ERRORLEVEL% NEQ 0 (
    echo Error activating virtual environment.
    exit /b 1
)

:: Install dependencies
echo Installing dependencies...
pip install -r requirements.txt
if %ERRORLEVEL% NEQ 0 (
    echo Error installing dependencies.
    exit /b 1
)

echo ===================================
echo Installation successful!
echo To run the application, execute the following commands:
echo - Activate virtual environment: venv\Scripts\activate
echo - Run application: python main.py
echo =================================== 