@echo off
title Cyber Hygiene Grader
cd /d "%~dp0"

python --version >nul 2>&1 || (
  echo Python was not found. Install Python 3.10 or newer from https://www.python.org/downloads/
  echo and tick "Add python.exe to PATH" during setup.
  pause
  exit /b 1
)

python -c "import flask, dns.resolver, requests, cryptography, certifi, reportlab" >nul 2>&1 || (
  echo Installing the required Python packages...
  python -m pip install -r requirements.txt || (
    echo Could not install the requirements.
    pause
    exit /b 1
  )
)

rem Opens the admin portal in your browser. Close this window (or press Ctrl+C) to stop the grader.
python -m cybergrader.webapp --open %*
if errorlevel 1 pause
