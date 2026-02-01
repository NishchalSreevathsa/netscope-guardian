@echo off
echo Starting NetScope Guardian Backend on Port 8080...
cd /d "%~dp0"

:: Activate virtual environment
call venv\Scripts\activate

:: Force Port and Host
set PORT=8080
set HOST=127.0.0.1

:: Run Server
python main.py
pause
