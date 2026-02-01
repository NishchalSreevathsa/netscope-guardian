@echo off
echo Starting NetScope Guardian Backend...
cd /d "%~dp0"

:: Activate virtual environment
call venv\Scripts\activate

:: Check if .env exists, if not create dummy
if not exist .env (
    echo GEMINI_API_KEY=YOUR_API_KEY_HERE > .env
    echo [WARNING] Created .env file. Please open it and paste your Gemini API Key!
    pause
    exit /b
)

:: Run Server
python main.py
pause
