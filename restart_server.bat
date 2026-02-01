@echo off
cd backend
echo Activating virtual environment...
call venv\Scripts\activate.bat

echo.
echo ==========================================
echo RUNNING DIAGNOSTICS...
echo ==========================================
python debug_key.py
echo.
echo If you saw a SUCCESS message above, the server will work.
echo If you saw FAILURE, please check the error message.
echo.
pause

echo.
echo ==========================================
echo STARTING SERVER...
echo ==========================================
python main.py
pause
