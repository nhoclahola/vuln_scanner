@echo off
echo Fixing dependencies for Vulnerability Scanner...
echo.

echo Uninstalling current crewai version...
pip uninstall -y crewai

echo.
echo Installing specific crewai version (0.28.0)...
pip install crewai==0.28.0

echo.
echo Reinstalling all dependencies from requirements.txt...
pip install -r requirements.txt

echo.
echo Done! You can now run the scanner with:
echo python main.py -u "http://testphp.vulnweb.com"
echo.
pause 