@echo off
cd /d "%~dp0"
echo Starting 777Client Auth Server on port 8000...
node auth-server.js
pause
