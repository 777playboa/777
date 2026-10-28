if "%~1"=="" (
  echo Usage: get-hash.bat ^<filename or path^>
  echo   Example: get-hash.bat "client\build\libs\balright.jar"
  echo   Prints the whole-file SHA-256 of the jar for registration on the auth server.
  exit /b 1
)
if not exist "%~1" (
  echo ERROR: jar not found: "%~1"
  exit /b 1
)
powershell.exe -NoProfile -ExecutionPolicy Bypass -File "%~dp0get-hash.ps1" -JarPath "%~1"
exit /b %errorlevel%