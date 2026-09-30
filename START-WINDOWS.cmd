@echo off
cd /d "%~dp0"
where node >nul 2>&1
if errorlevel 1 (
  echo Node.js 22 or newer is required. See README.md.
  pause
  exit /b 1
)
if not exist node_modules (
  call npm ci
  if errorlevel 1 (
    echo Dependency installation failed. See README.md.
    pause
    exit /b 1
  )
)
start "" http://127.0.0.1:4173/
call npm start
pause
