@echo off
REM ===== NisHack Agent Runner =====
REM Runs nishack.exe in an infinite restart loop so the agent comes back
REM whenever it exits or crashes. Scheduled to auto-start at login by
REM install.bat; can also be launched manually by double-clicking.

title NisHack Agent
setlocal

set "BASE=%~dp0"
if "%BASE:~-1%"=="\" set "BASE=%BASE:~0,-1%"
set "BIN=%BASE%\target\release\nishack.exe"
set "LOGDIR=%BASE%\logs"

if not exist "%BIN%" (
    echo nishack.exe not found at "%BIN%".
    echo Run install.bat first.
    pause
    exit /b 1
)

if not exist "%LOGDIR%" mkdir "%LOGDIR%"

cd /d "%BASE%"

:loop
echo [%date% %time%] Starting nishack.exe >> "%LOGDIR%\run.log"
"%BIN%" >> "%LOGDIR%\agent.log" 2>&1
set "RC=%ERRORLEVEL%"
echo [%date% %time%] nishack.exe exited (code %RC%). Restarting in 5s... >> "%LOGDIR%\run.log"
timeout /t 5 /nobreak >nul
goto loop
