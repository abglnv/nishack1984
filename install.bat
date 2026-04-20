@echo off
REM ===== NisHack Agent Installer (standalone bootstrap) =====
REM Tries winget first, falls back to direct downloads from GitHub
REM / rust-lang.org if winget is unavailable or fails (e.g.
REM "InternetOpenUrl() Failed" on restricted networks).

title NisHack Agent Installer

REM --- must be Administrator ---
net session >nul 2>&1
if errorlevel 1 (
    echo.
    echo This installer must be run as Administrator.
    echo Right-click install.bat and choose "Run as administrator".
    echo.
    pause
    exit /b 1
)

set "REPO_URL=https://github.com/abglnv/nishack1984"
set "ROOT=%ProgramData%\NisHack"
set "INSTALL_DIR=%ROOT%\nishack1984"
set "CARGO_BIN=%USERPROFILE%\.cargo\bin"

echo.
echo === NisHack Agent Installer ===
echo Repo:        %REPO_URL%
echo Install dir: %INSTALL_DIR%
echo.

call :ensure_git
if errorlevel 1 (pause & exit /b 1)

call :ensure_rust
if errorlevel 1 (pause & exit /b 1)

REM --- Clone or update source ---
echo.
echo [3/7] Fetching source code...
if not exist "%ROOT%" mkdir "%ROOT%"
if exist "%INSTALL_DIR%\.git" (
    echo Repo already present, pulling latest...
    pushd "%INSTALL_DIR%"
    git pull --ff-only
    popd
) else (
    git clone "%REPO_URL%" "%INSTALL_DIR%"
    if errorlevel 1 (echo git clone failed. & pause & exit /b 1)
)
if not exist "%INSTALL_DIR%\Cargo.toml" (
    echo Cargo.toml missing in "%INSTALL_DIR%" after clone.
    pause & exit /b 1
)

REM --- Redis URI prompt ---
echo.
echo [4/7] Redis configuration
echo Example: redis://default:password@my-redis.upstash.io:6379
echo (paste WITHOUT surrounding quotes)
set "REDIS_URI="
set /p REDIS_URI=Enter Redis URI:
if defined REDIS_URI set REDIS_URI=%REDIS_URI:"=%
if "%REDIS_URI%"=="" (echo Redis URI cannot be empty. & pause & exit /b 1)

powershell -NoProfile -ExecutionPolicy Bypass -Command ^
  "$uri = $env:REDIS_URI;" ^
  "$path = Join-Path $env:INSTALL_DIR 'config.toml';" ^
  "$c = Get-Content -Raw $path;" ^
  "$c = [regex]::Replace($c, '(?m)^url\s*=\s*\"[^\"]*\"', ('url = \"' + $uri + '\"'));" ^
  "Set-Content -NoNewline -Path $path -Value $c"
if errorlevel 1 (echo Failed to update config.toml. & pause & exit /b 1)
echo Redis URI written to config.toml.

REM --- Build ---
echo.
echo [5/7] Building release binary (this can take several minutes)...
pushd "%INSTALL_DIR%"
cargo build --release
if errorlevel 1 (echo Build failed. & popd & pause & exit /b 1)
popd
if not exist "%INSTALL_DIR%\target\release\nishack.exe" (
    echo nishack.exe not found after build.
    pause & exit /b 1
)
if not exist "%INSTALL_DIR%\run.bat" (
    echo run.bat is missing from the repo. Commit and push run.bat to %REPO_URL% and re-run.
    pause & exit /b 1
)

REM --- Scheduled task ---
echo.
echo [6/7] Registering auto-start scheduled task...
schtasks /Delete /TN "NisHack Agent" /F >nul 2>&1
schtasks /Create /F ^
    /TN "NisHack Agent" ^
    /TR "\"%INSTALL_DIR%\run.bat\"" ^
    /SC ONLOGON ^
    /RL HIGHEST
if errorlevel 1 (echo Scheduled task registration failed. & pause & exit /b 1)

REM --- Start now ---
echo.
echo [7/7] Starting NisHack now in a background window...
start "NisHack Agent" /MIN cmd /c "\"%INSTALL_DIR%\run.bat\""

echo.
echo === Install complete ===
echo Installed at:    %INSTALL_DIR%
echo Auto-start:      on every user logon (Task Scheduler: "NisHack Agent")
echo Auto-restart:    yes (run.bat loop)
echo.
echo To stop:         schtasks /End /TN "NisHack Agent"
echo To uninstall:    schtasks /Delete /TN "NisHack Agent" /F
echo                  rmdir /S /Q "%INSTALL_DIR%"
echo.
pause
goto :eof


REM =================================================================
REM  Subroutines
REM =================================================================

:ensure_git
where git >nul 2>&1 && exit /b 0
echo [1/7] Installing Git...

where winget >nul 2>&1
if not errorlevel 1 (
    winget install --id Git.Git -e --silent --accept-source-agreements --accept-package-agreements 2>nul
    if exist "C:\Program Files\Git\cmd\git.exe" set "PATH=C:\Program Files\Git\cmd;%PATH%"
    where git >nul 2>&1 && exit /b 0
    echo winget install of Git failed, falling back to direct download...
) else (
    echo winget not available, downloading Git directly...
)

set "GIT_EXE=%TEMP%\git-installer.exe"
del /f /q "%GIT_EXE%" 2>nul
powershell -NoProfile -ExecutionPolicy Bypass -Command ^
  "[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12;" ^
  "try { $r = Invoke-RestMethod -UseBasicParsing 'https://api.github.com/repos/git-for-windows/git/releases/latest';" ^
  "      $a = $r.assets ^| Where-Object { $_.name -match 'Git-.*-64-bit\.exe$' } ^| Select-Object -First 1;" ^
  "      Invoke-WebRequest -UseBasicParsing -Uri $a.browser_download_url -OutFile $env:GIT_EXE }" ^
  "catch { Write-Host $_.Exception.Message; exit 1 }"
if not exist "%GIT_EXE%" (echo Failed to download Git installer. & exit /b 1)
echo Running Git installer silently...
"%GIT_EXE%" /VERYSILENT /NORESTART /NOCANCEL /SUPPRESSMSGBOXES
del /f /q "%GIT_EXE%" 2>nul
if exist "C:\Program Files\Git\cmd\git.exe" set "PATH=C:\Program Files\Git\cmd;%PATH%"
where git >nul 2>&1 && exit /b 0
echo Git installation failed.
exit /b 1


:ensure_rust
set "PATH=%CARGO_BIN%;%PATH%"
where cargo >nul 2>&1
if not errorlevel 1 goto :rust_toolchain
echo [2/7] Installing Rust...

where winget >nul 2>&1
if not errorlevel 1 (
    winget install --id Rustlang.Rustup -e --silent --accept-source-agreements --accept-package-agreements 2>nul
    set "PATH=%CARGO_BIN%;%PATH%"
    where cargo >nul 2>&1
    if not errorlevel 1 goto :rust_toolchain
    echo winget install of Rust failed, falling back to direct download...
) else (
    echo winget not available, downloading rustup-init directly...
)

set "RUSTUP_EXE=%TEMP%\rustup-init.exe"
del /f /q "%RUSTUP_EXE%" 2>nul
powershell -NoProfile -ExecutionPolicy Bypass -Command ^
  "[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12;" ^
  "try { Invoke-WebRequest -UseBasicParsing -Uri 'https://win.rustup.rs/x86_64' -OutFile $env:RUSTUP_EXE }" ^
  "catch { Write-Host $_.Exception.Message; exit 1 }"
if not exist "%RUSTUP_EXE%" (echo Failed to download rustup-init.exe. & exit /b 1)
"%RUSTUP_EXE%" -y --profile minimal --default-toolchain stable-x86_64-pc-windows-gnu --default-host x86_64-pc-windows-gnu
del /f /q "%RUSTUP_EXE%" 2>nul
set "PATH=%CARGO_BIN%;%PATH%"

:rust_toolchain
"%CARGO_BIN%\rustup.exe" toolchain install stable-x86_64-pc-windows-gnu
"%CARGO_BIN%\rustup.exe" default stable-x86_64-pc-windows-gnu
if errorlevel 1 (echo Rust toolchain setup failed. & exit /b 1)
exit /b 0
