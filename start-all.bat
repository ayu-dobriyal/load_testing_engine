@echo off
title BreakPoint & NSMS Platform Launcher
echo =======================================================
echo   Launching BreakPoint & NSMS Platform
echo =======================================================
echo Starting NSMS Server (Port 4000)...
start "NSMS Server (Port 4000)" cmd /k "cd /d ""%~dp0nsms"" && node src/app.js"

echo Starting Break Point Server (Port 3000)...
start "Break Point (Port 3000)" cmd /k "cd /d ""%~dp0breakpoint"" && node server.js"

echo.
echo Both servers launched in background windows:
echo - NSMS Security Dashboard: http://localhost:4000
echo - Break Point Load Engine: http://localhost:3000
echo =======================================================
timeout /t 3 >nul
exit
