@echo off
title NSMS Server (Port 4000)
cd /d "%~dp0nsms"
echo Starting NSMS Security Server on Port 4000...
node src/app.js
pause
