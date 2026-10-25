@echo off
title Break Point Server (Port 3000)
cd /d "%~dp0breakpoint"
echo Starting Break Point Load Testing Server on Port 3000...
node server.js
pause
