@echo off
cd /d "%~dp0"
start "GL Electromechanic" http://127.0.0.1:3015
node server.js
