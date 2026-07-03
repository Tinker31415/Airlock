@echo off
REM Subproject access. Examples:
REM   scripts\release.bat list "BLR - open data mining"
REM   scripts\release.bat fetch "BLR - open data mining" --dest .\_inbox --keep-name
cd /d "%~dp0.."
call .venv\Scripts\activate.bat
python -m airlock.release %*
