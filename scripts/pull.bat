@echo off
REM Fetch cleared files for a subproject. Examples:
REM   scripts\pull.bat pull-new "BLR - open data mining" --dest .\data
REM   scripts\pull.bat list "BLR - open data mining"
cd /d "%~dp0.."
call .venv\Scripts\activate.bat
python -m airlock %*
