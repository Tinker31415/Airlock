@echo off
REM Review console. Examples:
REM   scripts\review.bat list
REM   scripts\review.bat approve <file_id>
REM   scripts\review.bat delete <file_id>
cd /d "%~dp0.."
call .venv\Scripts\activate.bat
python -m airlock.review %*
