@echo off
REM Initialise the repo and push to GitHub. Run from the project root.
cd /d "%~dp0.."
if exist ".git" (
  echo Removing stale .git created during setup...
  rmdir /s /q ".git"
)
git init
git add -A
git commit -m "Airlock v1.0.0"
git branch -M main
set /p URL="Paste your empty GitHub repo URL (https://github.com/you/airlock.git): "
git remote add origin %URL%
git push -u origin main
pause
