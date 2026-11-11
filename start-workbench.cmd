@echo off
setlocal
cd /d "%~dp0" || exit /b 2

if not exist ".venv\Scripts\codesentry.exe" (
    echo CodeSentry virtual environment is missing. See README.md.
    exit /b 2
)
if not exist ".env" (
    echo Create .env from .env.example and configure DEEPSEEK_API_KEY locally.
    exit /b 2
)

rem Only this launcher and its child use the file key. System settings stay unchanged.
set "DEEPSEEK_API_KEY="
".venv\Scripts\codesentry.exe" serve --host 127.0.0.1 --port 8765 --env-file ".env" --data-dir ".venv\workbench-data" --frontend-dir "frontend\dist"
set "CODESENTRY_EXIT_CODE=%ERRORLEVEL%"
exit /b %CODESENTRY_EXIT_CODE%
