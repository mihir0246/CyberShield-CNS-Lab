@echo off
title CyberShield Laboratory Server
echo ========================================================
echo   CYBERSHIELD: INTEGRATED CNS LABORATORY SYSTEM
echo ========================================================
echo.

IF NOT EXIST ".venv" (
    echo [*] Creating virtual environment...
    python -m venv .venv
    echo [*] Installing dependencies...
    call .venv\Scripts\pip install -r requirements.txt
)

IF NOT EXIST ".env" (
    copy .env.example .env
)

echo [*] Starting CyberShield on http://127.0.0.1:5000/ ...
call .venv\Scripts\python run.py
pause
