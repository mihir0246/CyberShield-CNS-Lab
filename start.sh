#!/usr/bin/env bash
set -e

echo "========================================================"
echo "  CYBERSHIELD: INTEGRATED CNS LABORATORY SYSTEM"
echo "========================================================"
echo ""

if [ ! -d ".venv" ]; then
    echo "[*] Creating virtual environment..."
    python3 -m venv .venv
    echo "[*] Installing dependencies..."
    .venv/bin/pip install --upgrade pip
    .venv/bin/pip install -r requirements.txt
fi

if [ ! -f ".env" ]; then
    cp .env.example .env
fi

echo "[*] Starting CyberShield on http://127.0.0.1:5000/ ..."
.venv/bin/python run.py
