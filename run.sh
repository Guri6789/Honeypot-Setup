#!/bin/bash
# HoneyBank Run Script
# Activates venv and starts the honeypot

PROJECT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
VENV_DIR="$PROJECT_DIR/venv"

if [ ! -d "$VENV_DIR" ]; then
    echo "❌ Virtual environment not found. Run setup first:"
    echo "   bash setup.sh"
    exit 1
fi

echo "🍯 Starting HoneyBank..."
cd "$PROJECT_DIR"
"$VENV_DIR/bin/python" main.py
