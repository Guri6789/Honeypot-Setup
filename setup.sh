#!/bin/bash
# HoneyBank Setup Script for Kali Linux
# Run this ONCE to set up the virtual environment

set -e

PROJECT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
VENV_DIR="$PROJECT_DIR/venv"

echo "================================================="
echo "  🍯 HoneyBank — Setup"
echo "================================================="
echo "  Project: $PROJECT_DIR"

# Step 1: Create data directories with correct permissions
echo ""
echo "[1/3] Creating data directories..."
mkdir -p "$PROJECT_DIR/data/logs"
mkdir -p "$PROJECT_DIR/data/payloads"
chmod -R 755 "$PROJECT_DIR/data"
echo "  ✅ data/ directories created"

# Step 2: Create virtual environment
echo ""
echo "[2/3] Creating Python virtual environment..."
python3 -m venv "$VENV_DIR"
echo "  ✅ venv created at $VENV_DIR"

# Step 3: Install requirements inside venv
echo ""
echo "[3/3] Installing dependencies..."
"$VENV_DIR/bin/pip" install --upgrade pip -q
"$VENV_DIR/bin/pip" install -r "$PROJECT_DIR/requirements.txt"
echo "  ✅ Dependencies installed"

echo ""
echo "================================================="
echo "  ✅ Setup complete!"
echo ""
echo "  To run the honeypot:"
echo "    ./run.sh"
echo "================================================="
