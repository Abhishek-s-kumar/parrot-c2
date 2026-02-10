#!/bin/bash

# Configuration
BASE_DIR="/home/user/Desktop/c2/c2"
VENV_DIR="$BASE_DIR/venv"
LOG_DIR="$BASE_DIR/logs"
SCRIPTS_DIR="$BASE_DIR/scripts"

echo "Starting C2 Beacon Detection System..."

# Activate virtual environment
source "$VENV_DIR/bin/activate"

# Start Zeek Log Importer
echo "Starting Zeek Log Importer..."
nohup python3 "$SCRIPTS_DIR/zeek_importer.py" > "$LOG_DIR/importer_out.log" 2>&1 &
echo $! > "$BASE_DIR/.importer.pid"

# Start Monitor Service
echo "Starting C2 Monitor Service..."
nohup python3 "$SCRIPTS_DIR/monitor_c2.py" > "$LOG_DIR/monitor_out.log" 2>&1 &
echo $! > "$BASE_DIR/.monitor.pid"

# Start Flask Dashboard
echo "Starting Flask Dashboard (Port 5000)..."
nohup python3 "$SCRIPTS_DIR/dashboard.py" > "$LOG_DIR/dashboard_out.log" 2>&1 &
echo $! > "$BASE_DIR/.dashboard.pid"

echo "System started successfully."
echo "Use ./status_check.sh to verify services."
