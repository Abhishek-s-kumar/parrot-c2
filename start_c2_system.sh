#!/bin/bash

# Configuration
BASE_DIR="/home/user/Desktop/c2/c2"
VENV_DIR="$BASE_DIR/venv"
LOG_DIR="$BASE_DIR/logs"
SCRIPTS_DIR="$BASE_DIR/scripts"

echo "Starting C2 Beacon Detection System..."

# Check if port 5000 is in use
if lsof -i :5000 > /dev/null 2>&1; then
    echo "WARNING: Port 5000 is already in use. Attempting to stop existing dashboard..."
    fuser -k 5000/tcp > /dev/null 2>&1
    sleep 1
fi

# Start Zeek Log Forwarder (Sudo required for /opt access)
echo "Starting Zeek Log Forwarder..."
# Ensure the local log directory exists
mkdir -p "$BASE_DIR/logs/zeek"
# Kill existing tail process if any
sudo pkill -f "tail -F /opt/zeek/logs/current/conn.log" || true
# Start the forwarder in background
nohup sudo tail -F /opt/zeek/logs/current/conn.log > "$BASE_DIR/logs/zeek/conn.log" 2>/dev/null &
echo $! > "$BASE_DIR/.zeek_forwarder.pid"

# Activate virtual environment
source "$VENV_DIR/bin/activate"

# Start Zeek Log Importer
if [ -f "$BASE_DIR/.importer.pid" ] && ps -p $(cat "$BASE_DIR/.importer.pid") > /dev/null 2>&1; then
    echo "Zeek Log Importer is already running."
else
    echo "Starting Zeek Log Importer..."
    nohup "$VENV_DIR/bin/python3" "$SCRIPTS_DIR/zeek_importer.py" > "$LOG_DIR/importer_out.log" 2>&1 &
    echo $! > "$BASE_DIR/.importer.pid"
fi

# Start Monitor Service
if [ -f "$BASE_DIR/.monitor.pid" ] && ps -p $(cat "$BASE_DIR/.monitor.pid") > /dev/null 2>&1; then
    echo "C2 Monitor Service is already running."
else
    echo "Starting C2 Monitor Service..."
    nohup "$VENV_DIR/bin/python3" "$SCRIPTS_DIR/monitor_c2.py" > "$LOG_DIR/monitor_out.log" 2>&1 &
    echo $! > "$BASE_DIR/.monitor.pid"
fi

# Start Flask Dashboard
if [ -f "$BASE_DIR/.dashboard.pid" ] && ps -p $(cat "$BASE_DIR/.dashboard.pid") > /dev/null 2>&1; then
    echo "Flask Dashboard is already running."
else
    echo "Starting Flask Dashboard (Port 5000)..."
    # Double check port 5000 one last time
    if lsof -i :5000 > /dev/null 2>&1; then
        echo "Port 5000 still in use. Force clearing..."
        sudo fuser -k 5000/tcp > /dev/null 2>&1
        sleep 2
    fi
    nohup "$VENV_DIR/bin/python3" "$SCRIPTS_DIR/dashboard.py" > "$LOG_DIR/dashboard_out.log" 2>&1 &
    echo $! > "$BASE_DIR/.dashboard.pid"
fi

echo "System check complete."
echo "Use ./status_check.sh to verify services."

