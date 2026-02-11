#!/bin/bash

BASE_DIR="/home/user/Desktop/c2/c2"

echo "--- C2 System Status ---"

# Check Importer
if [ -f "$BASE_DIR/.importer.pid" ]; then
    PID=$(cat "$BASE_DIR/.importer.pid")
    if ps -p $PID > /dev/null; then
        echo "[RUNNING] Zeek Log Importer (PID $PID)"
    else
        echo "[FAILED ] Zeek Log Importer (PID $PID - not responding)"
    fi
else
    echo "[STOPPED] Zeek Log Importer"
fi

# Check Monitor
if [ -f "$BASE_DIR/.monitor.pid" ]; then
    PID=$(cat "$BASE_DIR/.monitor.pid")
    if ps -p $PID > /dev/null; then
        echo "[RUNNING] C2 Monitor Service (PID $PID)"
    else
        echo "[FAILED ] C2 Monitor Service (PID $PID - not responding)"
    fi
else
    echo "[STOPPED] C2 Monitor Service"
fi

# Check Dashboard
if [ -f "$BASE_DIR/.dashboard.pid" ]; then
    PID=$(cat "$BASE_DIR/.dashboard.pid")
    if ps -p $PID > /dev/null; then
        if netstat -tuln | grep -q ":5000 "; then
            echo "[RUNNING] Flask Dashboard (PID $PID)"
        else
            echo "[STARTING] Flask Dashboard (PID $PID - waiting for port 5000)"
        fi
    else
        echo "[FAILED ] Flask Dashboard (PID $PID - not responding)"
    fi
else
    echo "[STOPPED] Flask Dashboard"
fi

echo "------------------------"
