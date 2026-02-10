#!/bin/bash

BASE_DIR="/home/user/Desktop/c2/c2"

echo "Stopping C2 Beacon Detection System..."

# Stop Dashboard
if [ -f "$BASE_DIR/.dashboard.pid" ]; then
    PID=$(cat "$BASE_DIR/.dashboard.pid")
    echo "Stopping Dashboard (PID $PID)..."
    kill $PID && rm "$BASE_DIR/.dashboard.pid"
fi

# Stop Monitor
if [ -f "$BASE_DIR/.monitor.pid" ]; then
    PID=$(cat "$BASE_DIR/.monitor.pid")
    echo "Stopping Monitor (PID $PID)..."
    kill $PID && rm "$BASE_DIR/.monitor.pid"
fi

# Stop Importer
if [ -f "$BASE_DIR/.importer.pid" ]; then
    PID=$(cat "$BASE_DIR/.importer.pid")
    echo "Stopping Importer (PID $PID)..."
    kill $PID && rm "$BASE_DIR/.importer.pid"
fi

echo "System stopped."
