#!/bin/bash

BASE_DIR="/home/user/Desktop/c2/c2"
LOG_DIR="$BASE_DIR/logs"

echo "=== C2 Detection System Health Check ==="

# 1. Check Zeek Forwarder
if ps -ef | grep -v grep | grep "tail -F /opt/zeek/logs/current/conn.log" > /dev/null; then
    echo "Zeek Forwarder: [OK]"
else
    echo "Zeek Forwarder: [FAILED]"
fi

# 2. Check Importer
if [ -f "$BASE_DIR/.importer.pid" ] && ps -p $(cat "$BASE_DIR/.importer.pid") > /dev/null 2>&1; then
    echo "Zeek Importer: [OK]"
else
    echo "Zeek Importer: [FAILED]"
fi

# 3. Check Monitor
if [ -f "$BASE_DIR/.monitor.pid" ] && ps -p $(cat "$BASE_DIR/.monitor.pid") > /dev/null 2>&1; then
    echo "C2 Monitor: [OK]"
else
    echo "C2 Monitor: [FAILED]"
fi

# 4. Check Dashboard
if [ -f "$BASE_DIR/.dashboard.pid" ] && ps -p $(cat "$BASE_DIR/.dashboard.pid") > /dev/null 2>&1; then
    echo "Dashboard: [OK] (Port 5000)"
else
    echo "Dashboard: [FAILED]"
fi

# 5. Check Database Connectivity
export PGPASSWORD="c2password"
if psql -h 127.0.0.1 -U c2user -d c2db -c "SELECT 1;" > /dev/null 2>&1; then
    echo "Database: [OK]"
else
    echo "Database: [FAILED]"
fi

# 6. Check Analyzer Runtime (from Performance Log)
PERF_LOG="$BASE_DIR/output/performance_metrics.csv"
if [ -f "$PERF_LOG" ]; then
    LAST_RUNTIME=$(tail -n 1 "$PERF_LOG" | cut -d',' -f4)
    if (( $(echo "$LAST_RUNTIME < 2.0" | bc -l) )); then
        echo "Analyzer Runtime: [OK] (${LAST_RUNTIME}s)"
    else
        echo "Analyzer Runtime: [WARNING] (${LAST_RUNTIME}s > 2s)"
    fi
else
    echo "Analyzer Runtime: [UNKNOWN] (No logs found)"
fi

echo "========================================"
