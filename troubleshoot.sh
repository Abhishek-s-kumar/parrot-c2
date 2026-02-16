#!/bin/bash

# Configuration
c2_DIR="/home/user/Desktop/c2/c2"
ZEEK_DIR="/opt/zeek"
DB_NAME="c2db"
DB_USER="c2user"

echo "=== C2 System Troubleshooting Tool ==="
echo "Time: $(date)"
echo "--------------------------------------"

# 1. Check Zeek Status
echo "[*] Checking Zeek Status..."
if sudo $ZEEK_DIR/bin/zeekctl status | grep -q "crashed"; then
    echo " [!] CRITICAL: Zeek has CRASHED!"
    echo "     Attempting to restart Zeek..."
    sudo $ZEEK_DIR/bin/zeekctl deploy
else
    echo " [OK] Zeek seems to be running."
fi

# 2. Check Zeek Log Updates
echo "[*] Checking Zeek Log Capture..."
CONN_LOG="$ZEEK_DIR/spool/zeek/conn.log"
if sudo test -f "$CONN_LOG"; then
    LAST_MOD=$(sudo stat -c %Y "$CONN_LOG")
    CURR_TIME=$(date +%s)
    DIFF=$((CURR_TIME - LAST_MOD))
    if [ $DIFF -gt 60 ]; then
        echo " [!] WARNING: Zeek conn.log hasn't updated in $DIFF seconds."
    else
        echo " [OK] Zeek conn.log is updating (Last update: $DIFF seconds ago)."
    fi
else
    echo " [!] CRITICAL: Zeek conn.log NOT FOUND in spool directory!"
fi

# 3. Check Database Connectivity
echo "[*] Checking Database Connectivity..."
if PGPASSWORD=c2password psql -h 127.0.0.1 -U $DB_USER -d $DB_NAME -c "SELECT 1;" > /dev/null 2>&1; then
    echo " [OK] Database connection successful."
else
    echo " [!] CRITICAL: Cannot connect to Database!"
    echo "     Check PostgreSQL status: sudo systemctl status postgresql"
fi

# 4. Check Data Ingestion Lag
echo "[*] Checking Data Ingestion Lag..."
LAST_DB_TS=$(PGPASSWORD=c2password psql -h 127.0.0.1 -U $DB_USER -d $DB_NAME -t -c "SELECT MAX(ts) FROM conn_log;" | xargs)
if [ "$LAST_DB_TS" == "" ]; then
    echo " [!] WARNING: No data in database!"
else
    echo " [INFO] Last DB Entry: $LAST_DB_TS"
    # Simple check if date matches today
    TODAY=$(date +%Y-%m-%d)
    if [[ "$LAST_DB_TS" == *"$TODAY"* ]]; then
        echo " [OK] Data for today found in DB."
    else
        echo " [!] WARNING: No data for today ($TODAY) in DB!"
    fi
fi

# 5. Check Log Importer Process
echo "[*] Checking Log Importer..."
if pgrep -f "zeek_importer.py" > /dev/null; then
    echo " [OK] Importer process running."
else
    echo " [!] CRITICAL: Importer process NOT running."
fi

echo "--------------------------------------"
echo "Troubleshooting Complete."
