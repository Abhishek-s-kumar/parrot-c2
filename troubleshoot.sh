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
ZEEK_STATUS=$(sudo $ZEEK_DIR/bin/zeekctl status 2>&1)
if echo "$ZEEK_STATUS" | grep -q "crashed"; then
    echo " [!] CRITICAL: Zeek has CRASHED!"
    echo "     Attempting to restart Zeek (zeekctl restart)..."
    sudo $ZEEK_DIR/bin/zeekctl restart
    sleep 2
    # Guard: restore promiscuous mode on enp0s8 in case it dropped
    sudo ip link set enp0s8 promisc on
    echo " [INFO] Promiscuous mode re-enabled on enp0s8."
elif echo "$ZEEK_STATUS" | grep -q "running"; then
    echo " [OK] Zeek is running."
    # Verify promiscuous mode is on (it should be)
    if ip link show enp0s8 | grep -q "PROMISC"; then
        echo " [OK] enp0s8 is in promiscuous mode (capturing all traffic)."
    else
        echo " [!] WARNING: enp0s8 is NOT in promiscuous mode! Re-enabling..."
        sudo ip link set enp0s8 promisc on
    fi
else
    echo " [!] Zeek status unknown:"
    echo "$ZEEK_STATUS"
fi

# 2. Check Zeek Log Updates
echo "[*] Checking Zeek Log Capture..."
CONN_LOG="$ZEEK_DIR/logs/current/conn.log"
if [ ! -f "$CONN_LOG" ]; then
    CONN_LOG="$ZEEK_DIR/spool/zeek/conn.log"
fi

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
    echo " [!] CRITICAL: Zeek conn.log NOT FOUND!"
fi

# 2.5 Check Zeek Log Forwarder (tail -F)
echo "[*] Checking Zeek Log Forwarder..."
FORWARDER_PID_FILE="$c2_DIR/.zeek_forwarder.pid"
LOCAL_CONN_LOG="$c2_DIR/logs/zeek/conn.log"

FORWARDER_RUNNING=false
if [ -f "$FORWARDER_PID_FILE" ]; then
    FPID=$(cat "$FORWARDER_PID_FILE")
    if ps -p $FPID > /dev/null 2>&1; then
        FORWARDER_RUNNING=true
    fi
fi

if [ "$FORWARDER_RUNNING" = true ]; then
    echo " [OK] Forwarder process is running (PID $FPID)."
    # Check if local log is updating alongside the source
    if [ -f "$LOCAL_CONN_LOG" ]; then
        L_SIZE=$(stat -c %s "$LOCAL_CONN_LOG")
        S_SIZE=$(sudo stat -c %s "$CONN_LOG")
        if [ "$L_SIZE" -lt "$S_SIZE" ]; then
             echo " [!] WARNING: Local log ($L_SIZE bytes) is smaller than source ($S_SIZE bytes)."
             echo "     Forwarder may be stuck. Attempting to restart..."
             sudo pkill -f "tail -F $CONN_LOG" || true
             nohup sudo tail -n +1 -F "$CONN_LOG" > "$LOCAL_CONN_LOG" 2>/dev/null &
             echo $! > "$FORWARDER_PID_FILE"
             echo " [INFO] Forwarder restarted and synced."
        else
             echo " [OK] Local log is synced with source."
        fi
    fi
else
    echo " [!] CRITICAL: Zeek Log Forwarder NOT running."
    echo "     Attempting to start forwarder..."
    mkdir -p "$(dirname "$LOCAL_CONN_LOG")"
    nohup sudo tail -n +1 -F "$CONN_LOG" > "$LOCAL_CONN_LOG" 2>/dev/null &
    echo $! > "$FORWARDER_PID_FILE"
    echo " [INFO] Forwarder started."
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

# 6. Check C2 Monitor Process
echo "[*] Checking C2 Monitor..."
if pgrep -f "monitor_c2.py" > /dev/null; then
    echo " [OK] Monitor process running."
else
    echo " [!] CRITICAL: Monitor process NOT running."
fi

# 7. Check Dashboard Status
echo "[*] Checking Dashboard..."
if pgrep -f "dashboard.py" > /dev/null; then
    if curl -s -o /dev/null -w "%{http_code}" http://127.0.0.1:5000/api/status | grep -q "200"; then
        echo " [OK] Dashboard process running and responding on port 5000."
    else
        echo " [!] WARNING: Dashboard process running but NOT RESPONDING on port 5000."
    fi
else
    echo " [!] CRITICAL: Dashboard process NOT running."
fi


# 8. Detection Status — Active Hosts Being Monitored
echo "[*] Checking Live Host Detection..."
# Use the same fallback logic as the Python Detection Engine:
# 1. Prefer orig_l2_addr as the host identity
# 2. Fall back to resp_l2_addr if orig is missing
HOST_COUNT=$(PGPASSWORD=c2password psql -h 127.0.0.1 -U $DB_USER -d $DB_NAME -t -c "SELECT COUNT(DISTINCT COALESCE(orig_l2_addr, resp_l2_addr)) FROM conn_log WHERE ts >= NOW() - INTERVAL '10 minutes';" 2>/dev/null | xargs)
if [ "$HOST_COUNT" -gt 0 ] 2>/dev/null; then
    echo " [OK] $HOST_COUNT active source hosts seen in last 10 minutes:"
    PGPASSWORD=c2password psql -h 127.0.0.1 -U $DB_USER -d $DB_NAME -t -c \
        "SELECT '  -> MAC: ' || COALESCE(orig_l2_addr, resp_l2_addr) || ' (' || COUNT(*) || ' conns)' FROM conn_log WHERE ts >= NOW() - INTERVAL '10 minutes' GROUP BY COALESCE(orig_l2_addr, resp_l2_addr);" 2>/dev/null
    
    # NEW: Diagnose hosts with < 3 connections (below detection threshold)
    LOW_SAMPLE_HOSTS=$(PGPASSWORD=c2password psql -h 127.0.0.1 -U $DB_USER -d $DB_NAME -t -c \
        "SELECT '  -> [!] MAC: ' || COALESCE(orig_l2_addr, resp_l2_addr) || ' has only ' || COUNT(*) || ' conns (Detection Engine needs >= 3 samples to analyze).' FROM conn_log WHERE ts >= NOW() - INTERVAL '10 minutes' GROUP BY COALESCE(orig_l2_addr, resp_l2_addr) HAVING COUNT(*) < 3;" 2>/dev/null)
    
    if [ -n "$LOW_SAMPLE_HOSTS" ] && [ "$LOW_SAMPLE_HOSTS" != " " ]; then
        echo " [!] DIAGNOSIS: Some hosts are active but below the analysis threshold:"
        echo "$LOW_SAMPLE_HOSTS"
    fi
else
    echo " [!] WARNING: No live hosts seen in the last 10 minutes."
    echo "     Zeek may not be capturing traffic on enp0s8, or no traffic is flowing."
fi

DETECTED_HOSTS=$(PGPASSWORD=c2password psql -h 127.0.0.1 -U $DB_USER -d $DB_NAME -t -c "SELECT COUNT(*) FROM detection_results WHERE detected = true AND analyzed_at >= NOW() - INTERVAL '60 minutes';" 2>/dev/null | xargs)
if [ "$DETECTED_HOSTS" -gt 0 ] 2>/dev/null; then
    echo " [OK] $DETECTED_HOSTS beacon detection(s) in the last 60 minutes."
else
    echo " [INFO] No beacon detections in the last 60 minutes — awaiting traffic."
fi

# 9. Detection Engine Diagnostic
echo "[*] Diagnostic: Investigating Low P-Scores..."
HVOL_LOW_SCORE=$(PGPASSWORD=c2password psql -h 127.0.0.1 -U $DB_USER -d $DB_NAME -t -c "SELECT host_ip, p_score, sample_count FROM detection_results WHERE analyzed_at >= NOW() - INTERVAL '60 minutes' AND sample_count > 100 AND p_score < 0.45 ORDER BY analyzed_at DESC LIMIT 5;" 2>/dev/null)

if [ -n "$HVOL_LOW_SCORE" ] && [ "$HVOL_LOW_SCORE" != " " ]; then
    echo " [!] ALERT: Identified hosts with HIGH TRAFFIC but LOW P-SCORE:"
    echo "$HVOL_LOW_SCORE" | while read -r line; do
        IP=$(echo "$line" | awk '{print $1}')
        SCORE=$(echo "$line" | awk '{print $3}')
        SAMPLES=$(echo "$line" | awk '{print $5}')
        echo "  -> IP: $IP (Score: $SCORE, Samples: $SAMPLES)"
        
        # Check for Destination Diversity (Behavioral Dilution)
        DIVERSITY=$(PGPASSWORD=c2password psql -h 127.0.0.1 -U $DB_USER -d $DB_NAME -t -c "SELECT COUNT(DISTINCT id_resp_h) FROM conn_log WHERE id_orig_h = '$IP' AND ts >= NOW() - INTERVAL '60 minutes';" 2>/dev/null | xargs)
        if [ "$DIVERSITY" -gt 5 ]; then
            echo "     [DIAGNOSIS] Behavioral Noise: Host talks to $DIVERSITY distinct IPs. Legitimate traffic and background noise are masking the beacon."
            echo "     [INFO] The system uses 'Periodicity Priority' to help, but high noise still reduces confidence."
        fi
        
        # Check for Aliasing / Spectral Jitter (Verify if the recommendation was applied)
        WINDOW=$(grep "window_high_rate" $c2_DIR/config/detection_weights.ini | cut -d'=' -f2 | xargs)
        if [ "$SAMPLES" -gt 300 ]; then
            if (( $(echo "$WINDOW > 2.0" | bc -l) )); then
                echo "     [DIAGNOSIS] Aliasing: FFT resolution is insufficient for fast beacons (Current Window: ${WINDOW}s)."
                echo "     [ACTION] CRITICAL: Reduce 'window_high_rate' to 2.0 in config/detection_weights.ini"
            else
                echo "     [DIAGNOSIS] Spectral Jitter/Leakage: 2s resolution active but score remains low. Fast beacons (e.g. 3.2s) mismatch buckets."
                echo "     [INFO] Hybrid logic implemented in Detection Engine will now fallback to Autocorrelation for better intervals."
            fi
        fi
    done
else
    echo " [OK] No high-volume hosts with suspicious low scores found."
fi

echo "--------------------------------------"
echo "Troubleshooting Complete."
