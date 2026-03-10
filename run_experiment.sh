#!/bin/bash

# Phase 2: Automated Multi-Scenario Experiment Pipeline
# This script runs the full C2 beacon detection lifecycle across multiple datasets

BASE_DIR="/home/user/Desktop/c2/c2"
VENV_PYTHON="${BASE_DIR}/venv/bin/python3"
METADATA_FILE="${BASE_DIR}/output/experiment_metadata.json"

# Non-interactive database credentials
export PGPASSWORD="c2password"
export PGHOST="127.0.0.1"
export PGUSER="c2user"
export PGDATABASE="c2db"

# Auto-discover all scenario directories in datasets/iot23/ safely
SCENARIOS=($(find "${BASE_DIR}/datasets/iot23" -maxdepth 1 -type d -name "scenario_*" -printf "%f\n" | sort))
TIMESTAMP=$(date -u +"%Y-%m-%dT%H:%M:%SZ")

echo "=== C2 Detection Experiment Starting: ${TIMESTAMP} ==="
echo "Found ${#SCENARIOS[@]} scenarios."

# Initialize metadata
echo "{\"experiment_timestamp\": \"${TIMESTAMP}\", \"scenarios\": {}}" > ${METADATA_FILE}

echo "[*] Checking available scenarios..."
AVAILABLE_SCENARIOS=()
for SCENARIO in "${SCENARIOS[@]}"; do
    LOG_FILE="${BASE_DIR}/datasets/iot23/${SCENARIO}/conn.log.labeled"
    if [ -f "${LOG_FILE}" ] || [ -f "${LOG_FILE}.gz" ]; then
        AVAILABLE_SCENARIOS+=("${SCENARIO}")
    else
        echo " [!] Note: ${SCENARIO} dataset not found. Skipping."
    fi
done

if [ ${#AVAILABLE_SCENARIOS[@]} -eq 0 ]; then
    echo " [!] Error: No scenarios found to process. Exiting."
    exit 1
fi

for SCENARIO in "${AVAILABLE_SCENARIOS[@]}"; do
    echo "=== Processing Scenario: ${SCENARIO} ==="

    # Define the log file path (prioritize slim, then gz, then raw)
    LOG_FILE="${BASE_DIR}/datasets/iot23/${SCENARIO}/conn.log.labeled.slim"
    if [ ! -f "${LOG_FILE}" ]; then
        LOG_FILE="${BASE_DIR}/datasets/iot23/${SCENARIO}/conn.log.labeled.gz"
        if [ ! -f "${LOG_FILE}" ]; then
            LOG_FILE="${BASE_DIR}/datasets/iot23/${SCENARIO}/conn.log.labeled"
        fi
    fi

    echo "--- [0/5] Cleaning database ---"
    psql -w -X -c "
        TRUNCATE ground_truth; 
        TRUNCATE conn_log;
        ALTER TABLE detection_results ADD COLUMN IF NOT EXISTS scenario VARCHAR(50);
    " > /dev/null

    echo "--- [1/5] Ingesting Dataset ---"
    ${VENV_PYTHON} ${BASE_DIR}/scripts/load_labeled_dataset.py "${LOG_FILE}" --recent > /dev/null

    echo "--- [2/5] Running Detection Analysis ---"
    # Use real_time_analyzer.py via python so we can capture output if needed
    # Use a large window (1 week) to ensure we catch dataset scenarios with skews
    ${VENV_PYTHON} ${BASE_DIR}/scripts/real_time_analyzer.py --window 10080 > /dev/null
    
    # Tag the newly generated results with the current scenario name
    psql -w -c "UPDATE detection_results SET scenario = '${SCENARIO}' WHERE scenario IS NULL;" > /dev/null

    echo "--- [3/5] Evaluating Results ---"
    # Capture evaluation metrics
    ${VENV_PYTHON} ${BASE_DIR}/scripts/evaluation.py "${SCENARIO}"
    
    echo "--- [4/5] Generating Visualizations ---"
    HOST_IP=$(psql -w -t -c "SELECT host_ip FROM detection_results ORDER BY p_score DESC LIMIT 1;" | xargs)
    if [ ! -z "$HOST_IP" ]; then
        ${VENV_PYTHON} ${BASE_DIR}/scripts/plot_analysis.py --host ${HOST_IP} > /dev/null
    fi

    echo "--- [5/5] Cross-Host Correlation ---"
    ${VENV_PYTHON} ${BASE_DIR}/scripts/cross_host_correlation.py > /dev/null

    # Log completion for this scenario
    echo "Scenario ${SCENARIO} complete."
done

echo "=== Experiment Pipeline Complete ==="
echo "Metadata saved in: ${METADATA_FILE}"
