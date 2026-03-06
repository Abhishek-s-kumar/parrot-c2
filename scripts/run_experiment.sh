#!/bin/bash

# Task 9.1: Build Automated Experiment Pipeline
# This script runs the full C2 beacon detection lifecycle

BASE_DIR="/home/user/Desktop/c2/c2"
VENV_PYTHON="${BASE_DIR}/venv/bin/python3"

echo "=== [1/5] Starting Monitoring System ==="
sudo ${BASE_DIR}/start_c2_system.sh
sleep 5

echo "=== [2/5] Ingesting Labeled Dataset ==="
${VENV_PYTHON} ${BASE_DIR}/scripts/load_labeled_dataset.py ${BASE_DIR}/datasets/iot23/sample_scenario/conn.log.labeled --recent

echo "=== [3/5] Running Detection Engine analysis ==="
time ${VENV_PYTHON} ${BASE_DIR}/scripts/real_time_analyzer.py

echo "=== [4/5] Evaluating Results against Ground Truth ==="
${VENV_PYTHON} ${BASE_DIR}/scripts/evaluation.py

echo "=== [5/5] Generating Analysis Visualizations ==="
# We assume there is at least one host in the results to plot
HOST_IP=$(export PGPASSWORD="c2password" && psql -h 127.0.0.1 -U c2user -d c2db -t -c "SELECT host_ip FROM detection_results ORDER BY p_score DESC LIMIT 1;" | xargs)
if [ ! -z "$HOST_IP" ]; then
    echo "Plotting results for most significant host: ${HOST_IP}"
    ${VENV_PYTHON} ${BASE_DIR}/scripts/plot_analysis.py --host ${HOST_IP}
else
    echo "No detection results found to plot."
fi

# Run cross-host correlation if multiple hosts exist
${VENV_PYTHON} ${BASE_DIR}/scripts/cross_host_correlation.py

echo "=== Experiment Pipeline Complete ==="
echo "Artifacts saved in: ${BASE_DIR}/output/graphs/"
