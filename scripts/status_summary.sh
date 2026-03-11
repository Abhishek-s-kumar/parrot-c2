#!/bin/bash

export PGPASSWORD="c2password"

echo "---- Pipeline Status ----"

psql -h 127.0.0.1 -U c2user -d c2db -c "
SELECT COUNT(*) AS total_flows FROM conn_log;
"

psql -h 127.0.0.1 -U c2user -d c2db -c "
SELECT COUNT(*) AS detections FROM detection_results;
"

psql -h 127.0.0.1 -U c2user -d c2db -c "
SELECT scenario, MAX(p_score)
FROM detection_results
GROUP BY scenario
ORDER BY scenario;
"
