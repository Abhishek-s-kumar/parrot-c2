-- C2 Beacon Detection System Schema

-- Table for Zeek connection logs
CREATE TABLE IF NOT EXISTS conn_log (
    id SERIAL PRIMARY KEY,
    ts TIMESTAMP WITH TIME ZONE NOT NULL,
    uid VARCHAR(50),
    id_orig_h INET NOT NULL,
    id_orig_p INTEGER,
    id_resp_h INET NOT NULL,
    id_resp_p INTEGER,
    proto VARCHAR(10),
    service VARCHAR(50),
    duration FLOAT,
    orig_bytes BIGINT,
    resp_bytes BIGINT,
    conn_state VARCHAR(30),
    local_orig BOOLEAN,
    local_resp BOOLEAN,
    imported_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

-- Indexes for performance
CREATE INDEX IF NOT EXISTS idx_conn_log_ts ON conn_log (ts DESC);
CREATE INDEX IF NOT EXISTS idx_conn_log_orig_h ON conn_log (id_orig_h);
CREATE INDEX IF NOT EXISTS idx_conn_log_resp_h ON conn_log (id_resp_h);

-- Table for detection results
CREATE TABLE IF NOT EXISTS detection_results (
    id SERIAL PRIMARY KEY,
    host_ip INET NOT NULL,
    analyzed_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    p_score FLOAT NOT NULL,
    fft_peak FLOAT,
    autocorr_max FLOAT,
    entropy_norm FLOAT,
    sample_count INTEGER,
    detected BOOLEAN DEFAULT FALSE,
    alert_generated BOOLEAN DEFAULT FALSE
);

-- Indexes for detection results
CREATE INDEX IF NOT EXISTS idx_det_results_ip ON detection_results (host_ip);
CREATE INDEX IF NOT EXISTS idx_det_results_ts ON detection_results (analyzed_at DESC);
CREATE INDEX IF NOT EXISTS idx_det_results_detected ON detection_results (detected) WHERE detected = TRUE;
