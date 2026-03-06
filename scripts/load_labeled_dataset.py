import pandas as pd
import psycopg2
import configparser
from datetime import datetime, timezone
import logging
import sys
import os

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

def load_config(config_path):
    config = configparser.ConfigParser()
    config.read(config_path)
    return dict(config['database'])

def connect_db(db_config):
    try:
        params = db_config.copy()
        if 'name' in params:
            params['dbname'] = params.pop('name')
        return psycopg2.connect(**params)
    except Exception as e:
        logging.error(f"Database connection failed: {e}")
        return None

def map_label(label_str):
    """Maps IoT-23 labels to 0 (benign) or 1 (malicious)."""
    label_str = label_str.lower()
    if 'benign' in label_str:
        return 0
    if 'c&c' in label_str or 'malicious' in label_str or 'attack' in label_str or 'part of horizontal port scan' in label_str:
        return 1
    return 0 # Default to benign if unknown

def ingest_labeled_log(file_path, db_config):
    conn = connect_db(db_config)
    if not conn:
        return

    cursor = conn.cursor()
    try:
        logging.info(f"Starting ingestion of {file_path}")
        
        # Calculate timestamp offset if needed (to make it 'recent')
        offset = 0
        if "--recent" in sys.argv:
            with open(file_path, 'r') as f:
                for line in f:
                    if not line.startswith('#'):
                        parts = line.strip().split('\t')
                        if len(parts) > 0:
                            last_ts = float(parts[0])
                            offset = datetime.now(timezone.utc).timestamp() - last_ts
                            break
            logging.info(f"Shifting timestamps by {offset} seconds to make them recent.")

        # Read the file line by line to handle large files
        with open(file_path, 'r') as f:
            count = 0
            batch_conn = []
            batch_gt = []
            
            for line in f:
                if line.startswith('#'):
                    continue
                
                parts = line.strip().split('\t')
                if len(parts) < 21:
                    continue
                
                try:
                    ts_epoch = float(parts[0]) + offset
                    ts_dt = datetime.fromtimestamp(ts_epoch, tz=timezone.utc)
                    
                    uid = parts[1]
                    orig_h = parts[2]
                    orig_p = int(parts[3])
                    resp_h = parts[4]
                    resp_p = int(parts[5])
                    proto = parts[6]
                    service = parts[7]
                    duration = float(parts[8]) if parts[8] != '-' else 0.0
                    orig_bytes = int(parts[9]) if parts[9] != '-' else 0
                    resp_bytes = int(parts[10]) if parts[10] != '-' else 0
                    conn_state = parts[11]
                    local_orig = parts[12] == 'T'
                    local_resp = parts[13] == 'T'
                    missed_bytes = int(parts[14]) if parts[14] != '-' else 0
                    history = parts[15]
                    orig_pkts = int(parts[16]) if parts[16] != '-' else 0
                    orig_ip_bytes = int(parts[17]) if parts[17] != '-' else 0
                    resp_pkts = int(parts[18]) if parts[18] != '-' else 0
                    resp_ip_bytes = int(parts[19]) if parts[19] != '-' else 0
                    label_str = parts[20]
                    
                    label_val = map_label(label_str)
                    
                    # Prepare batch for conn_log
                    batch_conn.append((
                        ts_dt, uid, orig_h, orig_p, resp_h, resp_p, proto, service,
                        duration, orig_bytes, resp_bytes, conn_state, local_orig,
                        local_resp, missed_bytes, history, orig_pkts, orig_ip_bytes,
                        resp_pkts, resp_ip_bytes, ts_dt # imported_at
                    ))
                    
                    # Prepare batch for ground_truth
                    batch_gt.append((orig_h, ts_dt, label_val))
                    
                    count += 1
                    
                    if len(batch_conn) >= 1000:
                        insert_batches(cursor, batch_conn, batch_gt)
                        batch_conn = []
                        batch_gt = []
                        logging.info(f"Ingested {count} records...")
                        
                except Exception as e:
                    logging.warning(f"Error parsing line: {e}")
                    continue
            
            # Final remaining batch
            if batch_conn:
                insert_batches(cursor, batch_conn, batch_gt)
                
            conn.commit()
            logging.info(f"Successfully ingested {count} records from {file_path}")
            
    except Exception as e:
        conn.rollback()
        logging.error(f"Ingestion failed: {e}")
    finally:
        cursor.close()
        conn.close()

def insert_batches(cursor, batch_conn, batch_gt):
    query_conn = """
        INSERT INTO conn_log (
            ts, uid, id_orig_h, id_orig_p, id_resp_h, id_resp_p, proto, service,
            duration, orig_bytes, resp_bytes, conn_state, local_orig,
            local_resp, missed_bytes, history, orig_pkts, orig_ip_bytes,
            resp_pkts, resp_ip_bytes, imported_at
        ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
    """
    cursor.executemany(query_conn, batch_conn)
    
    query_gt = """
        INSERT INTO ground_truth (host_ip, timestamp, label)
        VALUES (%s, %s, %s)
    """
    cursor.executemany(query_gt, batch_gt)

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python3 load_labeled_dataset.py <path_to_conn_log_labeled>")
        sys.exit(1)
        
    log_file = sys.argv[1]
    db_config_path = '/home/user/Desktop/c2/c2/config/database.conf'
    
    if not os.path.exists(db_config_path):
        logging.error(f"Config file not found: {db_config_path}")
        sys.exit(1)
        
    db_config = load_config(db_config_path)
    ingest_labeled_log(log_file, db_config)
