import pandas as pd
import psycopg2
import configparser
from datetime import datetime, timezone
import logging
import sys
import os
import gzip
import glob
import traceback

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
    if not label_str: return 0
    label_str = label_str.lower()
    if 'benign' in label_str:
        return 0
    if 'c&c' in label_str or 'malicious' in label_str or 'attack' in label_str or 'heartbeat' in label_str or 'port scan' in label_str:
        return 1
    return 0

def ingest_labeled_log(file_path, db_config):
    conn = connect_db(db_config)
    if not conn: return

    cursor = conn.cursor()
    try:
        logging.info(f"Starting ingestion of {file_path}")
        
        # Detect field indices
        opener = gzip.open if file_path.endswith('.gz') else open
        mode = 'rt' if file_path.endswith('.gz') else 'r'
        
        fields_map = {}
        max_ts = 0
        
        # Pass 1: Scan for header and find max timestamp for offset
        with opener(file_path, mode) as f:
            for line in f:
                if line.startswith('#fields'):
                    fields = line.strip().split('\t')[1:]
                    for i, field in enumerate(fields):
                        # Zeek fields often use '.' instead of '_'
                        clean_field = field.replace('.', '_')
                        fields_map[clean_field] = i
                elif not line.startswith('#'):
                    if "--recent" in sys.argv:
                         parts = line.strip().split('\t')
                         ts_idx = fields_map.get('ts')
                         if ts_idx is not None and ts_idx < len(parts):
                             try:
                                 ts = float(parts[ts_idx])
                                 if ts > max_ts: max_ts = ts
                             except: pass

        if not fields_map:
            # Fallback to defaults if no header found
            logging.warning("No #fields header found, using default IoT-23 indices.")
            fields_map = {
                'ts': 0, 'uid': 1, 'id_orig_h': 2, 'id_orig_p': 3, 'id_resp_h': 4, 'id_resp_p': 5,
                'proto': 6, 'service': 7, 'duration': 8, 'orig_bytes': 9, 'resp_bytes': 10,
                'conn_state': 11, 'local_orig': 12, 'local_resp': 13, 'missed_bytes': 14,
                'history': 15, 'orig_pkts': 16, 'orig_ip_bytes': 17, 'resp_pkts': 18,
                'resp_ip_bytes': 19, 'label': 21
            }

        offset = 0
        if "--recent" in sys.argv and max_ts > 0:
            offset = datetime.now(timezone.utc).timestamp() - max_ts
            logging.info(f"Shifting timestamps by {offset} seconds.")

        # Pass 2: Ingest
        with opener(file_path, mode) as f:
            count = 0
            error_count = 0
            batch_conn = []
            batch_gt = []
            
            for line in f:
                if line.startswith('#'): continue
                
                parts = line.rstrip('\n\r').split('\t')
                
                try:
                    def get_field(name, default=None):
                        idx = fields_map.get(name)
                        if idx is not None and idx < len(parts):
                            val = parts[idx]
                            return val if val != '-' else default
                        return default

                    ts_raw = get_field('ts')
                    if not ts_raw: continue
                    ts_epoch = float(ts_raw) + offset
                    ts_dt = datetime.fromtimestamp(ts_epoch, tz=timezone.utc)
                    
                    uid = get_field('uid', '')
                    orig_h = get_field('id_orig_h', '')
                    if orig_h.startswith('192.168.1.'):
                        orig_h = orig_h.replace('192.168.1.', '192.168.56.')
                    
                    orig_p = int(get_field('id_orig_p', 0))
                    resp_h = get_field('id_resp_h', '')
                    if resp_h.startswith('192.168.1.'):
                        resp_h = resp_h.replace('192.168.1.', '192.168.56.')
                    
                    resp_p = int(get_field('id_resp_p', 0))
                    proto = get_field('proto', '')
                    service = get_field('service', '')
                    duration = float(get_field('duration', 0.0))
                    orig_bytes = int(get_field('orig_bytes', 0))
                    resp_bytes = int(get_field('resp_bytes', 0))
                    conn_state = get_field('conn_state', '')
                    local_orig = get_field('local_orig') == 'T'
                    local_resp = get_field('local_resp') == 'T'
                    missed_bytes = int(get_field('missed_bytes', 0))
                    history = get_field('history', '')
                    orig_pkts = int(get_field('orig_pkts', 0))
                    orig_ip_bytes = int(get_field('orig_ip_bytes', 0))
                    resp_pkts = int(get_field('resp_pkts', 0))
                    resp_ip_bytes = int(get_field('resp_ip_bytes', 0))
                    
                    label_str = get_field('label', 'Benign')
                    label_val = map_label(label_str)
                    
                    batch_conn.append((
                        ts_dt, uid, orig_h, orig_p, resp_h, resp_p, proto, service,
                        duration, orig_bytes, resp_bytes, conn_state, local_orig,
                        local_resp, missed_bytes, history, orig_pkts, orig_ip_bytes,
                        resp_pkts, resp_ip_bytes, ts_dt
                    ))
                    batch_gt.append((orig_h, ts_dt, label_val))
                    count += 1
                    
                    if len(batch_conn) >= 1000:
                        insert_batches(cursor, batch_conn, batch_gt)
                        batch_conn = []
                        batch_gt = []
                        if count % 10000 == 0:
                            logging.info(f"Ingested {count} records...")
                except Exception as e:
                    error_count += 1
                    if error_count <= 5:
                        logging.warning(f"Error parsing line: {e}")
                        if error_count == 5:
                            logging.warning("Further errors will be suppressed.")
                    continue
            
            if batch_conn:
                insert_batches(cursor, batch_conn, batch_gt)
            conn.commit()
            logging.info(f"Successfully ingested {count} records.")
            
    except Exception as e:
        conn.rollback()
        logging.error(f"Ingestion failed: {e}\n{traceback.format_exc()}")
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
    query_gt = "INSERT INTO ground_truth (host_ip, timestamp, label) VALUES (%s, %s, %s)"
    cursor.executemany(query_gt, batch_gt)

def process_input(target_path, db_config):
    if os.path.isdir(target_path):
        paths = sorted(glob.glob(os.path.join(target_path, "*", "conn.log.labeled*")))
        for p in paths: ingest_labeled_log(p, db_config)
    elif os.path.isfile(target_path):
        ingest_labeled_log(target_path, db_config)

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python3 load_labeled_dataset.py <path>")
        sys.exit(1)
    db_config = load_config('/home/user/Desktop/c2/c2/config/database.conf')
    process_input(sys.argv[1], db_config)
