import pandas as pd
import psycopg2
import configparser
from datetime import datetime, timezone, timedelta
import logging
import sys
import os
import gzip
import glob
import io
import re

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
    if not label_str: return 0
    label_str = label_str.lower()
    if 'benign' in label_str:
        return 0
    if 'c&c' in label_str or 'malicious' in label_str or 'attack' in label_str or 'heartbeat' in label_str or 'port scan' in label_str:
        return 1
    return 0

def map_ip(ip_str):
    """Maps any 192.168.x.y to 192.168.56.y for environment alignment."""
    if ip_str.startswith('192.168.'):
        parts = ip_str.split('.')
        if len(parts) == 4:
            return f"192.168.56.{parts[3]}"
    return ip_str

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
        # Pre-scan for header
        with opener(file_path, mode) as f:
            for line in f:
                if line.startswith('#fields'):
                    fields = line.strip().split('\t')[1:]
                    for i, field in enumerate(fields):
                        fields_map[field.replace('.', '_')] = i
                    break
        
        if not fields_map:
            logging.warning("No #fields header found, using default IoT-23 indices.")
            fields_map = {
                'ts': 0, 'uid': 1, 'id_orig_h': 2, 'id_orig_p': 3, 'id_resp_h': 4, 'id_resp_p': 5,
                'proto': 6, 'service': 7, 'duration': 8, 'orig_bytes': 9, 'resp_bytes': 10,
                'conn_state': 11, 'local_orig': 12, 'local_resp': 13, 'missed_bytes': 14,
                'history': 15, 'orig_pkts': 16, 'orig_ip_bytes': 17, 'resp_pkts': 18,
                'resp_ip_bytes': 19, 'label': 21
            }

        # Calculate offset if --recent
        offset = 0
        if "--recent" in sys.argv:
            max_ts = 0
            with opener(file_path, mode) as f:
                for line in f:
                    if not line.startswith('#'):
                        parts = line.strip().split('\t')
                        ts_idx = fields_map.get('ts')
                        if ts_idx is not None and ts_idx < len(parts):
                            try:
                                ts = float(parts[ts_idx])
                                if ts > max_ts: max_ts = ts
                            except: pass
            if max_ts > 0:
                offset = datetime.now(timezone.utc).timestamp() - max_ts
                logging.info(f"Timestamp offset: {offset}s")

        # Optimized ingestion using COPY
        f_conn = io.StringIO()
        f_gt = io.StringIO()
        count = 0
        batch_size = 50000
        
        with opener(file_path, mode) as f:
            for line in f:
                if line.startswith('#'): continue
                
                parts = line.rstrip('\n\r').split('\t')
                
                try:
                    def get_f(name, default_val):
                        idx = fields_map.get(name)
                        if idx is not None and idx < len(parts):
                            v = parts[idx]
                            return v if v != '-' else default_val
                        return default_val

                    ts_raw = get_f('ts', None)
                    if not ts_raw: continue
                    ts_epoch = float(ts_raw) + offset
                    ts_dt = datetime.fromtimestamp(ts_epoch, tz=timezone.utc).isoformat()
                    
                    uid = get_f('uid', '')
                    orig_h = map_ip(get_f('id_orig_h', ''))
                    orig_p = get_f('id_orig_p', '0')
                    resp_h = map_ip(get_f('id_resp_h', ''))
                    resp_p = get_f('id_resp_p', '0')
                    proto = get_f('proto', '')
                    service = get_f('service', '')
                    duration = get_f('duration', '0.0')
                    orig_bytes = get_f('orig_bytes', '0')
                    resp_bytes = get_f('resp_bytes', '0')
                    conn_state = get_f('conn_state', '')
                    local_orig = 'TRUE' if get_f('local_orig', 'F') == 'T' else 'FALSE'
                    local_resp = 'TRUE' if get_f('local_resp', 'F') == 'T' else 'FALSE'
                    missed_bytes = get_f('missed_bytes', '0')
                    history = get_f('history', '')
                    orig_pkts = get_f('orig_pkts', '0')
                    orig_ip_bytes = get_f('orig_ip_bytes', '0')
                    resp_pkts = get_f('resp_pkts', '0')
                    resp_ip_bytes = get_f('resp_ip_bytes', '0')
                    
                    label_str = get_f('label', 'Benign')
                    label_val = map_label(label_str)
                    
                    # conn_log line (TSV format for COPY)
                    f_conn.write(f"{ts_dt}\t{uid}\t{orig_h}\t{orig_p}\t{resp_h}\t{resp_p}\t{proto}\t{service}\t"
                                f"{duration}\t{orig_bytes}\t{resp_bytes}\t{conn_state}\t{local_orig}\t"
                                f"{local_resp}\t{missed_bytes}\t{history}\t{orig_pkts}\t{orig_ip_bytes}\t"
                                f"{resp_pkts}\t{resp_ip_bytes}\t{ts_dt}\n")
                    
                    # ground_truth line
                    f_gt.write(f"{orig_h}\t{ts_dt}\t{label_val}\n")
                    
                    count += 1
                    if count % batch_size == 0:
                        f_conn.seek(0)
                        f_gt.seek(0)
                        cursor.copy_from(f_conn, 'conn_log', columns=('ts', 'uid', 'id_orig_h', 'id_orig_p', 'id_resp_h', 'id_resp_p', 'proto', 'service', 'duration', 'orig_bytes', 'resp_bytes', 'conn_state', 'local_orig', 'local_resp', 'missed_bytes', 'history', 'orig_pkts', 'orig_ip_bytes', 'resp_pkts', 'resp_ip_bytes', 'imported_at'))
                        cursor.copy_from(f_gt, 'ground_truth', columns=('host_ip', 'timestamp', 'label'))
                        conn.commit()
                        f_conn = io.StringIO()
                        f_gt = io.StringIO()
                        logging.info(f"Ingested {count} records...")

                except Exception:
                    continue

            # Final batch
            if count % batch_size != 0:
                f_conn.seek(0)
                f_gt.seek(0)
                cursor.copy_from(f_conn, 'conn_log', columns=('ts', 'uid', 'id_orig_h', 'id_orig_p', 'id_resp_h', 'id_resp_p', 'proto', 'service', 'duration', 'orig_bytes', 'resp_bytes', 'conn_state', 'local_orig', 'local_resp', 'missed_bytes', 'history', 'orig_pkts', 'orig_ip_bytes', 'resp_pkts', 'resp_ip_bytes', 'imported_at'))
                cursor.copy_from(f_gt, 'ground_truth', columns=('host_ip', 'timestamp', 'label'))
                conn.commit()

        logging.info(f"Done. Successfully ingested {count} records.")
    except Exception as e:
        conn.rollback()
        logging.error(f"Failed: {e}")
    finally:
        cursor.close()
        conn.close()

def process_input(target_path, db_config):
    if os.path.isdir(target_path):
        paths = sorted(glob.glob(os.path.join(target_path, "*", "conn.log.labeled*")))
        for p in paths: ingest_labeled_log(p, db_config)
    else:
        ingest_labeled_log(target_path, db_config)

if __name__ == "__main__":
    if len(sys.argv) < 2: sys.exit(1)
    db_config = load_config('/home/user/Desktop/c2/c2/config/database.conf')
    process_input(sys.argv[1], db_config)
