import os
import sys
import logging
import configparser
import psycopg2
import pandas as pd
import io
import time
import re
import gzip
from datetime import datetime, timezone

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

def map_ip_vec(ip_series):
    # Normalize 192.168.x.y to 192.168.56.y
    return ip_series.fillna('').astype(str).str.replace(r'^192\.168\.\d+\.', '192.168.56.', regex=True)

def main():
    if len(sys.argv) < 2:
        print("Usage: python3 load_labeled_dataset.py <file_path> [--recent] [--limit <n>]")
        return

    file_path = sys.argv[1]
    use_recent_ts = "--recent" in sys.argv
    
    limit = None
    if "--limit" in sys.argv:
        idx = sys.argv.index("--limit")
        if idx + 1 < len(sys.argv):
            limit = int(sys.argv[idx + 1])

    config = configparser.ConfigParser()
    config.read('/home/user/Desktop/c2/c2/config/database.conf')
    db_config = config['database']

    conn = psycopg2.connect(
        host=db_config['host'],
        database=db_config['name'],
        user=db_config['user'],
        password=db_config['password']
    )
    cursor = conn.cursor()

    try:
        # 1. Parse Header
        fields = []
        with open(file_path, 'r') if not file_path.endswith('.gz') else gzip.open(file_path, 'rt') as f:
            for line in f:
                if line.startswith("#fields"):
                    fields = re.split(r'\s+', line.strip())[1:]
                    fields = [f.replace('.', '_').replace('-', '_') for f in fields]
                    break
        
        if not fields:
            logging.error("Could not find #fields in header")
            return

        # 2. Determine Timestamp Offset
        offset = 0
        if use_recent_ts:
            with open(file_path, 'r') if not file_path.endswith('.gz') else gzip.open(file_path, 'rt') as f:
                for line in f:
                    if not line.startswith("#"):
                        parts = line.split('\t')
                        if len(parts) > 0:
                            try:
                                max_ts = float(parts[0])
                                # Start at now - 2 hours to ensure everything is in the past
                                offset = datetime.now(timezone.utc).timestamp() - max_ts - 7200
                                logging.info(f"Using offset: {offset}s (Start at T-2h)")
                                break
                            except: pass

        # 3. Optimized Ingestion Loop
        # Reduce chunk size for better visibility and memory management
        batch_size = 200000 
        reader = pd.read_csv(file_path, sep='\t', names=fields, comment='#', chunksize=batch_size, low_memory=False, na_values='-', engine='c')
        
        total_count = 0
        start_time = time.time()
        
        for df in reader:
            # Drop unneeded columns early to save memory
            # Keep only what we need for conn_log and ground_truth
            needed_cols = ['ts', 'uid', 'id_orig_h', 'id_orig_p', 'id_resp_h', 'id_resp_p', 'proto', 'service', 'duration', 'orig_bytes', 'resp_bytes', 'conn_state', 'local_orig', 'local_resp', 'missed_bytes', 'history', 'orig_pkts', 'orig_ip_bytes', 'resp_pkts', 'resp_ip_bytes', 'label']
            # Add tunnel_parents if label is missing (fix for Scenario 17)
            if 'label' not in df.columns and 'tunnel_parents' in df.columns:
                # In Scenario 17, the last columns are merged into tunnel_parents due to space-separator
                # Split tunnel_parents into temp columns
                # Typically: [tunnel_parents, label, detailed_label]
                # data looks like: "-   Malicious   PartOf..."
                split_df = df['tunnel_parents'].astype(str).str.split(r'\s+', expand=True, n=2)
                df['tunnel_parents'] = split_df[0]
                if split_df.shape[1] > 1:
                    df['label'] = split_df[1]
                if split_df.shape[1] > 2:
                    df['detailed_label'] = split_df[2]
            
            # Filter columns we actually use
            active_cols = [c for c in needed_cols if c in df.columns]
            df = df[active_cols].copy()

            # Process timestamps
            df['ts_numeric'] = pd.to_numeric(df['ts'], errors='coerce') + offset
            df['ts_dt'] = pd.to_datetime(df['ts_numeric'], unit='s')
            
            # Normalize IPs
            df['id_orig_h'] = map_ip_vec(df['id_orig_h'])
            df['id_resp_h'] = map_ip_vec(df['id_resp_h'])
            
            # Standardize numerics
            for col in ['orig_bytes', 'resp_bytes', 'id_orig_p', 'id_resp_p', 'missed_bytes', 'orig_pkts', 'orig_ip_bytes', 'resp_pkts', 'resp_ip_bytes']:
                if col in df.columns:
                    df[col] = pd.to_numeric(df[col], errors='coerce').fillna(0).astype('int64')

            # Boolean logic
            for col in ['local_orig', 'local_resp']:
                if col in df.columns:
                    df[col] = df[col].astype(str).str.upper().isin(['T', 'TRUE', '1'])
                else:
                    df[col] = False

            # Label mapping
            if 'label' in df.columns:
                df['label_val'] = df['label'].fillna('Benign').astype(str).str.lower().apply(
                    lambda s: 1 if any(kw in s for kw in ['c&c', 'malicious', 'attack', 'heartbeat', 'port scan']) else 0
                )
            else:
                df['label_val'] = 0

            # COPY to conn_log
            conn_cols = ['ts_dt', 'uid', 'id_orig_h', 'id_orig_p', 'id_resp_h', 'id_resp_p', 'proto', 'service', 'duration', 'orig_bytes', 'resp_bytes', 'conn_state', 'local_orig', 'local_resp', 'missed_bytes', 'history', 'orig_pkts', 'orig_ip_bytes', 'resp_pkts', 'resp_ip_bytes']
            # Ensure all exist
            for col in conn_cols:
                if col not in df.columns: df[col] = '-' if df[col].dtype == object else 0
            
            # Map duration if missing
            if 'duration' not in df.columns: df['duration'] = 0.0
            else: df['duration'] = pd.to_numeric(df['duration'], errors='coerce').fillna(0.0)

            conn_buffer = io.StringIO()
            # Use a faster separator or just standard CSV
            df[conn_cols].to_csv(conn_buffer, index=False, header=False, sep=',', na_rep='-')
            conn_buffer.seek(0)
            
            copy_sql = f"COPY conn_log({','.join(['ts' if c == 'ts_dt' else c for c in conn_cols])}, imported_at) FROM STDIN WITH CSV"
            # Add imported_at manually to buffer if needed, or just let DB handle it?
            # Actually, I added imported_at in the COPY list but not in the CSV.
            # I'll Fix the SQL to use CURRENT_TIMESTAMP default by omitting it or providing it.
            copy_sql = f"COPY conn_log({','.join(['ts' if c == 'ts_dt' else c for c in conn_cols])}) FROM STDIN WITH CSV"
            cursor.copy_expert(copy_sql, conn_buffer)

            # COPY to ground_truth
            gt_buffer = io.StringIO()
            df[['id_orig_h', 'ts_dt', 'label_val']].to_csv(gt_buffer, index=False, header=False, sep=',')
            gt_buffer.seek(0)
            cursor.copy_expert("COPY ground_truth(host_ip, timestamp, label) FROM STDIN WITH CSV", gt_buffer)

            conn.commit()
            total_count = total_count + int(len(df))
            logging.info(f"Ingested {total_count} records...")
            
            if limit is not None and total_count >= limit:
                logging.info(f"Reached limit of {limit} records. Stopping.")
                break

        logging.info(f"Done. {total_count} records in {time.time() - start_time:.2f}s")
        
    except Exception as e:
        conn.rollback()
        logging.error(f"Error: {e}")
        import traceback
        traceback.print_exc()
    finally:
        conn.close()

if __name__ == "__main__":
    main()
