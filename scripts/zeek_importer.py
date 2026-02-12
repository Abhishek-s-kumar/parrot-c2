import os
import sys
import time
import logging
import configparser
import psycopg2
from datetime import datetime
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler

# Configure logging
logging.basicConfig(
    filename='/home/user/Desktop/c2/c2/logs/importer.log',
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)

class ZeekLogHandler(FileSystemEventHandler):
    def __init__(self, log_file, db_config):
        self.log_file = log_file
        self.db_config = db_config
        self.last_position = 0
        self.conn = self._connect_db()

    def _connect_db(self):
        try:
            conn = psycopg2.connect(
                host=self.db_config['host'],
                port=self.db_config['port'],
                database=self.db_config['name'],
                user=self.db_config['user'],
                password=self.db_config['password']
            )
            logging.info("Connected to PostgreSQL")
            return conn
        except Exception as e:
            logging.error(f"Failed to connect to PG: {e}")
            return None

    def on_modified(self, event):
        if event.src_path == self.log_file:
            self.process_log()

    def process_log(self):
        if not self.conn or self.conn.closed:
            self.conn = self._connect_db()
            if not self.conn:
                return

        try:
            with open(self.log_file, 'r') as f:
                f.seek(self.last_position)
                lines = f.readlines()
                self.last_position = f.tell()

                if not lines:
                    return

                cursor = self.conn.cursor()
                for line in lines:
                    if line.startswith('#') or not line.strip():
                        continue
                    
                    parts = line.strip().split('\t')
                    if len(parts) < 20: # Zeek conn.log usually has 20+ fields
                        continue

                    try:
                        # Map Zeek fields to DB columns
                        # conn.log format typically:
                        # ts, uid, id_orig_h, id_orig_p, id_resp_h, id_resp_p, proto, service, duration, orig_bytes, resp_bytes, conn_state, ...
                        ts = datetime.fromtimestamp(float(parts[0]))
                        uid = parts[1]
                        orig_h = parts[2]
                        orig_p = int(parts[3]) if parts[3] != '-' else None
                        resp_h = parts[4]
                        resp_p = int(parts[5]) if parts[5] != '-' else None
                        proto = parts[6]
                        service = parts[7] if parts[7] != '-' else None
                        duration = float(parts[8]) if parts[8] != '-' else None
                        orig_bytes = int(parts[9]) if parts[9] != '-' else None
                        resp_bytes = int(parts[10]) if parts[10] != '-' else None
                        conn_state = parts[11]

                        cursor.execute("""
                            INSERT INTO conn_log (
                                ts, uid, id_orig_h, id_orig_p, id_resp_h, id_resp_p, 
                                proto, service, duration, orig_bytes, resp_bytes, conn_state
                            ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
                        """, (ts, uid, orig_h, orig_p, resp_h, resp_p, proto, service, duration, orig_bytes, resp_bytes, conn_state))
                    except Exception as e:
                        logging.error(f"Error parsing line: {e}")
                
                self.conn.commit()
                cursor.close()
                logging.info(f"Imported {len(lines)} records from conn.log")

        except Exception as e:
            logging.error(f"Error processing log file: {e}")

def main():
    config = configparser.ConfigParser()
    config.read('/home/user/Desktop/c2/c2/config/database.conf')
    db_config = config['database']

    # Zeek log path (adjust based on environment, usually /opt/zeek/logs/current/conn.log)
    # For testing, we might need to create a dummy log or point to a known location
    zeek_log_path = os.environ.get('ZEEK_LOG_PATH', '/home/user/Desktop/c2/c2/logs/zeek/conn.log')
    
    if not os.path.exists(os.path.dirname(zeek_log_path)):
        os.makedirs(os.path.dirname(zeek_log_path), exist_ok=True)
    if not os.path.exists(zeek_log_path):
        with open(zeek_log_path, 'w') as f:
            f.write("#fields\tts\tuid\tid.orig_h\tid.orig_p\tid.resp_h\tid.resp_p\tproto\tservice\tduration\torig_bytes\tresp_bytes\tconn_state\n")

    handler = ZeekLogHandler(zeek_log_path, db_config)
    # Initial processing
    handler.process_log()

    observer = Observer()
    observer.schedule(handler, path=os.path.dirname(zeek_log_path), recursive=False)
    observer.start()

    logging.info(f"Started Monitoring Zeek logs at {zeek_log_path}")
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        observer.stop()
    observer.join()

if __name__ == "__main__":
    main()
