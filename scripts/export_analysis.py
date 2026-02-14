import os
import sys
import argparse
import configparser
import logging
import json
import psycopg2
import pandas as pd
import numpy as np
from datetime import datetime, timedelta, timezone

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)

class DataExporter:
    def __init__(self, db_config):
        self.db_config = db_config
        self.output_dir = '/home/user/Desktop/c2/c2/output'
        if not os.path.exists(self.output_dir):
            os.makedirs(self.output_dir)

    def _connect_db(self):
        try:
            conn = psycopg2.connect(
                host=self.db_config['host'],
                port=self.db_config['port'],
                database=self.db_config['name'],
                user=self.db_config['user'],
                password=self.db_config['password']
            )
            return conn
        except Exception as e:
            logging.error(f"Failed to connect to PG: {e}")
            return None

    def get_time_series(self, host, hours=24):
        conn = self._connect_db()
        if not conn:
            return None

        try:
            end_time = datetime.now(timezone.utc)
            start_time = end_time - timedelta(hours=hours)

            query = """
                SELECT ts, (COALESCE(orig_bytes, 0) + COALESCE(resp_bytes, 0)) as total_bytes 
                FROM conn_log 
                WHERE (id_orig_h = %s OR id_resp_h = %s)
                AND ts >= %s AND ts <= %s
                ORDER BY ts ASC
            """
            # Suppress pandas warning
            import warnings
            warnings.filterwarnings('ignore')
            
            df = pd.read_sql_query(query, conn, params=(host, host, start_time, end_time))
            
            if df.empty:
                logging.warning(f"No data found for host {host} in the last {hours} hours.")
                return None

            df.set_index('ts', inplace=True)
            # Resample to 1s intervals
            resampled = df['total_bytes'].resample('1s').sum().fillna(0)
            return resampled

        except Exception as e:
            logging.error(f"Error retrieving time series: {e}")
            return None
        finally:
            conn.close()

    def calculate_fft_details(self, time_series):
        N = len(time_series)
        if N < 10:
            return None, None

        # Apply FFT
        fft_result = np.fft.rfft(time_series.values)
        frequencies = np.fft.rfftfreq(N, d=1.0)
        magnitude = 2.0 / N * np.abs(fft_result)

        return frequencies, magnitude

    def calculate_autocorrelation_details(self, time_series):
        if len(time_series) < 10:
            return None

        ts_centered = time_series - np.mean(time_series)
        if np.std(ts_centered) == 0:
            return np.zeros(len(time_series)//2) # Flatline

        autocorr = np.correlate(ts_centered, ts_centered, mode='full')
        autocorr = autocorr[len(autocorr)//2:] # Keep positive lags
        
        # Normalize
        if autocorr[0] > 0:
            autocorr = autocorr / autocorr[0]
            
        return autocorr

    def export_host_data(self, host, hours=24):
        logging.info(f"Exporting data for host: {host} (Last {hours} hours)")
        
        # 1. Get Time Series
        ts_data = self.get_time_series(host, hours)
        if ts_data is None:
            return

        # Save Time Series
        ts_df = pd.DataFrame(ts_data)
        ts_filename = os.path.join(self.output_dir, f'time_series_{host}.csv')
        ts_df.to_csv(ts_filename)
        logging.info(f"Saved time series to {ts_filename}")

        # 2. Calculate and Save FFT
        freqs, mags = self.calculate_fft_details(ts_data)
        if freqs is not None:
            fft_df = pd.DataFrame({'frequency': freqs, 'magnitude': mags})
            fft_filename = os.path.join(self.output_dir, f'fft_{host}.csv')
            fft_df.to_csv(fft_filename, index=False)
            logging.info(f"Saved FFT data to {fft_filename}")

        # 3. Calculate and Save Autocorrelation
        autocorr = self.calculate_autocorrelation_details(ts_data)
        if autocorr is not None:
            lags = np.arange(len(autocorr))
            ac_df = pd.DataFrame({'lag': lags, 'correlation': autocorr})
            ac_filename = os.path.join(self.output_dir, f'autocorr_{host}.csv')
            ac_df.to_csv(ac_filename, index=False)
            logging.info(f"Saved Autocorrelation data to {ac_filename}")

        # 4. Export Recent Detection Results
        self.export_detection_results(host)

    def export_detection_results(self, host):
        conn = self._connect_db()
        if not conn:
            return

        try:
            query = """
                SELECT * FROM detection_results 
                WHERE host_ip = %s 
                ORDER BY analyzed_at DESC 
                LIMIT 50
            """
            df = pd.read_sql_query(query, conn, params=(host,))
            if not df.empty:
                filename = os.path.join(self.output_dir, f'detection_results_{host}.csv')
                df.to_csv(filename, index=False)
                logging.info(f"Saved detection results to {filename}")
            else:
                logging.warning(f"No detection results found for {host}")
        except Exception as e:
            logging.error(f"Error exporting detection results: {e}")
        finally:
            conn.close()

def main():
    parser = argparse.ArgumentParser(description='Export C2 Analysis Data')
    parser.add_argument('--host', required=True, help='Target Host IP to analyze')
    parser.add_argument('--hours', type=int, default=24, help='Analysis window in hours')
    args = parser.parse_args()

    config = configparser.ConfigParser()
    config_path = '/home/user/Desktop/c2/c2/config/database.conf'
    if not os.path.exists(config_path):
        logging.error(f"Config file not found: {config_path}")
        sys.exit(1)
        
    config.read(config_path)
    db_config = config['database']

    exporter = DataExporter(db_config)
    exporter.export_host_data(args.host, args.hours)

if __name__ == "__main__":
    main()
