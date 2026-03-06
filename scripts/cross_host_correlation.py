import numpy as np
import pandas as pd
from datetime import datetime, timedelta, timezone
import psycopg2
import logging
import configparser

class CrossHostCorrelation:
    def __init__(self, db_config):
        self.db_config = db_config
        self.threshold = 0.7 # Minimum correlation to consider "synchronized"

    def _connect_db(self):
        try:
            params = self.db_config.copy()
            if 'name' in params:
                params['dbname'] = params.pop('name')
            return psycopg2.connect(**params)
        except Exception as e:
            logging.error(f"Correlation DB connection failed: {e}")
            return None

    def get_time_series_for_host(self, host, start_time, end_time, conn):
        query = """
            SELECT ts
            FROM conn_log 
            WHERE id_orig_h = %s AND ts >= %s AND ts <= %s
            ORDER BY ts ASC
        """
        df = pd.read_sql_query(query, conn, params=(host, start_time, end_time))
        if df.empty:
            return pd.Series(dtype=float)
            
        df['conn_count'] = 1
        df.set_index('ts', inplace=True)
        # 5s interval matching the analyzer
        resampled = df['conn_count'].resample('5s').sum().fillna(0)
        return resampled

    def compute_cross_correlation(self, series_a, series_b):
        if len(series_a) < 10 or len(series_b) < 10:
            return 0.0
            
        # Align lengths if different (should be aligned by resample usually)
        common_len = min(len(series_a), len(series_b))
        a = series_a.values[:common_len]
        b = series_b.values[:common_len]
        
        # Mean center
        a = a - np.mean(a)
        b = b - np.mean(b)
        
        # Standardize
        std_a = np.std(a)
        std_b = np.std(b)
        
        if std_a == 0 or std_b == 0:
            return 0.0
            
        # Cross-correlation at lag 0 (Pearson correlation)
        correlation = np.dot(a, b) / (std_a * std_b * common_len)
        return float(correlation)

    def analyze_synchronization(self, window_minutes=30):
        conn = self._connect_db()
        if not conn:
            return []

        try:
            end_time = datetime.now(timezone.utc)
            start_time = end_time - timedelta(minutes=window_minutes)
            
            # Get hosts that have recent traffic
            query = "SELECT DISTINCT id_orig_h FROM conn_log WHERE ts >= %s"
            cursor = conn.cursor()
            cursor.execute(query, (start_time,))
            hosts = [row[0] for row in cursor.fetchall()]
            cursor.close()
            
            if len(hosts) < 2:
                return []

            # Extract signals
            signals = {}
            for host in hosts:
                signal = self.get_time_series_for_host(host, start_time, end_time, conn)
                if len(signal) > 10:
                    signals[host] = signal

            # Pairwise correlation
            sync_groups = []
            visited = set()
            
            host_list = list(signals.keys())
            for i in range(len(host_list)):
                host_a = host_list[i]
                if host_a in visited: continue
                
                current_group = {host_a}
                for j in range(i + 1, len(host_list)):
                    host_b = host_list[j]
                    corr = self.compute_cross_correlation(signals[host_a], signals[host_b])
                    
                    if corr > self.threshold:
                        current_group.add(host_b)
                        visited.add(host_b)
                
                if len(current_group) > 1:
                    sync_groups.append(list(current_group))
                    visited.add(host_a)
            
            return sync_groups

        finally:
            conn.close()

if __name__ == "__main__":
    config = configparser.ConfigParser()
    config.read('/home/user/Desktop/c2/c2/config/database.conf')
    db_config = dict(config['database'])
    
    correlator = CrossHostCorrelation(db_config)
    groups = correlator.analyze_synchronization()
    if groups:
        print(f"Detected {len(groups)} synchronized host groups:")
        for group in groups:
            print(f" - {group}")
    else:
        print("No synchronized behavior detected.")
