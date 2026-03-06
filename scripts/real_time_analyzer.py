import os
import sys
import logging
import configparser
import psycopg2
import subprocess
import re
import numpy as np
import pandas as pd
from scipy import stats
from datetime import datetime, timedelta, timezone

# Configure logging
logging.basicConfig(
    filename='/home/user/Desktop/c2/c2/logs/c2_monitor.log',
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)

class DetectionEngine:
    def __init__(self, db_config):
        self.db_config = db_config
        self.p_threshold = 0.6 # Task 6.1: Optimized threshold
        self.ALPHA = 0.4 # FFT weight
        self.BETA = 0.4  # Autocorrelation weight
        self.GAMMA = 0.2 # Entropy weight
        self._ip_cache = {}
        self.MONITOR_IP = '192.168.56.20'

    def _is_host_address(self, ip):
        """Returns True if the IP is likely a host (not broadcast/multicast/unspecified)."""
        if not ip or ip in ['0.0.0.0', '255.255.255.255', '::', self.MONITOR_IP]:
            return False
        
        # IPv4 Multicast (224.0.0.0/4)
        if ip.startswith(('224.', '225.', '226.', '227.', '228.', '229.', '230.', '231.', '232.', '233.', '234.', '235.', '236.', '237.', '238.', '239.')):
            return False
            
        # IPv6 Multicast (ff00::/8)
        if ip.lower().startswith('ff'):
            return False
            
        # IPv4 Broadcast (common lab patterns)
        if ip.endswith('.255'):
            return False

        return True

    def _ipv6_to_mac(self, ipv6):
        """Safe heuristic to extract MAC part from IPv6 suffix."""
        try:
            if not isinstance(ipv6, str):
                return None
            parts = ipv6.split(":")
            if len(parts) < 4:
                return None
            return parts[-1] # User's recommended safe fix
        except Exception:
            return None

    def _get_ip_mapping(self):
        """Builds a mapping of IPv6 to IPv4 based on neighbor table (MAC matching)."""
        mapping = {}
        mac_to_ipv4 = {}
        try:
            # Get ARP/Neighbor table
            output = subprocess.check_output(['ip', 'neigh', 'show'], stderr=subprocess.STDOUT).decode()
            
            for line in output.splitlines():
                parts = line.split()
                if len(parts) >= 5 and 'lladdr' in parts:
                    ip = parts[0]
                    mac = parts[parts.index('lladdr') + 1].lower()
                    if '.' in ip: # IPv4
                        mac_to_ipv4[mac] = ip

            # Now try to match IPv6 addresses to these MACs
            # 1. Direct neighbor table match
            for line in output.splitlines():
                parts = line.split()
                if len(parts) >= 5 and 'lladdr' in parts:
                    ip = parts[0]
                    mac = parts[parts.index('lladdr') + 1].lower()
                    if ':' in ip and mac in mac_to_ipv4:
                        mapping[ip] = mac_to_ipv4[mac]
        except Exception as e:
            logging.error(f"Error building IP mapping: {e}")
        
        return mapping, mac_to_ipv4

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

    def calculate_fft(self, time_series):
        # Phase 2: Fix FFT Type Error
        if not isinstance(time_series, (pd.Series, np.ndarray, list)):
            return 0.0, 0.0

        N = len(time_series)
        if N < 8: # User recommended 8
            return 0.0, 0.0
        
        # Apply FFT on values
        if isinstance(time_series, pd.Series):
            values = time_series.values
        else:
            values = time_series
            
        fft_result = np.fft.rfft(values)
        frequencies = np.fft.rfftfreq(N, d=1.0)
        
        magnitude = 2.0 / N * np.abs(fft_result)
        
        if len(magnitude) > 1:
            peak_magnitude = np.max(magnitude[1:])
            peak_idx = np.argmax(magnitude[1:]) + 1
            peak_frequency = frequencies[peak_idx]
            max_mag = np.max(magnitude)
            fft_peak = peak_magnitude / max_mag if max_mag > 0 else 0.0
        else:
            fft_peak = 0.0
            peak_frequency = 0.0
            
        return float(fft_peak), float(peak_frequency)

    def calculate_autocorrelation(self, time_series):
        # Phase 4: Tune Autocorrelation
        if not isinstance(time_series, (pd.Series, np.ndarray, list)):
            return 0.0

        if len(time_series) < 10:
            return 0.0
        
        # Check if the signal is purely zero or constant
        if isinstance(time_series, pd.Series):
            vals = time_series.values
        else:
            vals = time_series
            
        if np.std(vals) == 0:
            return 0.0

        # Normalize signal before processing
        ts_centered = vals - np.mean(vals)
        std = np.std(ts_centered)
        if std == 0:
            return 0.0
            
        autocorr = np.correlate(ts_centered, ts_centered, mode='full')
        autocorr = autocorr[len(autocorr)//2:]
        
        # Normalize by the zero-lag value
        if autocorr[0] > 0:
            autocorr = autocorr / autocorr[0]
            
        # For beacons, we look for secondary peaks
        if len(autocorr) > 2:
            # Skip the first lag to avoid the self-correlation peak
            secondary_peaks = autocorr[1:len(autocorr)//2] # User recommended len//2
            if len(secondary_peaks) > 0:
                autocorr_max = np.max(secondary_peaks)
            else:
                autocorr_max = 0.0
        else:
            autocorr_max = 0.0
            
        return float(autocorr_max)

    def calculate_entropy(self, time_series):
        # Phase 5: Fix Entropy Calculation
        if not isinstance(time_series, (pd.Series, np.ndarray, list)):
            return 1.0

        if len(time_series) < 10:
            return 1.0
            
        if isinstance(time_series, pd.Series):
            counts = time_series.values
        else:
            counts = time_series

        if np.std(counts) == 0: # User's fix
            return 1.0 # High regularity
            
        # Normalize and compute entropy
        hist, _ = np.histogram(counts, bins=10, density=True)
        hist = hist[hist > 0]
        
        if len(hist) <= 1:
            return 0.0
            
        hist = hist / hist.sum()
        entropy = -np.sum(hist * np.log2(hist))
        
        max_entropy = np.log2(len(hist))
        entropy_norm = entropy / max_entropy if max_entropy > 0 else 0.0
        
        return float(entropy_norm)

    def calculate_p_score(self, fft_peak, autocorr_max, entropy_norm):
        # Increased weight for autocorrelation as it's more reliable for C2
        P_SCORE = (
            0.3 * fft_peak +
            0.5 * autocorr_max +
            0.2 * (1.0 - entropy_norm)
        )
        return float(P_SCORE)

    def analyze_recent_traffic(self, window_minutes=60):
        conn = self._connect_db()
        if not conn:
            return []

        try:
            # Query recent traffic from conn_log
            end_time = datetime.now(timezone.utc)
            start_time = end_time - timedelta(minutes=window_minutes)
            
            # Count connections per second/interval
            query = """
                SELECT id_orig_h, ts
                FROM conn_log 
                WHERE ts >= %s AND ts <= %s
                ORDER BY ts ASC
            """
            df = pd.read_sql_query(query, conn, params=(start_time, end_time))
            
            if df.empty:
                return []

            results = []
            hosts = df['id_orig_h'].unique()
            
            # Phase 1.1: Move IP Mapping Outside Loop
            mapping, mac_to_ipv4 = self._get_ip_mapping()
            
            # Phase 1.2: Batch Database inserts
            cursor = conn.cursor()
            
            for host in hosts:
                if not self._is_host_address(host):
                    continue

                host_df = df[df['id_orig_h'] == host].copy()
                if len(host_df) < 5:
                    continue

                # --- Type 1: Periodic Volume (Connection Counts) ---
                host_df_v = host_df.copy()
                host_df_v['conn_count'] = 1
                host_df_v.set_index('ts', inplace=True)
                resampled = host_df_v['conn_count'].resample('5s').sum().fillna(0)
                
                p_score_v = 0.0
                if len(resampled) >= 10:
                    fft_peak_v, _ = self.calculate_fft(resampled)
                    autocorr_max_v = self.calculate_autocorrelation(resampled)
                    entropy_norm_v = self.calculate_entropy(resampled)
                    p_score_v = self.calculate_p_score(fft_peak_v, autocorr_max_v, entropy_norm_v)

                # --- Type 2: Sparse Events (Inter-arrival Times) ---
                # Task 1.2: Support sparse event signals
                host_df_t = host_df.sort_values('ts')
                deltas = host_df_t['ts'].diff().dt.total_seconds().dropna()
                
                p_score_t = 0.0
                fft_peak_t = 0.0
                autocorr_max_t = 0.0
                entropy_norm_t = 1.0
                
                if len(deltas) >= 10:
                    fft_peak_t, _ = self.calculate_fft(deltas)
                    autocorr_max_t = self.calculate_autocorrelation(deltas)
                    entropy_norm_t = self.calculate_entropy(deltas)
                    p_score_t = self.calculate_p_score(fft_peak_t, autocorr_max_t, entropy_norm_t)

                # Final Detection Fusion (take the more significant pattern)
                p_score = max(p_score_v, p_score_t)
                detected = p_score > self.p_threshold 
                
                mapped_ip = mapping.get(host)
                if not mapped_ip:
                    mac = self._ipv6_to_mac(host)
                    if mac and mac in mac_to_ipv4:
                        mapped_ip = mac_to_ipv4[mac]
                
                display_host = f"{host} ({mapped_ip})" if mapped_ip else host

                results.append({
                    'host': host,
                    'display_host': display_host,
                    'p_score': p_score,
                    'detected': detected,
                    'type': 'volume' if p_score_v >= p_score_t else 'sparse'
                })
                
                # Store in DB (batch)
                cursor.execute("""
                    INSERT INTO detection_results (
                        host_ip, p_score, fft_peak, autocorr_max, entropy_norm, sample_count, detected
                    ) VALUES (%s, %s, %s, %s, %s, %s, %s)
                """, (host, p_score, 
                      max(fft_peak_v, fft_peak_t), 
                      max(autocorr_max_v, autocorr_max_t), 
                      min(entropy_norm_v, entropy_norm_t), 
                      len(host_df), detected))

                if detected:
                    logging.info(f"BEACON DETECTED: host={host} p_score={p_score:.3f} autocorr={max(autocorr_max_v, autocorr_max_t):.3f}")
                    # Export for Task 5.1 (Visualization)
                    try:
                        out_dir = "/home/user/Desktop/c2/c2/output"
                        os.makedirs(out_dir, exist_ok=True)
                        if p_score_v >= p_score_t:
                            resampled.to_csv(os.path.join(out_dir, f'time_series_{host}.csv'), header=['total_bytes'])
                        else:
                            deltas.to_csv(os.path.join(out_dir, f'time_series_{host}.csv'), header=['total_bytes'])
                    except Exception as e:
                        logging.warning(f"Could not save plotting data: {e}")

            # Commit batch
            conn.commit()
            cursor.close()
            return results

        except Exception as e:
            logging.error(f"Error during analysis: {e}")
            return []
        finally:
            conn.close()

    def get_online_systems(self, window_minutes=10080):
        """Returns a list of unique hosts seen in the last X minutes."""
        conn = self._connect_db()
        if not conn:
            return []

        try:
            end_time = datetime.now(timezone.utc)
            start_time = end_time - timedelta(minutes=window_minutes)

            query = """
                SELECT id_orig_h as host, MAX(ts) as last_seen FROM conn_log WHERE ts >= %s AND ts <= %s GROUP BY id_orig_h
                UNION
                SELECT id_resp_h as host, MAX(ts) as last_seen FROM conn_log WHERE ts >= %s AND ts <= %s GROUP BY id_resp_h
                ORDER BY last_seen DESC
            """
            df = pd.read_sql_query(query, conn, params=(start_time, end_time, start_time, end_time))

            if df.empty:
                return []

            # Deduplicate just in case of overlaps in last_seen
            df = df.sort_values('last_seen', ascending=False).drop_duplicates('host')

            mapping, mac_to_ipv4 = self._get_ip_mapping()
            
            systems = []
            for _, row in df.iterrows():
                host = row['host']
                if not self._is_host_address(host):
                    continue
                    
                last_seen = row['last_seen']
                
                mapped_ip = mapping.get(host)
                if not mapped_ip:
                    mac = self._ipv6_to_mac(host)
                    if mac and mac in mac_to_ipv4:
                        mapped_ip = mac_to_ipv4[mac]
                
                display_host = f"{host} ({mapped_ip})" if mapped_ip else host
                
                systems.append({
                    'host': host,
                    'display_host': display_host,
                    'last_seen': last_seen.isoformat() if isinstance(last_seen, datetime) else str(last_seen)
                })
            
            return systems

        except Exception as e:
            logging.error(f"Error fetching online systems: {e}")
            return []
        finally:
            conn.close()

def main():
    config = configparser.ConfigParser()
    config.read('/home/user/Desktop/c2/c2/config/database.conf')
    db_config = config['database']
    
    engine = DetectionEngine(db_config)
    results = engine.analyze_recent_traffic()
    print(f"Analyzed {len(results)} hosts.")

if __name__ == "__main__":
    main()
