import os
import sys
import logging
import configparser
import psycopg2
import subprocess
import re
import numpy as np
import pandas as pd
import warnings
from scipy import stats
from datetime import datetime, timedelta, timezone

# Suppress specific numpy warnings for constant signals
warnings.filterwarnings('ignore', category=RuntimeWarning, message='invalid value encountered in divide')

# Configure logging
logging.basicConfig(
    filename='/home/user/Desktop/c2/c2/logs/c2_monitor.log',
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)

class DetectionEngine:
    def __init__(self, db_config):
        self.db_config = db_config
        
        # Load weights and logic from config
        self.weights_config = configparser.ConfigParser()
        self.weights_config.read('/home/user/Desktop/c2/c2/config/detection_weights.ini')
        
        self.p_threshold = 0.6 
        self.ALPHA = float(self.weights_config.get('weights', 'fft_peak', fallback=0.4))
        self.BETA = float(self.weights_config.get('weights', 'autocorr_max', fallback=0.4))
        self.GAMMA = float(self.weights_config.get('weights', 'entropy_norm', fallback=0.2))
        
        self.window_low = int(self.weights_config.get('logic', 'window_low_rate', fallback=15))
        self.window_high = int(self.weights_config.get('logic', 'window_high_rate', fallback=5))
        self.rate_threshold = int(self.weights_config.get('logic', 'rate_threshold', fallback=5))

        self._ip_mapping_cache = (None, None)
        self._last_mapping_update = 0
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
        import time
        now = time.time()
        if self._ip_mapping_cache[0] is not None and (now - self._last_mapping_update) < 300:
            return self._ip_mapping_cache

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
        
        self._ip_mapping_cache = (mapping, mac_to_ipv4)
        self._last_mapping_update = now
        return self._ip_mapping_cache

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

    def calculate_fft(self, signal):
        """Calculates normalized FFT and returns peak magnitude and peak frequency."""
        if not isinstance(signal, (pd.Series, np.ndarray, list)):
            return 0.0, 0.0
            
        sig = signal.values if hasattr(signal, 'values') else np.array(signal)
        n = len(sig)
        if n < 5:
            return 0.0, 0.0
        
        # Normalize signal (Mean center and scale)
        sig = sig - np.mean(sig)
        std = np.std(sig)
        if std > 0:
            sig = sig / std
            
        fft_values = np.abs(np.fft.rfft(sig))
        freqs = np.fft.rfftfreq(n, d=1.0)
        
        # Skip DC component
        if len(fft_values) > 1:
            peak_idx = np.argmax(fft_values[1:]) + 1
            peak_v = fft_values[peak_idx] / n
            peak_f = freqs[peak_idx]
            return float(peak_v), float(peak_f)
        return 0.0, 0.0

    def calculate_autocorrelation(self, signal):
        """Calculates normalized autocorrelation and returns the maximum coefficient."""
        if not isinstance(signal, (pd.Series, np.ndarray, list)):
            return 0.0
            
        sig = signal.values if hasattr(signal, 'values') else np.array(signal)
        n = len(sig)
        if n < 5:
            return 0.0
        
        # Normalize signal (Mean center and scale)
        sig = sig - np.mean(sig)
        std = np.std(sig)
        if std > 0:
            sig = sig / std

        # Use skip_lags=1 to catch 10-30s beacons (Issue 3)
        lags = range(1, min(n, 50)) 
        if not lags: return 0.0
        
        corrs = []
        for lag in lags:
            if (n - lag) > 1:
                # Use Pearson correlation for normalized signal
                c = np.corrcoef(sig[:-lag], sig[lag:])[0, 1]
                if not np.isnan(c):
                    corrs.append(c)
        
        return float(max(corrs)) if corrs else 0.0

    def calculate_entropy(self, signal):
        """Calculates normalized Shannon entropy of the signal."""
        if not isinstance(signal, (pd.Series, np.ndarray, list)):
            return 1.0

        sig = signal.values if hasattr(signal, 'values') else np.array(signal)
        n = len(sig)
        if n < 5:
            return 1.0
            
        if np.std(sig) == 0: 
            return 1.0 # High regularity
            
        # Normalize and compute entropy
        hist, _ = np.histogram(sig, bins=10, density=True)
        hist = hist[hist > 0]
        
        if len(hist) <= 1:
            return 0.0
            
        hist = hist / hist.sum()
        entropy = -np.sum(hist * np.log2(hist))
        
        max_entropy = np.log2(len(hist))
        entropy_norm = entropy / max_entropy if max_entropy > 0 else 0.0
        
        return float(entropy_norm)

    def calculate_p_score(self, fft_peak, autocorr_max, entropy_norm):
        """Fusion score using current weights."""
        P_SCORE = (
            self.ALPHA * fft_peak +
            self.BETA * autocorr_max +
            self.GAMMA * (1.0 - entropy_norm)
        )
        return float(P_SCORE)

    def analyze_recent_traffic(self, window_minutes=60):
        conn = self._connect_db()
        if not conn:
            return []

        try:
            # Query recent traffic from conn_log
            # Ensure we use UTC for everything
            end_time = datetime.now(timezone.utc).replace(tzinfo=None) # Make naive for 'timestamp without time zone'
            start_time = end_time - timedelta(minutes=window_minutes)
            
            logging.info(f"Analyzing traffic from {start_time} to {end_time}")
            
            # Count connections per second/interval
            query = """
                SELECT id_orig_h, ts
                FROM conn_log 
                WHERE ts >= %s AND ts <= %s
                ORDER BY ts ASC
            """
            df = pd.read_sql_query(query, conn, params=(start_time, end_time))
            
            logging.info(f"Retrieved {len(df)} rows from conn_log")
            
            if df.empty:
                print(f"No traffic found in the last {window_minutes} minutes.")
                return []

            results = []
            db_batch = []
            hosts = df['id_orig_h'].unique()
            
            import time as pytime
            start_perf = pytime.time()
            
            # Phase 1.1: Move IP Mapping Outside Loop (Issue 6)
            mapping, mac_to_ipv4 = self._get_ip_mapping()
            
            hosts_analyzed = 0
            for host in hosts:
                if not self._is_host_address(host):
                    continue
                hosts_analyzed += 1

                host_df = df[df['id_orig_h'] == host].copy()
                if len(host_df) < 5:
                    continue

                # --- Improvement 2: Adaptive Windowing (Task 4.2) ---
                # Calculate simple rate: events per minute in the window
                events_per_min = len(host_df) / window_minutes
                step = f"{self.window_low}s" if events_per_min < self.rate_threshold else f"{self.window_high}s"

                # --- Type 1: Periodic Volume (Issue 1) ---
                host_df_v = host_df.copy()
                host_df_v['conn_count'] = 1
                host_df_v.set_index('ts', inplace=True)
                resampled = host_df_v['conn_count'].resample(step).sum().fillna(0)
                
                p_score_v = 0.0
                fft_peak_v, autocorr_max_v, entropy_norm_v = 0.0, 0.0, 1.0
                if len(resampled) >= 5:
                    fft_peak_v, _ = self.calculate_fft(resampled)
                    autocorr_max_v = self.calculate_autocorrelation(resampled)
                    entropy_norm_v = self.calculate_entropy(resampled)
                    p_score_v = self.calculate_p_score(fft_peak_v, autocorr_max_v, entropy_norm_v)

                # --- Type 2: Sparse Events (Issue 2) ---
                host_df_t = host_df.sort_values('ts')
                deltas = host_df_t['ts'].diff().dt.total_seconds().dropna()
                
                p_score_t = 0.0
                fft_peak_t, autocorr_max_t, entropy_norm_t = 0.0, 0.0, 1.0
                
                if len(deltas) >= 5:
                    fft_peak_t, _ = self.calculate_fft(deltas)
                    autocorr_max_t = self.calculate_autocorrelation(deltas)
                    entropy_norm_t = self.calculate_entropy(deltas)
                    p_score_t = self.calculate_p_score(fft_peak_t, autocorr_max_t, entropy_norm_t)

                # Final Detection Fusion
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
                    'type': 'volume' if p_score_v >= p_score_t else 'sparse',
                    'fft_peak': max(fft_peak_v, fft_peak_t),
                    'autocorr_max': max(autocorr_max_v, autocorr_max_t),
                    'entropy_norm': min(entropy_norm_v, entropy_norm_t),
                    'samples': len(host_df)
                })
                
                # Prepare for Database Batch (Issue 7 + Phase 2 Enrichment)
                interval_est = 0.0
                if p_score_v >= p_score_t:
                    _, peak_f = self.calculate_fft(resampled)
                    interval_est = 1.0 / peak_f if peak_f > 0 else 0.0
                else:
                    # For sparse, the interval is directly in the deltas
                    interval_est = np.mean(deltas) if len(deltas) > 0 else 0.0

                db_batch.append((
                    host, p_score, 
                    max(fft_peak_v, fft_peak_t), 
                    max(autocorr_max_v, autocorr_max_t), 
                    min(entropy_norm_v, entropy_norm_t), 
                    len(host_df), detected,
                    interval_est, len(host_df), 30 # interval_est, signal_length, analysis_window
                ))

                if detected:
                    logging.info(f"BEACON DETECTED: host={host} p_score={p_score:.3f} interval={interval_est:.1f}s")
                    try:
                        out_dir = "/home/user/Desktop/c2/c2/output"
                        os.makedirs(out_dir, exist_ok=True)
                        
                        # Save Time Series
                        signal_to_save = resampled if p_score_v >= p_score_t else deltas
                        signal_to_save.to_csv(os.path.join(out_dir, f'time_series_{host}.csv'), header=['total_bytes'], index_label='ts' if p_score_v >= p_score_t else 'idx')
                        
                        # Save FFT Data (Task 4.1 benefit)
                        sig = signal_to_save.values if hasattr(signal_to_save, 'values') else np.array(signal_to_save)
                        sig = sig - np.mean(sig)
                        if np.std(sig) > 0: sig = sig / np.std(sig)
                        fft_vals = np.abs(np.fft.rfft(sig))
                        freqs = np.fft.rfftfreq(len(sig), d=1.0)
                        pd.DataFrame({'frequency': freqs, 'magnitude': fft_vals}).to_csv(os.path.join(out_dir, f'fft_{host}.csv'), index=False)
                        
                        # Save Autocorrelation Data
                        lags = range(1, min(len(sig), 50))
                        corrs = [np.corrcoef(sig[:-lag], sig[lag:])[0, 1] for lag in lags if (len(sig)-lag) > 1]
                        pd.DataFrame({'lag': list(lags)[:len(corrs)], 'correlation': corrs}).to_csv(os.path.join(out_dir, f'autocorr_{host}.csv'), index=False)
                        
                    except Exception as e:
                        logging.warning(f"Could not save plotting data for {host}: {e}")

            # Phase 1.2: Execute Batch Insert (Issue 7)
            if db_batch:
                cursor = conn.cursor()
                cursor.executemany("""
                    INSERT INTO detection_results (
                        host_ip, p_score, fft_peak, autocorr_max, entropy_norm, 
                        sample_count, detected, beacon_interval_estimate, 
                        signal_length, analysis_window
                    ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
                """, db_batch)
                conn.commit()
                cursor.close()
            
            # Improvement: Performance Logging (Task 6.2)
            end_perf = pytime.time()
            perf_file = "/home/user/Desktop/c2/c2/output/performance_metrics.csv"
            exists = os.path.exists(perf_file)
            with open(perf_file, 'a') as f:
                if not exists:
                    f.write("timestamp,hosts_analyzed,records_processed,analysis_time\n")
                f.write(f"{datetime.now().isoformat()},{hosts_analyzed},{len(df)},{end_perf - start_perf:.4f}\n")

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
