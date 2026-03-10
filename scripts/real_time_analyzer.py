import os
import time
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
        
        self.p_threshold = float(self.weights_config.get('logic', 'p_threshold', fallback=0.55)) 
        self.ALPHA = float(self.weights_config.get('weights', 'fft_peak', fallback=0.30))
        self.BETA = float(self.weights_config.get('weights', 'autocorr_max', fallback=0.25))
        self.GAMMA = float(self.weights_config.get('weights', 'entropy_norm', fallback=0.15))
        self.DELTA = float(self.weights_config.get('weights', 'iat_variance', fallback=0.15))
        self.EPSILON = float(self.weights_config.get('weights', 'pkt_stability', fallback=0.15))
        
        self.window_low = int(self.weights_config.get('logic', 'window_low_rate', fallback=15))
        self.window_high = int(self.weights_config.get('logic', 'window_high_rate', fallback=5))
        self.rate_threshold = int(self.weights_config.get('logic', 'rate_threshold', fallback=5))
        self.z_threshold = float(self.weights_config.get('logic', 'z_threshold', fallback=2.5))

        self._ip_mapping_cache = (None, None)
        self._last_mapping_update = 0
        self.MONITOR_IP = '192.168.56.20'

    def _is_host_address(self, ip):
        """Returns True if the IP is likely a host (not broadcast/multicast/unspecified)."""
        if not ip or ip in ['0.0.0.0', '255.255.255.255', '::', self.MONITOR_IP]:
            return False

        # FOR THIS DATASET/EXPERIMENT: Only analyze local hosts (192.168.x.x)
        if not ip.startswith('192.168.'):
            return False

        # IPv4 Multicast (224.0.0.0/4)
        if ip.startswith(('224.', '225.', '226.', '227.', '228.', '229.', '230.', '231.', '232.', '233.', '234.', '235.', '236.', '237.', '238.', '239.')):
            return False

        # IPv6 Multicast (ff00::/8)
        if ip.lower().startswith('ff'):
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

    def _get_ip_mapping(self, active_hosts=None):
        """Builds a mapping of IPv6 to IPv4 based on combined ARP (IPv4) and NDP (IPv6) tables."""
        import time
        now = time.time()
        if self._ip_mapping_cache[0] is not None and (now - self._last_mapping_update) < 120:
            return self._ip_mapping_cache

        mapping = {}
        mac_to_ipv4 = {}
        mac_to_ipv6 = {}
        
        try:
            # Proactively populate ARP and NDP tables by pinging active hosts
            import subprocess
            if active_hosts:
                for h in active_hosts:
                    if h != self.MONITOR_IP:
                        if ':' in h:
                            # Ping IPv6 (NDP)
                            subprocess.Popen(['ping6', '-c', '1', '-W', '1', h], 
                                           stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                        elif '.' in h:
                            # Ping IPv4 (ARP)
                            subprocess.Popen(['ping', '-c', '1', '-W', '1', h], 
                                           stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                time.sleep(0.5) # Give ARP/NDP a moment to resolve

            # 1. Collect IPv4 Neighbors (ARP)
            output_v4 = subprocess.check_output(['ip', 'neigh', 'show'], stderr=subprocess.STDOUT).decode()
            for line in output_v4.splitlines():
                parts = line.split()
                if len(parts) >= 5 and 'lladdr' in parts:
                    ip = parts[0]
                    mac = parts[parts.index('lladdr') + 1].lower()
                    if '.' in ip: # IPv4
                        mac_to_ipv4[mac] = ip

            # 2. Collect IPv6 Neighbors (NDP)
            output_v6 = subprocess.check_output(['ip', '-6', 'neigh', 'show'], stderr=subprocess.STDOUT).decode()
            for line in output_v6.splitlines():
                parts = line.split()
                if len(parts) >= 5 and 'lladdr' in parts:
                    ip = parts[0]
                    mac = parts[parts.index('lladdr') + 1].lower()
                    if ':' in ip: # IPv6
                        if mac not in mac_to_ipv6:
                            mac_to_ipv6[mac] = []
                        mac_to_ipv6[mac].append(ip)

            # 3. Unify them (MAC -> Primary IP)
            for mac, ipv6_list in mac_to_ipv6.items():
                if mac in mac_to_ipv4:
                    primary_ip = mac_to_ipv4[mac]
                    for ipv6 in ipv6_list:
                        mapping[ipv6] = primary_ip
                else:
                    primary_ip = ipv6_list[0]
                    for ipv6 in ipv6_list[1:]:
                        mapping[ipv6] = primary_ip
                        
            # Also catch any stray mapped IPv6s from output_v4
            for line in output_v4.splitlines():
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
            return 0.0 # High regularity (constant signal) - Updated per research guide
            
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

    def calculate_iat_variance_score(self, deltas):
        """Measure consistency of inter-arrival times. Low variance = High Score."""
        if len(deltas) < 5:
            return 0.0
        
        mean = np.mean(deltas)
        if mean == 0:
            return 0.0
            
        cv = np.std(deltas) / mean
        score = 1.0 - cv
        return float(np.clip(score, 0, 1))

    def calculate_pkt_stability_score(self, host_df):
        """Measure consistency of packet sizes (total bytes per connection). High = stable = suspicious."""
        sizes = (host_df['orig_bytes'].fillna(0) + host_df['resp_bytes'].fillna(0))
        # Filter out 0-byte TCP control packets (like REJ/ACK) to find the true payload stability
        payload_sizes = sizes[sizes > 0]
        
        # If all packets were 0 bytes, or too few payloads, evaluate all packets
        eval_sizes = payload_sizes if len(payload_sizes) >= 5 else sizes
        
        if len(eval_sizes) < 5:
            return 0.0
            
        mean = np.mean(eval_sizes)
        if mean == 0:
            return 1.0 # All-zero packets are maximally stable
            
        cv = np.std(eval_sizes) / mean
        return float(np.clip(1.0 - cv, 0, 1))

    def calculate_destination_diversity(self, host_df):
        """Single destination = maximally suspicious (score=1). Many = benign (score near 0)."""
        # Filter out broadcast/multicast noise that dilutes the C2 destination count
        dests = host_df['id_resp_h'].dropna().astype(str)
        dests = dests[
            ~dests.str.endswith('.255') & 
            ~dests.str.startswith('224.') & 
            ~dests.str.startswith('ff') &
            (dests != '255.255.255.255')
        ]
        
        unique_dests = dests.nunique()
        if unique_dests == 0:
            return 1.0 # If only broadcast traffic exists, or 1 destination, penalize
        return float(np.clip(1.0 / unique_dests, 0, 1))

    def calculate_session_duration_score(self, host_df):
        """Short sessions = C2-like (score near 1). Long sessions = benign (score near 0)."""
        mean_dur = host_df['duration'].dropna().mean()
        if np.isnan(mean_dur) or mean_dur < 0:
            return 0.5 # Unknown duration is neutral
        return float(np.clip(1.0 / (1.0 + mean_dur), 0, 1))

    def calculate_destination_reputation(self, host_df):
        """Traffic ONLY to trusted IPs = score 0. All untrusted = score 1."""
        TRUSTED_IPS = {'8.8.8.8', '8.8.4.4', '1.1.1.1', '1.0.0.1', '9.9.9.9',
                       '208.67.222.222', '208.67.220.220'}
        dests = set(host_df['id_resp_h'].dropna().astype(str).unique())
        if not dests:
            return 0.5
        suspicious = dests - TRUSTED_IPS
        return float(len(suspicious) / len(dests))

    def calculate_final_score(self, periodicity_score, dest_diversity, pkt_stability,
                              session_score, dest_reputation):
        """Two-part 60/40 behavioral fusion per spec."""
        behavior_score = (
            0.30 * dest_diversity +
            0.20 * pkt_stability +
            0.10 * session_score +
            0.10 * dest_reputation
        )
        return float(np.clip(0.6 * periodicity_score + 0.4 * behavior_score, 0, 1))

    def calculate_p_score(self, fft_peak, autocorr_max, entropy_norm, iat_var_score, pkt_stab_score):
        """Legacy periodicity-only score (kept for internal use as periodicity_score component)."""
        P_SCORE = (
            self.ALPHA * fft_peak +
            self.BETA * autocorr_max +
            self.GAMMA * (1.0 - entropy_norm) +
            self.DELTA * iat_var_score +
            self.EPSILON * pkt_stab_score
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
            
            # Query recent traffic from conn_log
            # Pull all fields needed for behavioral analysis
            query = """
                SELECT id_orig_h, id_resp_h, ts, orig_bytes, resp_bytes, duration,
                       local_orig, local_resp, orig_l2_addr, resp_l2_addr
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
            
            start_perf = time.time()
            
            # Compute host_mac and host_ip:
            # We prefer the ORIGINATOR side (orig_l2_addr / id_orig_h) as the primary host identity
            # because in a C2 scenario, the victim machine INITIATES the beacon callout.
            # Define a unified host_id: Use MAC if available, otherwise fall back to IP.
            # We use the 'local_orig' and 'local_resp' flags from Zeek to determine the local host.
            # Optimized host identity assignment using vector operations
            def get_lo(v): return str(v).lower() in ('true', 't', '1')
            def get_lr(v): return str(v).lower() in ('true', 't', '1')
            
            lo_mask = df['local_orig'].apply(get_lo)
            lr_mask = df['local_resp'].apply(get_lr)
            
            # Case 1: Local Originator or (not local orig and not local resp)
            mask1 = lo_mask | (~lo_mask & ~lr_mask)
            # Case 2: Local Responder (only if not caught by Case 1)
            mask2 = ~mask1 & lr_mask
            
            df['host_id'] = None
            df['host_ip_clean'] = None
            
            # Prefer MAC if available, fallback to IP
            df.loc[mask1, 'host_id'] = df.loc[mask1, 'orig_l2_addr'].where(df.loc[mask1, 'orig_l2_addr'].notna() & (df.loc[mask1, 'orig_l2_addr'] != '-'), df.loc[mask1, 'id_orig_h'])
            df.loc[mask1, 'host_ip_clean'] = df.loc[mask1, 'id_orig_h']
            
            df.loc[mask2, 'host_id'] = df.loc[mask2, 'resp_l2_addr'].where(df.loc[mask2, 'resp_l2_addr'].notna() & (df.loc[mask2, 'resp_l2_addr'] != '-'), df.loc[mask2, 'id_resp_h'])
            df.loc[mask2, 'host_ip_clean'] = df.loc[mask2, 'id_resp_h']
            
            df = df.dropna(subset=['host_id'])
            df = df.dropna(subset=['host_id'])
            
            # Filter for valid local host IDs (exclude broadcast/multicast)
            df = df[df['host_ip_clean'].apply(self._is_host_address)]

            if df.empty:
                print(f"No valid local host traffic found in the last {window_minutes} minutes.")
                return []

            # Group natively by the unified host_id
            host_ids = df['host_id'].unique()
            
            hosts_analyzed = 0
            for hid in host_ids:
                host_df = df[df['host_id'] == hid].copy()
                
                # Use the most frequent IP for this host_id as the display IP
                display_ip = host_df['host_ip_clean'].mode()[0] if not host_df['host_ip_clean'].empty else '0.0.0.0'
                
                hosts_analyzed += 1
                
                if len(host_df) < 3:  # Minimum samples needed for analysis
                    continue

                # --- Improvement 2: Adaptive Windowing (Task 4.2) ---
                # Calculate simple rate: events per minute in the window
                events_per_min = len(host_df) / window_minutes
                step = f"{self.window_low}s" if events_per_min < self.rate_threshold else f"{self.window_high}s"

                # --- Type 1: Periodic Volume ---
                host_df_v = host_df.copy()
                host_df_v['conn_count'] = 1
                host_df_v.set_index('ts', inplace=True)
                resampled = host_df_v['conn_count'].resample(step).sum().fillna(0)
                
                p_score_v = 0.0
                fft_peak_v, autocorr_max_v, entropy_norm_v = 0.0, 0.0, 1.0
                iat_score_v, pkt_score_v = 0.0, 0.0
                
                if len(resampled) >= 5:
                    fft_peak_v, _ = self.calculate_fft(resampled)
                    autocorr_max_v = self.calculate_autocorrelation(resampled)
                    entropy_norm_v = self.calculate_entropy(resampled)
                    iat_score_v = self.calculate_iat_variance_score(resampled.values)
                    pkt_score_v = self.calculate_pkt_stability_score(host_df)
                    p_score_v = self.calculate_p_score(fft_peak_v, autocorr_max_v, entropy_norm_v, iat_score_v, pkt_score_v)

                # --- Type 2: Sparse Events ---
                host_df_t = host_df.sort_values('ts')
                deltas = host_df_t['ts'].diff().dt.total_seconds().dropna()
                
                p_score_t = 0.0
                fft_peak_t, autocorr_max_t, entropy_norm_t = 0.0, 0.0, 1.0
                iat_score_t, pkt_score_t = 0.0, 0.0
                
                if len(deltas) >= 5:
                    fft_peak_t, _ = self.calculate_fft(deltas)
                    autocorr_max_t = self.calculate_autocorrelation(deltas)
                    entropy_norm_t = self.calculate_entropy(deltas)
                    iat_score_t = self.calculate_iat_variance_score(deltas.values)
                    pkt_score_t = pkt_score_v # Reuse packet stability from same host
                    p_score_t = self.calculate_p_score(fft_peak_t, autocorr_max_t, entropy_norm_t, iat_score_t, pkt_score_t)

                # --- Behavioral Features (Improvement 2) ---
                dest_diversity = self.calculate_destination_diversity(host_df)
                session_score = self.calculate_session_duration_score(host_df)
                dest_reputation = self.calculate_destination_reputation(host_df)

                # --- Final Detection Fusion (60% periodicity + 40% behavior) ---
                periodicity_score = max(p_score_v, p_score_t)
                best_pkt_stability = max(pkt_score_v, pkt_score_t) if pkt_score_v or pkt_score_t else self.calculate_pkt_stability_score(host_df)
                p_score = self.calculate_final_score(
                    periodicity_score, dest_diversity, best_pkt_stability,
                    session_score, dest_reputation
                )
                detected = p_score > self.p_threshold
                
                results.append({
                    'host': display_ip,
                    'display_host': display_ip,
                    'p_score': p_score,
                    'detected': detected,
                    'detection_type': 'beacon',
                    'fft_peak': max(fft_peak_v, fft_peak_t),
                    'autocorr_max': max(autocorr_max_v, autocorr_max_t),
                    'entropy_norm': min(entropy_norm_v, entropy_norm_t),
                    'iat_score': max(iat_score_v, iat_score_t),
                    'pkt_score': best_pkt_stability,
                    'dest_diversity': round(dest_diversity, 3),
                    'session_score': round(session_score, 3),
                    'dest_reputation': round(dest_reputation, 3),
                    'samples': len(host_df)
                })
                
                # Prepare for Database Batch
                interval_est = 0.0
                if p_score_v >= p_score_t:
                    _, peak_f = self.calculate_fft(resampled)
                    interval_est = float(1.0 / peak_f if peak_f > 0 else 0.0)
                else:
                    interval_est = float(np.mean(deltas)) if len(deltas) > 0 else 0.0

                db_batch.append((
                    str(display_ip),
                    float(p_score),
                    float(max(fft_peak_v, fft_peak_t)),
                    float(max(autocorr_max_v, autocorr_max_t)),
                    float(min(entropy_norm_v, entropy_norm_t)),
                    int(len(host_df)),
                    bool(detected),
                    float(interval_est),
                    int(len(host_df)),
                    int(30)
                ))

                if detected:
                    logging.info(f"BEACON DETECTED: host={hid} ip={display_ip} p_score={p_score:.3f} interval={interval_est:.1f}s")
                    try:
                        out_dir = "/home/user/Desktop/c2/c2/output"
                        os.makedirs(out_dir, exist_ok=True)
                        
                        # Save Time Series
                        signal_to_save = resampled if p_score_v >= p_score_t else deltas
                        signal_to_save.to_csv(os.path.join(out_dir, f'time_series_{display_ip}.csv'), header=['total_bytes'], index_label='ts' if p_score_v >= p_score_t else 'idx')
                        
                        # Save FFT Data (Task 4.1 benefit)
                        sig = signal_to_save.values if hasattr(signal_to_save, 'values') else np.array(signal_to_save)
                        sig = sig - np.mean(sig)
                        if np.std(sig) > 0: sig = sig / np.std(sig)
                        fft_vals = np.abs(np.fft.rfft(sig))
                        freqs = np.fft.rfftfreq(len(sig), d=1.0)
                        pd.DataFrame({'frequency': freqs, 'magnitude': fft_vals}).to_csv(os.path.join(out_dir, f'fft_{display_ip}.csv'), index=False)
                        
                        # Save Autocorrelation Data
                        lags_list = list(range(1, min(len(sig), 50)))
                        sig_arr = np.array(sig)
                        corrs = [np.corrcoef(sig_arr[:-lag], sig_arr[lag:])[0, 1] for lag in lags_list if (len(sig_arr)-lag) > 1]
                        pd.DataFrame({'lag': lags_list[:len(corrs)], 'correlation': corrs}).to_csv(os.path.join(out_dir, f'autocorr_{display_ip}.csv'), index=False)
                        
                    except Exception as e:
                        logging.warning(f"Could not save plotting data for {display_ip}: {e}")

            # Phase 2.2: Z-Score Anomaly Detection
            sample_counts = [r['samples'] for r in results]
            if len(sample_counts) >= 2:
                mu = np.mean(sample_counts)
                sigma = np.std(sample_counts)
                
                for r in results:
                    z = (r['samples'] - mu) / (sigma + 1e-9)
                    r['z_score'] = float(round(z, 3))
                    
                    if abs(z) > self.z_threshold:
                        r['detected'] = True
                        r['detection_type'] = 'anomaly'
                        logging.info(f"ANOMALY DETECTED: host={r['host']} z_score={z:.3f} samples={r['samples']}")

            # Phase 1.2: Execute Batch Insert (Real-time update moved out of loop for performance, but committing now)
            if db_batch:
                cursor = conn.cursor()
                try:
                    query = """
                        INSERT INTO detection_results (
                            host_ip, p_score, fft_peak, autocorr_max, entropy_norm, 
                            sample_count, detected, beacon_interval_estimate, 
                            signal_length, analysis_window, detection_type
                        ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
                    """
                    # Ensure alignment between db_batch and results
                    insert_data = []
                    for i, b in enumerate(db_batch):
                        dtype = results[i]['detection_type'] if i < len(results) else 'beacon'
                        insert_data.append(b + (dtype,))
                    
                    cursor.executemany(query, insert_data)
                    conn.commit()
                except Exception as e:
                    logging.error(f"Failed to insert detections: {e}")
                    conn.rollback()
                finally:
                    cursor.close()
            
            # Improvement: Performance Logging (Task 6.2)
            end_perf = time.time()
            perf_file = "/home/user/Desktop/c2/c2/output/performance_metrics.csv"
            exists = os.path.exists(perf_file)
            with open(perf_file, 'a') as f:
                if not exists:
                    f.write("timestamp,hosts_analyzed,records_processed,analysis_time\n")
                f.write(f"{datetime.now().isoformat()},{hosts_analyzed},{len(df)},{end_perf - start_perf:.4f}\n")
            logging.info(f"Analysis finished: {hosts_analyzed} hosts analyzed in {end_perf - start_perf:.2f}s")

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
                SELECT orig_l2_addr as mac, id_orig_h as host, MAX(ts) as last_seen FROM conn_log WHERE ts >= %s AND ts <= %s AND orig_l2_addr IS NOT NULL AND orig_l2_addr != '-' GROUP BY orig_l2_addr, id_orig_h
                UNION
                SELECT resp_l2_addr as mac, id_resp_h as host, MAX(ts) as last_seen FROM conn_log WHERE ts >= %s AND ts <= %s AND resp_l2_addr IS NOT NULL AND resp_l2_addr != '-' GROUP BY resp_l2_addr, id_resp_h
                ORDER BY last_seen DESC
            """
            df = pd.read_sql_query(query, conn, params=(start_time, end_time, start_time, end_time))

            if df.empty:
                return []

            # Group natively by hardware MAC address 
            # Prefer IPv4 as primary display IP
            mac_to_display_ip = {}
            for _, row in df.iterrows():
                mac = row['mac']
                ip = row['host']
                if mac not in mac_to_display_ip:
                    mac_to_display_ip[mac] = ip
                elif '.' in ip and ':' in mac_to_display_ip[mac]:
                    mac_to_display_ip[mac] = ip

            df['display_host'] = df.apply(lambda row: mac_to_display_ip.get(row['mac'], row['host']), axis=1)
            
            # Group again after mapping to merge the last_seen times for the same MAC
            df = df.groupby('display_host', as_index=False)['last_seen'].max()
            df = df.sort_values('last_seen', ascending=False)
            
            systems = []
            for _, row in df.iterrows():
                host = row['display_host'] # This is the primary IPv4
                if not self._is_host_address(host):
                    continue
                    
                last_seen = row['last_seen']
                
                systems.append({
                    'host': host,
                    'display_host': host,
                    'last_seen': last_seen.isoformat() if isinstance(last_seen, datetime) else str(last_seen)
                })
            
            return systems

        except Exception as e:
            logging.error(f"Error fetching online systems: {e}")
            return []
        finally:
            conn.close()

def main():
    import argparse
    parser = argparse.ArgumentParser(description='C2 Detection Engine')
    parser.add_argument('--window', type=int, default=60, help='Analysis window in minutes')
    args = parser.parse_args()
    
    config = configparser.ConfigParser()
    config.read('/home/user/Desktop/c2/c2/config/database.conf')
    db_config = config['database']
    
    engine = DetectionEngine(db_config)
    results = engine.analyze_recent_traffic(window_minutes=args.window) or []
    print(f"Analyzed {len(results)} hosts.")

if __name__ == "__main__":
    main()
