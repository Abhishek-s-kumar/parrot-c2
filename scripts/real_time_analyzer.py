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
        """Attempts to derive MAC from SLAAC IPv6 (Modified EUI-64)."""
        try:
            if not ipv6.startswith('fe80::'):
                return None
            
            # Extract IID part
            iid_str = ipv6.replace('fe80::', '')
            # Expanded representation (partial)
            parts = iid_str.split(':')
            if len(parts) < 2: return None
            
            # Handle cases like a00:27ff:fe4e:aa95
            full_hex = "".join(part.zfill(4) for part in parts)
            if 'fffe' not in full_hex: return None
            
            # e.g. 0a0027fffe4eaa95
            mac_raw = full_hex.replace('fffe', '')
            # 0a00274eaa95
            
            # Flip 7th bit of first byte
            first_byte = int(mac_raw[:2], 16)
            first_byte ^= 0x02
            
            mac_parts = [f"{first_byte:02x}"] + [mac_raw[i:i+2] for i in range(2, len(mac_raw), 2)]
            return ":".join(mac_parts)
        except:
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
        N = len(time_series)
        if N < 10:
            return 0.0, 0.0
        
        # Apply FFT on resp_bytes
        fft_result = np.fft.rfft(time_series.values)
        frequencies = np.fft.rfftfreq(N, d=1.0)
        
        magnitude = 2.0 / N * np.abs(fft_result)
        
        if len(magnitude) > 1:
            peak_magnitude = np.max(magnitude[1:])
            peak_idx = np.argmax(magnitude[1:]) + 1
            peak_frequency = frequencies[peak_idx]
            fft_peak = peak_magnitude / np.max(magnitude) if np.max(magnitude) > 0 else 0.0
        else:
            fft_peak = 0.0
            peak_frequency = 0.0
            
        return float(fft_peak), float(peak_frequency)

    def calculate_autocorrelation(self, time_series):
        if len(time_series) < 10:
            return 0.0
        
        # Check if the signal is purely zero or constant
        if np.all(time_series == time_series.iloc[0]):
            return 0.0

        ts_centered = time_series - np.mean(time_series)
        std = np.std(ts_centered)
        if std == 0:
            return 0.0
            
        autocorr = np.correlate(ts_centered, ts_centered, mode='full')
        autocorr = autocorr[len(autocorr)//2:]
        
        # Normalize by the zero-lag value (variance * N)
        if autocorr[0] > 0:
            autocorr = autocorr / autocorr[0]
            
        # For beacons, we look for secondary peaks
        # A good beacon should have a strong peak at its period
        if len(autocorr) > 10:
            # Skip the first few lags to avoid the main peak
            secondary_peaks = autocorr[5:300] if len(autocorr) > 300 else autocorr[5:]
            if len(secondary_peaks) > 0:
                autocorr_max = np.max(secondary_peaks)
            else:
                autocorr_max = 0.0
        else:
            autocorr_max = 0.0
            
        return float(autocorr_max)

    def calculate_entropy(self, time_series):
        if len(time_series) < 10:
            return 1.0
            
        # Use connection counts for entropy
        counts = time_series.values
        if np.sum(counts) == 0:
            return 1.0
            
        hist, _ = np.histogram(counts, bins=10, density=True)
        hist = hist[hist > 0]
        
        if len(hist) <= 1:
            return 0.0 # Highly regular if all samples in one bin
            
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
            
            for host in hosts:
                if not self._is_host_address(host):
                    continue

                host_df = df[df['id_orig_h'] == host].copy()
                host_df['conn_count'] = 1
                host_df.set_index('ts', inplace=True)
                
                # Resample to 5s intervals for clearer beacon patterns
                # This reduces noise from jitter and small timing variations
                resampled = host_df['conn_count'].resample('5s').sum().fillna(0)
                
                if len(host_df) < 5:
                    continue

                fft_peak, _ = self.calculate_fft(resampled)
                autocorr_max = self.calculate_autocorrelation(resampled)
                entropy_norm = self.calculate_entropy(resampled)
                p_score = self.calculate_p_score(fft_peak, autocorr_max, entropy_norm)
                
                # Threshold for detection
                detected = p_score > 0.45 
                
                mapping, mac_to_ipv4 = self._get_ip_mapping()
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
                    'fft_peak': fft_peak,
                    'autocorr_max': autocorr_max,
                    'entropy_norm': entropy_norm,
                    'samples': len(resampled),
                    'detected': detected
                })
                
                # Store in DB
                cursor = conn.cursor()
                cursor.execute("""
                    INSERT INTO detection_results (
                        host_ip, p_score, fft_peak, autocorr_max, entropy_norm, sample_count, detected
                    ) VALUES (%s, %s, %s, %s, %s, %s, %s)
                """, (host, p_score, fft_peak, autocorr_max, entropy_norm, len(resampled), detected))
                conn.commit()
                cursor.close()

                if detected:
                    logging.info(f"BEACON DETECTED: host={host} p_score={p_score:.3f} autocorr={autocorr_max:.3f}")

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
