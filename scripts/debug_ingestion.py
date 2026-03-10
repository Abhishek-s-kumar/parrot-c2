import os
import gzip
from datetime import datetime, timezone

def debug_parse():
    file_path = "/home/user/Desktop/c2/c2/datasets/iot23/scenario_1/conn.log.labeled"
    
    with open(file_path, 'r') as f:
        for line in f:
            if line.startswith('#'):
                continue
            
            # Using the same logic as the current load_labeled_dataset.py
            parts = line.rstrip('\n\r').split('\t')
            print(f"Parts length: {len(parts)}")
            
            try:
                # These indices are what were used in the latest version
                ts_epoch = float(parts[0])
                uid = parts[1]
                orig_h = parts[2]
                orig_p = int(parts[3])
                resp_h = parts[4]
                resp_p = int(parts[5])
                proto = parts[6]
                service = parts[7]
                duration = float(parts[8]) if parts[8] != '-' else 0.0
                orig_bytes = int(parts[9]) if parts[9] != '-' else 0
                resp_bytes = int(parts[10]) if parts[10] != '-' else 0
                conn_state = parts[11]
                local_orig = parts[12] == 'T'
                local_resp = parts[13] == 'T'
                missed_bytes = int(parts[14]) if parts[14] != '-' else 0
                history = parts[15]
                orig_pkts = int(parts[16]) if parts[16] != '-' else 0
                orig_ip_bytes = int(parts[17]) if parts[17] != '-' else 0
                resp_pkts = int(parts[18]) if parts[18] != '-' else 0
                resp_ip_bytes = int(parts[19]) if parts[19] != '-' else 0
                
                # Check 20-22
                print(f"Index 20: {parts[20]}")
                print(f"Index 21: {parts[21]}")
                # print(f"Index 22: {parts[22]}") # This might be the one!
                
                label_str = parts[21]
                print(f"Label found: {label_str}")
                break
            except Exception as e:
                import traceback
                print(f"Error on line: {line.strip()}")
                print(traceback.format_exc())
                break

if __name__ == "__main__":
    debug_parse()
