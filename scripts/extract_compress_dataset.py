import tarfile
import os
import gzip
import re

TAR_FILE = "/home/user/Desktop/c2/c2/datasets/iot_23_datasets_small.tar.gz"
OUT_DIR = "/home/user/Desktop/c2/c2/datasets/iot23"

os.makedirs(OUT_DIR, exist_ok=True)
print("Starting fast streaming extraction...")

try:
    with tarfile.open(TAR_FILE, 'r:gz') as tar:
        for member in tar:
            if member.isfile() and member.name.endswith("conn.log.labeled"):
                match = re.search(r"Capture-(\d+)", member.name)
                if not match:
                    continue
                
                scenario_num = match.group(1)
                scenario_dir = os.path.join(OUT_DIR, f"scenario_{scenario_num}")
                os.makedirs(scenario_dir, exist_ok=True)
                
                out_path = os.path.join(scenario_dir, "conn.log.labeled.gz")
                print(f"Extracting {member.name} -> {out_path}...")
                
                # Extract directly to gzip using a context manager
                # Using read in 10MB chunks to prevent memory blowup but maximize throughput
                f_in = tar.extractfile(member)
                if f_in:
                    with gzip.open(out_path, 'wb', compresslevel=6) as f_out:
                         while True:
                              chunk = f_in.read(1024 * 1024 * 10)
                              if not chunk:
                                   break
                              f_out.write(chunk)
                    f_in.close()

    print("Complete.")
except Exception as e:
    print(f"Error: {e}")
