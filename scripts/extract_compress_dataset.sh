#!/bin/bash
TAR_FILE="/home/user/Desktop/c2/c2/datasets/iot_23_datasets_small.tar.gz"
OUT_DIR="/home/user/Desktop/c2/c2/datasets/iot23"
mkdir -p "$OUT_DIR"

echo "Listing contents of archive..."
# Just list the contents quickly without uncompressing the payload data
tar -tf "$TAR_FILE" | grep "conn.log.labeled$" > /tmp/iot23_manifest.txt

echo "Found $(wc -l < /tmp/iot23_manifest.txt) labeled logs."

# Iterate through the manifest line by line
while read -r FILE; do
    SCENARIO_NUM=$(echo "$FILE" | grep -oE "Capture-[0-9]+" | cut -d'-' -f2)
    if [ -z "$SCENARIO_NUM" ]; then
        continue
    fi
    
    SCENARIO_DIR="$OUT_DIR/scenario_$SCENARIO_NUM"
    mkdir -p "$SCENARIO_DIR"
    OUT_FILE="$SCENARIO_DIR/conn.log.labeled.gz"
    
    # Skip if already extracted
    if [ -f "$OUT_FILE" ]; then
        echo "Skipping $OUT_FILE, already exists."
        continue
    fi
    
    echo "Extracting $FILE to $OUT_FILE..."
    # Extract only this specific file to stdout, and compress it immediately to disk
    tar -xzO -f "$TAR_FILE" "$FILE" | gzip -c > "$OUT_FILE"
    
done < /tmp/iot23_manifest.txt

echo "Extraction complete."
