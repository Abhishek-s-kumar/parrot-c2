#!/bin/bash

# Configuration
DB_NAME="c2db"
DB_USER="c2user"
DB_HOST="127.0.0.1"
export PGPASSWORD="c2password"

echo "=== C2 Database Console ==="
echo "Host: $DB_HOST"
echo "Database: $DB_NAME"
echo "User: $DB_USER"
echo "---------------------------"
echo "Usage Tips:"
echo "  \dt                - List tables"
echo "  SELECT * FROM ...; - Run a query (end with semicolon)"
echo "  \q                 - Quit"
echo "---------------------------"

psql -h "$DB_HOST" -U "$DB_USER" -d "$DB_NAME"
