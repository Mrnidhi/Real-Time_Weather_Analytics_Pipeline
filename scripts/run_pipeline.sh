#!/bin/bash
# runs the full ETL pipeline
# make sure to generate seed data first: ./scripts/seed_data.sh

set -e

cd "$(dirname "$0")/.."

echo "running security analytics ETL pipeline..."
python3 processing/batch_etl.py

echo "pipeline complete. checking outputs..."
echo ""
echo "parquet files:"
find data/parquet -name "*.parquet" | head -20
echo ""
echo "done."
