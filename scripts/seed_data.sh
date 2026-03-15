#!/bin/bash
# generates seed data for the pipeline
# run this before running the ETL to have something to process

set -e

cd "$(dirname "$0")/.."

echo "generating firewall logs..."
python3 data_generators/firewall_log_gen.py --count 20000 --output data/raw/firewall_logs.jsonl

echo "generating endpoint telemetry..."
python3 data_generators/endpoint_telemetry_gen.py --count 10000 --output data/raw/endpoint_telemetry.jsonl

echo "generating netflow records..."
python3 data_generators/netflow_gen.py --count 10000 --output data/raw/netflow_records.jsonl

echo "generating threat intel feed..."
python3 data_generators/threat_intel_gen.py --count 500 --output data/raw/threat_intel.jsonl

echo "done. data written to data/raw/"
ls -lh data/raw/
