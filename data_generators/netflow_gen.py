"""
netflow record generator -- source/dest IP pairs with byte counts,
packet counts, and duration. simulates what you'd see from a
network tap or router export.
"""

import json
import random
import uuid
from datetime import datetime, timedelta


def generate_netflow_records(num_records=5000, start_date=None, output_path=None):
    if start_date is None:
        start_date = datetime(2025, 1, 15)

    records = []
    for _ in range(num_records):
        ts = start_date + timedelta(
            days=random.randint(0, 29),
            hours=random.randint(0, 23),
            seconds=random.randint(0, 3599)
        )

        src_ip = f"192.168.{random.randint(0,10)}.{random.randint(1,254)}"
        dst_ip = f"{random.randint(1,223)}.{random.randint(0,255)}.{random.randint(0,255)}.{random.randint(1,254)}"
        protocol = random.choices(["TCP", "UDP", "ICMP"], weights=[70, 25, 5], k=1)[0]

        # large byte counts on uncommon ports might be exfiltration
        is_anomalous = random.random() < 0.03
        bytes_out = random.randint(100000, 50000000) if is_anomalous else random.randint(64, 100000)

        record = {
            "event_id": str(uuid.uuid4()),
            "event_timestamp": ts.isoformat(),
            "source_type": "netflow",
            "source_ip": src_ip,
            "dest_ip": dst_ip,
            "source_port": random.randint(1024, 65535),
            "dest_port": random.choice([80, 443, 53, 22, 8080, 25, 993, random.randint(1, 65535)]),
            "protocol": protocol,
            "action": "flow",
            "severity": 8 if is_anomalous else random.randint(1, 3),
            "raw_payload": {
                "bytes_in": random.randint(64, bytes_out),
                "bytes_out": bytes_out,
                "packets_in": random.randint(1, 5000),
                "packets_out": random.randint(1, 5000),
                "duration_ms": random.randint(100, 600000),
                "tcp_flags": random.choice(["SYN", "SYN-ACK", "ACK", "FIN", "RST"]) if protocol == "TCP" else None,
            }
        }
        records.append(record)

    if output_path:
        with open(output_path, 'w') as f:
            for r in records:
                f.write(json.dumps(r) + '\n')
        print(f"wrote {len(records)} netflow records to {output_path}")

    return records


if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser()
    parser.add_argument("--count", type=int, default=5000)
    parser.add_argument("--output", type=str, default="data/raw/netflow_records.jsonl")
    args = parser.parse_args()
    generate_netflow_records(args.count, output_path=args.output)
