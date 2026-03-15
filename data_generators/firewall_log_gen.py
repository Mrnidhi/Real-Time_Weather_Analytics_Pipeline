"""
generates fake firewall logs that look somewhat realistic.
80% allow, 15% deny, 5% alert. business-hours bias for traffic volume.
sprinkles in some known-bad IPs at ~2% rate so the enrichment
pipeline has something to match against.
"""

import json
import random
import uuid
from datetime import datetime, timedelta
from ipaddress import IPv4Address


# some ranges to pick IPs from
INTERNAL_RANGES = ["10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"]
EXTERNAL_RANGE_START = int(IPv4Address("1.0.0.0"))
EXTERNAL_RANGE_END = int(IPv4Address("223.255.255.255"))

# these will show up as hits when we cross-reference with threat intel
KNOWN_BAD_IPS = [
    "45.33.32.156", "185.220.101.1", "91.219.236.222",
    "198.51.100.23", "203.0.113.42", "162.247.74.7",
    "185.56.83.83", "37.187.129.166", "178.73.215.171",
]

ACTIONS = ["allow"] * 80 + ["deny"] * 15 + ["alert"] * 5
PROTOCOLS = ["TCP", "UDP", "ICMP"]
COMMON_PORTS = [22, 53, 80, 443, 8080, 8443, 3389, 445, 25, 110]


def random_internal_ip():
    octet2 = random.randint(0, 255)
    octet3 = random.randint(0, 255)
    octet4 = random.randint(1, 254)
    return f"192.168.{octet2}.{octet3}" if random.random() < 0.6 else f"10.{octet2}.{octet3}.{octet4}"


def random_external_ip(inject_bad=False):
    if inject_bad and random.random() < 0.02:
        return random.choice(KNOWN_BAD_IPS)
    ip_int = random.randint(EXTERNAL_RANGE_START, EXTERNAL_RANGE_END)
    return str(IPv4Address(ip_int))


def generate_firewall_event(base_time, hour_offset_hours=0):
    ts = base_time + timedelta(hours=hour_offset_hours, seconds=random.randint(0, 3599))
    action = random.choice(ACTIONS)
    severity = {"allow": random.randint(1, 3), "deny": random.randint(4, 6), "alert": random.randint(7, 10)}[action]

    return {
        "event_id": str(uuid.uuid4()),
        "event_timestamp": ts.isoformat(),
        "source_type": "firewall",
        "source_ip": random_internal_ip(),
        "dest_ip": random_external_ip(inject_bad=True),
        "source_port": random.randint(1024, 65535),
        "dest_port": random.choice(COMMON_PORTS),
        "protocol": random.choice(PROTOCOLS),
        "action": action,
        "severity": severity,
        "raw_payload": {
            "rule_id": f"FW-{random.randint(1000, 9999)}",
            "bytes_sent": random.randint(64, 65535),
            "bytes_recv": random.randint(0, 131072),
            "session_duration_ms": random.randint(10, 300000),
        }
    }


def generate_firewall_logs(num_events=10000, start_date=None, output_path=None):
    """
    main entry point. generates num_events firewall log entries
    with realistic time distribution (more during business hours).
    """
    if start_date is None:
        start_date = datetime(2025, 1, 15, 0, 0, 0)

    events = []
    for i in range(num_events):
        # business hours get more traffic
        hour = random.choices(
            range(24),
            weights=[1,1,1,1,1,1,2,4,8,10,10,10,10,10,10,8,6,4,3,2,2,1,1,1],
            k=1
        )[0]
        day_offset = random.randint(0, 29)
        base = start_date + timedelta(days=day_offset)
        event = generate_firewall_event(base, hour)
        events.append(event)

    if output_path:
        with open(output_path, 'w') as f:
            for e in events:
                f.write(json.dumps(e) + '\n')
        print(f"wrote {len(events)} firewall events to {output_path}")

    return events


if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser()
    parser.add_argument("--count", type=int, default=10000)
    parser.add_argument("--output", type=str, default="data/raw/firewall_logs.jsonl")
    args = parser.parse_args()
    generate_firewall_logs(args.count, output_path=args.output)
