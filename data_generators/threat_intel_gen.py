"""
generates fake threat intel indicators in a format loosely based on STIX.
includes malicious IPs, phishing domains (DGA-style), and file hashes.
confidence scores follow a realistic distribution -- mostly 50-80 range.
"""

import json
import random
import string
import hashlib
import uuid
from datetime import datetime, timedelta


# these match the KNOWN_BAD_IPS in firewall_log_gen so enrichment
# actually finds hits when we run the pipeline
MALICIOUS_IPS = [
    "45.33.32.156", "185.220.101.1", "91.219.236.222",
    "198.51.100.23", "203.0.113.42", "162.247.74.7",
    "185.56.83.83", "37.187.129.166", "178.73.215.171",
    "5.188.86.172", "77.247.181.162", "171.25.193.78",
]

THREAT_TYPES = ["malware", "phishing", "c2_server", "botnet", "ransomware", "apt"]
SOURCE_FEEDS = ["alienvault_otx", "abuseipdb", "internal_honeypot", "virustotal", "threatfox"]
TLD_LIST = [".com", ".net", ".xyz", ".info", ".ru", ".cn", ".tk"]


def random_dga_domain():
    """generates a domain that looks like DGA output"""
    length = random.randint(8, 16)
    name = ''.join(random.choices(string.ascii_lowercase + string.digits, k=length))
    tld = random.choice(TLD_LIST)
    return name + tld


def random_file_hash():
    data = str(uuid.uuid4()).encode()
    return hashlib.sha256(data).hexdigest()


def generate_threat_indicators(num_indicators=500, output_path=None):
    indicators = []
    base_date = datetime(2024, 6, 1)

    # always include the known bad IPs so the pipeline has guaranteed matches
    for ip in MALICIOUS_IPS:
        first_seen = base_date + timedelta(days=random.randint(0, 180))
        indicators.append({
            "ioc_id": str(uuid.uuid4()),
            "indicator_type": "ip",
            "indicator_value": ip,
            "threat_type": random.choice(THREAT_TYPES),
            "confidence": random.randint(70, 95),
            "source_feed": random.choice(SOURCE_FEEDS),
            "first_seen": first_seen.isoformat(),
            "last_seen": (first_seen + timedelta(days=random.randint(1, 90))).isoformat(),
            "active": True,
            "metadata": {"tags": random.sample(["tor_exit", "scanner", "brute_force", "c2_beacon", "spam"], k=2)}
        })

    # fill the rest with random indicators
    remaining = num_indicators - len(indicators)
    for _ in range(remaining):
        ioc_type = random.choices(["ip", "domain", "hash"], weights=[40, 35, 25], k=1)[0]
        first_seen = base_date + timedelta(days=random.randint(0, 300))

        if ioc_type == "ip":
            value = f"{random.randint(1,223)}.{random.randint(0,255)}.{random.randint(0,255)}.{random.randint(1,254)}"
        elif ioc_type == "domain":
            value = random_dga_domain()
        else:
            value = random_file_hash()

        indicators.append({
            "ioc_id": str(uuid.uuid4()),
            "indicator_type": ioc_type,
            "indicator_value": value,
            "threat_type": random.choice(THREAT_TYPES),
            "confidence": int(random.gauss(65, 15)),  # centered around 65
            "source_feed": random.choice(SOURCE_FEEDS),
            "first_seen": first_seen.isoformat(),
            "last_seen": (first_seen + timedelta(days=random.randint(1, 120))).isoformat(),
            "active": random.random() < 0.85,
            "metadata": {}
        })

    # clamp confidence to valid range
    for ind in indicators:
        ind["confidence"] = max(0, min(100, ind["confidence"]))

    if output_path:
        with open(output_path, 'w') as f:
            for ind in indicators:
                f.write(json.dumps(ind) + '\n')
        print(f"wrote {len(indicators)} threat indicators to {output_path}")

    return indicators


if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser()
    parser.add_argument("--count", type=int, default=500)
    parser.add_argument("--output", type=str, default="data/raw/threat_intel.jsonl")
    args = parser.parse_args()
    generate_threat_indicators(args.count, output_path=args.output)
