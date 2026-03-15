"""
endpoint telemetry -- process starts, file writes, network connections
from simulated workstations. mimics what you'd get from an EDR agent.
"""

import json
import random
import uuid
from datetime import datetime, timedelta


PROCESS_NAMES = [
    "chrome.exe", "firefox.exe", "outlook.exe", "powershell.exe",
    "cmd.exe", "python.exe", "svchost.exe", "explorer.exe",
    "notepad.exe", "code.exe", "teams.exe", "slack.exe",
    "rundll32.exe", "wscript.exe",  # these two are sus
]

FILE_PATHS = [
    "C:\\Users\\{user}\\Downloads\\report.pdf",
    "C:\\Users\\{user}\\Desktop\\invoice.docx",
    "C:\\Windows\\Temp\\update.exe",
    "C:\\ProgramData\\svchost_update.dll",  # suspicious
    "/tmp/.hidden_script.sh",
]

USERS = ["jsmith", "mjones", "admin", "svc_account", "developer01"]


def generate_endpoint_events(num_events=5000, start_date=None, output_path=None):
    if start_date is None:
        start_date = datetime(2025, 1, 15)

    events = []
    for _ in range(num_events):
        ts = start_date + timedelta(
            days=random.randint(0, 29),
            hours=random.randint(0, 23),
            seconds=random.randint(0, 3599)
        )
        user = random.choice(USERS)
        proc = random.choice(PROCESS_NAMES)

        # powershell and wscript get higher severity
        is_suspicious = proc in ("powershell.exe", "wscript.exe", "rundll32.exe")
        severity = random.randint(5, 9) if is_suspicious else random.randint(1, 4)

        event = {
            "event_id": str(uuid.uuid4()),
            "event_timestamp": ts.isoformat(),
            "source_type": "endpoint",
            "source_ip": f"192.168.1.{random.randint(10, 200)}",
            "dest_ip": None,  # endpoint events don't always have a dest
            "source_port": None,
            "dest_port": None,
            "protocol": None,
            "action": "process_start" if random.random() < 0.6 else "file_write",
            "severity": severity,
            "raw_payload": {
                "hostname": f"WS-{random.randint(100, 999)}",
                "username": user,
                "process_name": proc,
                "parent_process": random.choice(["explorer.exe", "svchost.exe", "cmd.exe"]),
                "command_line": f"{proc} {'--encoded' if is_suspicious else ''}".strip(),
                "file_path": random.choice(FILE_PATHS).format(user=user) if random.random() < 0.4 else None,
            }
        }
        events.append(event)

    if output_path:
        with open(output_path, 'w') as f:
            for e in events:
                f.write(json.dumps(e) + '\n')
        print(f"wrote {len(events)} endpoint events to {output_path}")

    return events


if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser()
    parser.add_argument("--count", type=int, default=5000)
    parser.add_argument("--output", type=str, default="data/raw/endpoint_telemetry.jsonl")
    args = parser.parse_args()
    generate_endpoint_events(args.count, output_path=args.output)
