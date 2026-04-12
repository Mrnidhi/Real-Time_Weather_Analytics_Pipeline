"""
tests for the data generators -- make sure they produce valid data.
don't need spark for these, just pure python.
"""

import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

from data_generators.firewall_log_gen import generate_firewall_logs, KNOWN_BAD_IPS
from data_generators.threat_intel_gen import generate_threat_indicators, MALICIOUS_IPS
from data_generators.endpoint_telemetry_gen import generate_endpoint_events
from data_generators.netflow_gen import generate_netflow_records
from analytics.genai_summarizer import summarize_alert, _summarize_template


class TestFirewallGen:
    def test_generates_correct_count(self):
        events = generate_firewall_logs(100)
        assert len(events) == 100

    def test_has_required_fields(self):
        events = generate_firewall_logs(10)
        required = ["event_id", "event_timestamp", "source_type", "source_ip", "dest_ip", "severity"]
        for e in events:
            for field in required:
                assert field in e, f"missing {field}"

    def test_source_type_is_firewall(self):
        events = generate_firewall_logs(50)
        for e in events:
            assert e["source_type"] == "firewall"

    def test_severity_in_range(self):
        events = generate_firewall_logs(200)
        for e in events:
            assert 1 <= e["severity"] <= 10

    def test_injects_bad_ips(self):
        # with enough events, at least some should hit known bad IPs
        events = generate_firewall_logs(5000)
        dest_ips = {e["dest_ip"] for e in events}
        hits = dest_ips & set(KNOWN_BAD_IPS)
        assert len(hits) > 0, "no known bad IPs found in 5000 events"


class TestThreatIntelGen:
    def test_includes_known_malicious(self):
        indicators = generate_threat_indicators(100)
        values = {i["indicator_value"] for i in indicators}
        for ip in MALICIOUS_IPS:
            assert ip in values, f"missing known bad IP: {ip}"

    def test_confidence_in_range(self):
        indicators = generate_threat_indicators(200)
        for i in indicators:
            assert 0 <= i["confidence"] <= 100

    def test_has_multiple_types(self):
        indicators = generate_threat_indicators(200)
        types = {i["indicator_type"] for i in indicators}
        assert "ip" in types
        assert "domain" in types


class TestEndpointGen:
    def test_generates_events(self):
        events = generate_endpoint_events(100)
        assert len(events) == 100
        for e in events:
            assert e["source_type"] == "endpoint"


class TestNetflowGen:
    def test_generates_records(self):
        records = generate_netflow_records(100)
        assert len(records) == 100
        for r in records:
            assert r["source_type"] == "netflow"


class TestGenAISummarizer:
    def test_template_fallback(self):
        ctx = {
            "source_ip": "192.168.1.100",
            "dest_ip": "45.33.32.156",
            "ioc_threat_type": "c2_server",
            "event_count": 47,
            "duration_hours": 2.5,
            "risk_score": 85,
            "ioc_confidence": 90,
        }
        summary = _summarize_template(ctx)
        assert "192.168.1.100" in summary
        assert "47" in summary
        assert "beaconing" in summary.lower()

    def test_summarize_uses_template_by_default(self):
        # GENAI_PROVIDER defaults to "template"
        ctx = {"source_ip": "10.0.0.1", "dest_ip": "1.2.3.4",
               "ioc_threat_type": "malware", "event_count": 5,
               "duration_hours": 1.0, "risk_score": 40, "ioc_confidence": 60}
        summary = summarize_alert(ctx)
        assert len(summary) > 0
        assert "10.0.0.1" in summary
