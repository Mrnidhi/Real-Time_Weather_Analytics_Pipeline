"""
pre-built SQL queries for the dashboard / analytics layer.
these would normally be run against the postgres instance
or against the parquet files via spark sql.
"""


# top 10 riskiest alerts
TOP_ALERTS = """
SELECT 
    ca.alert_id,
    ca.risk_score,
    ca.correlation_type,
    ca.genai_summary,
    ti.indicator_value,
    ti.threat_type,
    ti.confidence
FROM correlated_alerts ca
JOIN threat_indicators ti ON ca.ioc_id = ti.ioc_id
WHERE ca.analyst_status = 'new'
ORDER BY ca.risk_score DESC
LIMIT 10;
"""

# event volume by source type (last 7 days)
EVENT_VOLUME = """
SELECT 
    source_type,
    DATE(event_timestamp) as event_date,
    COUNT(*) as event_count,
    AVG(severity) as avg_severity,
    COUNT(*) FILTER (WHERE severity >= 7) as high_severity_count
FROM security_events
WHERE event_timestamp >= NOW() - INTERVAL '7 days'
GROUP BY source_type, DATE(event_timestamp)
ORDER BY event_date DESC, event_count DESC;
"""

# most contacted malicious IPs
HOT_IOCS = """
SELECT 
    ti.indicator_value,
    ti.threat_type,
    COUNT(DISTINCT se.source_ip) as unique_sources,
    COUNT(*) as total_connections,
    MAX(se.severity) as max_severity
FROM security_events se
JOIN threat_indicators ti 
    ON se.dest_ip::text = ti.indicator_value
WHERE ti.active = TRUE
GROUP BY ti.indicator_value, ti.threat_type
HAVING COUNT(*) > 5
ORDER BY total_connections DESC
LIMIT 20;
"""

# internal hosts with most threat connections (potential compromised hosts)
COMPROMISED_HOSTS = """
SELECT 
    se.source_ip,
    COUNT(DISTINCT se.dest_ip) as unique_bad_dests,
    COUNT(*) as total_bad_connections,
    ARRAY_AGG(DISTINCT ti.threat_type) as threat_types,
    MAX(ca.risk_score) as max_risk_score
FROM security_events se
JOIN correlated_alerts ca ON se.event_id = ca.event_id
JOIN threat_indicators ti ON ca.ioc_id = ti.ioc_id
GROUP BY se.source_ip
HAVING COUNT(*) > 3
ORDER BY max_risk_score DESC;
"""

# hourly event distribution (for detecting anomalous spikes)
HOURLY_DISTRIBUTION = """
SELECT 
    EXTRACT(HOUR FROM event_timestamp) as hour_of_day,
    source_type,
    COUNT(*) as event_count,
    AVG(severity) as avg_severity
FROM security_events
WHERE event_timestamp >= NOW() - INTERVAL '24 hours'
GROUP BY EXTRACT(HOUR FROM event_timestamp), source_type
ORDER BY hour_of_day;
"""
