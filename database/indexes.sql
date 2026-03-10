-- indexes tuned for the queries we actually run

-- events: most queries filter by IP or time range
CREATE INDEX idx_events_src_ip ON security_events (source_ip);
CREATE INDEX idx_events_dst_ip ON security_events (dest_ip);
CREATE INDEX idx_events_ts ON security_events (event_timestamp DESC);

-- only index high-severity stuff, no point indexing severity=1 noise
CREATE INDEX idx_events_severity_high ON security_events (severity)
    WHERE severity >= 7;

-- GIN for searching inside the jsonb payload
CREATE INDEX idx_events_payload ON security_events USING GIN (raw_payload);

-- IOC lookups: we almost always filter by active=true
CREATE INDEX idx_iocs_active ON threat_indicators (indicator_value)
    WHERE active = TRUE;
CREATE INDEX idx_iocs_type ON threat_indicators (indicator_type, indicator_value);

-- alerts: usually sorted by risk score for the dashboard
CREATE INDEX idx_alerts_risk ON correlated_alerts (risk_score DESC, created_at DESC);
CREATE INDEX idx_alerts_status ON correlated_alerts (analyst_status)
    WHERE analyst_status = 'new';

-- summaries: time-series queries
CREATE INDEX idx_summaries_time ON event_summaries (time_bucket DESC);
