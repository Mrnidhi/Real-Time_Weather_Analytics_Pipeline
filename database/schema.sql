-- security events table, partitioned by month
-- using INET for IPs instead of varchar so we can do range queries natively
CREATE TABLE security_events (
    event_id        UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    event_timestamp TIMESTAMPTZ NOT NULL,
    source_type     VARCHAR(50) NOT NULL,
    source_ip       INET,
    dest_ip         INET,
    source_port     INTEGER,
    dest_port       INTEGER,
    protocol        VARCHAR(10),
    action          VARCHAR(20),
    severity        SMALLINT CHECK (severity BETWEEN 1 AND 10),
    raw_payload     JSONB,
    created_at      TIMESTAMPTZ DEFAULT NOW()
) PARTITION BY RANGE (event_timestamp);

-- create a few monthly partitions
CREATE TABLE security_events_2025_01 PARTITION OF security_events
    FOR VALUES FROM ('2025-01-01') TO ('2025-02-01');
CREATE TABLE security_events_2025_02 PARTITION OF security_events
    FOR VALUES FROM ('2025-02-01') TO ('2025-03-01');
CREATE TABLE security_events_2025_03 PARTITION OF security_events
    FOR VALUES FROM ('2025-03-01') TO ('2025-04-01');
CREATE TABLE security_events_2025_04 PARTITION OF security_events
    FOR VALUES FROM ('2025-04-01') TO ('2025-05-01');
CREATE TABLE security_events_2025_05 PARTITION OF security_events
    FOR VALUES FROM ('2025-05-01') TO ('2025-06-01');
CREATE TABLE security_events_2025_06 PARTITION OF security_events
    FOR VALUES FROM ('2025-06-01') TO ('2025-07-01');

-- threat intelligence indicators
CREATE TABLE threat_indicators (
    ioc_id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    indicator_type  VARCHAR(30) NOT NULL,  -- ip, domain, hash, url
    indicator_value TEXT NOT NULL,
    threat_type     VARCHAR(50),
    confidence      SMALLINT CHECK (confidence BETWEEN 0 AND 100),
    source_feed     VARCHAR(100),
    first_seen      TIMESTAMPTZ,
    last_seen       TIMESTAMPTZ,
    active          BOOLEAN DEFAULT TRUE,
    metadata        JSONB
);

-- when events match known IOCs, we create alerts here
CREATE TABLE correlated_alerts (
    alert_id        UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    event_id        UUID NOT NULL,
    ioc_id          UUID REFERENCES threat_indicators(ioc_id),
    correlation_type VARCHAR(30),
    risk_score      NUMERIC(5,2),
    genai_summary   TEXT,
    analyst_status  VARCHAR(20) DEFAULT 'new',
    created_at      TIMESTAMPTZ DEFAULT NOW()
);

-- summary stats that the dashboard queries hit
CREATE TABLE event_summaries (
    summary_id      SERIAL PRIMARY KEY,
    time_bucket     TIMESTAMPTZ NOT NULL,
    source_type     VARCHAR(50),
    total_events    BIGINT DEFAULT 0,
    threat_events   BIGINT DEFAULT 0,
    avg_severity    NUMERIC(4,2),
    top_source_ips  JSONB,
    created_at      TIMESTAMPTZ DEFAULT NOW()
);
