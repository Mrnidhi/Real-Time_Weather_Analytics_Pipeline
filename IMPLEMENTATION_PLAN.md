# Hyperscale Data Lake & Security Analytics Engine — Implementation Plan

## 1. Project Overview

A unified hyperscale data lake prototype using Apache Spark to ingest, process, and analyze massive simulated threat intelligence logs across a distributed computing cluster, with PostgreSQL for structured persistence and GenAI-driven summarization of security events.

> **Interview Narrative:** "I built a data lake prototype that ingests simulated threat intelligence feeds — think STIX/TAXII-format IOCs, firewall logs, endpoint telemetry — processes them through Spark for enrichment and correlation, stores structured results in PostgreSQL with ACID guarantees, and uses a GenAI layer to dynamically summarize security events for SOC analysts."

---

## 2. Architecture

```
┌──────────────────────────────────────────────────────────────┐
│                    Data Sources (Simulated)                    │
│  ┌─────────┐  ┌──────────┐  ┌──────────────┐  ┌───────────┐ │
│  │Firewall │  │ Endpoint │  │  Threat Intel│  │  NetFlow  │ │
│  │  Logs   │  │Telemetry │  │  (STIX IOCs) │  │   Data    │ │
│  └────┬────┘  └────┬─────┘  └──────┬───────┘  └─────┬─────┘ │
└───────┼────────────┼───────────────┼─────────────────┼───────┘
        │            │               │                 │
        ▼            ▼               ▼                 ▼
┌──────────────────────────────────────────────────────────────┐
│              Ingestion Layer (Python Producers)               │
│         Kafka Topics / Direct File-Based Ingestion            │
└──────────────────────────┬───────────────────────────────────┘
                           │
                           ▼
┌──────────────────────────────────────────────────────────────┐
│                  Processing Layer (Apache Spark)              │
│  ┌────────────┐  ┌───────────────┐  ┌─────────────────────┐ │
│  │ Batch ETL  │  │  Enrichment   │  │  Correlation Engine │ │
│  │ (PySpark)  │  │  (IOC Lookup) │  │  (Threat Matching)  │ │
│  └────────────┘  └───────────────┘  └─────────────────────┘ │
└──────────────────────────┬───────────────────────────────────┘
                           │
              ┌────────────┼────────────┐
              ▼            ▼            ▼
┌──────────────────┐ ┌──────────┐ ┌──────────────────┐
│  Raw Data Lake   │ │PostgreSQL│ │  GenAI Analytics  │
│ (Parquet/Delta)  │ │(Enriched │ │  (Event Summary)  │
│                  │ │  Data)   │ │                   │
└──────────────────┘ └──────────┘ └──────────────────┘
```

---

## 3. Directory Structure

```
hyperscale-data-lake/
├── README.md
├── docker-compose.yml           # Spark cluster + PostgreSQL + (optional Kafka)
├── requirements.txt
├── config/
│   ├── spark_config.py          # Spark session configuration
│   ├── db_config.py             # PostgreSQL connection settings
│   └── logging_config.py        # Structured logging setup
├── data_generators/
│   ├── firewall_log_gen.py      # Simulates firewall logs
│   ├── endpoint_telemetry_gen.py# Simulates endpoint events
│   ├── threat_intel_gen.py      # Generates STIX-format IOCs
│   └── netflow_gen.py           # Simulates NetFlow records
├── ingestion/
│   ├── file_ingestor.py         # Reads raw files into Spark
│   ├── kafka_producer.py        # Publishes to Kafka topics (optional)
│   └── schema_registry.py       # Enforces schemas on ingestion
├── processing/
│   ├── batch_etl.py             # Main Spark ETL pipeline
│   ├── enrichment.py            # IOC lookup, GeoIP enrichment
│   ├── correlation_engine.py    # Correlates events across sources
│   └── transformations.py       # Shared UDFs and transforms
├── storage/
│   ├── data_lake_writer.py      # Writes Parquet/Delta to data lake
│   ├── postgres_writer.py       # Writes enriched data to PostgreSQL
│   └── partitioning.py          # Partition strategies (time, source)
├── analytics/
│   ├── genai_summarizer.py      # GenAI-driven event summarization
│   ├── threat_scorer.py         # Risk scoring logic
│   └── dashboard_queries.py     # Pre-built analytical queries
├── database/
│   ├── schema.sql               # PostgreSQL DDL
│   ├── indexes.sql              # Performance indexes
│   └── migrations/              # Schema migration scripts
├── tests/
│   ├── test_etl.py
│   ├── test_enrichment.py
│   ├── test_correlation.py
│   └── test_genai.py
└── scripts/
    ├── setup_cluster.sh         # Initialize Spark cluster
    ├── seed_data.sh             # Generate and load seed data
    └── run_pipeline.sh          # End-to-end pipeline execution
```

---

## 4. PostgreSQL Schema (KEY RESUME CLAIM: ACID + High-Concurrency)

### 4.1 Core Tables

```sql
-- Raw security events (partitioned by timestamp)
CREATE TABLE security_events (
    event_id        UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    event_timestamp TIMESTAMPTZ NOT NULL,
    source_type     VARCHAR(50) NOT NULL,  -- 'firewall', 'endpoint', 'netflow'
    source_ip       INET,
    dest_ip         INET,
    source_port     INTEGER,
    dest_port       INTEGER,
    protocol        VARCHAR(10),
    action          VARCHAR(20),           -- 'allow', 'deny', 'alert'
    severity        SMALLINT CHECK (severity BETWEEN 1 AND 10),
    raw_payload     JSONB,
    created_at      TIMESTAMPTZ DEFAULT NOW()
) PARTITION BY RANGE (event_timestamp);

-- Monthly partitions
CREATE TABLE security_events_2025_01 PARTITION OF security_events
    FOR VALUES FROM ('2025-01-01') TO ('2025-02-01');
-- ... more partitions

-- Enriched threat intelligence
CREATE TABLE threat_indicators (
    ioc_id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    indicator_type  VARCHAR(30) NOT NULL,  -- 'ip', 'domain', 'hash', 'url'
    indicator_value TEXT NOT NULL,
    threat_type     VARCHAR(50),           -- 'malware', 'phishing', 'c2'
    confidence      SMALLINT CHECK (confidence BETWEEN 0 AND 100),
    source_feed     VARCHAR(100),
    first_seen      TIMESTAMPTZ,
    last_seen       TIMESTAMPTZ,
    active          BOOLEAN DEFAULT TRUE,
    metadata        JSONB
);

-- Correlated alerts (events matched to threat intel)
CREATE TABLE correlated_alerts (
    alert_id        UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    event_id        UUID REFERENCES security_events(event_id),
    ioc_id          UUID REFERENCES threat_indicators(ioc_id),
    correlation_type VARCHAR(30),          -- 'ip_match', 'domain_match', 'hash_match'
    risk_score      NUMERIC(5,2),
    genai_summary   TEXT,                  -- GenAI-generated summary
    analyst_status  VARCHAR(20) DEFAULT 'new',
    created_at      TIMESTAMPTZ DEFAULT NOW()
);
```

### 4.2 Indexes for High-Concurrency Reads

```sql
-- B-tree indexes for exact lookups
CREATE INDEX idx_events_source_ip ON security_events (source_ip);
CREATE INDEX idx_events_dest_ip ON security_events (dest_ip);
CREATE INDEX idx_events_severity ON security_events (severity) WHERE severity >= 7;
CREATE INDEX idx_events_timestamp ON security_events (event_timestamp DESC);

-- GIN index for JSONB payload queries
CREATE INDEX idx_events_payload ON security_events USING GIN (raw_payload);

-- Partial index for active IOCs only
CREATE INDEX idx_active_iocs ON threat_indicators (indicator_value)
    WHERE active = TRUE;

-- Composite index for correlation lookups
CREATE INDEX idx_alerts_risk ON correlated_alerts (risk_score DESC, created_at DESC);
```

### 4.3 ACID Properties (Interview Talking Points)

- **Atomicity:** All enrichment writes use transactions — if IOC lookup succeeds but alert creation fails, everything rolls back
- **Consistency:** `CHECK` constraints on severity/confidence, `FOREIGN KEY` references between tables
- **Isolation:** Use `READ COMMITTED` isolation level (PostgreSQL default) for high-concurrency reads; `SERIALIZABLE` for critical alert updates
- **Durability:** WAL (Write-Ahead Logging) ensures crash recovery

### 4.4 Anti-Patterns Avoided

| Anti-Pattern | Why It's Wrong | Our Approach |
|---|---|---|
| No partitioning on event tables | Full table scans on millions of rows | Range partition by month |
| Missing indexes on JOIN columns | O(N×M) nested loop joins | B-tree on all FK columns |
| Storing IPs as VARCHAR | No range queries, wasted space | Use `INET` type (native PostgreSQL) |
| Single monolithic events table | Partition pruning impossible | Separate partitions per month |
| No partial indexes | Index bloat on rarely-queried rows | Partial indexes on `severity >= 7`, `active = TRUE` |
| Using `SELECT *` in queries | Unnecessary I/O, breaks with schema changes | Explicit column lists always |

---

## 5. Apache Spark Pipeline (KEY RESUME CLAIM: Hyperscale Processing)

### 5.1 Spark Session Configuration

```python
# config/spark_config.py
def create_spark_session(app_name="SecurityAnalytics"):
    return SparkSession.builder \
        .appName(app_name) \
        .config("spark.sql.shuffle.partitions", "200") \
        .config("spark.serializer", "org.apache.spark.serializer.KryoSerializer") \
        .config("spark.sql.adaptive.enabled", "true") \
        .config("spark.sql.adaptive.coalescePartitions.enabled", "true") \
        .config("spark.jars", "/opt/spark/jars/postgresql-42.7.1.jar") \
        .getOrCreate()
```

### 5.2 Batch ETL Pipeline

```python
# processing/batch_etl.py — Main pipeline
class SecurityETLPipeline:
    def __init__(self, spark, config):
        self.spark = spark
        self.config = config
    
    def run(self):
        # 1. Ingest raw logs
        raw_df = self.ingest_raw_data()
        
        # 2. Parse and normalize schemas
        normalized_df = self.normalize_events(raw_df)
        
        # 3. Enrich with threat intelligence
        enriched_df = self.enrich_with_iocs(normalized_df)
        
        # 4. Correlate across sources
        correlated_df = self.correlate_events(enriched_df)
        
        # 5. Write to data lake (Parquet) + PostgreSQL
        self.write_to_data_lake(enriched_df)
        self.write_to_postgres(correlated_df)
        
        # 6. Generate GenAI summaries for high-severity alerts
        self.generate_summaries(correlated_df)
```

### 5.3 Enrichment Engine

```python
# processing/enrichment.py
class ThreatEnrichment:
    def __init__(self, spark, ioc_df):
        self.spark = spark
        # Broadcast small IOC table for efficient joins
        self.ioc_broadcast = broadcast(ioc_df)
    
    def enrich(self, events_df):
        # Broadcast join: IOC table (~100K rows) vs events (~millions)
        return events_df.join(
            self.ioc_broadcast,
            events_df.source_ip == self.ioc_broadcast.indicator_value,
            "left"
        ).withColumn("is_threat", col("ioc_id").isNotNull())
```

**Interview-critical Spark concepts:**
- **Broadcast join:** Small table broadcast to all workers, avoids shuffle
- **Adaptive Query Execution (AQE):** Spark 3.x auto-optimizes shuffle partitions at runtime
- **Partition pruning:** Parquet partitioned by date → only relevant partitions scanned
- **Predicate pushdown:** Filters pushed to Parquet/JDBC source level

### 5.4 Anti-Patterns Avoided

| Anti-Pattern | Why It's Wrong | Our Approach |
|---|---|---|
| Collecting large DataFrames to driver | OOM on driver node | Process distributed, write distributed |
| Not caching reused DataFrames | Recomputes DAG each time | `.cache()` or `.persist(StorageLevel.MEMORY_AND_DISK)` |
| Too many small partitions | Scheduler overhead | AQE coalescing + repartition on write |
| Shuffle join on skewed keys | Single task takes forever | Broadcast join for small tables, salt keys for skewed |
| UDFs when built-in functions exist | Python UDFs are 10-100x slower | Use `pyspark.sql.functions` wherever possible |
| Not setting `spark.sql.shuffle.partitions` | Default 200 may be wrong | Tune based on data size + cluster cores |

---

## 6. Data Generators (Simulated Threat Intel)

### 6.1 Firewall Log Generator

```python
# data_generators/firewall_log_gen.py
"""
Generates realistic firewall log entries with:
- Source/dest IPs from configurable CIDR ranges
- Weighted action distribution (80% allow, 15% deny, 5% alert)
- Temporal patterns (more traffic during business hours)
- Injected malicious IPs at configurable rate (default 2%)
"""
```

### 6.2 Threat Intel Feed Generator (STIX Format)

```python
# data_generators/threat_intel_gen.py
"""
Generates STIX-format IOCs:
- Malicious IP addresses (from known botnet ranges)
- Phishing domains (DGA-style random strings)
- Malware file hashes (random SHA-256)
- Confidence scores with realistic distribution (mostly 60-80)
"""
```

**Why STIX format matters (interview):** STIX (Structured Threat Information eXpression) is the industry standard for sharing threat intelligence. Using it shows you understand real SOC data formats, not just toy datasets.

---

## 7. GenAI Analytics Layer (KEY RESUME CLAIM)

### 7.1 Event Summarizer

```python
# analytics/genai_summarizer.py
class SecurityEventSummarizer:
    """
    Uses an open-source LLM (e.g., Ollama/Llama3 locally, or OpenAI API)
    to generate natural-language summaries of correlated security events.
    """
    
    def summarize_alert(self, alert_context: dict) -> str:
        """
        Input: {
            "source_ip": "192.168.1.105",
            "dest_ip": "45.33.32.156",
            "matched_ioc": "45.33.32.156",
            "threat_type": "c2_server",
            "event_count": 47,
            "time_window": "2h",
            "severity": 9
        }
        
        Output: "Host 192.168.1.105 made 47 connections to known C2 
        server 45.33.32.156 over a 2-hour window. This pattern is 
        consistent with beaconing behavior. Recommend immediate 
        isolation and forensic analysis."
        """
```

### 7.2 Threat Scorer

```python
# analytics/threat_scorer.py
class ThreatScorer:
    """
    Combines multiple signals into a composite risk score:
    - IOC confidence level (0-100)
    - Event frequency (connections per hour)
    - Destination reputation
    - Time-of-day anomaly factor
    
    Score = weighted_sum(signals) normalized to 0-100
    """
```

**Interview depth on GenAI integration:**
- "I used GenAI specifically for summarization, not classification — the structured correlation engine handles detection. GenAI adds a natural-language layer for analyst consumption."
- "We use prompt engineering with structured context injection — the LLM never sees raw logs, only pre-extracted features."
- "Fallback: if GenAI service is unavailable, the system degrades gracefully to template-based summaries."

---

## 8. Docker Compose Setup

```yaml
# docker-compose.yml
version: '3.8'
services:
  spark-master:
    image: bitnami/spark:3.5
    environment:
      - SPARK_MODE=master
    ports:
      - "8080:8080"   # Spark UI
      - "7077:7077"   # Spark master
  
  spark-worker:
    image: bitnami/spark:3.5
    environment:
      - SPARK_MODE=worker
      - SPARK_MASTER_URL=spark://spark-master:7077
    depends_on: [spark-master]
    deploy:
      replicas: 2
  
  postgres:
    image: postgres:16
    environment:
      POSTGRES_DB: security_analytics
      POSTGRES_USER: analyst
      POSTGRES_PASSWORD: ${PG_PASSWORD}
    ports:
      - "5432:5432"
    volumes:
      - ./database/schema.sql:/docker-entrypoint-initdb.d/01_schema.sql
      - ./database/indexes.sql:/docker-entrypoint-initdb.d/02_indexes.sql
      - pg_data:/var/lib/postgresql/data

volumes:
  pg_data:
```

---

## 9. Implementation Order

| Phase | Days | Tasks |
|-------|------|-------|
| Foundation | 1-2 | Docker Compose, PostgreSQL schema, Spark session config |
| Data Gen | 3-4 | All 4 data generators, seed data script |
| ETL Core | 5-7 | batch_etl.py, enrichment.py, correlation_engine.py |
| Storage | 8-9 | Parquet/Delta writer, PostgreSQL writer, partition strategy |
| GenAI | 10-11 | genai_summarizer.py, threat_scorer.py |
| Testing | 12-13 | Unit tests, integration tests, benchmark runs |
| Polish | 14 | README, architecture diagrams, sample outputs |

---

## 10. Interview Q&A

**Q: Why Parquet for the data lake?**
A: "Columnar format — security queries are typically column-selective (e.g., 'all events from IP X'). Parquet gives 10x compression over CSV and supports predicate pushdown, so Spark only reads relevant row groups."

**Q: How do you handle schema evolution?**
A: "Parquet supports schema evolution natively (add columns). For PostgreSQL, we use numbered migration scripts. The ingestion layer has a schema registry that validates incoming data against expected schemas and quarantines non-conforming records."

**Q: What's your partitioning strategy?**
A: "Two-level: partition by date (month) in both Parquet and PostgreSQL for time-range queries, then by source_type within Parquet for source-specific analysis. This enables partition pruning — a query for 'firewall events in January' only touches 1 partition."

**Q: How does the enrichment broadcast join work?**
A: "The IOC table is small (~100K rows, <50MB). We broadcast it to all Spark workers so the join happens locally without any network shuffle. For the events table (~millions of rows), this avoids the most expensive operation in distributed computing: data movement."

**Q: What happens if the GenAI service is down?**
A: "Graceful degradation. The correlation engine and risk scoring work independently of GenAI. If the LLM is unavailable, we fall back to template-based summaries using Python string formatting with the structured alert data. The alert still gets created and scored."

---

## 11. Git Strategy

1. `Initial project structure, Docker Compose, PostgreSQL schema`
2. `Add Spark session configuration and data generators`
3. `Implement batch ETL pipeline with normalization`
4. `Add threat intelligence enrichment with broadcast join`
5. `Add correlation engine and risk scoring`
6. `Implement Parquet data lake writer with partitioning`
7. `Add PostgreSQL writer with transaction management`
8. `Integrate GenAI summarizer with fallback templates`
9. `Add comprehensive test suite`
10. `Add CI pipeline, README, architecture diagrams`
