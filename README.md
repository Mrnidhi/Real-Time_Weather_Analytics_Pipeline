# Hyperscale Data Lake & Security Analytics Engine

A data lake for security event processing built on Apache Spark + PostgreSQL. Ingests simulated firewall logs, endpoint telemetry, netflow records, and threat intel feeds, enriches them against known IOCs, correlates events across sources, and generates alerts with risk scoring and optional GenAI summaries.

## What it does

1. **Generates** realistic security data (firewall, endpoint, netflow) with injected malicious traffic
2. **Ingests** into Spark, normalizes schemas across sources
3. **Enriches** by broadcast-joining events against a threat intel IOC table
4. **Correlates** repeated connections to the same malicious indicators
5. **Scores** alerts using weighted signals (IOC confidence, frequency, severity, duration)
6. **Writes** to partitioned Parquet (data lake) + PostgreSQL (structured queries)
7. **Summarizes** high-risk alerts using GenAI or template fallback

## Architecture

```
  firewall logs ──┐
  endpoint data ──┤── Spark ETL ──┬── Parquet (partitioned by year/month)
  netflow records ┤               ├── PostgreSQL (enriched + correlated)
  threat intel ───┘               └── Alert summaries (GenAI/template)
```

The threat intel table is small enough to broadcast to all Spark workers, so the enrichment join runs without any shuffle. Events are partitioned by timestamp for partition pruning on time-range queries.

## Project structure

```
config/                 spark session, db connection, logging
data_generators/        firewall, endpoint, netflow, threat intel generators
ingestion/              file ingestor with schema enforcement
processing/             batch ETL, enrichment (broadcast join), correlation engine
storage/                parquet writer, postgres JDBC writer
analytics/              threat scoring, GenAI summarizer, dashboard SQL queries
database/               PostgreSQL DDL, indexes, migrations
tests/                  generator + summarizer tests
scripts/                seed data, run pipeline
```

## Quick start

```bash
# generate seed data (40K events + 500 IOCs)
chmod +x scripts/seed_data.sh
./scripts/seed_data.sh

# run the ETL pipeline locally
python3 processing/batch_etl.py

# or with docker (spark cluster + postgres)
docker-compose up -d
./scripts/run_pipeline.sh
```

## Running tests

```bash
pip install -r requirements.txt
python -m pytest tests/ -v
```

## Key design decisions

**Broadcast join for enrichment** — the IOC table is ~100K rows, well under Spark's broadcast threshold. Broadcasting it to all workers avoids shuffling millions of event rows across the network.

**Partitioned Parquet** — partitioned by year/month so time-range queries only read relevant partitions. Snappy compression for a good balance of speed vs size.

**Partial indexes in PostgreSQL** — only index `severity >= 7` events and `active = TRUE` IOCs since those are the only ones we query frequently. Saves index space and write overhead.

**GenAI with fallback** — the summarizer tries OpenAI or local Ollama first, but degrades gracefully to template-based summaries if neither is available. The correlation and scoring pipeline works regardless.

**Adaptive Query Execution** — Spark 3.x AQE is enabled so it can auto-coalesce small partitions and optimize skewed joins at runtime without manual tuning.

## Database

PostgreSQL schema uses:
- `INET` type for IPs (enables native range queries)
- `JSONB` for raw payloads with GIN index
- Range partitioning by month on events table
- `CHECK` constraints on severity/confidence
- Partial indexes for high-severity events and active IOCs

See `database/schema.sql` and `database/indexes.sql`.

## Tech stack

- Python 3.11
- Apache Spark 3.5 (PySpark)
- PostgreSQL 16
- Docker Compose for local cluster
- OpenAI API / Ollama for GenAI (optional)
