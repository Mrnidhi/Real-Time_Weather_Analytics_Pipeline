"""
main ETL pipeline -- reads raw events, normalizes, enriches with
threat intel, correlates, and writes to both parquet and postgres.
this is the core of the whole project.
"""

import os
import sys
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

from pyspark.sql import SparkSession, DataFrame
from pyspark.sql.functions import (
    col, to_timestamp, when, lit, from_json, current_timestamp,
    year, month, dayofmonth, hour, count, avg, desc,
    collect_list, struct
)
from pyspark.sql.types import StringType

from config.spark_config import get_spark
from config.logging_config import setup_logging
from ingestion.file_ingestor import FileIngestor
from processing.enrichment import ThreatEnrichment
from processing.correlation_engine import CorrelationEngine
from storage.data_lake_writer import DataLakeWriter
from analytics.threat_scorer import ThreatScorer

log = setup_logging("batch_etl")


class SecurityETLPipeline:
    def __init__(self, spark, data_dir="data/raw", output_dir="data"):
        self.spark = spark
        self.data_dir = data_dir
        self.output_dir = output_dir
        self.ingestor = FileIngestor(spark)
        self.writer = DataLakeWriter(output_dir)

    def run(self):
        """runs the full pipeline end-to-end"""
        log.info("starting ETL pipeline")

        # 1. ingest
        log.info("reading raw event data...")
        events_df = self.ingestor.read_all_sources(self.data_dir)
        events_df = self.normalize(events_df)
        event_count = events_df.count()
        log.info(f"ingested {event_count} events")

        # 2. load threat intel
        ioc_path = os.path.join(self.data_dir, "threat_intel.jsonl")
        ioc_df = self.ingestor.read_threat_intel(ioc_path)
        log.info(f"loaded {ioc_df.count()} threat indicators")

        # 3. enrich -- broadcast join the IOC table against events
        enrichment = ThreatEnrichment(self.spark, ioc_df)
        enriched_df = enrichment.enrich(events_df)
        enriched_df.cache()  # reused in correlation + writing

        threat_hits = enriched_df.filter(col("is_threat") == True).count()
        log.info(f"found {threat_hits} events matching known IOCs")

        # 4. correlate + score
        correlator = CorrelationEngine(self.spark)
        alerts_df = correlator.correlate(enriched_df)

        scorer = ThreatScorer()
        scored_df = scorer.score_alerts(alerts_df)
        log.info(f"generated {scored_df.count()} correlated alerts")

        # 5. write outputs
        log.info("writing to parquet data lake...")
        self.writer.write_parquet(enriched_df, "events")

        log.info("writing alerts...")
        self.writer.write_parquet(scored_df, "alerts")

        # 6. summary stats
        summary = self.compute_summary(enriched_df)
        self.writer.write_parquet(summary, "summaries")

        log.info("pipeline complete")
        enriched_df.unpersist()

        return {
            "events_processed": event_count,
            "threat_matches": threat_hits,
            "alerts_generated": scored_df.count(),
        }

    def normalize(self, df):
        """clean up timestamps, fill defaults, etc."""
        df = df.withColumn("event_timestamp", to_timestamp(col("event_timestamp")))
        df = df.withColumn("severity", when(col("severity").isNull(), 1).otherwise(col("severity")))
        df = df.withColumn("year", year(col("event_timestamp")))
        df = df.withColumn("month", month(col("event_timestamp")))
        return df

    def compute_summary(self, df):
        """aggregate stats per source type per day"""
        return (df
            .groupBy("source_type", "year", "month", dayofmonth("event_timestamp").alias("day"))
            .agg(
                count("*").alias("total_events"),
                count(when(col("is_threat") == True, 1)).alias("threat_events"),
                avg("severity").alias("avg_severity"),
            )
            .orderBy(desc("total_events"))
        )


def main():
    spark = get_spark(local=True)
    pipeline = SecurityETLPipeline(spark)
    results = pipeline.run()
    print(f"\nPipeline results: {results}")
    spark.stop()


if __name__ == "__main__":
    main()
