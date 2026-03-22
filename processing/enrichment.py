"""
enriches events by joining against the threat intel IOC table.
uses a broadcast join since the IOC table is small (~100K rows max)
while events can be millions -- avoids shuffle entirely.
"""

from pyspark.sql import SparkSession, DataFrame
from pyspark.sql.functions import col, broadcast, lit, when


class ThreatEnrichment:
    def __init__(self, spark, ioc_df):
        self.spark = spark
        # only care about active indicators
        self.ioc_df = ioc_df.filter(col("active") == "true").select(
            col("ioc_id"),
            col("indicator_type"),
            col("indicator_value"),
            col("threat_type").alias("ioc_threat_type"),
            col("confidence").alias("ioc_confidence"),
            col("source_feed").alias("ioc_source"),
        )

    def enrich(self, events_df):
        """
        broadcast join IOCs against events on dest_ip.
        an event is flagged as a threat if its destination IP
        matches any known malicious indicator.
        """
        # broadcast the small IOC table to avoid shuffle
        enriched = events_df.join(
            broadcast(self.ioc_df),
            events_df.dest_ip == self.ioc_df.indicator_value,
            "left"
        )

        # flag whether this event hit a known IOC
        enriched = enriched.withColumn(
            "is_threat",
            when(col("ioc_id").isNotNull(), True).otherwise(False)
        )

        return enriched

    def enrich_by_source_ip(self, events_df):
        """
        sometimes the source is the bad actor (e.g. inbound scans).
        separate method so we can run both directions if needed.
        """
        enriched = events_df.join(
            broadcast(self.ioc_df),
            events_df.source_ip == self.ioc_df.indicator_value,
            "left"
        )
        enriched = enriched.withColumn(
            "is_threat",
            when(col("ioc_id").isNotNull(), True).otherwise(False)
        )
        return enriched
