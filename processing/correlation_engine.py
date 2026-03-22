"""
takes enriched events and produces correlated alerts.
groups events by threat indicator and source IP to find
patterns like repeated connections to the same C2 server.
"""

from pyspark.sql import SparkSession, DataFrame
from pyspark.sql.functions import (
    col, count, min as spark_min, max as spark_max,
    first, collect_list, struct, window, lit
)


class CorrelationEngine:
    def __init__(self, spark):
        self.spark = spark

    def correlate(self, enriched_df):
        """
        finds clusters of events hitting the same IOC.
        if the same source IP talks to the same bad dest_ip
        multiple times, that's probably beaconing and we should alert.
        """
        threat_events = enriched_df.filter(col("is_threat") == True)

        if threat_events.rdd.isEmpty():
            # nothing to correlate
            return self.spark.createDataFrame([], schema=self._alert_schema())

        # group by source_ip + IOC to find repeated connections
        alerts = (threat_events
            .groupBy("source_ip", "dest_ip", "ioc_id", "ioc_threat_type")
            .agg(
                count("*").alias("event_count"),
                spark_min("event_timestamp").alias("first_seen"),
                spark_max("event_timestamp").alias("last_seen"),
                first("severity").alias("max_severity"),
                first("ioc_confidence").alias("ioc_confidence"),
                first("ioc_source").alias("ioc_source"),
                first("source_type").alias("source_type"),
            )
        )

        # compute a time window -- how long this has been going on
        alerts = alerts.withColumn(
            "duration_hours",
            (col("last_seen").cast("long") - col("first_seen").cast("long")) / 3600
        )

        # anything with multiple hits over time is more concerning
        alerts = alerts.withColumn(
            "correlation_type",
            lit("repeated_ioc_contact")
        )

        return alerts

    def find_lateral_movement(self, enriched_df):
        """
        looks for one internal IP talking to many other internal IPs
        on suspicious ports -- could be lateral movement after initial compromise.
        not used in the main pipeline yet but ready to plug in.
        """
        internal = enriched_df.filter(
            col("source_ip").startswith("192.168.") |
            col("source_ip").startswith("10.")
        ).filter(
            col("dest_ip").startswith("192.168.") |
            col("dest_ip").startswith("10.")
        )

        return (internal
            .groupBy("source_ip")
            .agg(
                count("*").alias("connection_count"),
                collect_list("dest_ip").alias("dest_ips"),
            )
            .filter(col("connection_count") > 50)
        )

    def _alert_schema(self):
        from pyspark.sql.types import StructType, StructField, StringType, IntegerType, LongType, DoubleType
        return StructType([
            StructField("source_ip", StringType()),
            StructField("dest_ip", StringType()),
            StructField("ioc_id", StringType()),
            StructField("ioc_threat_type", StringType()),
            StructField("event_count", LongType()),
            StructField("correlation_type", StringType()),
        ])
