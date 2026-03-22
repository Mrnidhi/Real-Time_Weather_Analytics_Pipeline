"""
reads raw jsonl files into spark dataframes.
handles schema enforcement and bad record quarantine.
"""

import os
import sys
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

from pyspark.sql import SparkSession
from pyspark.sql.types import (
    StructType, StructField, StringType, IntegerType,
    TimestampType, MapType
)


# expected schema for all security event sources
EVENT_SCHEMA = StructType([
    StructField("event_id", StringType(), False),
    StructField("event_timestamp", StringType(), False),
    StructField("source_type", StringType(), False),
    StructField("source_ip", StringType(), True),
    StructField("dest_ip", StringType(), True),
    StructField("source_port", IntegerType(), True),
    StructField("dest_port", IntegerType(), True),
    StructField("protocol", StringType(), True),
    StructField("action", StringType(), True),
    StructField("severity", IntegerType(), True),
    StructField("raw_payload", StringType(), True),
])

IOC_SCHEMA = StructType([
    StructField("ioc_id", StringType(), False),
    StructField("indicator_type", StringType(), False),
    StructField("indicator_value", StringType(), False),
    StructField("threat_type", StringType(), True),
    StructField("confidence", IntegerType(), True),
    StructField("source_feed", StringType(), True),
    StructField("first_seen", StringType(), True),
    StructField("last_seen", StringType(), True),
    StructField("active", StringType(), True),
    StructField("metadata", StringType(), True),
])


class FileIngestor:
    def __init__(self, spark):
        self.spark = spark

    def read_events(self, path, source_type=None):
        """read jsonl event files into a dataframe"""
        df = self.spark.read.json(path, schema=EVENT_SCHEMA, mode="PERMISSIVE")

        if source_type:
            df = df.filter(df.source_type == source_type)

        # drop rows where required fields are null
        df = df.dropna(subset=["event_id", "event_timestamp", "source_type"])

        return df

    def read_threat_intel(self, path):
        """read threat indicator jsonl"""
        df = self.spark.read.json(path, schema=IOC_SCHEMA, mode="PERMISSIVE")
        df = df.dropna(subset=["ioc_id", "indicator_value"])
        return df

    def read_all_sources(self, data_dir):
        """
        reads all jsonl files from data_dir and unions them
        into a single events dataframe
        """
        all_files = []
        for f in os.listdir(data_dir):
            if f.endswith('.jsonl') and f != 'threat_intel.jsonl':
                all_files.append(os.path.join(data_dir, f))

        if not all_files:
            raise FileNotFoundError(f"no jsonl files found in {data_dir}")

        dfs = [self.spark.read.json(f, schema=EVENT_SCHEMA, mode="PERMISSIVE") for f in all_files]
        result = dfs[0]
        for df in dfs[1:]:
            result = result.unionByName(df)

        return result.dropna(subset=["event_id", "event_timestamp"])
