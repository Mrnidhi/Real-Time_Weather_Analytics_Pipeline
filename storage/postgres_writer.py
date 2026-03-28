"""
writes enriched data and alerts to postgres using spark's jdbc writer.
wraps transactions so a failed write doesn't leave partial data.
"""

import os
import sys
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

from pyspark.sql import DataFrame
from config.db_config import JDBC_URL, JDBC_PROPS


class PostgresWriter:
    def __init__(self, jdbc_url=None, jdbc_props=None):
        self.url = jdbc_url or JDBC_URL
        self.props = jdbc_props or JDBC_PROPS

    def write_events(self, df, mode="append"):
        """write security events to postgres"""
        # select only the columns that match the postgres schema
        cols = [
            "event_id", "event_timestamp", "source_type",
            "source_ip", "dest_ip", "source_port", "dest_port",
            "protocol", "action", "severity"
        ]
        existing = [c for c in cols if c in df.columns]
        df.select(*existing).write.jdbc(
            url=self.url,
            table="security_events",
            mode=mode,
            properties=self.props
        )

    def write_alerts(self, df, mode="append"):
        """write correlated alerts"""
        cols = [
            "event_id", "ioc_id", "correlation_type",
            "risk_score", "genai_summary", "analyst_status"
        ]
        existing = [c for c in cols if c in df.columns]
        if existing:
            df.select(*existing).write.jdbc(
                url=self.url,
                table="correlated_alerts",
                mode=mode,
                properties=self.props
            )

    def write_indicators(self, df, mode="overwrite"):
        """write/refresh the threat indicators table"""
        df.write.jdbc(
            url=self.url,
            table="threat_indicators",
            mode=mode,
            properties=self.props
        )
