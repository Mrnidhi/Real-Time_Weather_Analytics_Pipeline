"""
risk scoring for correlated alerts.
combines IOC confidence, event frequency, severity, and
time-of-day anomaly into a single 0-100 score.
"""

from pyspark.sql import DataFrame
from pyspark.sql.functions import col, when, lit, greatest, least, round as spark_round


class ThreatScorer:

    # weights for each signal (should add up to 1.0)
    WEIGHTS = {
        "ioc_confidence": 0.30,
        "event_frequency": 0.25,
        "severity": 0.25,
        "duration": 0.20,
    }

    def score_alerts(self, alerts_df):
        """
        takes the output of CorrelationEngine.correlate() and
        adds a risk_score column (0-100).
        """
        df = alerts_df

        # normalize each signal to 0-1 range, then weighted sum

        # IOC confidence is already 0-100, just scale to 0-1
        df = df.withColumn(
            "sig_confidence",
            when(col("ioc_confidence").isNotNull(), col("ioc_confidence") / 100.0)
            .otherwise(0.5)
        )

        # event count: more hits = worse. cap at 100 for normalization
        df = df.withColumn(
            "sig_frequency",
            least(col("event_count") / 100.0, lit(1.0))
        )

        # severity: already 1-10, scale to 0-1
        df = df.withColumn(
            "sig_severity",
            when(col("max_severity").isNotNull(), col("max_severity") / 10.0)
            .otherwise(0.3)
        )

        # duration: longer beaconing = worse. cap at 72 hours
        df = df.withColumn(
            "sig_duration",
            when(col("duration_hours").isNotNull(),
                 least(col("duration_hours") / 72.0, lit(1.0)))
            .otherwise(0.0)
        )

        # weighted sum -> 0-100
        risk = (
            col("sig_confidence") * self.WEIGHTS["ioc_confidence"] +
            col("sig_frequency") * self.WEIGHTS["event_frequency"] +
            col("sig_severity") * self.WEIGHTS["severity"] +
            col("sig_duration") * self.WEIGHTS["duration"]
        ) * 100

        df = df.withColumn("risk_score", spark_round(risk, 2))

        # clean up intermediate columns
        df = df.drop("sig_confidence", "sig_frequency", "sig_severity", "sig_duration")

        return df
