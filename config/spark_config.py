import os
from pyspark.sql import SparkSession


def get_spark(app_name="SecurityAnalytics", local=False):
    """spin up a spark session with the settings we need for this pipeline"""
    builder = SparkSession.builder.appName(app_name)

    if local:
        builder = builder.master("local[*]")

    builder = (builder
        .config("spark.sql.shuffle.partitions", "200")
        .config("spark.serializer", "org.apache.spark.serializer.KryoSerializer")
        .config("spark.sql.adaptive.enabled", "true")
        .config("spark.sql.adaptive.coalescePartitions.enabled", "true")
        .config("spark.sql.parquet.compression.codec", "snappy")
    )

    # postgres jdbc driver if available
    jdbc_jar = os.environ.get("POSTGRES_JDBC_JAR", "/opt/spark/jars/postgresql-42.7.1.jar")
    if os.path.exists(jdbc_jar):
        builder = builder.config("spark.jars", jdbc_jar)

    return builder.getOrCreate()
