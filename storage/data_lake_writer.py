"""
writes dataframes to parquet, partitioned by year/month.
also handles the output directory structure.
"""

import os
from pyspark.sql import DataFrame


class DataLakeWriter:
    def __init__(self, base_dir="data"):
        self.base_dir = base_dir
        self.parquet_dir = os.path.join(base_dir, "parquet")

    def write_parquet(self, df, table_name, partition_cols=None):
        """
        write a dataframe to parquet with optional partitioning.
        defaults to partitioning by year/month if those columns exist.
        """
        output_path = os.path.join(self.parquet_dir, table_name)

        if partition_cols is None:
            cols = df.columns
            if "year" in cols and "month" in cols:
                partition_cols = ["year", "month"]

        writer = df.write.mode("overwrite").format("parquet")

        if partition_cols:
            writer = writer.partitionBy(*partition_cols)

        writer.save(output_path)
        print(f"wrote {table_name} to {output_path}")

    def write_csv(self, df, table_name):
        """csv output for quick inspection / debugging"""
        output_path = os.path.join(self.base_dir, "processed", f"{table_name}.csv")
        df.coalesce(1).write.mode("overwrite").option("header", True).csv(output_path)
        print(f"wrote {table_name} csv to {output_path}")
