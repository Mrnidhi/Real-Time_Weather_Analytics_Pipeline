import os


# pull from env so we don't hardcode passwords
DB_CONFIG = {
    "host": os.environ.get("PG_HOST", "localhost"),
    "port": int(os.environ.get("PG_PORT", 5432)),
    "database": os.environ.get("PG_DB", "security_analytics"),
    "user": os.environ.get("PG_USER", "analyst"),
    "password": os.environ.get("PG_PASSWORD", "changeme"),
}

# jdbc url for spark's df.write.jdbc()
JDBC_URL = f"jdbc:postgresql://{DB_CONFIG['host']}:{DB_CONFIG['port']}/{DB_CONFIG['database']}"
JDBC_PROPS = {
    "user": DB_CONFIG["user"],
    "password": DB_CONFIG["password"],
    "driver": "org.postgresql.Driver",
}
