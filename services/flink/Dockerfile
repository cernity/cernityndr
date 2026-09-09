# Flink with the Kafka SQL connector for the NDR detectors (plan U8).
# Pinned to 1.20 because the SQL Kafka connector jar is version-matched
# (a concrete reason to pin, per the :latest policy).
FROM flink:1.20
RUN curl -fLo /opt/flink/lib/flink-sql-connector-kafka-3.4.0-1.20.jar \
    https://repo1.maven.org/maven2/org/apache/flink/flink-sql-connector-kafka/3.4.0-1.20/flink-sql-connector-kafka-3.4.0-1.20.jar
