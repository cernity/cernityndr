-- NDR scan detectors (plan U8; v2 §16.1-2). Reference-stack Flink SQL.
-- Reads raw Suricata flow EVE from Redpanda, windows by source, emits scan
-- candidates to ndr.finding.candidate.v1. Uses processing-time windows (homelab
-- scale); the fleet form keys the same way on event-time with watermarks.
SET 'execution.runtime-mode' = 'streaming';
SET 'pipeline.name' = 'ndr-scan-detectors';

CREATE TABLE flow (
  src_ip    STRING,
  dest_ip   STRING,
  dest_port INT,
  proto     STRING,
  community_id STRING,
  proc AS PROCTIME()
) WITH (
  'connector' = 'kafka',
  'topic' = 'suricata.flow.v1',
  'properties.bootstrap.servers' = 'redpanda:9092',
  'properties.group.id' = 'flink-scan',
  'scan.startup.mode' = 'latest-offset',
  'format' = 'json',
  'json.ignore-parse-errors' = 'true'
);

CREATE TABLE candidate (
  finding_id       STRING,
  tenant_id        STRING,
  detector_id      STRING,
  detector_version STRING,
  category         STRING,
  severity         TINYINT,
  confidence       FLOAT,
  first_seen       STRING,
  last_seen        STRING,
  entities         STRING,
  state            STRING
) WITH (
  'connector' = 'kafka',
  'topic' = 'ndr.finding.candidate.v1',
  'properties.bootstrap.servers' = 'redpanda:9092',
  'format' = 'json'
);

-- Horizontal scan: one source touching many distinct destinations in a minute.
INSERT INTO candidate
SELECT
  CONCAT('hscan-', src_ip, '-', DATE_FORMAT(w_end, 'yyyyMMddHHmm')),
  'homelab', 'horizontal_scan', '1.0', 'recon',
  CAST(5 AS TINYINT), CAST(0.7 AS FLOAT),
  DATE_FORMAT(w_start, 'yyyy-MM-dd HH:mm:ss'),
  DATE_FORMAT(w_end, 'yyyy-MM-dd HH:mm:ss'),
  CONCAT('[{"type":"ip","role":"scanner","value":"', src_ip,
         '","distinct_dst":', CAST(ndst AS STRING), '}]'),
  'CANDIDATE'
FROM (
  SELECT src_ip,
         COUNT(DISTINCT dest_ip) AS ndst,
         TUMBLE_START(proc, INTERVAL '1' MINUTE) AS w_start,
         TUMBLE_END(proc, INTERVAL '1' MINUTE)   AS w_end
  FROM flow
  GROUP BY TUMBLE(proc, INTERVAL '1' MINUTE), src_ip
  HAVING COUNT(DISTINCT dest_ip) >= 20
);

-- Vertical scan: one source touching many distinct ports on one destination.
INSERT INTO candidate
SELECT
  CONCAT('vscan-', src_ip, '-', dest_ip, '-', DATE_FORMAT(w_end, 'yyyyMMddHHmm')),
  'homelab', 'vertical_scan', '1.0', 'recon',
  CAST(5 AS TINYINT), CAST(0.7 AS FLOAT),
  DATE_FORMAT(w_start, 'yyyy-MM-dd HH:mm:ss'),
  DATE_FORMAT(w_end, 'yyyy-MM-dd HH:mm:ss'),
  CONCAT('[{"type":"ip","role":"scanner","value":"', src_ip,
         '"},{"type":"ip","role":"target","value":"', dest_ip,
         '","distinct_ports":', CAST(nports AS STRING), '}]'),
  'CANDIDATE'
FROM (
  SELECT src_ip, dest_ip,
         COUNT(DISTINCT dest_port) AS nports,
         TUMBLE_START(proc, INTERVAL '1' MINUTE) AS w_start,
         TUMBLE_END(proc, INTERVAL '1' MINUTE)   AS w_end
  FROM flow
  GROUP BY TUMBLE(proc, INTERVAL '1' MINUTE), src_ip, dest_ip
  HAVING COUNT(DISTINCT dest_port) >= 30
);
