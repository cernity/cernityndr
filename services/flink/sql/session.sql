-- NDR session stitching (plan U18; v2 §16). Flink SQL SESSION windows fold many
-- flows between the same host pair into one logical session (opens on activity,
-- extends on more, closes after a 2-min gap). Emits to ndr.session.v1; the
-- reconstruction service (U19) persists them to ClickHouse.
-- Processing-time here (homelab); the fleet form keys the same on event-time +
-- watermarks so cross-sensor clock skew doesn't mis-stitch.
SET 'execution.runtime-mode' = 'streaming';
SET 'pipeline.name' = 'ndr-session-stitching';

CREATE TABLE flow_s (
  src_ip       STRING,
  dest_ip      STRING,
  app_proto    STRING,
  community_id STRING,
  proc AS PROCTIME()
) WITH (
  'connector' = 'kafka',
  'topic' = 'suricata.flow.v1',
  'properties.bootstrap.servers' = 'redpanda:9092',
  'properties.group.id' = 'flink-session',
  'scan.startup.mode' = 'latest-offset',
  'format' = 'json',
  'json.ignore-parse-errors' = 'true'
);

CREATE TABLE session_out (
  session_id    STRING,
  session_type  STRING,
  src_ip        STRING,
  dst_ip        STRING,
  app_proto     STRING,
  started       STRING,
  ended         STRING,
  community_ids STRING,
  flows         BIGINT
) WITH (
  'connector' = 'kafka',
  'topic' = 'ndr.session.v1',
  'properties.bootstrap.servers' = 'redpanda:9092',
  'format' = 'json'
);

-- Host-pair session: all flows between (src, dst, app_proto) within a 2-min gap.
INSERT INTO session_out
SELECT
  MD5(CONCAT(src_ip, '|', dest_ip, '|', COALESCE(app_proto, ''), '|',
             DATE_FORMAT(SESSION_START(proc, INTERVAL '2' MINUTE), 'yyyyMMddHHmmss'))),
  'host_pair',
  src_ip, dest_ip, COALESCE(app_proto, ''),
  DATE_FORMAT(SESSION_START(proc, INTERVAL '2' MINUTE), 'yyyy-MM-dd HH:mm:ss'),
  DATE_FORMAT(SESSION_END(proc, INTERVAL '2' MINUTE),   'yyyy-MM-dd HH:mm:ss'),
  LISTAGG(community_id),
  COUNT(*)
FROM flow_s
GROUP BY SESSION(proc, INTERVAL '2' MINUTE), src_ip, dest_ip, app_proto;
