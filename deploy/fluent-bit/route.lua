-- Route each Suricata EVE record to its Cernity topic and set the partition key.
-- Mirrors the reference shipper: topic by event_type, key by src_ip so a
-- source's whole window lands on one partition.
--
-- Trusted identity (F08): the tenant + sensor are stamped from THIS sensor's own
-- configuration (env), overwriting whatever the record carries. EVE fields come from
-- monitored traffic and are attacker-influenced, so a forged `tenant`/`sensor_id` in a
-- raw record must never be trusted — the authenticated shipper's identity is
-- authoritative. Downstream detectors/correlation key on this stamped value.
local TENANT = os.getenv("NDR_TENANT") or "default"
local SENSOR = os.getenv("NDR_SENSOR") or "sensor-1"

function route(tag, timestamp, record)
    record["tenant"] = TENANT
    record["sensor_id"] = SENSOR
    local et = record["event_type"]
    local topic = "suricata.raw.v1"
    if et == "flow" then topic = "suricata.flow.v1"
    elseif et == "dns" then topic = "suricata.dns.v1"
    elseif et == "tls" then topic = "suricata.tls.v1"
    elseif et == "http" then topic = "suricata.http.v1"
    elseif et == "ssh" then topic = "suricata.ssh.v1"
    elseif et == "fileinfo" then topic = "suricata.file.v1"
    elseif et == "anomaly" then topic = "suricata.anomaly.v1"
    elseif et == "stats" then topic = "suricata.stats.v1"
    end
    record["_topic"] = topic

    local key = record["src_ip"]
    if et == "stats" then key = "stats" end        -- stats has no src_ip
    if key == nil then key = "unkeyed" end
    record["_pkey"] = key

    return 2, timestamp, record                    -- 2 = record modified
end
