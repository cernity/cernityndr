# U1b: capture bus ACLs and sensor object-store access

Status: deployment artifacts implemented; pending independent review and operator
verification. This ADR is separate from `003-u6-preserved-packets.md` (the filename
here is the task's specified deliverable). PRODUCT.md is absent in this clone.

CN05 is a deployment gap, not proof that preservation or SIEM propagation works.
The offline gate checks configuration and executes provisioning with a fake rpk.
It cannot establish network reachability, broker enforcement, object permissions,
or an audited packet roundtrip. No live verification was performed here.

## Policy

The central forensics overlay enables provisioning of a distinct SCRAM capture
user. The sensor overlay selects it instead of the telemetry user. The principal
is never a superuser. The trusted central orchestrator retains its existing
central credential; do not distribute that credential to sensors.

| Resource | Capture operations |
| --- | --- |
| `ndr.capture.request.v1` | Describe only (family metadata; no request injection) |
| `ndr.capture.arm.v1` | Read, Describe |
| `ndr.capture.status.v1` | Write, Describe |
| `ndr.capture.request.v2` | Read, Describe |
| group `ndr-capture-agent-${NDR_SENSOR}` | Read, exact sensor ID |

`capture-request.v2` is the schema; `shared/capture_v2.py` binds it to
`ndr.capture.request.v2`. No topic prefix, wildcard resource, Create, cluster or
transactional-ID grant is added. The host wildcard means any source host may
authenticate; it does not broaden resources. Bootstrap deletes this dedicated
user's old ACLs before installing the exact grants, and stops on ACL failure.
This artifact provisions one sensor identity. For a fleet, provision separate
users and exact groups per sensor; do not share this credential. Shared topics
still expose directives across sensors: Kafka ACLs do not provide record-level
tenant isolation. Signed U6 policy validation remains necessary.

MinIO publishes only S3 port 9000 on an explicitly chosen private/VPN interface.
Central readers use `http://minio:9000`; sensors use the required routable endpoint.
Use the HTTP example only across an encrypted, authenticated VPN. Otherwise put
an operator-managed HTTPS gateway in front and use its trusted HTTPS URL. No
console port is published. A dedicated S3 user gets PutObject/GetObject only on
`ndr-pcap/<exact tenant_segment>/*`; no bucket listing or file bucket permissions.
Use a fresh dedicated S3 user, with no preexisting policies/group memberships.
Bootstrap does not remove unrelated MinIO policy attachments. On reuse, audit
and remove those grants before enabling capture. Tenant namespace is shared by
that tenant's sensors; this is not per-sensor object isolation.

## Apply (operator, from repo root)

1. Generate broker certs with `deploy/security/gen-bus-certs.sh` per the security
   README. Configure the existing admin, central and telemetry secrets. Keep
   `CERNITY_INSECURE_BUS=0`. Use separate generated secrets, e.g. `openssl rand -hex 32`.
2. In a protected central env file set `CERNITY_BUS_CAPTURE_USER=cernity-capture`,
   `CERNITY_BUS_CAPTURE_PASSWORD`, `NDR_SENSOR`, `MINIO_ROOT_USER`,
   `MINIO_ROOT_PASSWORD`, `CERNITY_MINIO_CAPTURE_USER`,
   `CERNITY_MINIO_CAPTURE_PASSWORD`, `CERNITY_CAPTURE_S3_BIND_IP` (private host IP),
   and `CERNITY_CAPTURE_S3_ENDPOINT` (e.g. `http://10.20.30.40:9000`). Set
   `CERNITY_CAPTURE_OBJECT_PREFIX` to the actual tenant namespace:

   ```bash
   PYTHONPATH=services/capture-agent:shared .venv/bin/python -c \
     'import os, agent; print(agent.tenant_segment(os.environ["NDR_TENANT"]))'
   ```

   Export `NDR_TENANT` for that command. Provision distinct keys per tenant.
   Keep env files outside version control; Compose config output can contain secrets.
3. Apply central services; inspect broker logs and require successful MinIO init:

   ```bash
   docker compose --env-file /secure/central.env \
     -f deploy/central/docker-compose.yml -f deploy/overlays/forensics.yml up -d
   docker compose --env-file /secure/central.env \
     -f deploy/central/docker-compose.yml -f deploy/overlays/forensics.yml ps -a
   ```

4. On the sensor, set the matching capture user/password, sensor ID, scoped S3
   credentials, endpoint, `REDPANDA_BOOTSTRAP=<broker DNS>:19092`, and `CERNITY_BUS_CA`.
   Copy only the CA certificate, never the central/admin credentials. Preview the
   merged configuration and, during the authorized capture verification window, apply:

   ```bash
   docker compose --env-file /secure/sensor.env \
     -f deploy/sensor/docker-compose.yml -f deploy/overlays/forensics-sensor.yml \
     --profile capture up -d
   ```

## Verify (operator only)

Install `deploy/security/requirements-test.txt` in the verifier's Python environment.
On a trusted administration host with the external broker route, export
`REDPANDA_BOOTSTRAP`, `CERNITY_BUS_CA`, `CERNITY_BUS_ADMIN_USER/PASSWORD`,
`CERNITY_BUS_CAPTURE_USER/PASSWORD` (each slash denotes two separate variables),
and `NDR_SENSOR`, then run:

```bash
./deploy/security/test_bus_acls.sh
```

This script connects to the existing broker using verified TLS and SCRAM. It
requires the exact capture ACL set, rejects wildcard-principal grants, checks
allowed topic metadata, and requires explicit authorization errors on existing
`ndr.finding.final.v1` and `suricata.flow.v1` topics. Create those topics as admin
if absent before running. Missing dependencies, transport failures and missing
topics fail; they never count as denied access or a successful skip. The script
is read-only and does not publish capture directives or findings. It assumes no
RBAC role grants for the capture principal; audit/remove role memberships first.
It checks ACLs and metadata enforcement, not produce/consume delivery.

From the sensor network, test S3 health and use the scoped key to put and retrieve
a harmless unique probe under the configured prefix. Compare bytes/hash. Require
AccessDenied for another tenant's prefix, bucket listing and `ndr-files`; have an
administrator remove the probe. Record the actual endpoint, principal, object
key, hashes and errors without logging secrets. Firewall rules, DNS, TLS gateway
trust and real reachability remain operator checks.

Keep `PCAP_RING_POLICY` and `PCAP_PRESERVE_POLICIES` disabled (their existing `{}`
defaults). These artifacts intentionally do not enable preservation. The current
agent also emits `ndr.enrichment.request.v1`, `ndr.enrichment.result.v1`, and
`ndr.file.extracted.v1`; all remain denied by the requested capture-only ACLs.
Consequently these artifacts alone cannot pass full evidence propagation. A
separate reviewed central relay or application change is required; do not widen
the sensor ACL to bypass this restriction. Only after that dependency is resolved
may an operator enable an authorized test policy and record a real trigger,
tenant-isolated preserved object, authenticated/audited retrieval, and persisted
finding linkage before declaring the capability verified.

Offline gate:

```bash
PYTHONPATH=shared .venv/bin/python -m pytest -q deploy/security/test_forensics_config.py
```

CLI references: [Redpanda ACL semantics](https://docs.redpanda.com/25.1/reference/rpk/rpk-security/rpk-security-acl/),
[ACL reconciliation](https://docs.redpanda.com/streaming/current/reference/rpk/rpk-security/rpk-security-acl-delete/),
[SCRAM credential update](https://docs.redpanda.com/streaming/current/reference/rpk/rpk-security/rpk-security-user-update/).
