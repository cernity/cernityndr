#!/usr/bin/env bash
# REAL ENVIRONMENT ONLY. Read-only checks against an ALREADY RUNNING broker.
# No broker creation, no demo credentials, no skip-success, no record publication.
# See docs/decisions/003-forensics-bus-acls.md for operator setup and limitations.
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
: "${REDPANDA_BOOTSTRAP:?set reachable external broker host:19092}"
: "${CERNITY_BUS_CA:?set local CA certificate path}"
: "${CERNITY_BUS_ADMIN_USER:?set admin user}"
: "${CERNITY_BUS_ADMIN_PASSWORD:?set admin password}"
: "${CERNITY_BUS_CAPTURE_USER:?set provisioned capture user}"
: "${CERNITY_BUS_CAPTURE_PASSWORD:?set capture password}"
: "${NDR_SENSOR:?set provisioned sensor ID}"
export REDPANDA_BOOTSTRAP CERNITY_BUS_CA CERNITY_BUS_ADMIN_USER CERNITY_BUS_ADMIN_PASSWORD
export CERNITY_BUS_CAPTURE_USER CERNITY_BUS_CAPTURE_PASSWORD NDR_SENSOR
"${PYTHON:-$ROOT/.venv/bin/python}" - <<'PY'
import os
from kafka.admin import (KafkaAdminClient, ACLFilter, ResourcePatternFilter,
                        ResourceType, ACLResourcePatternType, ACLOperation, ACLPermissionType)
from kafka.errors import TopicAuthorizationFailedError

def require(ok, message):
    if not ok:
        raise SystemExit('FAIL: ' + message)

common = dict(bootstrap_servers=os.environ['REDPANDA_BOOTSTRAP'].split(','),
              security_protocol='SASL_SSL', ssl_cafile=os.environ['CERNITY_BUS_CA'],
              ssl_check_hostname=True, sasl_mechanism='SCRAM-SHA-512',
              request_timeout_ms=10000, api_version_auto_timeout_ms=10000)
admin = KafkaAdminClient(**common, sasl_plain_username=os.environ['CERNITY_BUS_ADMIN_USER'],
                         sasl_plain_password=os.environ['CERNITY_BUS_ADMIN_PASSWORD'])
capture = KafkaAdminClient(**common, sasl_plain_username=os.environ['CERNITY_BUS_CAPTURE_USER'],
                           sasl_plain_password=os.environ['CERNITY_BUS_CAPTURE_PASSWORD'])
try:
    user = 'User:' + os.environ['CERNITY_BUS_CAPTURE_USER']
    acl_filter = ACLFilter(None, None, ACLOperation.ANY, ACLPermissionType.ANY,
                          ResourcePatternFilter(ResourceType.ANY, None, ACLResourcePatternType.ANY))
    acls, error = admin.describe_acls(acl_filter)
    require(getattr(error, 'errno', -1) == 0, 'broker ACL inventory failed')
    # Reject wildcard-principal grants too: they apply even when the user's own
    # ACL list looks perfect. This deployment intentionally uses no RBAC roles.
    require(not any(a.principal == 'User:*' and a.permission_type == ACLPermissionType.ALLOW
                    for a in acls), 'wildcard principal grants present')
    expected = set()
    topics = {
        'ndr.capture.request.v1': ['DESCRIBE'],
        'ndr.capture.arm.v1': ['READ', 'DESCRIBE'],
        'ndr.capture.status.v1': ['WRITE', 'DESCRIBE'],
        'ndr.capture.request.v2': ['READ', 'DESCRIBE'],
    }
    for topic, operations in topics.items():
        expected.update(('TOPIC', topic, 'LITERAL', op, 'ALLOW', '*') for op in operations)
    expected.add(('GROUP', 'ndr-capture-agent-' + os.environ['NDR_SENSOR'],
                  'LITERAL', 'READ', 'ALLOW', '*'))
    actual = {(a.resource_pattern.resource_type.name, a.resource_pattern.resource_name,
               a.resource_pattern.pattern_type.name, a.operation.name, a.permission_type.name, a.host)
              for a in acls if a.principal == user}
    require(actual == expected, 'capture ACLs differ from the exact topic/group policy')
    for topic in topics:
        rows = capture.describe_topics([topic])
        require(len(rows) == 1 and rows[0]['error_code'] == 0,
                'capture authentication/topic metadata failed: ' + topic)
    # Existing noncapture topics prevent UNKNOWN_TOPIC from masquerading as denial.
    # This also detects a capture superuser or disabled enforcement.
    for topic in ('ndr.finding.final.v1', 'suricata.flow.v1'):
        rows = admin.describe_topics([topic])
        require(len(rows) == 1 and rows[0]['error_code'] == 0,
                'operator must provide existing negative-test topic: ' + topic)
        try:
            rows = capture.describe_topics([topic])
        except TopicAuthorizationFailedError:
            continue
        require(len(rows) == 1 and rows[0]['error_code'] == 29,
                'expected TOPIC_AUTHORIZATION_FAILED for ' + topic)
    print('PASS: live capture ACL inventory, TLS/SASL authentication, allowed metadata, and denied noncapture metadata')
    print('Not a packet/object-store/finding delivery test. Preserve remains gated pending the audited roundtrip.')
finally:
    capture.close()
    admin.close()
PY
