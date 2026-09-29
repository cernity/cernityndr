"""sensor-health.v1 contract fixtures; mirrors test_contracts.py."""
import copy
from datetime import datetime
import re
import json
from pathlib import Path

from jsonschema import Draft202012Validator, FormatChecker, ValidationError

SCHEMA = json.loads((Path(__file__).parent / 'sensor-health.schema.json').read_text())
CHECKER = FormatChecker()


@CHECKER.checks('date-time', raises=ValueError)
def date_time(value):
    # jsonschema's optional RFC3339 dependency is absent in the base test env.
    if not isinstance(value, str):
        return True
    if not re.fullmatch(r'\d{4}-\d{2}-\d{2}[Tt]\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:[Zz]|[+-]\d{2}:\d{2})', value):
        return False
    return datetime.fromisoformat(value.upper().replace('Z', '+00:00')).tzinfo is not None


VALIDATOR = Draft202012Validator(SCHEMA, format_checker=CHECKER)
MINIMAL = {
    'schema_version': 'sensor-health.v1',
    'sensor_uuid': 'e04b79e4-6d53-4303-8183-382410120cc6',
    'tenant': 'acme', 'site': 'dc1', 'observed_at': '2026-09-28T00:00:00Z',
    'versions': {'agent': '0.1.0'},
    'resources': {'cpu_pct': None, 'mem_pct': None, 'disk_free_bytes': None},
    'capture': {'kernel_drops_total': None, 'suricata_capture_drops_total': None},
    'eve': {'events_per_second': None, 'bytes_per_second': None},
    'shipper': {'queue_depth': None, 'oldest_unsent_age_s': None},
    'connectivity': {'bus': 'unknown'},
    'clock_offset_ms': None, 'time_source': None, 'clock_status': 'unavailable',
}
FULL = dict(MINIMAL, versions={'agent': '0.1.0', 'suricata': '8.0.0', 'fluent_bit': '4.0'},
            resources={'cpu_pct': 20.5, 'mem_pct': 45, 'disk_free_bytes': 100000000},
            capture={'kernel_drops_total': 3, 'suricata_capture_drops_total': 2},
            eve={'events_per_second': 125.5, 'bytes_per_second': 102400},
            shipper={'queue_depth': 10, 'oldest_unsent_age_s': 1.5},
            connectivity={'bus': 'connected'}, clock_offset_ms=-12.5,
            time_source='192.0.2.123', clock_status='synchronized')


def rejects(doc):
    try:
        VALIDATOR.validate(doc)
    except ValidationError:
        return True
    return False


def test_full_and_minimal():
    Draft202012Validator.check_schema(SCHEMA)
    VALIDATOR.validate(FULL)
    VALIDATOR.validate(MINIMAL)


def test_every_required_field():
    for key in SCHEMA['required']:
        doc = copy.deepcopy(FULL)
        del doc[key]
        assert rejects(doc), key


def test_invalid_measurements_and_identity():
    for patch in ({'schema_version': 'v2'}, {'sensor_uuid': 'sensor-1'},
                  {'tenant': ''}, {'observed_at': 'not-a-date'}, {'extra': 1},
                  {'clock_offset_ms': None}, {'time_source': None},
                  {'clock_status': 'unavailable'}, {'clock_offset_ms': '12'}):
        assert rejects(dict(FULL, **patch)), patch
    for section, field, value in [('resources', 'cpu_pct', 101),
                                   ('resources', 'mem_pct', -1),
                                   ('capture', 'kernel_drops_total', -1),
                                   ('shipper', 'queue_depth', 0.5),
                                   ('eve', 'events_per_second', 'fast')]:
        doc = copy.deepcopy(FULL)
        doc[section][field] = value
        assert rejects(doc)


if __name__ == '__main__':
    for name, fn in list(globals().items()):
        if name.startswith('test_'):
            fn()
