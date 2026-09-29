"""Always-present sensor health reporting; no packet-capture dependency."""
from __future__ import annotations

import csv
import json
import logging
import math
import os
from pathlib import Path
import shutil
import subprocess
import time
from datetime import datetime, timezone
from uuid import UUID

TOPIC = 'ndr.sensor.health.v1'
VERSION = '0.1.0'
LOG = logging.getLogger('sensor-agent')


def clock_measurement(run=subprocess.run):
    """Read host chronyd, not a configured/assumed offset. Never changes its clock.

    chrony 4.x CSV: refid, source, stratum, ref time, current correction,
    last offset, RMS, frequency, residual, skew, delay, dispersion, interval, leap.
    current correction is positive when the SYSTEM clock is slow; negate for
    our sensor-minus-source convention. See README for upstream references.
    """
    unavailable = dict(clock_offset_ms=None, time_source=None, clock_status='unavailable')
    try:
        result = run(['chronyc', '-c', '-h', '127.0.0.1', 'tracking'],
                     capture_output=True, text=True, check=True, timeout=2)
        fields = next(csv.reader([result.stdout.strip()]))
        if (len(fields) != 14 or not 1 <= int(fields[2]) <= 15
                or fields[13] not in ('Normal', 'Insert second', 'Delete second')
                or fields[0] in ('00000000', '7F7F0101') or not fields[1]):
            return unavailable
        offset = -float(fields[4]) * 1000
        if not math.isfinite(offset) or float(fields[3]) <= 0:
            return unavailable
        return dict(clock_offset_ms=offset, time_source=fields[1], clock_status='synchronized')
    except (OSError, subprocess.SubprocessError, ValueError, csv.Error):
        return unavailable


class Resources:
    def __init__(self, proc='/proc', disk='/'):
        self.proc, self.disk = Path(proc), disk
        self.previous = None

    def sample(self):
        result = dict(cpu_pct=None, mem_pct=None, disk_free_bytes=None)
        try:
            # guest/guest_nice are already counted in user/nice.
            ticks = [int(x) for x in (self.proc / 'stat').read_text().splitlines()[0].split()[1:9]]
            total, idle = sum(ticks), ticks[3] + ticks[4]
            if self.previous and total > self.previous[0] and idle >= self.previous[1]:
                result['cpu_pct'] = max(0, min(100, 100 * (1 - (idle-self.previous[1])/(total-self.previous[0]))))
            self.previous = total, idle
        except (OSError, ValueError, IndexError):
            self.previous = None
        try:
            mem = {line.split(':')[0]: int(line.split()[1]) for line in (self.proc / 'meminfo').read_text().splitlines()}
            result['mem_pct'] = 100 * (1 - mem['MemAvailable']/mem['MemTotal'])
        except (OSError, ValueError, KeyError, ZeroDivisionError):
            pass
        try:
            result['disk_free_bytes'] = shutil.disk_usage(self.disk).free
        except OSError:
            pass
        return result


class EveRates:
    """Bounded tail read per heartbeat. Startup, rotation and overflow are unknown.

    Count complete EVE lines only. No capture-agent, packet socket or PCAP read.
    """
    def __init__(self, paths, max_bytes=4 * 1024 * 1024):
        self.paths, self.max_bytes = [Path(p) for p in paths], max_bytes
        self.previous = {}

    def _baseline(self, path, stream, stat, identity, now):
        # If starting at EOF inside a line, do not count its later suffix as an
        # entire event. This also applies after rotation or bounded-read overflow.
        stream.seek(max(0, stat.st_size - 1))
        partial = stat.st_size > 0 and stream.read(1) != b'\n'
        self.previous[path] = identity, stat.st_size, now, partial

    def sample(self, now):
        events = size = 0
        complete = bool(self.paths)
        for path in self.paths:
            try:
                with path.open('rb') as stream:
                    stat = os.fstat(stream.fileno())
                    identity = stat.st_dev, stat.st_ino
                    prior = self.previous.get(path)
                    if not prior or prior[0] != identity or stat.st_size < prior[1]:
                        self._baseline(path, stream, stat, identity, now)
                        complete = False
                        continue
                    elapsed = now - prior[2]
                    if elapsed <= 0 or stat.st_size - prior[1] > self.max_bytes:
                        self._baseline(path, stream, stat, identity, now)
                        complete = False
                        continue
                    stream.seek(prior[1])
                    data = stream.read(min(stat.st_size-prior[1], self.max_bytes))
                    # Leave partial lines for the next measurement.
                    end = data.rfind(b'\n') + 1
                    data = data[:end]
                    self.previous[path] = identity, prior[1] + end, now, prior[3] and not end
                    if prior[3] and end:
                        data = data[data.find(b'\n') + 1:]
                    events += data.count(b'\n') / elapsed
                    size += len(data) / elapsed
            except OSError:
                self.previous.pop(path, None)
                complete = False
        return dict(events_per_second=events if complete else None,
                    bytes_per_second=size if complete else None)


def empty_metrics():
    return dict(capture=dict(kernel_drops_total=None, suricata_capture_drops_total=None),
                eve=dict(events_per_second=None, bytes_per_second=None),
                shipper=dict(queue_depth=None, oldest_unsent_age_s=None))


def supplemental_metrics(path, now, max_age=60):
    """Optional fresh host-exporter snapshot for capture counters/shipper backlog.

    A missing, stale or invalid exporter must not stop the mandatory heartbeat.
    Snapshot is bounded, read only, and cannot override identity or clock data.
    """
    result = empty_metrics()
    if not path:
        return result
    try:
        with open(path) as stream:
            raw = stream.read(16385)
        if len(raw) > 16384:
            return result
        doc = json.loads(raw)
        age = now - float(doc['observed_at_unix'])
        if not math.isfinite(age) or not 0 <= age <= max_age:
            return result
        for section in ('capture', 'shipper'):
            for key in result[section]:
                value = doc.get(section, {}).get(key)
                integer = key.endswith('_total') or key == 'queue_depth'
                if (type(value) in (int, float) and math.isfinite(value) and value >= 0
                        and (not integer or type(value) is int)):
                    result[section][key] = value
    except (OSError, ValueError, KeyError, TypeError, AttributeError, OverflowError):
        pass
    return result


class Agent:
    def __init__(self, sensor_uuid, tenant, site, versions=None, resources=None,
                 eve=None, metrics_path=None, clock=clock_measurement):
        self.sensor_uuid = str(UUID(sensor_uuid))
        if not tenant.strip() or not site.strip():
            raise ValueError('tenant and site are required')
        self.tenant, self.site = tenant, site
        self.versions = dict(versions or {}, agent=VERSION)
        if any(not isinstance(v, str) or not v.strip() for v in self.versions.values()):
            raise ValueError('versions must contain nonempty strings')
        self.resources = resources or Resources()
        self.eve = eve or EveRates([])
        self.metrics_path, self.clock = metrics_path, clock
        self.bus = 'unknown'

    def heartbeat(self):
        now = time.time()
        record = dict(schema_version='sensor-health.v1', sensor_uuid=self.sensor_uuid,
                      tenant=self.tenant, site=self.site, versions=self.versions,
                      observed_at=datetime.fromtimestamp(now, timezone.utc).isoformat(),
                      resources=self.resources.sample(), connectivity={'bus': self.bus},
                      **supplemental_metrics(self.metrics_path, now), **self.clock())
        record['eve'] = self.eve.sample(time.monotonic())
        return record

    def run(self, publish, stop, interval=30, monotonic=time.monotonic):
        if not math.isfinite(interval) or interval <= 0:
            raise ValueError('heartbeat interval must be finite and positive')
        deadline = monotonic()
        while not stop.is_set():
            try:
                publish(self.heartbeat())
                self.bus = 'connected'
            except Exception:
                self.bus = 'disconnected'
                LOG.exception('health heartbeat failed; retrying next interval')
            deadline += interval
            # Skip missed ticks; never burst old heartbeats after an outage.
            now = monotonic()
            if deadline < now:
                deadline += (math.floor((now - deadline) / interval) + 1) * interval
            stop.wait(max(0, deadline - now))
