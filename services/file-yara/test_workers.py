"""Fork/watchdog tests plus Linux-only real resource enforcement tests."""
import io
import os
import resource
import signal
import sys
import time
import zipfile

import pytest
import workers as w

ROW = {'max_file_size': 1024 * 1024, 'target_mime_types': []}
SOURCE = b'rule test { condition: true }'


@pytest.fixture
def portable_limits(monkeypatch):
    """macOS cannot install RLIMIT_AS; only that syscall is stubbed locally."""
    real = resource.setrlimit
    if sys.platform != 'linux':
        monkeypatch.setattr(resource, 'setrlimit',
                            lambda kind, value: None if kind == resource.RLIMIT_AS else real(kind, value))


def _hang(*_):
    while True:
        time.sleep(.01)


def _oom(*_):
    raise MemoryError


def test_wall_timeout_kills_and_reaps(portable_limits, monkeypatch):
    monkeypatch.setattr(w, '_match', _hang)
    result = w.run_scan(SOURCE, b'abc', ROW, w.Limits(wall_seconds=.1))
    assert result['scan_error'] == 'timeout'
    assert result['watchdog_killed'] is True
    assert result['exitcode'] == -signal.SIGKILL
    assert result['matches'] == []
    # Multiprocessing must have reaped the child, not left a zombie.
    import multiprocessing
    assert not multiprocessing.active_children()


def test_allocation_failure_is_killed_as_oom(portable_limits, monkeypatch):
    monkeypatch.setattr(w, '_match', _oom)
    result = w.run_scan(SOURCE, b'abc', ROW)
    assert result['scan_error'] == 'oom'
    assert result['exitcode'] == -signal.SIGKILL
    assert result['matches'] == []


def test_limits_are_installed_in_child(monkeypatch, tmp_path):
    trace = tmp_path / 'limits'
    def record(kind, value):
        with trace.open('a') as out:
            out.write(f'{os.getpid()} {kind} {value}\n')
    monkeypatch.setattr(resource, 'setrlimit', record)
    result = w.run_scan(SOURCE, b'abc', ROW, w.Limits(memory_bytes=123456, cpu_seconds=2))
    assert result['scan_error'] is None
    lines = trace.read_text().splitlines()
    assert len(lines) == 2
    assert all(not line.startswith(str(os.getpid()) + ' ') for line in lines)
    assert f'{resource.RLIMIT_AS} (123456, 123456)' in lines[0]
    assert f'{resource.RLIMIT_CPU} (2, 3)' in lines[1]


def test_limit_setup_failure_fails_closed(monkeypatch):
    def denied(*_):
        raise ValueError('unsupported')
    monkeypatch.setattr(resource, 'setrlimit', denied)
    result = w.run_scan(SOURCE, b'abc', ROW)
    assert result['scan_error'] == 'worker_error'
    assert result['matches'] == []


def test_unknown_sigkill_is_not_invented_oom(portable_limits, monkeypatch):
    monkeypatch.setattr(w, '_match', lambda *_: os.kill(os.getpid(), signal.SIGKILL))
    result = w.run_scan(SOURCE, b'abc', ROW)
    assert result['scan_error'] == 'worker_killed'
    assert result['exitcode'] == -signal.SIGKILL


def test_mime_and_policy_in_child(portable_limits, monkeypatch):
    parent = os.getpid()
    sniff = w.sniff_mime
    def child_sniff(data):
        assert os.getpid() != parent
        return sniff(data)
    monkeypatch.setattr(w, 'sniff_mime', child_sniff)
    assert w.run_scan(SOURCE, b'MZabc', ROW)['mime'] == 'application/x-dosexec'
    assert w.run_scan(SOURCE, b'abc', ROW, w.Limits(max_bytes=2))['scan_error'] == 'size_limit'
    assert w.run_scan(SOURCE, b'abc', {**ROW, 'max_file_size': 2})['scan_error'] == 'size_limit'
    assert w.run_scan(SOURCE, b'abc', {**ROW, 'target_mime_types': ['application/pdf']})['scan_error'] == 'mime_not_targeted'
    data = b'abc'
    for _ in range(2):
        buf = io.BytesIO()
        with zipfile.ZipFile(buf, 'w') as archive:
            archive.writestr('nested', data)
        data = buf.getvalue()
    assert w.run_scan(SOURCE, data, ROW, w.Limits(archive_depth=1))['scan_error'] == 'archive_policy'


@pytest.mark.skipif(sys.platform != 'linux', reason='real RLIMIT_AS enforcement requires Linux')
def test_real_address_space_limit(monkeypatch):
    def allocate(*_):
        return bytearray(1024 * 1024 * 1024)
    monkeypatch.setattr(w, '_match', allocate)
    result = w.run_scan(SOURCE, b'abc', ROW, w.Limits(memory_bytes=512 * 1024 * 1024))
    assert result['scan_error'] == 'oom'
    assert result['exitcode'] == -signal.SIGKILL


def test_real_cpu_limit(portable_limits, monkeypatch):
    def spin(*_):
        while True:
            pass
    monkeypatch.setattr(w, '_match', spin)
    result = w.run_scan(SOURCE, b'abc', ROW, w.Limits(cpu_seconds=1, wall_seconds=8))
    assert result['watchdog_killed'] is False
    assert result['scan_error'] == 'timeout'
    assert result['exitcode'] == -signal.SIGKILL


def test_native_allocator_failure_is_oom(portable_limits, monkeypatch):
    import yara
    def native_oom(*_):
        raise yara.Error('insufficient memory')
    monkeypatch.setattr(w, '_match', native_oom)
    result = w.run_scan(SOURCE, b'abc', ROW)
    assert result['scan_error'] == 'oom'
    assert result['exitcode'] == -signal.SIGKILL


@pytest.mark.skipif(sys.platform != 'linux', reason='Linux hard CPU limit semantics')
def test_hard_cpu_kill_is_timeout(portable_limits, monkeypatch):
    def spin(*_):
        signal.signal(signal.SIGXCPU, signal.SIG_IGN)
        while True:
            pass
    monkeypatch.setattr(w, '_match', spin)
    result = w.run_scan(SOURCE, b'abc', ROW, w.Limits(cpu_seconds=1, wall_seconds=8))
    assert result['watchdog_killed'] is False
    assert result['scan_error'] == 'timeout'
    assert result['exitcode'] == -signal.SIGKILL
