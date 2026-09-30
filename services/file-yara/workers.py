"""Per-scan fork isolation. No parsers or YARA compilation run in the parent.

The result travels through a temporary file, so a full IPC pipe cannot deadlock
child exit. The parent always reaps the child, including watchdog failures.
"""
import json
import os
import resource
import signal
import tempfile
import time
from dataclasses import dataclass
from pathlib import Path

# Reuse U2 policy, with the same flat-container/sibling-source import convention.
try:
    import artifact_store
except ModuleNotFoundError:
    import importlib.util
    spec = importlib.util.spec_from_file_location(
        "artifact_store", Path(__file__).resolve().parents[1] / "file-artifact/store.py")
    artifact_store = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(artifact_store)


@dataclass(frozen=True)
class Limits:
    memory_bytes: int = 1024 * 1024 * 1024
    cpu_seconds: int = 5
    wall_seconds: float = 10
    max_bytes: int = 64 * 1024 * 1024
    archive_depth: int = 4


STRING_BYTES = 64
MAX_STRINGS = 16
MAX_MATCHES = 128


def escaped_preview(data):
    # Escape every byte: printable content is still sensitive, so this is a
    # bounded forensic preview, NOT a claim of PII anonymisation.
    return ''.join(f'\\x{b:02x}' for b in data[:STRING_BYTES])


def sniff_mime(data):
    """Bounded signature sniff; unknown data stays opaque. Never trusts wire MIME."""
    if data.startswith(b'MZ'):
        return 'application/x-dosexec'
    if data.startswith(b'\x7fELF'):
        return 'application/x-elf'
    if data.startswith(b'%PDF-'):
        return 'application/pdf'
    if artifact_store.is_zip(data):
        return 'application/zip'
    if data and all(b in (9, 10, 13) or 32 <= b < 127 for b in data[:4096]):
        return 'text/plain'
    return 'application/octet-stream'


def _match(source, data):
    import yara
    matches = []
    overflow = False

    def collect(match):
        nonlocal overflow
        if not match['matches']:
            return yara.CALLBACK_CONTINUE
        if len(matches) >= MAX_MATCHES:
            overflow = True
            return yara.CALLBACK_ABORT
        strings = []
        count = 0
        for string in match['strings']:
            for instance in string.instances:
                count += 1
                if len(strings) < MAX_STRINGS:
                    raw = instance.matched_data
                    strings.append({'identifier': string.identifier[:128],
                                    'offset': instance.offset,
                                    'data': escaped_preview(raw),
                                    'truncated': instance.matched_length > STRING_BYTES})
        matches.append({'rule': match['rule'][:256], 'strings': strings,
                        'strings_truncated': count > MAX_STRINGS})
        return yara.CALLBACK_CONTINUE

    yara.compile(source=source.decode('utf-8')).match(
        data=data, callback=collect, which_callbacks=yara.CALLBACK_MATCHES)
    return {'matches': matches, 'matches_truncated': overflow}


def _child(output, source, data, row, limits):
    def killed(reason):
        # Small pre-encoded marker remains writable following allocation failure.
        os.lseek(output.fileno(), 0, os.SEEK_SET)
        os.ftruncate(output.fileno(), 0)
        os.write(output.fileno(), b'{"scan_error":"' + reason + b'"}')
        os.kill(os.getpid(), signal.SIGKILL)

    signal.signal(signal.SIGXCPU, lambda *_: killed(b'timeout'))
    try:
        resource.setrlimit(resource.RLIMIT_AS, (limits.memory_bytes, limits.memory_bytes))
        resource.setrlimit(resource.RLIMIT_CPU, (limits.cpu_seconds, limits.cpu_seconds + 1))
        if not data or len(data) > min(limits.max_bytes, row['max_file_size']):
            result = {'scan_error': 'size_limit'}
        else:
            mime = sniff_mime(data)
            artifact_store.validate_archive(data, max_depth=limits.archive_depth,
                                            max_file_size=limits.max_bytes)
            if row['target_mime_types'] and mime not in row['target_mime_types']:
                result = {'scan_error': 'mime_not_targeted', 'mime': mime}
            else:
                result = {**_match(source, data), 'mime': mime, 'scan_error': None}
                if result['matches']:
                    import fileforensics
                    result['file_forensics'] = fileforensics.forensics(data)
        output.write(json.dumps(result).encode())
        output.flush()
    except MemoryError:
        killed(b'oom')
    except artifact_store.PolicyError:
        output.write(b'{"scan_error":"archive_policy"}')
        output.flush()
    except Exception as exc:
        # yara-python reports native allocator failure as yara.Error, rather
        # than Python MemoryError. Match only the engine's allocation error.
        import yara
        if isinstance(exc, yara.Error) and str(exc).lower() == "insufficient memory":
            killed(b'oom')
        # Do not export parser errors that might quote file content.
        output.write(b'{"scan_error":"worker_error"}')
        output.flush()


def run_scan(source, data, row, limits=Limits()):
    if (limits.memory_bytes <= 0 or limits.cpu_seconds < 1 or limits.wall_seconds <= 0
            or limits.max_bytes < 1 or limits.archive_depth < 0):
        raise ValueError('invalid scan limits')
    with tempfile.TemporaryFile() as output:
        pid = os.fork()  # Explicit: Python 3.14 defaults must not change isolation.
        if pid == 0:
            try:
                _child(output, source, data, row, limits)
            finally:
                os._exit(0)
        reaped = False
        timed_out = False
        deadline = time.monotonic() + limits.wall_seconds
        try:
            while True:
                waited, status, usage = os.wait4(pid, os.WNOHANG)
                if waited:
                    reaped = True
                    break
                if time.monotonic() >= deadline:
                    timed_out = True
                    os.kill(pid, signal.SIGKILL)
                    _, status, usage = os.wait4(pid, 0)
                    reaped = True
                    break
                time.sleep(min(.01, max(0, deadline - time.monotonic())))
            exitcode = os.waitstatus_to_exitcode(status)
            output.seek(0)
            try:
                result = json.loads(output.read(2 * 1024 * 1024))
            except (ValueError, UnicodeDecodeError):
                result = {'scan_error': 'worker_exit'}
            # A C extension can defer the Python SIGXCPU handler until after the
            # hard limit. wait4's per-child CPU usage disambiguates that SIGKILL.
            cpu_exhausted = (exitcode in (-signal.SIGKILL, -signal.SIGXCPU)
                             and usage.ru_utime + usage.ru_stime >= limits.cpu_seconds)
            if timed_out or cpu_exhausted:
                result = {'scan_error': 'timeout'}
            elif exitcode and result.get('scan_error') not in ('timeout', 'oom'):
                # SIGKILL alone cannot distinguish OOM from an external kill.
                result = {'scan_error': 'worker_killed' if exitcode < 0 else 'worker_exit'}
            result['watchdog_killed'] = timed_out
            result['exitcode'] = exitcode
            if result.get('scan_error'):
                result['matches'] = []
            return result
        finally:
            if not reaped:
                try:
                    os.kill(pid, signal.SIGKILL)
                except ProcessLookupError:
                    pass
                os.wait4(pid, 0)
