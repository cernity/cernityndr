# U4: bounded YARA workers and rule-stamped file observations

Status: implemented, pending independent review.

Every selected active or shadow registry row is scanned in its own explicit POSIX
fork child, including compilation, MIME sniffing and U2 archive validation. No
SQLite operations run in the child. Resource limits bound address space and CPU;
the parent enforces a separate wall watchdog, SIGKILLs and reaps runaway children.
A temporary result file avoids pipe-buffer deadlocks. Memory allocation failures
write an oom marker before SIGKILL. CPU exhaustion is recognized from its marker
or the killed child's wait4 CPU usage. An unexplained SIGKILL is worker_killed,
not an invented OOM diagnosis. Limit setup failures fail closed. This is resource
isolation, not a syscall sandbox. Forking a process containing client-library
threads can inherit locks; a stuck child becomes an explicit watchdog error.

Policy bounds are 64 source bytes per string (each byte encoded as \\xHH), 16
instances per rule, and 128 matching rules per result. Truncation flags identify
partial output. Escaping is not PII anonymisation; these are bounded forensic
previews stored under the evidence access policy. MIME uses conservative bounded
signature checks, otherwise opaque octet-stream or an ASCII text heuristic. ZIP
validation reuses U2's traversal, member-size and nesting checks; this scanner does
not recursively scan decompressed members or claim to unpack other archive types.

Active and shadow results retain separate exact registry id, version and digest,
plus engine version. Only successful active hits affect findings. The old combined
compiled cache is removed; registry selection happens for each artifact, so
retirement takes effect on the next scan. Image-owned baseline bytes are registered
and promoted using a dedicated local identity; any existing non-draft lifecycle
decision for those bytes wins. Remote refresh still stages drafts only.

The input binding changes from ndr.file.extracted.v1 to U2's existing
ndr.file.artifact.v1. U2 already consumes extraction announcements and emits this
link only after validation and storage. Keeping the old trigger while requiring
accepted U2 bytes would race acceptance and replay forever for rejected artifacts.
U4 uses U2 retrieve unchanged: tenant configuration authorizes access, the exact
accepted key is checked, and retention, size and content digest are verified.
No direct reads of staging bytes or duplicate artifact storage are introduced.

The closed U1 canonical scan_verdict supports one digest, engine and rule names.
One observation per ruleset preserves that contract; engine includes its version.
Shadow scans, errors and unconfigured scans omit scan_verdict. The full structured
scan result lives in that observation's stored raw_record, addressed by the
source_ref and its digest, including pcap_evidence_id if the input supplies one.
U2's current linkage producer does not itself supply PCAP linkage, so this does
not establish end-to-end packet lineage. bytes_available always names a verified
U2 artifact, even if scanning failed. Observations are inserted into the existing
file table before acknowledged canonical publication; findings are acknowledged
before manual input commits. Retries can duplicate writes; no exactly-once claim.

Deployment requires the U2 service and its artifact topic, LogAppendTime on that
topic, the existing file-observation table, read access to accepted objects, and
canonical observation publish rights. The overlay adds the required ClickHouse
credentials to file-yara. The Dockerfile includes the worker, shared object-key
module, U2 store module and both observation schemas. No contract migration.

Local verification uses Python 3.14 and real yara-python. macOS rejects RLIMIT_AS,
so local functional tests stub that syscall, explicitly test setup failure, and
exercise real fork, wall kills and CPU kills. The real address-space exhaustion
and hard CPU-kill tests run on Linux and are skipped on macOS. Soft CPU-limit
handling is exercised locally, with an assertion that the wall watchdog did not
cause the kill. Docker daemon access is unavailable
in this environment; image build and Linux memory enforcement remain deployment
verification gates, as do live broker, ClickHouse and object-store delivery.
