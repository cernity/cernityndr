"""Pure forward logic: hand findings to the sink adapter. Uses the adapter's
emit_batch when available (efficient bulk delivery), else per-finding emit."""


def handle_batch(findings, adapter):
    if not findings:
        return
    if hasattr(adapter, "emit_batch"):
        adapter.emit_batch(findings)
    else:
        for f in findings:
            adapter.emit(f)
