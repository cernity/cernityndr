"""Pure forward logic: hand each finding to the sink adapter. Kept separate from
the I/O shell so it is testable without a broker."""


def handle_batch(findings, adapter):
    for f in findings:
        adapter.emit(f)
