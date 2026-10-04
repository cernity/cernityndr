# U3c: a TLS/HTTP attribute attaches to the entity the field actually describes

Status: implemented, pending independent review.

U3c wires `extract_evidence` to populate the U3a additive attributes from `tls`
and `http` EVE records. A TLS/HTTP event spans two endpoints — a client (`src_ip`)
and a server (`dest_ip`) — and its fields describe different ones:

- `tls.ja4` is the CLIENT's handshake fingerprint → the client (src).
- `tls.ja4s` is the SERVER's response fingerprint → the server (dst).
- `tls.subject` / `tls.issuerdn` / `tls.fingerprint` are the SERVER's presented
  certificate → the server (dst).
- `http.http_user_agent` is the CLIENT's software → the client (src), `applications`.
- `http.hostname` (the Host header) is the name the client used to reach the
  SERVER → the server (dst), `hostname`.

Decision: each value attaches ONLY to the endpoint it attests. The alternative —
folding every TLS/HTTP field onto the connection's src asset — reads simpler and
matches a literal reading of the task's "ja4/ja4s into ja4, cert into certificates",
but it fabricates identity the packet does not carry: it would record the SERVER's
certificate as the CLIENT's, and the visited site's Host header as the CLIENT's own
hostname (which also feeds the `hostname` fact predicate — the entity's own name).
That is exactly the unobserved inference U3c's honesty gate forbids. ja4 and ja4s
still land in the same `ja4` list FIELD; they are split across entities, not fields.

A field the record lacks yields no attribute (no default, no inference), so a TLS
event with neither a server fingerprint nor a cert produces no dst attribute row,
and a bare handshake with no client ja4 produces no src row — an honest gap.

Consequence: `extract_evidence` can emit up to two attribute rows per TLS/HTTP
record (one per endpoint that carries an observed field), each resolved to its own
entity through the shared `asset_key` spine. dns/flow set no attributes at all —
they produce relationship edges (`relationships.build_edges`).
