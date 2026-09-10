# Zeek reference-arm policy for the benchmark. Run offline over the SAME pcap:
#   zeek -r /pcaps/<file>.pcap -C LogAscii::use_json=T local
#
# Loads Zeek's default analysis (the "as good as Zeek standalone" baseline the
# parity study compares against — equivalent to running Suricata with stock ET Open,
# per the fair-methodology anchor) and emits JSON logs the scorer can read. No
# custom detections are added: the point is a fair default-vs-default reference.

@load base/protocols/conn
@load base/protocols/dns
@load base/protocols/http
@load base/protocols/ssl
@load base/protocols/ssh
@load base/protocols/smb
@load base/protocols/krb
@load base/protocols/dce-rpc
@load base/files/hash

@load policy/protocols/ssl/validate-certs
@load policy/protocols/conn/known-hosts

# JSON logs so benchmarks/run.py can parse notice.log / conn.log uniformly.
redef LogAscii::use_json = T;
