"""Minimal suricatasc client (unix socket, JSON protocol).

Avoids bundling the Suricata binary in the agent image. The protocol: connect,
send {"version": "0.2"}, read {"return":"OK"}; then per command send
{"command": ..., "arguments": {...}} and read one JSON reply. Suricata frames
replies as newline/size-terminated JSON; we read until a full JSON parses.
"""
from __future__ import annotations
import json
import socket

PROTO_VERSION = "0.2"


class SuricataSocketError(RuntimeError):
    pass


def _recv_json(sock: socket.socket, timeout: float = 10.0) -> dict:
    sock.settimeout(timeout)
    buf = b""
    while True:
        chunk = sock.recv(4096)
        if not chunk:
            break
        buf += chunk
        try:
            return json.loads(buf.decode())
        except ValueError:
            continue  # partial frame; keep reading
    raise SuricataSocketError(f"incomplete reply: {buf!r}")


def command(sock_path: str, cmd: str, arguments: dict | None = None,
            timeout: float = 10.0) -> dict:
    """Run one suricatasc command against the local socket. Returns the reply."""
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as s:
        s.connect(sock_path)
        s.sendall(json.dumps({"version": PROTO_VERSION}).encode())
        hello = _recv_json(s, timeout)
        if hello.get("return") != "OK":
            raise SuricataSocketError(f"handshake failed: {hello}")
        msg = {"command": cmd}
        if arguments:
            msg["arguments"] = arguments
        s.sendall(json.dumps(msg).encode())
        reply = _recv_json(s, timeout)
        if reply.get("return") != "OK":
            raise SuricataSocketError(f"{cmd} failed: {reply}")
        return reply


def dataset_add(sock_path: str, setname: str, settype: str, value: str) -> dict:
    return command(sock_path, "dataset-add",
                   {"setname": setname, "settype": settype, "datavalue": value})


def dataset_remove(sock_path: str, setname: str, settype: str, value: str) -> dict:
    return command(sock_path, "dataset-remove",
                   {"setname": setname, "settype": settype, "datavalue": value})
