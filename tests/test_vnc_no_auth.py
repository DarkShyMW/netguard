"""Tests for VNC without authentication plugin (vnc_no_auth)."""
from __future__ import annotations

import os
import socket
import sys
import threading
from typing import Callable, Tuple

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "netguard"))

from models import Host, Service
from netguard.plugins.vulns import VncNoAuthPlugin


def _serve(handler: Callable[[socket.socket], None]) -> Tuple[str, int]:
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind(("127.0.0.1", 0))
    srv.listen(1)
    host, port = srv.getsockname()

    def runner() -> None:
        try:
            conn, _ = srv.accept()
        except OSError:
            return
        try:
            conn.settimeout(2.0)
            handler(conn)
        except OSError:
            pass
        finally:
            conn.close()
            srv.close()

    threading.Thread(target=runner, daemon=True).start()
    return host, port


def _make_target(host_ip: str, port: int, name: str = "vnc") -> Tuple[Host, Service]:
    return Host(ip=host_ip), Service(port=port, name=name)


# Fake VNC-servers (RFB handshake)

def _vnc_no_auth(conn: socket.socket) -> None:
    conn.sendall(b"RFB 003.008\n")
    conn.recv(12)                 # client version echo
    conn.sendall(b"\x01\x01")     # 1 security type: 1 = None


def _vnc_auth_required(conn: socket.socket) -> None:
    conn.sendall(b"RFB 003.008\n")
    conn.recv(12)
    conn.sendall(b"\x01\x02")     # 1 security type: 2 = VNC Auth


def _vnc_zero_types(conn: socket.socket) -> None:
    conn.sendall(b"RFB 003.008\n")
    conn.recv(12)
    conn.sendall(b"\x00")         # server refused before


def _not_vnc(conn: socket.socket) -> None:
    conn.sendall(b"HELLO WORLD\n")


# tests

def test_plugin_metadata() -> None:
    p = VncNoAuthPlugin()
    assert p.id == "vnc_no_auth"
    assert p.severity == "high"
    assert "vnc" in p.applies_to_services
    assert 5900 in p.applies_to_ports


def test_detects_vnc_without_auth() -> None:
    host_ip, port = _serve(_vnc_no_auth)
    host, svc = _make_target(host_ip, port)

    findings = VncNoAuthPlugin().check(host, svc)

    assert findings is not None
    assert len(findings) == 1
    f = findings[0]
    assert "security types=" in f.evidence
    assert "None" in f.description


def test_connection_refused_returns_none() -> None:
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.bind(("127.0.0.1", 0))
    host_ip, port = srv.getsockname()
    srv.close()

    host, svc = _make_target(host_ip, port)
    assert VncNoAuthPlugin().check(host, svc) is None


@pytest.mark.parametrize("handler", [
    _vnc_auth_required,
    _vnc_zero_types,
    _not_vnc,
])
def test_not_flagged(handler: Callable[[socket.socket], None]) -> None:
    host_ip, port = _serve(handler)
    host, svc = _make_target(host_ip, port)
    assert VncNoAuthPlugin().check(host, svc) is None
