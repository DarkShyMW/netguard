import pytest
from netguard.fingerprint import guess_service_by_port, _apply_banner, fingerprint_service

def test_guess_service_by_port():
    assert guess_service_by_port(22) == "ssh"
    assert guess_service_by_port(80) == "http"
    # Note: Implementation detail mentioned in prompt
    assert guess_service_by_port(3389) == "ms-wbt-server" 

def test_apply_banner_ssh():
    banner = "SSH-2.0-OpenSSH_8.0p1 Ubuntu-4"
    service = _apply_banner("ssh", banner)
    assert "OpenSSH" in service.version or "8.0" in service.version

def test_apply_banner_http():
    banner = "HTTP/1.1 200 OK\r\nServer: Apache/2.4.41\r\n"
    service = _apply_banner("http", banner)
    assert "Apache" in service.server

def test_fingerprint_service_ephemeral_unknown():
    # Simulate service on non-standard port without HTTP probe capability
    # Assuming fingerprint_service only does HTTP probes for known http ports/names
    result = fingerprint_service("127.0.0.1", 54321, "unknown_service", banner="Some Banner")
    assert result.name == "unknown"