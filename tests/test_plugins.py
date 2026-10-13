import pytest
from netguard.plugins import registry, get_plugin_by_id

def test_registry_loaded():
    assert len(registry) >= 10
    ids = [p.id for p in registry]
    assert len(ids) == len(set(ids)), "Plugin IDs must be unique"

def test_applies_logic():
    # Assume we have a telnet plugin
    telnet_plugin = next(p for p in registry if p.id == "telnet")
    assert telnet_plugin.applies({"port": 23, "banner": ""})
    assert not telnet_plugin.applies({"port": 80, "banner": ""})

def test_make_finding():
    ftp_plugin = next(p for p in registry if p.id == "ftp")
    banner = "220 FTP Server Ready"
    finding = ftp_plugin.make_finding(banner=banner, port=21)
    assert finding.service == "ftp"
    assert finding.severity.name in ["LOW", "MEDIUM", "HIGH", "CRITICAL"]

def test_ssh_clean():
    ssh_plugin = next(p for p in registry if p.id == "ssh")
    # SSH usually requires more than just banner to flag as vulnerable in simple scanners
    finding = ssh_plugin.make_finding(banner="SSH-2.0-OpenSSH_8.0", port=22)
    # Depending on implementation, might be None or low severity info
    if finding:
        assert finding.severity.name == "INFO" or finding.severity.value < 3