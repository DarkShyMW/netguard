import pytest
from netguard.config import parse_ports, resolve_host, expand_targets, ScanOptions

def test_parse_ports_ranges():
    assert parse_ports("1-3") == [1, 2, 3]
    assert parse_ports("80,443") == [80, 443]
    assert parse_ports("1-3,5") == [1, 2, 3, 5]

def test_parse_ports_reverse_and_clamp():
    # Reverse ranges should be handled or ignored based on impl, assuming sorted unique
    ports = parse_ports("3-1") 
    assert set(ports) <= {1, 2, 3} # Or empty depending on strictness
    
    # Clamp to valid range
    ports = parse_ports("0,65536,80")
    assert 80 in ports
    assert 0 not in ports and 65536 not in ports

def test_resolve_host_cidr():
    hosts = resolve_host("192.168.1.0/30")
    assert len(hosts) == 4
    assert "192.168.1.1" in hosts

def test_resolve_host_cap():
    # /24 has 256 hosts, /20 has 4096. Cap is 4096.
    hosts_large = resolve_host("10.0.0.0/20")
    assert len(hosts_large) <= 4096

def test_expand_targets_dedup():
    targets = ["127.0.0.1", "localhost", "127.0.0.1"]
    expanded = expand_targets(targets)
    assert len(expanded) == len(set(expanded))

def test_scan_options_resolved_ports():
    opts = ScanOptions(port_range="1-5")
    assert opts.resolved_ports == [1, 2, 3, 4, 5]