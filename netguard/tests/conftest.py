import sys
import os
import pytest

# Bootstrap sys.path for local imports if needed
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

@pytest.fixture
def sample_host():
    return {
        "ip": "127.0.0.1",
        "hostname": "localhost",
        "open_ports": [22, 80],
        "services": {"22": "ssh", "80": "http"}
    }

@pytest.fixture
def scan_result(sample_host):
    from netguard.models import ScanResult
    return ScanResult(target="127.0.0.1", hosts=[sample_host], errors=[], duration=1.0)