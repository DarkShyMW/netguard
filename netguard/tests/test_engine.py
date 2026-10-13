import pytest
from netguard.engine import run_scan
from netguard.config import ScanOptions

def test_run_scan_smoke():
    opts = ScanOptions(
        targets=["127.0.0.1"],
        port_range="22",
        skip_discovery=True,
        timeout=1.0
    )
    result = run_scan(opts)
    assert result.target == "127.0.0.1"
    assert len(result.hosts) == 1
    # If port 22 is closed in CI, findings might be empty, but structure exists
    assert hasattr(result, 'duration')

def test_run_scan_unresolvable():
    opts = ScanOptions(
        targets=["nonexistent.invalid.domain.xyz"],
        port_range="80",
        timeout=1.0
    )
    result = run_scan(opts)
    assert len(result.errors) > 0
    assert "nonexistent" in str(result.errors)