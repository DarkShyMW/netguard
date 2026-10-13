import io
import csv
import json
import pytest
from netguard.reports import generate_json_report, generate_csv_report, generate_html_report
from netguard.models import ScanResult, Finding, Severity

@pytest.fixture
def mock_findings():
    return [
        Finding(service="ftp", description="Anonymous Login Allowed", severity=Severity.HIGH),
        Finding(service="http", description="<script>alert('XSS')</script>", severity=Severity.MEDIUM)
    ]

def test_json_valid(mock_findings):
    result = ScanResult(target="127.0.0.1", hosts=[{"findings": mock_findings}], errors=[], duration=1.0)
    report = generate_json_report(result)
    parsed = json.loads(report)
    assert "hosts" in parsed
    assert parsed["hosts"][0]["findings"][0]["service"] == "ftp"

def test_csv_bom_and_structure(mock_findings):
    result = ScanResult(target="127.0.0.1", hosts=[{"findings": mock_findings}], errors=[], duration=1.0)
    report = generate_csv_report(result)
    
    # Check BOM
    assert report.startswith('\ufeff')
    
    # Parse CSV
    reader = csv.reader(io.StringIO(report[1:])) # Skip BOM for parsing simplicity if needed
    rows = list(reader)
    assert len(rows) > 1 # Header + Data
    
    # Empty result check
    empty_result = ScanResult(target="127.0.0.1", hosts=[], errors=[], duration=0.0)
    empty_report = generate_csv_report(empty_result)
    empty_rows = list(csv.reader(io.StringIO(empty_report[1:])))
    assert len(empty_rows) == 1 # Only header

def test_html_xss_escape(mock_findings):
    result = ScanResult(target="127.0.0.1", hosts=[{"findings": mock_findings}], errors=[], duration=1.0)
    report = generate_html_report(result)
    assert "&lt;script&gt;" in report
    assert "<script>" not in report