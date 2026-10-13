import json
import pytest
from netguard.models import Finding, Severity, risk_score, worst_severity

def test_risk_score_calculation():
    findings = [
        Finding(service="ftp", severity=Severity.HIGH, confidence=0.9),
        Finding(service="telnet", severity=Severity.CRITICAL, confidence=0.8)
    ]
    score = risk_score(findings)
    assert score >= 8.0 # Critical dominates
    assert score <= 10.0

def test_worst_severity():
    findings = [
        Finding(severity=Severity.LOW),
        Finding(severity=Severity.MEDIUM),
        Finding(severity=Severity.HIGH)
    ]
    assert worst_severity(findings) == Severity.HIGH

def test_json_roundtrip_cyrillic():
    finding = Finding(description="Уязвимость найдена", service="test")
    data = finding.to_dict()
    restored = Finding.from_dict(data)
    assert restored.description == "Уязвимость найдена"
    
    # Ensure ensure_ascii=False behavior in dumps if used directly
    json_str = json.dumps(data, ensure_ascii=False)
    assert "Уязвимость" in json_str