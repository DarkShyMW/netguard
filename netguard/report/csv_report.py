"""CSV-отчёт: строка на находку (для импорта в GRC/таблицы)."""
from __future__ import annotations

import csv

from netguard.models import ScanResult

FIELDS = [
    "host_ip", "hostname", "mac", "risk_score", "port", "protocol",
    "service", "severity", "plugin_id", "title", "cvss", "cwe",
    "description", "evidence", "remediation", "references", "discovered_at",
]


def write_csv(result: ScanResult, path: str) -> str:
    with open(path, "w", newline="", encoding="utf-8-sig") as f:
        w = csv.DictWriter(f, fieldnames=FIELDS)
        w.writeheader()
        for h in result.hosts:
            if not h.findings:
                continue
            for fi in h.findings:
                svc = h.get_service(fi.port or 0) if fi.port else None
                w.writerow({
                    "host_ip": h.ip,
                    "hostname": h.hostname,
                    "mac": h.mac,
                    "risk_score": h.risk_score,
                    "port": fi.port or "",
                    "protocol": fi.protocol,
                    "service": svc.name if svc else "",
                    "severity": fi.severity,
                    "plugin_id": fi.plugin_id,
                    "title": fi.title,
                    "cvss": fi.cvss,
                    "cwe": fi.cwe,
                    "description": fi.description,
                    "evidence": fi.evidence,
                    "remediation": fi.remediation,
                    "references": "; ".join(fi.references),
                    "discovered_at": fi.discovered_at,
                })
    return path
