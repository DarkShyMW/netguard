"""Модели данных NetGuard: Host, Service, Finding, Risk."""
from __future__ import annotations

import dataclasses
import datetime as _dt
import ipaddress
import json
from typing import Any, Dict, List, Optional


SEVERITY_WEIGHTS = {
    "critical": 10.0,
    "high": 7.0,
    "medium": 4.0,
    "low": 2.0,
    "info": 0.0,
}

SEVERITY_ORDER = ["critical", "high", "medium", "low", "info"]


def now_iso() -> str:
    return _dt.datetime.now(_dt.timezone.utc).replace(microsecond=0).isoformat()


@dataclasses.dataclass
class Service:
    """Распознанный сетевой сервис на порту хоста."""

    port: int
    protocol: str = "tcp"
    name: str = "unknown"            # логическое имя: http, ssh, ftp, ...
    product: str = ""                # напр. "Apache httpd"
    version: str = ""                # напр. "2.4.49"
    extrainfo: str = ""
    banner: str = ""
    tunnel: str = ""                 # "", "ssl", "tls"
    hostname: str = ""               # из SAN сертификата
    tls: Dict[str, Any] = dataclasses.field(default_factory=dict)
    http: Dict[str, Any] = dataclasses.field(default_factory=dict)
    cpe: str = ""
    confidence: int = 5              # 1..10

    def key(self) -> str:
        return f"{self.protocol}/{self.port}"

    def to_dict(self) -> Dict[str, Any]:
        d = dataclasses.asdict(self)
        return d


@dataclasses.dataclass
class Host:
    """Обнаруженный узел сети со списком сервисов и находок."""

    ip: str
    mac: str = ""
    hostname: str = ""
    status: str = "down"             # up | down
    os_hint: str = ""
    services: List[Service] = dataclasses.field(default_factory=list)
    findings: List["Finding"] = dataclasses.field(default_factory=list)
    scan_started: str = ""
    scan_finished: str = ""

    def get_service(self, port: int, protocol: str = "tcp") -> Optional[Service]:
        for s in self.services:
            if s.port == port and s.protocol == protocol:
                return s
        return None

    @property
    def risk_score(self) -> float:
        """Риск хоста: максимум severity + аддитивный «хвост» остальных."""
        if not self.findings:
            return 0.0
        weights = sorted(
            (SEVERITY_WEIGHTS[f.severity] for f in self.findings), reverse=True
        )
        score = weights[0]
        for w in weights[1:]:
            score += w * 0.25
        return round(min(score, 10.0), 2)

    @property
    def worst_severity(self) -> str:
        if not self.findings:
            return "info"
        for sev in SEVERITY_ORDER:
            if any(f.severity == sev for f in self.findings):
                return sev
        return "info"

    def to_dict(self) -> Dict[str, Any]:
        d = dataclasses.asdict(self)
        d["risk_score"] = self.risk_score
        d["worst_severity"] = self.worst_severity
        d["findings"] = [f.to_dict() for f in self.findings]
        return d


@dataclasses.dataclass
class Finding:
    """Находка плагина: факт + оценка риска + рекомендации."""

    plugin_id: str
    title: str
    severity: str                    # critical|high|medium|low|info
    description: str = ""
    evidence: str = ""
    port: Optional[int] = None
    protocol: str = "tcp"
    cwe: str = ""
    cvss: float = 0.0
    references: List[str] = dataclasses.field(default_factory=list)
    remediation: str = ""
    discovered_at: str = dataclasses.field(default_factory=now_iso)

    def to_dict(self) -> Dict[str, Any]:
        return dataclasses.asdict(self)


@dataclasses.dataclass
class ScanResult:
    """Итог прогона: хосты, статистика, метаданные запуска."""

    targets: List[str] = dataclasses.field(default_factory=list)
    hosts: List[Host] = dataclasses.field(default_factory=list)
    started_at: str = dataclasses.field(default_factory=now_iso)
    finished_at: str = ""
    duration_sec: float = 0.0
    tool_version: str = "1.0.0"
    errors: List[str] = dataclasses.field(default_factory=list)

    @property
    def up_hosts(self) -> List[Host]:
        return [h for h in self.hosts if h.status == "up"]

    @property
    def all_findings(self) -> List[Finding]:
        out: List[Finding] = []
        for h in self.hosts:
            out.extend(h.findings)
        return out

    def summary(self) -> Dict[str, Any]:
        counts = {sev: 0 for sev in SEVERITY_ORDER}
        for f in self.all_findings:
            counts[f.severity] = counts.get(f.severity, 0) + 1
        return {
            "hosts_total": len(self.hosts),
            "hosts_up": len(self.up_hosts),
            "services_found": sum(len(h.services) for h in self.up_hosts),
            "findings_total": len(self.all_findings),
            "by_severity": counts,
            "started_at": self.started_at,
            "finished_at": self.finished_at,
            "duration_sec": self.duration_sec,
        }

    def to_dict(self) -> Dict[str, Any]:
        return {
            "tool": "netguard",
            "version": self.tool_version,
            "targets": self.targets,
            "summary": self.summary(),
            "errors": self.errors,
            "hosts": [h.to_dict() for h in self.hosts],
        }

    def to_json(self, indent: int = 2) -> str:
        return json.dumps(self.to_dict(), indent=indent, ensure_ascii=False)


def normalize_target(token: str) -> List[str]:
    """CIDR/IP/имя → список строковых IP или имён для сканирования."""
    token = token.strip()
    if not token:
        return []
    if "/" in token:
        net = ipaddress.ip_network(token, strict=False)
        if net.version == 6 or net.prefixlen >= 30:
            return [str(a) for a in net.hosts()] or [str(net.network_address)]
        return [str(a) for a in net.hosts()]
    try:
        ipaddress.ip_address(token)
        return [token]
    except ValueError:
        return [token]  # доменное имя — резолвинг сделает socket
