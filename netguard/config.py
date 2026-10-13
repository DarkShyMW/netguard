"""Параметры запуска и нормализация целей."""
from __future__ import annotations

import dataclasses
import ipaddress
import socket
from typing import List, Tuple


# Топ-порты по распространённости (аналог nmap --top-ports)
TOP_PORTS = [
    21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 161, 389, 443, 445,
    993, 995, 1433, 1521, 2049, 3306, 3389, 5432, 5900, 6379, 8000, 8080,
    8443, 8888, 9200, 9300, 11211, 2375, 2376, 27017, 5000, 5001, 5432,
    9100, 10000, 13306, 15672, 161, 3306, 4369, 5601, 5672, 5984, 6443,
    7000, 8086, 8088, 8888, 9000, 9042, 9092, 9443, 10250, 10255, 15000,
    15672, 18080, 1984, 20000, 25565, 27017, 28017, 50070, 50000, 61616,
]
# уникальные, отсортированные
TOP_PORTS = sorted(set(TOP_PORTS))

WELL_KNOWN_RANGES: List[Tuple[int, int]] = [
    (20, 25), (53, 53), (80, 88), (110, 111), (135, 143), (161, 161),
    (389, 389), (443, 445), (512, 515), (636, 636), (990, 995), (1433, 1433),
    (1521, 1521), (2049, 2049), (2375, 2379), (3000, 3306), (3389, 3390),
    (4444, 4445), (5432, 5433), (5601, 5601), (5672, 5672), (5900, 5910),
    (6379, 6380), (7000, 7002), (8000, 8100), (8443, 8443), (8888, 8888),
    (9000, 9200), (9300, 9300), (9443, 9443), (10000, 10255), (11211, 11211),
    (15672, 15672), (18080, 18080), (1984, 1984), (27017, 27017),
    (50070, 50070), (61616, 61616),
]


def parse_ports(spec: str) -> List[int]:
    """'80,443,8000-8100' → список портов. 'top:N'/'all' обрабатываются выше."""
    ports: set = set()
    for part in spec.split(","):
        part = part.strip()
        if not part:
            continue
        if "-" in part:
            a, b = part.split("-", 1)
            lo, hi = int(a), int(b)
            if lo > hi:
                lo, hi = hi, lo
            ports.update(range(max(1, lo), min(65535, hi) + 1))
        else:
            p = int(part)
            if 1 <= p <= 65535:
                ports.add(p)
    return sorted(ports)


@dataclasses.dataclass
class ScanOptions:
    threads: int = 128
    connect_timeout: float = 1.0
    read_timeout: float = 2.0
    top: int = 100                  # 0 = не использовать топ
    ports: List[int] = dataclasses.field(default_factory=list)
    do_fingerprint: bool = True
    do_plugins: bool = True
    skip_discovery: bool = False
    max_hosts_per_scan: int = 4096

    def resolved_ports(self) -> List[int]:
        if self.ports:
            return self.ports
        if self.top > 0:
            return TOP_PORTS[: self.top]
        return TOP_PORTS[:100]


def resolve_host(token: str) -> List[str]:
    """Имя/CIDR/IP → список адресов. Возвращает [] если не разрешилось."""
    token = token.strip()
    if "/" in token:
        try:
            net = ipaddress.ip_network(token, strict=False)
        except ValueError:
            return []
        hosts = list(net.hosts())
        if not hosts:  # /31, /32
            hosts = [net.network_address]
        return [str(h) for h in hosts][:4096]
    try:
        ipaddress.ip_address(token)
        return [token]
    except ValueError:
        pass
    try:
        infos = socket.getaddrinfo(token, None, proto=socket.IPPROTO_TCP)
        return sorted({i[4][0] for i in infos})
    except OSError:
        return []


def expand_targets(tokens: List[str]) -> List[str]:
    out: List[str] = []
    seen = set()
    for t in tokens:
        for addr in resolve_host(t):
            if addr not in seen:
                seen.add(addr)
                out.append(addr)
    return out
