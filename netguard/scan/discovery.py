"""Обнаружение живых хостов без привилегий (cross-platform).

Стратегия:
1. Быстрый отбор по TCP-портам из TOP_PORTS (connect-пинг) — работает везде.
2. Чтение ARP-таблицы ОС (`arp -a` / `ip neigh`) для получения MAC и «тёплых» хостов.
3. Обратный DNS (PTR) для имён.
ICMP raw-сокеты требуют root, поэтому сознательно не используются — вместо них
используется TCP-пинг, что совместимо с запуском «вне зависимости от ОС».
"""
from __future__ import annotations

import concurrent.futures as cf
import ipaddress
import re
import socket
import subprocess
from typing import Dict, Iterable, List, Optional

from netguard.models import Host


def reverse_dns(ip: str) -> str:
    try:
        name, _, _ = socket.gethostbyaddr(ip)
        return name
    except (OSError, UnicodeError):
        return ""


def tcp_ping(ip: str, ports: Iterable[int], timeout: float = 0.8) -> bool:
    """Жив ли хост: хотя бы один TCP-порт отвечает (или RST/REFUSED ≠ dead)."""
    for port in ports:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(timeout)
        try:
            s.connect((ip, port))
            return True
        except ConnectionRefusedError:
            # стек ответил RST → хост жив, порт закрыт
            return True
        except OSError:
            continue
        finally:
            s.close()
    return False


_ARP_RE = re.compile(
    r"^(?P<ip>\d{1,3}(?:\.\d{1,3}){3})\s.*?(?P<mac>(?:[0-9a-fA-F]{2}[:-]){5}[0-9a-fA-F]{2}|incomplete)",
)


def read_arp_table() -> Dict[str, str]:
    """ip → mac из системной ARP-таблицы (best effort)."""
    result: Dict[str, str] = {}
    cmds = [["ip", "neigh"], ["arp", "-a"]]
    for cmd in cmds:
        try:
            out = subprocess.run(
                cmd, capture_output=True, text=True, timeout=3
            ).stdout
        except (OSError, subprocess.SubprocessError):
            continue
        for line in out.splitlines():
            m = _ARP_RE.search(line.strip())
            if not m:
                continue
            mac = m.group("mac")
            if "incomplete" in mac:
                continue
            ip = m.group("ip")
            if ip not in result:
                result[ip] = mac.replace("-", ":").lower()
        if result:
            break
    return result


def is_local_subnet(ip: str) -> bool:
    try:
        a = ipaddress.ip_address(ip)
    except ValueError:
        return False
    return a in ipaddress.ip_network("10.0.0.0/8") or \
        a in ipaddress.ip_network("172.16.0.0/12") or \
        a in ipaddress.ip_network("192.168.0.0/16") or \
        a in ipaddress.ip_network("169.254.0.0/16") or \
        a.is_link_local or a.is_private


def discover_hosts(
    ips: List[str],
    *,
    ping_ports: Optional[List[int]] = None,
    timeout: float = 0.8,
    threads: int = 128,
    progress=None,
) -> List[Host]:
    """Возвращает список Host со status='up'/'down', hostname и mac."""
    if ping_ports is None:
        from netguard.config import TOP_PORTS
        ping_ports = [80, 443, 22, 21, 23, 25, 3389, 445, 8080, 139]

    arp = read_arp_table()
    hosts: Dict[str, Host] = {}

    def worker(ip: str) -> Host:
        h = Host(ip=ip)
        h.mac = arp.get(ip, "")
        alive = tcp_ping(ip, ping_ports, timeout)
        if not alive and ip in arp:
            # в ARP есть, но порты молчат — возможно файрвол; считаем live
            alive = True
        h.status = "up" if alive else "down"
        if alive:
            h.hostname = reverse_dns(ip)
        return h

    with cf.ThreadPoolExecutor(max_workers=threads) as ex:
        futs = {ex.submit(worker, ip): ip for ip in ips}
        done = 0
        for fut in cf.as_completed(futs):
            done += 1
            ip = futs[fut]
            try:
                h = fut.result()
            except Exception as e:  # noqa: BLE001
                h = Host(ip=ip, status="down")
                if progress:
                    progress(f"[discover] ошибка {ip}: {e}")
                continue
            hosts[ip] = h
            if progress:
                progress(f"[discover] {done}/{len(ips)} {ip} → {h.status}")

    return [hosts[ip] for ip in ips if ip in hosts]
