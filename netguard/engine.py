"""Движок NetGuard: discovery → portscan → fingerprint → plugins."""
from __future__ import annotations

import concurrent.futures as cf
import time
from typing import Callable, List, Optional

from netguard.config import ScanOptions, expand_targets
from models import Host, ScanResult
from netguard.plugins.base import all_plugins
from netguard.scan.discovery import discover_hosts
from netguard.scan.fingerprint import fingerprint_service
from netguard.scan.portscan import scan_host_ports


def run_scan(
    targets: List[str],
    opts: ScanOptions,
    progress: Optional[Callable[[str], None]] = None,
) -> ScanResult:
    result = ScanResult(targets=list(targets))
    t0 = time.monotonic()
    ips = expand_targets(targets)
    if not ips:
        result.errors.append("Не удалось разрешить ни одну цель")
        result.finished_at = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
        return result
    ips = ips[: opts.max_hosts_per_scan]

    # 1. Discovery
    if opts.skip_discovery:
        hosts = [Host(ip=ip, status="up") for ip in ips]
    else:
        if progress:
            progress(f"Обнаружение хостов: {len(ips)} адрес(ов) ...")
        hosts = discover_hosts(
            ips, timeout=min(opts.connect_timeout, 1.0),
            threads=opts.threads, progress=progress,
        )
    up = [h for h in hosts if h.status == "up"]
    if progress:
        progress(f"Живых хостов: {len(up)} из {len(hosts)}")

    ports = opts.resolved_ports()
    plugins = all_plugins() if opts.do_plugins else []

    def process_host(h: Host) -> Host:
        h.scan_started = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
        scan_host_ports(h, ports, threads=max(16, opts.threads // max(1, len(up))),
                        timeout=opts.connect_timeout, progress=progress)
        if opts.do_fingerprint:
            for svc in h.services:
                try:
                    fingerprint_service(svc, h.ip, hostname=h.hostname or "",
                                        timeout=opts.read_timeout)
                except Exception as e:  # noqa: BLE001
                    if progress:
                        progress(f"[fp] ошибка {h.ip}:{svc.port}: {e}")
        if opts.do_plugins:
            for svc in h.services:
                for pl in plugins:
                    if not pl.applies(h, svc):
                        continue
                    try:
                        found = pl.check(h, svc)
                    except Exception as e:  # noqa: BLE001
                        if progress:
                            progress(f"[plugin {pl.id}] ошибка на {h.ip}:{svc.port}: {e}")
                        continue
                    if found:
                        h.findings.extend(found)
        h.scan_finished = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
        if progress and h.findings:
            progress(f"[{h.ip}] найдено уязвимостей: {len(h.findings)}")
        return h

    # параллельная обработка хостов; потоки портов уже внутри
    workers = min(8, max(1, len(up)))
    with cf.ThreadPoolExecutor(max_workers=workers) as ex:
        futs = [ex.submit(process_host, h) for h in up]
        for fut in cf.as_completed(futs):
            try:
                fut.result()
            except Exception as e:  # noqa: BLE001
                result.errors.append(str(e))

    result.hosts = hosts
    result.duration_sec = round(time.monotonic() - t0, 2)
    result.finished_at = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
    return result
