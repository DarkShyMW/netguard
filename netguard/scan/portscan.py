"""Параллельный TCP connect-скан портов (без привилегий)."""
from __future__ import annotations

import concurrent.futures as cf
import socket
from typing import Callable, List, Optional, Tuple

from netguard.models import Host, Service


def probe_port(ip: str, port: int, timeout: float) -> Tuple[bool, str]:
    """(открыт?, banner-начало). Connect + попытка прочитать приветствие."""
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(timeout)
    try:
        s.connect((ip, port))
        banner = ""
        try:
            s.settimeout(min(timeout, 1.0))
            data = s.recv(1024)
            if data:
                banner = data.decode("utf-8", "replace").strip("\r\n")
        except OSError:
            pass
        return True, banner
    except ConnectionRefusedError:
        return False, ""
    except socket.timeout:
        return False, ""
    except OSError:
        return False, ""
    finally:
        try:
            s.close()
        except OSError:
            pass


def scan_host_ports(
    host: Host,
    ports: List[int],
    *,
    threads: int = 128,
    timeout: float = 1.0,
    progress: Optional[Callable[[str], None]] = None,
) -> Host:
    """Заполняет host.services открытыми портами (пока без фингерпринта)."""
    open_results: List[Tuple[int, str]] = []

    def worker(port: int) -> Optional[Tuple[int, str]]:
        ok, banner = probe_port(host.ip, port, timeout)
        if ok:
            return port, banner
        return None

    with cf.ThreadPoolExecutor(max_workers=min(threads, max(1, len(ports)))) as ex:
        futs = {ex.submit(worker, p): p for p in ports}
        done = 0
        for fut in cf.as_completed(futs):
            done += 1
            res = fut.result()
            if res is not None:
                port, banner = res
                open_results.append((port, banner))
                if progress:
                    progress(
                        f"[{host.ip}] порт {port} открыт"
                        + (f" ({banner[:60]})" if banner else "")
                    )

    for port, banner in sorted(open_results):
        svc = Service(port=port, banner=banner)
        # предварительная идентификация по номеру порта
        from netguard.scan.fingerprint import guess_service_by_port

        svc.name = guess_service_by_port(port)
        host.services.append(svc)
    return host
