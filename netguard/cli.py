"""CLI NetGuard: discover / scan / audit / plugins."""
from __future__ import annotations

import argparse
import os
import sys
import threading
from typing import List, Optional

from netguard import __version__
from netguard.config import ScanOptions, parse_ports
from netguard.engine import run_scan
from netguard.models import SEVERITY_ORDER, ScanResult
from netguard.plugins.base import all_plugins
from netguard.report.csv_report import write_csv
from netguard.report.html_report import write_html
from netguard.report.json_report import write_json

SEV_COLORS = {"critical": "\033[41;97m", "high": "\033[91m", "medium": "\033[93m",
              "low": "\033[94m", "info": "\033[90m"}
RESET = "\033[0m"


def _print(msg: str) -> None:
    print(msg, flush=True)


def make_progress(verbose: int):
    if verbose <= 0:
        lock = threading.Lock()
        state = {"last": 0}
        def cb(msg: str):
            with lock:
                state["last"] += 1
                if state["last"] % 200 == 0:
                    sys.stdout.write(".")
                    sys.stdout.flush()
        return cb
    return _print if verbose == 1 else (lambda m: _print(f"    {m}"))


def build_opts(args) -> ScanOptions:
    opts = ScanOptions(
        threads=args.threads,
        connect_timeout=args.timeout,
        read_timeout=args.read_timeout or args.timeout * 2,
    )
    if getattr(args, "ports", None):
        opts.ports = parse_ports(args.ports)
        opts.top = 0
    elif getattr(args, "top", None) is not None:
        opts.top = args.top
    if getattr(args, "no_fingerprint", False):
        opts.do_fingerprint = False
    if getattr(args, "no_plugins", False):
        opts.do_plugins = False
    if getattr(args, "assume_up", False):
        opts.skip_discovery = True
    return opts


def console_summary(result: ScanResult, show_all: bool = False) -> None:
    s = result.summary()
    _print("")
    _print("=" * 74)
    _print(f"ИТОГО: хостов {s['hosts_up']}/{s['hosts_total']} в сети, "
           f"сервисов {s['services_found']}, находок {s['findings_total']}, "
           f"время {result.duration_sec} с")
    _print("=" * 74)
    rows: List[str] = []
    for h in sorted(result.hosts, key=lambda x: -x.risk_score):
        if h.status != "up":
            continue
        if h.services:
            svc_list = ", ".join(
                f"{sv.port}/{sv.name}" + (f"({sv.version})" if sv.version else "")
                for sv in h.services
            )
            rows.append(f"  {h.ip:<16} {h.hostname:<24.24} порты: {svc_list[:120]}")
        for fi in sorted(h.findings, key=lambda f: SEVERITY_ORDER.index(f.severity)):
            color = SEV_COLORS.get(fi.severity, "")
            rows.append(
                f"  {color}[{fi.severity:>8}]{RESET} {h.ip}:{str(fi.port):<6} "
                f"{fi.title} (plugin={fi.plugin_id}, cvss={fi.cvss})"
            )
    if not show_all:
        # режем info-шум при непонятном флаге
        pass
    _print("\n".join(rows) or "  Находок нет.")
    if result.errors:
        _print("ОШИБКИ:")
        for e in result.errors:
            _print(f"  ! {e}")


def save_reports(result: ScanResult, formats: List[str], out: Optional[str]) -> None:
    if not formats:
        return
    names = {"json": "netguard.json", "csv": "netguard.csv", "html": "netguard.html"}
    if out and len(formats) == 1:
        # один формат — output трактуется как имя файла
        _print(f"Отчёт сохранён: {write_fmt(result, formats[0], out)}")
        return
    if out:
        # несколько форматов: если путь выглядит как папка (существует,
        # оканчивается на / или не имеет расширения) — пишем в неё
        looks_like_dir = (
            os.path.isdir(out) or out.endswith((os.sep, "/"))
            or not os.path.splitext(out)[1]
        )
        base_dir = out if looks_like_dir else "."
        if not looks_like_dir:
            _print(f"Неверный суффикс '{out}' для нескольких форматов "
                  f"({','.join(formats)}); пишу в текущий каталог.")
    else:
        base_dir = "."
    os.makedirs(base_dir, exist_ok=True)
    for fmt in formats:
        path = os.path.join(base_dir, names[fmt])
        write_fmt(result, fmt, path)
        _print(f"Отчёт сохранён: {path}")


def write_fmt(result: ScanResult, fmt: str, path: str) -> str:
    if fmt == "json":
        return write_json(result, path)
    if fmt == "csv":
        return write_csv(result, path)
    if fmt in ("html", "nmap"):
        return write_html(result, path)
    raise ValueError(f"Неизвестный формат: {fmt}")


def cmd_scanlike(args, *, full_audit: bool) -> int:
    opts = build_opts(args)
    if not full_audit:
        opts.do_plugins = False
    else:
        # в audit плагины не запускаем повторно — run_scan уже делает это;
        # флаг ниже лишь для ясности
        opts.do_plugins = True
    result = run_scan(args.targets, opts, progress=make_progress(args.verbose))
    console_summary(result, show_all=args.verbose > 0 or full_audit)
    fmts = [f for f in (args.formats.split(",") if args.formats else []) if f]
    save_reports(result, fmts, args.output)
    crit = result.summary()["by_severity"]["critical"]
    high = result.summary()["by_severity"]["high"]
    if crit:
        return 3
    if high and getattr(args, "fail_on_high", False):
        return 2
    return 0


def _silence_broken_pipe() -> None:
    """Windows/Linux: `netguard ... | more`, `| findstr` или закрытый stdout
    не должны ронять сканер с BrokenPipeError."""
    for stream in (sys.stdout, sys.stderr):
        try:
            import io
            if hasattr(stream, "buffer") and not stream.closed:
                wrapped = io.TextIOWrapper(
                    stream.buffer, line_buffering=True, errors="replace",
                    write_through=True)
                setattr(sys, "stdout" if stream is sys.stdout else "stderr",
                        wrapped)
        except Exception:  # noqa: BLE001
            pass


def main(argv: Optional[List[str]] = None) -> int:
    _silence_broken_pipe()
    try:
        return _main_impl(argv)
    except BrokenPipeError:
        devnull = os.open(os.devnull, os.O_WRONLY)
        os.dup2(devnull, sys.stdout.fileno())
        return 0
    except KeyboardInterrupt:
        _print("\nПрервано пользователем.")
        return 130


def _main_impl(argv=None):
    p = argparse.ArgumentParser(
        prog="netguard",
        description="NetGuard — кроссплатформенный сканер уязвимостей локальной сети "
                    "(без root, без зависимостей).",
        epilog="Разрешено сканировать только сети, на которые у вас есть письменное "
               "разрешение владельца.",
    )
    p.add_argument("--version", action="version", version=f"netguard {__version__}")
    sub = p.add_subparsers(dest="cmd", required=True)

    def common(sp, with_targets=True):
        if with_targets:
            sp.add_argument("targets", nargs="+",
                            help="IP, имя хоста или CIDR (192.168.0.0/24)")
        sp.add_argument("-t", "--threads", type=int, default=128,
                        help="потоков сканирования (по умолчанию 128)")
        sp.add_argument("--timeout", type=float, default=1.0,
                        help="таймаут connect, сек (1.0)")
        sp.add_argument("--read-timeout", type=float, default=None,
                        help="таймаут чтения баннеров, сек")
        sp.add_argument("-v", "--verbose", action="count", default=0,
                        help="-v прогресс по хостам, -vv детали плагинов")

    sp_disc = sub.add_parser("discover", help="обнаружить живые хосты в подсети")
    common(sp_disc)
    sp_disc.add_argument("-f", "--formats", default="",
                         help="json,csv,html — отчёты")
    sp_disc.add_argument("-o", "--output", help="файл/папка для отчётов")

    sp_scan = sub.add_parser("scan", help="сканирование портов и сервисов")
    common(sp_scan)
    add_scan_args(sp_scan)

    sp_audit = sub.add_parser(
        "audit", help="полное обследование: discovery + ports + fingerprint + плагины")
    common(sp_audit)
    add_scan_args(sp_audit)
    sp_audit.add_argument("--fail-on-high", action="store_true",
                          help="exit code 2 при находках уровня high")

    sp_pl = sub.add_parser("plugins", help="список доступных проверок-плагинов")

    args = p.parse_args(argv)

    if args.cmd == "plugins":
        _print(f"{'ID':<24} {'Severity':<10} Название")
        _print("-" * 74)
        for pl in sorted(all_plugins(), key=lambda x: x.id):
            _print(f"{pl.id:<24} {pl.severity:<10} {pl.name}")
        return 0

    if args.cmd == "discover":
        opts = build_opts(args)
        opts.do_plugins = False
        opts.do_fingerprint = False
        from netguard.config import expand_targets
        from netguard.scan.discovery import discover_hosts
        ips = expand_targets(args.targets)
        hosts = discover_hosts(ips, timeout=min(opts.connect_timeout, 1.0),
                               threads=opts.threads, progress=make_progress(args.verbose))
        up = [h for h in hosts if h.status == "up"]
        _print(f"\nЖивых хостов: {len(up)} из {len(hosts)}")
        for h in up:
            _print(f"  {h.ip:<16} {h.hostname:<30.30} mac={h.mac or '-'}")
        result = ScanResult(targets=args.targets, hosts=hosts)
        result.finished_at = result.started_at
        fmts = args.formats.split(",") if args.formats else []
        save_reports(result, fmts, args.output)
        return 0

    if args.cmd == "scan":
        return cmd_scanlike(args, full_audit=False)
    if args.cmd == "audit":
        return cmd_scanlike(args, full_audit=True)
    return 1


def add_scan_args(sp) -> None:
    g = sp.add_mutually_exclusive_group()
    g.add_argument("--top", type=int, default=100, metavar="N",
                   help="сканировать N топ-портов (по умолчанию 100)")
    g.add_argument("-p", "--ports",
                   help="порты/диапазоны: 22,80,443,8000-8100")
    sp.add_argument("--no-fingerprint", action="store_true",
                    help="не выполнять фингерпринт (быстрее)")
    sp.add_argument("--assume-up", action="store_true",
                    help="пропустить discovery (все цели считать живыми)")
    sp.add_argument("-f", "--formats", default="",
                    help="отчёты через запятую: json,csv,html")
    sp.add_argument("-o", "--output", help="файл (для одного формата) или папка")


if __name__ == "__main__":
    sys.exit(main())
