"""HTML-отчёт: автономный дашборд (без внешних ресурсов)."""
from __future__ import annotations

import html as _html

from netguard.models import SEVERITY_ORDER, ScanResult

SEV_COLORS = {
    "critical": "#d32f2f", "high": "#f57c00", "medium": "#fbc02d",
    "low": "#1976d2", "info": "#9e9e9e",
}
SEV_RU = {"critical": "Критический", "high": "Высокий", "medium": "Средний",
          "low": "Низкий", "info": "Информация"}


def _esc(x) -> str:
    return _html.escape(str(x), quote=True)


def render_html(result: ScanResult) -> str:
    s = result.summary()
    sev_counts = s["by_severity"]
    cards = "".join(
        f'<div class="card" style="border-top:4px solid {SEV_COLORS[sev]}">'
        f'<div class="num">{sev_counts.get(sev, 0)}</div>'
        f'<div class="lbl">{SEV_RU[sev]}</div></div>'
        for sev in SEVERITY_ORDER
    )

    rows = []
    for h in sorted(result.hosts, key=lambda x: -x.risk_score):
        if h.status != "up":
            continue
        for fi in sorted(h.findings, key=lambda f: SEVERITY_ORDER.index(f.severity)):
            svc = h.get_service(fi.port or 0) if fi.port else None
            refs = "<br>".join(
                f'<a href="{_esc(r)}" target="_blank">{_esc(r)}</a>' for r in fi.references
            )
            rows.append(f"""
<tr>
 <td><b>{_esc(h.ip)}</b><br><span class="dim">{_esc(h.hostname)}</span></td>
 <td>{fi.port or ''}/{_esc(fi.protocol)}</td>
 <td>{_esc(svc.name if svc else '')}</td>
 <td><span class="badge" style="background:{SEV_COLORS[fi.severity]}">{SEV_RU[fi.severity]}</span></td>
 <td><b>{_esc(fi.title)}</b><div class="dim">{_esc(fi.description)}</div>
     <div class="ev">Доказательство: {_esc(fi.evidence)}</div>
     <div>Рекомендация: {_esc(fi.remediation)}</div>
     <div class="dim">{refs}</div></td>
 <td>{_esc(fi.plugin_id)}</td>
 <td>{fi.cvss or ''}</td>
 <td>{_esc(fi.cwe)}</td>
</tr>""")

    hosts_rows = "".join(
        f"<tr><td>{_esc(h.ip)}</td><td>{_esc(h.hostname)}</td><td>{_esc(h.mac)}</td>"
        f"<td>{h.status}</td><td>{len(h.services)}</td><td>{len(h.findings)}</td>"
        f"<td>{h.risk_score}</td></tr>"
        for h in sorted(result.hosts, key=lambda x: -x.risk_score)
    )

    errors = "".join(f"<li>{_esc(e)}</li>" for e in result.errors)

    return f"""<!DOCTYPE html>
<html lang="ru"><head><meta charset="utf-8">
<title>NetGuard — отчёт сканирования</title>
<style>
 body{{font-family:system-ui,'Segoe UI',Roboto,Arial,sans-serif;margin:24px;color:#212121;background:#fafafa}}
 h1{{margin-bottom:4px}} .meta{{color:#666;margin-bottom:20px}}
 .cards{{display:flex;gap:12px;flex-wrap:wrap;margin-bottom:24px}}
 .card{{background:#fff;border-radius:8px;padding:14px 22px;box-shadow:0 1px 3px rgba(0,0,0,.15);min-width:110px}}
 .card .num{{font-size:28px;font-weight:700}} .card .lbl{{color:#666;font-size:13px}}
 table{{width:100%;border-collapse:collapse;background:#fff;box-shadow:0 1px 3px rgba(0,0,0,.12)}}
 th,td{{padding:8px 10px;border-bottom:1px solid #eee;text-align:left;vertical-align:top;font-size:14px}}
 th{{background:#263238;color:#fff;position:sticky;top:0}}
 .badge{{color:#fff;padding:2px 8px;border-radius:10px;font-size:12px;white-space:nowrap}}
 .dim{{color:#777;font-size:12px}} .ev{{background:#f5f5f5;padding:4px 6px;border-radius:4px;font-family:monospace;font-size:12px;margin:4px 0}}
 tr:hover{{background:#f8f9fa}}
 details summary{{cursor:pointer;margin:18px 0 8px;font-weight:600}}
</style></head><body>
<h1>NetGuard: отчёт об обследовании сети</h1>
<div class="meta">Цели: <code>{_esc(', '.join(result.targets))}</code> ·
 Начало: {_esc(result.started_at)} · Длительность: {result.duration_sec} с ·
 Хостов живых: {s['hosts_up']}/{s['hosts_total']} · Сервисов: {s['services_found']}</div>
<div class="cards">{cards}<div class="card" style="border-top:4px solid #455a64">
<div class="num">{s['findings_total']}</div><div class="lbl">Всего находок</div></div></div>

<details open><summary>Находки ({s['findings_total']})</summary>
<table><thead><tr><th>Хост</th><th>Порт</th><th>Сервис</th><th>Опасность</th>
<th>Проблема / доказательства / меры</th><th>Плагин</th><th>CVSS</th><th>CWE</th></tr></thead>
<tbody>{''.join(rows) or '<tr><td colspan=8>Находок нет</td></tr>'}</tbody></table></details>

<details><summary>Обнаруженные хосты</summary>
<table><thead><tr><th>IP</th><th>Имя</th><th>MAC</th><th>Статус</th>
<th>Сервисов</th><th>Находок</th><th>Риск</th></tr></thead>
<tbody>{hosts_rows}</tbody></table></details>

{'<h3>Ошибки</h3><ul>' + errors + '</ul>' if errors else ''}
<p class="dim">Сгенерировано NetGuard v{result.tool_version}. Отчёт содержит сведения о безопасности —
храните его в защищённом месте.</p>
</body></html>"""


def write_html(result: ScanResult, path: str) -> str:
    with open(path, "w", encoding="utf-8") as f:
        f.write(render_html(result))
    return path
