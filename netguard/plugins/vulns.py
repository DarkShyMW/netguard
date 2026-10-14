"""Плагин: активные проверки сервисов, доступных без авторизации.

Использует только stdlib (socket, urllib). Пробники read-only и безопасны:
PING/HELP/INFO-запросы, ничего не изменяются на целевой системе.
"""
from __future__ import annotations

import json
import socket
import ssl as _ssl
import urllib.error
import urllib.parse
import urllib.request
from typing import List, Optional

from models import Finding, Host, Service
from netguard.plugins.base import Plugin, register


def _send_recv(ip: str, port: int, payload: bytes, timeout: float = 2.0) -> bytes:
    s = socket.create_connection((ip, port), timeout=timeout)
    try:
        if payload:
            s.sendall(payload)
        s.settimeout(timeout)
        chunks: List[bytes] = []
        try:
            while True:
                b = s.recv(65536)
                if not b:
                    break
                chunks.append(b)
                if sum(len(c) for c in chunks) > (1 << 20):
                    break
        except socket.timeout:
            pass
        return b"".join(chunks)
    finally:
        s.close()


def _http_get(url: str, timeout: float = 3.0):
    ctx = _ssl._create_unverified_context() if url.startswith("https") else None
    req = urllib.request.Request(url, headers={"User-Agent": "netguard/1.0"})
    with urllib.request.urlopen(req, timeout=timeout, context=ctx) as r:
        return r.status, r.read(200000)


@register
class AnonymousFtpPlugin(Plugin):
    id = "ftp_anonymous"
    name = "FTP: разрешён анонимный вход"
    severity = "high"
    cvss = 8.1
    cwe = "CWE-306"
    applies_to_services = ["ftp"]
    references = ["https://attack.mitre.org/techniques/T1078/"]
    remediation = "Запретите anonymous login в конфигурации ftpd (vsftpd: anonymous_enable=NO)."

    def check(self, host: Host, svc: Service) -> Optional[List[Finding]]:
        try:
            data = _send_recv(host.ip, svc.port, b"USER anonymous\r\n", timeout=2.0)
        except OSError:
            return None
            # response codes: 230 = login ok, 331 = password required (может быть пустой пароль)
        text = data.decode("utf-8", "replace")
        if "230" in text or ("331" in text and "password" in text.lower()):
            # уточняем: пробуем пустой пароль
            try:
                d2 = _send_recv(host.ip, svc.port,
                                b"USER anonymous\r\nPASS netguard@\r\n", timeout=2.0)
                if b"230" in d2:
                    return [self.make_finding(
                        svc,
                        evidence=f"Ответ ftpd: {text[:120]!r}",
                        description="FTP-сервер принимает анонимное подключение — "
                                    "возможна выгрузка/загрузка файлов анонимно.",
                    )]
            except OSError:
                pass
        return None


@register
class RedisNoAuthPlugin(Plugin):
    id = "redis_no_auth"
    name = "Redis доступен без авторизации"
    severity = "critical"
    cvss = 9.8
    cwe = "CWE-306"
    applies_to_services = ["redis"]
    applies_to_ports = [6379, 6380]
    references = [
        "https://redis.io/docs/latest/operate/oss_and_stack/management/security/",
        "https://attack.mitre.org/techniques/T1195/",
    ]
    remediation = "Включите requirepass / ACL, bind 127.0.0.1, protected-mode yes, firewall."

    def check(self, host: Host, svc: Service) -> Optional[List[Finding]]:
        try:
            data = _send_recv(host.ip, svc.port, b"PING\r\n", timeout=2.0)
        except OSError:
            return None
        if data.startswith(b"+PONG"):
            info = b""
            try:
                info = _send_recv(host.ip, svc.port, b"INFO server\r\n", timeout=2.0)
            except OSError:
                pass
            ver = ""
            for line in info.splitlines():
                if line.startswith(b"redis_version"):
                    ver = line.decode(errors="replace").split(":")[-1].strip()
            return [self.make_finding(
                svc,
                evidence=f"PING → +PONG{', redis_version=' + ver if ver else ''} на {host.ip}:{svc.port}",
                description="Redis отвечает на команды без аутентификации. Через него "
                            "возможны запись файлов (cron/SSH keys), чтение данных, RCE при "
                            "наличии модулей.",
            )]
        if b"-NOAUTH" in data:
            return None
        return None

@register
class VncNoAuthPlugin(Plugin):
    id = "vnc_no_auth"
    name = "VNC: Accessing without authentication"
    severity = "high"
    cvss = 8.1
    cwe = "CWE-306"
    applies_to_services = ["vnc"]
    applies_to_ports = [5900, 5901, 5902]
    references = [
        "https://www.rfc-editor.org/rfc/rfc6143",
        "https://attack.mitre.org/techniques/T1078/",
    ]
    remediation = "Enable VNC authentication (password) and use SSH/VPN tunnel."

    def check(self, host: Host, svc: Service) -> Optional[List[Finding]]:
        try:
            s = socket.create_connection((host.ip, svc.port), timeout=2.0)
        except OSError:
            return None
        try:
            s.settimeout(2.0)
            banner = s.recv(12)
            if not banner.startswith(b"RFB "):
                return None
            s.sendall(banner[:12])
            n_raw = s.recv(1)
            if not n_raw:
                return None
            n = n_raw[0]
            if n == 0:
                return None
            types = s.recv(n)
            if 1 not in types:
                return None
            return [self.make_finding(
                svc,
                evidence=f"RFB {banner[4:].decode('ascii', 'replace').strip()} → "
                         f"security types={sorted(types)} на {host.ip}:{svc.port}",
                description="VNC-server accepts Security Type 1 (None) - access without password, "
                            "full access to remote desktop.",
            )]
        except OSError:
            return None
        finally:
            s.close()

@register
class MemcachedInfoPlugin(Plugin):
    id = "memcached_exposed"
    name = "Memcached доступен из сети (статистика/UDP amplification)"
    severity = "high"
    cvss = 7.5
    cwe = "CWE-306"
    applies_to_services = ["memcached"]
    applies_to_ports = [11211]
    references = ["https://www.us-cert.gov/ncas/alerts/TA18-010A"]
    remediation = "bind 127.0.0.1/-u localhost, включите SASL, ограничьте UDP 11211 на межсетевом экране."

    def check(self, host: Host, svc: Service) -> Optional[List[Finding]]:
        try:
            data = _send_recv(host.ip, svc.port, b"stats\r\nquit\r\n", timeout=2.0)
        except OSError:
            return None
        if b"STAT" in data and b"END" in data:
            lines = data.decode("utf-8", "replace").splitlines()
            interesting = [l for l in lines if any(k in l for k in
                           ("version", "num_items", "bytes", "curr_connections"))][:6]
            return [self.make_finding(
                svc,
                evidence="; ".join(interesting)[:200],
                description="Memcached отдаёт статистику без аутентификации; UDP-порт "
                            "также используется для DDoS-амплификации.",
            )]
        return None


@register
class ElasticsearchOpenPlugin(Plugin):
    id = "elasticsearch_open"
    name = "Elasticsearch/OpenSearch доступен без авторизации"
    severity = "critical"
    cvss = 9.1
    cwe = "CWE-306"
    applies_to_services = ["elasticsearch"]
    applies_to_ports = [9200, 9300, 5601]
    references = ["https://www.elastic.co/guide/en/elasticsearch/reference/current/security-api.html"]
    remediation = "xpack.security.enabled=true, смените bootstrap-пароли, restrict 9200 по IP."

    def check(self, host: Host, svc: Service) -> Optional[List[Finding]]:
        if svc.port == 5601:
            return None
        url = f"http://{host.ip}:{svc.port}/_cluster/health"
        try:
            status, body = _http_get(url, timeout=3.0)
        except (urllib.error.URLError, OSError):
            return None
        if status == 200:
            try:
                j = json.loads(body.decode("utf-8", "replace"))
            except (json.JSONDecodeError, UnicodeDecodeError):
                return None
            if "cluster_name" in j:
                idx = ""
                try:
                    _, b2 = _http_get(f"http://{host.ip}:{svc.port}/_cat/indices?format=json", 3.0)
                    names = [i.get("index") for i in json.loads(b2.decode())][:5]
                    idx = ", индексы: " + ", ".join(str(n) for n in names)
                except Exception:  # noqa: BLE001
                    pass
                return [self.make_finding(
                    svc,
                    evidence=f"cluster={j.get('cluster_name')}{idx}",
                    description="Кластер Elasticsearch отвечает без аутентификации — "
                                "полный доступ к данным и риск удалённого выполнения кода "
                                "(через старые версии scripting).",
                )]
        return None


@register
class DockerApiPlugin(Plugin):
    id = "docker_api_exposed"
    name = "Docker Remote API доступен без TLS/авторизации"
    severity = "critical"
    cvss = 10.0
    cwe = "CWE-306"
    applies_to_services = ["docker-api"]
    applies_to_ports = [2375]
    references = [
        "https://docs.docker.com/engine/security/#docker-daemon-attack-surface",
        "https://attack.mitre.org/techniques/T1610/",
    ]
    remediation = "Не слушайте 2375 наружу; используйте 2376 с mTLS или unix-сокет; ограничьте ACL."

    def check(self, host: Host, svc: Service) -> Optional[List[Finding]]:
        url = f"http://{host.ip}:{svc.port}/version"
        try:
            status, body = _http_get(url, timeout=3.0)
        except (urllib.error.URLError, OSError):
            return None
        if status == 200:
            try:
                j = json.loads(body.decode("utf-8", "replace"))
            except (json.JSONDecodeError, UnicodeDecodeError):
                return None
            if "ApiVersion" in j or "Version" in j:
                containers = ""
                try:
                    _, cb = _http_get(f"http://{host.ip}:{svc.port}/containers/json", 3.0)
                    containers = f", контейнеров: {len(json.loads(cb.decode()))}"
                except Exception:  # noqa: BLE001
                    pass
                return [self.make_finding(
                    svc,
                    evidence=f"Docker {j.get('Version', '?')} ApiVersion {j.get('ApiVersion', '?')}{containers}",
                    description="Полный контроль над демоном Docker = запуск привилегированного "
                                "контейнера с монтированием хоста → RCE на узле от root.",
                )]
        return None


@register
class KubeletAnonymousPlugin(Plugin):
    id = "kubelet_anonymous"
    name = "Kubelet (10250) допускает анонимные запросы /pods"
    severity = "critical"
    cvss = 9.1
    cwe = "CWE-306"
    applies_to_ports = [10250, 10255]
    references = ["https://kubernetes.io/docs/reference/config-api/kubelet-config.v1beta1/"]
    remediation = "anonymousAuth=false, authorizationMode=Webhook, restrict 10250/10255 сетью."

    def check(self, host: Host, svc: Service) -> Optional[List[Finding]]:
        urls = [f"https://{host.ip}:10250/pods", f"http://{host.ip}:10255/pods"]
        for url in urls:
            try:
                status, body = _http_get(url, timeout=3.0)
            except (urllib.error.URLError, OSError):
                continue
            if status == 200 and b'"kind":"PodList"' in body.replace(b" ", b""):
                return [self.make_finding(
                    svc,
                    evidence=f"{url} → 200 PodList ({len(body)} байт)",
                    description="Анонимный доступ к kubelet раскрывает спеки подов "
                                "(секреты в env) и позволяет exec/run через API.",
                )]
        return None


@register
class HttpAdminPanelsPlugin(Plugin):
    id = "http_admin_panel"
    name = "Доступна панель управления из локальной сети"
    severity = "medium"
    cvss = 6.5
    cwe = "CWE-200"
    applies_to_services = ["http", "https", "http-alt", "http-proxy", "https-alt"]
    references = ["https://owasp.org/www-project-top-ten/OWASP_Top_Ten_2017/D10_2017_Insufficient_Logging_and_Monitoring"]
    remediation = "Ограничьте доступ к панелям по IP/VPN, включите MFA, смените дефолтные учётные данные."

    KNOWN_PANELS = {
        "/manager/html": "Apache Tomcat Manager",
        "/phpmyadmin/": "phpMyAdmin",
        "/phpinfo.php": "phpinfo()",
        "/wp-admin/": "WordPress Admin",
        "/grafana/": "Grafana",
        "/rabbitmq-management/": "RabbitMQ Management",
        "/h2-console": "H2 Console",
        "/webui/": "Device Web UI",
        "/Login.htm": "IP-camera Web UI",
        "/model/__get": "Jenkins CLI endpoint",
    }

    def check(self, host: Host, svc: Service) -> Optional[List[Finding]]:
        base = ("https" if (svc.tunnel == "ssl" or svc.port in (443, 8443)) else "http")
        findings: List[Finding] = []
        # 1. известные пути
        for path, label in self.KNOWN_PANELS.items():
            url = f"{base}://{host.ip}:{svc.port}{path}"
            try:
                status, body = _http_get(url, timeout=2.5)
            except (urllib.error.URLError, OSError):
                continue
            if status in (200, 401):
                sev = "medium" if status == 200 else "low"
                findings.append(self.make_finding(
                    svc, severity=sev,
                    title=f"Панель управления доступна: {label}",
                    evidence=f"{url} → HTTP {status}",
                    description="Панель администрирования доступна с сегмента ЛС; "
                                "дефолтные/подобранные учётные данные дают полный контроль.",
                ))
        # 2. базовая HTTP-аутентификация со стандартными учётками — только детект
        http_meta = svc.http or {}
        if http_meta.get("status") == 401 and "basic" in str(http_meta).lower():
            findings.append(self.make_finding(
                svc, severity="info",
                title="HTTP Basic Auth на панели",
                evidence=f"{host.ip}:{svc.port} отдаёт 401 Basic realm",
                description="Убедитесь, что используются сильные пароли и нет учётных "
                            "данных по умолчанию (admin/admin, root/root).",
            ))
        return findings or None


@register
class MissingSecurityHeadersPlugin(Plugin):
    id = "http_missing_headers"
    name = "HTTP-сервис без базовых защитных заголовков"
    severity = "low"
    cvss = 3.7
    cwe = "CWE-693"
    applies_to_services = ["http", "https", "http-alt", "http-proxy", "https-alt"]
    references = ["https://owasp.org/www-project-secure-headers/"]
    remediation = "Добавьте X-Content-Type-Options: nosniff, X-Frame-Options: DENY, CSP, HSTS (для HTTPS)."

    def check(self, host: Host, svc: Service) -> Optional[List[Finding]]:
        missing = (svc.http or {}).get("missing_security_headers") or []
        if len(missing) < 2:
            return None
        return [self.make_finding(
            svc,
            evidence=f"{host.ip}:{svc.port} отсутствуют: {', '.join(missing)}",
            description="Отсутствие защитных HTTP-заголовков повышает риск clickjacking, "
                        "MIME-confusion и XSS.",
        )]


@register
class CookieFlagsPlugin(Plugin):
    id = "http_cookie_flags"
    name = "Сессионная cookie без флагов Secure/HttpOnly"
    severity = "medium"
    cvss = 5.4
    cwe = "CWE-1004"
    applies_to_services = ["http", "https", "http-alt", "http-proxy", "https-alt"]
    references = ["https://owasp.org/www-community/controls/SecureCookieAttribute"]
    remediation = "Выставьте Secure, HttpOnly, SameSite=Lax/Strict для сессионных cookie."

    def check(self, host: Host, svc: Service) -> Optional[List[Finding]]:
        flags = (svc.http or {}).get("cookie_flags") or {}
        if not flags:
            return None
        bad = [k for k, v in flags.items() if not v]
        if len(bad) >= 2:
            return [self.make_finding(
                svc,
                evidence=f"Set-Cookie без {', '.join(bad)} на {host.ip}:{svc.port}",
            )]
        return None


@register
class BannerDisclosurePlugin(Plugin):
    id = "banner_disclosure"
    name = "Раскрытие точной версии ПО в баннере"
    severity = "info"
    cvss = 0.0
    cwe = "CWE-200"
    applies_to_services = ["*"]
    references = ["https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/01-Information_Gathering/04-Enumerate_Applications_on_Web_Server"]
    remediation = "Снизьте детализацию баннеров (ServerTokens Prod, ssh -V masking), чтобы усложнить подбор эксплойтов."

    def check(self, host: Host, svc: Service) -> Optional[List[Finding]]:
        if svc.version and svc.confidence >= 7:
            return [self.make_finding(
                svc,
                evidence=f"{svc.name} {svc.product} {svc.version} на {host.ip}:{svc.port}",
                description="Точная версия позволяет атакующему сразу подобрать публичные эксплойты.",
            )]
        return None
