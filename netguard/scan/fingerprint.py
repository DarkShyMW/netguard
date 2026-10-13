"""Фингерпринт сервисов: идентификация по порту/баннеру, TLS и HTTP-разведка.

Всё на стандартной библиотеке (ssl, http.client), работает на Linux/macOS/Windows.
"""
from __future__ import annotations

import datetime as dt
import http.client
import re
import socket
import ssl
import urllib.parse
from typing import Dict, Optional

from netguard.models import Service


# порт → имя сервиса (эвристика, как nmap nmap-services)
PORT_SERVICE = {
    21: "ftp", 22: "ssh", 23: "telnet", 25: "smtp", 53: "dns",
    69: "tftp", 80: "http", 110: "pop3", 111: "rpcbind", 135: "msrpc",
    137: "netbios-ns", 139: "netbios-ssn", 143: "imap", 161: "snmp",
    179: "bgp", 389: "ldap", 443: "https", 445: "microsoft-ds",
    465: "smtps", 512: "exec", 513: "rlogin", 514: "syslog",
    587: "submission", 636: "ldaps", 873: "rsync", 990: "ftps",
    993: "imaps", 995: "pop3s", 1080: "socks", 1433: "ms-sql-s",
    1521: "oracle-tns", 2049: "nfs", 2181: "zookeeper", 2375: "docker-api",
    2376: "docker-api-tls", 3000: "http", 3128: "squid-proxy",
    3306: "mysql", 3389: "ms-wbt-server", 4369: "epmd", 5432: "postgresql",
    5500: "radmin-port", 5601: "elasticsearch", 5672: "amqp",
    5900: "vnc", 5901: "vnc", 5984: "couchdb", 6379: "redis",
    6443: "kube-apiserver", 7000: "http", 8000: "http-alt",
    8080: "http-proxy", 8086: "influxdb", 8088: "http-alt",
    8443: "https-alt", 8888: "http-alt", 9000: "cslistener",
    9042: "cassandra-thrift", 9092: "kafka", 9100: "jetdirect-printer",
    9200: "elasticsearch", 9300: "elasticsearch-cluster",
    10000: "webmin", 10250: "kubelet", 10255: "kubelet-ro",
    11211: "memcached", 15672: "rabbitmq-mgmt", 18080: "http-alt",
    27017: "mongodb", 28017: "mongodb-web", 50070: "hdfs-namenode",
    61616: "activemq",
}

BANNER_PATTERNS = [
    (re.compile(r"^SSH-\d.*?-([\w.@-]+)", re.I), "ssh", 1),
    (re.compile(r"^220[ -].*?(?:FTP|ftp)", re.I), "ftp", None),
    (re.compile(r"^220[ -]", re.I), "smtp", None),
    (re.compile(r"Welcome to Telnet", re.I), "telnet", None),
    (re.compile(r"HTTP/\d\.\d \d{3}", re.I), "http", None),
    (re.compile(r"MySQL", re.I), "mysql", None),
    (re.compile(r"PostgreSQL", re.I), "postgresql", None),
    (re.compile(r"-Redis Version", re.I), "redis", None),
    (re.compile(r"^OK$|^PONG", re.I), "redis", None),
    (re.compile(r"STAT .*? pid=", re.I), "memcached", None),
    (re.compile(r"Elasticsearch", re.I), "elasticsearch", None),
    (re.compile(r"_http/_open_rest_data", re.I), "docker-api", None),
]

PRODUCT_VERSION_RES = [
    re.compile(r"(?:Apache|nginx|Microsoft-IIS|Jetty|Tomcat)/([\w.]+)", re.I),
    re.compile(r"OpenSSH[_ ]([\w.~]+)", re.I),
    re.compile(r"(?:MySQL|MariaDB)[ -]server[ -]([\d.]+)", re.I),
    re.compile(r"PostgreSQL (\d+(?:\.\d+)*)", re.I),
    re.compile(r"Redis (\d+(?:\.\d+)*)", re.I),
]


def guess_service_by_port(port: int) -> str:
    return PORT_SERVICE.get(port, "unknown")


def _apply_banner(svc: Service) -> None:
    b = svc.banner or ""
    if not b:
        return
    for rx, name, g in BANNER_PATTERNS:
        m = rx.search(b)
        if m:
            if svc.name in ("unknown", "") or svc.confidence < 5:
                svc.name = name
            svc.confidence = max(svc.confidence, 7)
            if g:
                svc.product = m.group(g)
            break
    for rx in PRODUCT_VERSION_RES:
        m = rx.search(b)
        if m:
            svc.version = m.group(1)
            svc.confidence = max(svc.confidence, 8)
            break


def _tls_probe(host_ip: str, port: int, timeout: float, server_name: str = "") -> Optional[Dict]:
    """Попытка TLS handshake; возвращает dict с параметрами соединения/сертификата."""
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE          # сканер: принимаем любые сертификаты
    try:
        raw = socket.create_connection((host_ip, port), timeout=timeout)
        ssock = ctx.wrap_socket(raw, server_hostname=server_name or host_ip)
    except (ssl.SSLError, OSError):
        return None
    info: Dict = {}
    try:
        info["protocol"] = ssock.version() or ""
        cipher = ssock.cipher()
        if cipher:
            info["cipher"] = cipher[0]
            info["bits"] = cipher[2]
        cert = ssock.getpeercert(binary_form=True)
        if cert:
            pem = ssl.DER_cert_to_PEM_cert(cert)
            try:
                info.update(_parse_pem_dates(pem))
            except Exception:  # noqa: BLE001
                pass
        # getpeercert() без verify_mode=CERT_NONE всегда пустой — получаем dict
        # через отдельный контекст с проверкой, отключённой только для хостнейма.
        peer = _decode_cert_via_cryptography(cert) or ssock.getpeercert()
        if peer:
            subj = dict(x[0] for x in peer.get("subject", ()))
            info["subject_cn"] = subj.get("commonName", "")
            san = [v for k, v in peer.get("subjectAltName", ())]
            info["san"] = san[:8]
            issuer = dict(x[0] for x in peer.get("issuer", ()))
            info["issuer_cn"] = issuer.get("organizationName", "") or issuer.get("commonName", "")
            info["self_signed"] = bool(
                info["issuer_cn"] and info["subject_cn"] and info["issuer_cn"] == info["subject_cn"]
            ) or not peer.get("issuer")
        info["supported_protocols"] = sorted(_tls_versions_available())
    finally:
        try:
            ssock.close()
        except OSError:
            pass
    return info or None


def _decode_cert_via_cryptography(der: bytes) -> Optional[Dict]:
    """Разбор DER-сертификата в формат, совместимый с ssl.Dict (subject/issuer/SAN).

    Нужен потому, что getpeercert() при CERT_NONE возвращает {}.
    """
    try:
        from cryptography import x509
        from cryptography.x509.oid import NameOID
    except ImportError:
        return None
    try:
        cert = x509.load_der_x509_certificate(der)
    except Exception:  # noqa: BLE001
        return None

    def _name_to_tuple(name):
        mapping = {
            NameOID.COMMON_NAME: "commonName",
            NameOID.ORGANIZATION_NAME: "organizationName",
            NameOID.ORGANIZATIONAL_UNIT_NAME: "organizationalUnitName",
            NameOID.EMAIL_ADDRESS: "emailAddress",
            NameOID.COUNTRY_NAME: "countryName",
            NameOID.STATE_OR_PROVINCE_NAME: "stateOrProvinceName",
            NameOID.LOCALITY_NAME: "localityName",
        }
        out = []
        for at in name:
            key = mapping.get(at.oid, at.oid.dotted_string)
            out.append(((key, str(at.value)),))
        return tuple(out) or ((("commonName", ""),),)

    peer: Dict = {
        "subject": _name_to_tuple(cert.subject),
        "issuer": _name_to_tuple(cert.issuer),
    }
    try:
        san = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName)
        entries = []
        for dns in san.value.get_values_for_type(x509.DNSName):
            entries.append(("DNS", dns))
        for ipa in san.value.get_values_for_type(x509.IPAddress):
            entries.append(("IP Address", str(ipa)))
        peer["subjectAltName"] = tuple(entries[:8])
    except Exception:  # noqa: BLE001 — ExtensionNotFound и т.п.
        pass
    return peer


def _parse_pem_dates(pem: str) -> Dict:
    """Даты/алгоритм подписи сертификата.

    Сначала пробуем `cryptography` (если установлен), иначе — внешний `openssl`,
    иначе — минимальный ASN.1-парсер дат из DER (только notBefore/notAfter).
    """
    res: Dict = {}
    der = ssl.PEM_cert_to_DER_cert(pem)
    if _cert_dates_cryptography(der, res):
        return res
    openssl_res = _cert_dates_openssl(pem)
    if openssl_res:
        return openssl_res
    _cert_dates_der(der, res)
    return res


def _cert_dates_cryptography(der: bytes, res: Dict) -> bool:
    try:
        from cryptography import x509
        from cryptography.hazmat.primitives import hashes
        from cryptography.x509.oid import NameOID
    except ImportError:
        return False
    try:
        cert = x509.load_der_x509_certificate(der)
    except Exception:  # noqa: BLE001
        return False
    fmt = "%Y-%m-%d %H:%M:%S"
    nb = cert.not_valid_before_utc.replace(tzinfo=None)
    na = cert.not_valid_after_utc.replace(tzinfo=None)
    res["not_before"] = nb.strftime(fmt)
    res["not_after"] = na.strftime(fmt)
    now = dt.datetime.utcnow()
    res["expired"] = na < now
    res["expires_in_days"] = (na - now).days
    if res["expires_in_days"] <= 30:
        res["expiring_soon"] = True
    try:
        cn = cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)
        res["subject_cn"] = cn[0].value if cn else ""
        icn = cert.issuer.get_attributes_for_oid(NameOID.COMMON_NAME)
        o = cert.issuer.get_attributes_for_oid(NameOID.ORGANIZATION_NAME)
        res["issuer_cn"] = (icn[0].value if icn else "") or (o[0].value if o else "")
        res["self_signed"] = cert.issuer == cert.subject
        san = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName)
        res["san"] = list(san.value.names.keys())[:8] if hasattr(san.value, "names") else \
            (san.value.get_values_for_type(x509.DNSName)[:8])
    except Exception:  # noqa: BLE001
        pass
    try:
        algo_name = cert.signature_hash_algorithm.name.lower()
        if algo_name in ("md5", "sha1"):
            res["weak_signature"] = True
            res["signature_algorithm"] = algo_name
        res["sha1_fingerprint"] = cert.fingerprints[hashes.SHA1()].hex(":")
    except Exception:  # noqa: BLE001
        pass
    return True


def _cert_dates_openssl(pem: str) -> Dict:
    import os
    import subprocess
    import tempfile
    with tempfile.NamedTemporaryFile("w", suffix=".pem", delete=False) as f:
        f.write(pem)
        path = f.name
    try:
        out = subprocess.run(
            ["openssl", "x509", "-in", path, "-noout",
             "-startdate", "-enddate", "-fingerprint", "-sha1", "-text"],
            capture_output=True, text=True, timeout=5,
        ).stdout
    except (OSError, subprocess.SubprocessError):
        return {}
    finally:
        try:
            os.unlink(path)
        except OSError:
            pass
    res: Dict = {}
    m = re.search(r"notBefore=(.+)", out)
    if m:
        res["not_before"] = m.group(1).strip()
    m = re.search(r"notAfter=(.+)", out)
    if m:
        res["not_after"] = m.group(1).strip()
        try:
            end = dt.datetime.strptime(res["not_after"], "%b %d %H:%M:%S %Y %Z")
            res["expired"] = end < dt.datetime.utcnow()
            days = (end - dt.datetime.utcnow()).days
            res["expires_in_days"] = days
            if days <= 30:
                res["expiring_soon"] = True
        except ValueError:
            pass
    m = re.search(r"SHA1 Fingerprint=([\w:]+)", out)
    if m:
        res["sha1_fingerprint"] = m.group(1)
    if re.search(r"Signature Algorithm: .*(md5|sha1)", out, re.I):
        res["weak_signature"] = True
    return res


class _MiniDer:
    """Читатель DER-структур для извлечения UTCTime/GeneralizedTime."""

    def __init__(self, data: bytes):
        self.d = data
        self.i = 0

    def tlv(self):
        tag = self.d[self.i]; self.i += 1
        ln = self.d[self.i]; self.i += 1
        if ln & 0x80:
            nbytes = ln & 0x7F
            ln = int.from_bytes(self.d[self.i:self.i + nbytes], "big")
            self.i += nbytes
        val = self.d[self.i:self.i + ln]
        self.i += ln
        return tag, val


def _cert_dates_der(der: bytes, res: Dict) -> None:
    """Минимальный парсер: ищем первые два UTCTime/GeneralizedTime в TBSCertificate."""
    times = []
    i = 0
    n = len(der)
    while i < n - 2 and len(times) < 2:
        tag = der[i]
        if tag in (0x17, 0x18):     # UTCTime / GeneralizedTime
            ln = der[i + 1]
            if ln & 0x80:
                i += 1
                continue
            s = der[i + 2:i + 2 + ln]
            try:
                txt = s.decode("ascii")
            except UnicodeDecodeError:
                i += 1
                continue
            if tag == 0x17 and len(txt) >= 11:      # YYMMDDHHMMZ
                yy = int(txt[0:2])
                year = 2000 + yy if yy < 50 else 1900 + yy
                parsed = dt.datetime(year, int(txt[2:4]), int(txt[4:6]),
                                     int(txt[6:8]), int(txt[8:10]), int(txt[10:12]))
                times.append(parsed)
                i += 2 + ln
                continue
            if tag == 0x18 and len(txt) >= 13:      # YYYYMMDDHHMMSSZ
                parsed = dt.datetime(int(txt[0:4]), int(txt[4:6]), int(txt[6:8]),
                                     int(txt[8:10]), int(txt[10:12]), int(txt[12:14]))
                times.append(parsed)
                i += 2 + ln
                continue
        i += 1
    fmt = "%Y-%m-%d %H:%M:%S"
    if len(times) >= 1:
        res["not_before"] = times[0].strftime(fmt)
    if len(times) >= 2:
        res["not_after"] = times[1].strftime(fmt)
        now = dt.datetime.utcnow()
        res["expired"] = times[1] < now
        res["expires_in_days"] = (times[1] - now).days
        if res["expires_in_days"] <= 30:
            res["expiring_soon"] = True


def _tls_versions_available() -> set:
    versions = set()
    for name in ("TLSv1", "TLSv1_1", "TLSv1_2", "TLSv1_3"):
        attr = getattr(ssl, f"PROTOCOL_{name.upper().replace('TLS', 'TLS_')}", None)
        if attr is None:
            continue
        try:
            ssl.SSLContext(attr)
            versions.add(name)
        except ValueError:
            pass
    return versions


def _http_probe(svc: Service, host_ip: str, timeout: float) -> None:
    """GET / для http-сервисов: статус, сервер, редиректы, заголовки безопасности."""
    use_tls = svc.tunnel == "ssl" or svc.port in (443, 8443, 4643) or svc.name in ("https",)
    conn_cls = http.client.HTTPSConnection if use_tls else http.client.HTTPConnection
    headers_wanted = {
        "Server", "X-Powered-By", "X-AspNet-Version", "Set-Cookie",
        "Strict-Transport-Security", "X-Frame-Options", "Content-Security-Policy",
        "X-XSS-Protection", "X-Content-Type-Options", "Location",
    }
    try:
        ctx = None
        if use_tls:
            ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
        c = conn_cls(host_ip, svc.port, timeout=timeout, context=ctx)
        c.request("GET", "/", headers={"Host": host_ip, "User-Agent": "netguard/1.0"})
        r = c.getresponse()
        body = r.read(4096).decode("utf-8", "replace")
        h = {k: v for k, v in r.getheaders()}
        low = {k.lower(): v for k, v in h.items()}
        svc.http = {
            "status": r.status,
            "reason": r.reason,
            "title": _extract_title(body),
            "server": low.get("server", ""),
            "x_powered_by": low.get("x-powered-by", ""),
            "set_cookie": low.get("set-cookie", ""),
            "security_headers": {
                k: low.get(k.lower(), "") for k in headers_wanted
                if k.lower() in low
            },
            "missing_security_headers": [
                k for k in ("strict-transport-security", "x-frame-options",
                            "content-security-policy", "x-content-type-options")
                if k not in low
            ],
            "redirect_location": low.get("location", ""),
            "cookie_flags": _cookie_flags(low.get("set-cookie", "")),
        }
        if low.get("server"):
            svc.product = svc.product or low["server"].split("/")[0]
            m = re.search(r"/([\w.]+)$", low["server"])
            if m:
                svc.version = svc.version or m.group(1)
        c.close()
    except (OSError, http.client.HTTPException, UnicodeError):
        return


def _extract_title(html: str) -> str:
    m = re.search(r"<title[^>]*>(.*?)</title>", html, re.I | re.S)
    return m.group(1).strip()[:120] if m else ""


def _cookie_flags(cookie: str) -> Dict[str, bool]:
    low = cookie.lower()
    return {
        "httponly": "httponly" in low,
        "secure": "secure" in low,
        "samesite": "samesite" in low,
    }


def fingerprint_service(svc: Service, host_ip: str, hostname: str = "",
                        timeout: float = 2.0) -> Service:
    """Определяет name/product/version/tunnel/http/tls для уже открытого порта."""
    _apply_banner(svc)

    # TLS-порт?
    if svc.port in (443, 465, 636, 990, 993, 995, 8443, 4643, 2376, 8883) or \
            svc.banner.startswith("\x16\x03"):
        svc.tunnel = "ssl"

    tls_info = _tls_probe(host_ip, svc.port, timeout,
                          server_name=hostname or "")
    if tls_info:
        svc.tls = tls_info
        if not svc.tunnel:
            svc.tunnel = "ssl"
        proto = tls_info.get("protocol", "")
        if proto and "SSL" in proto.upper():
            svc.tls["legacy_ssl"] = True

    if svc.name in ("http", "https", "http-alt", "http-proxy", "https-alt") or \
            svc.port in (80, 8000, 8080, 8086, 8088, 8888, 3000, 5601, 9200,
                         10000, 15672, 18080, 28017, 6443, 10250, 10255):
        if svc.name in ("unknown", ""):
            svc.name = "http"
        _http_probe(svc, host_ip, timeout)

    if svc.name == "unknown" and svc.banner:
        svc.confidence = max(svc.confidence, 3)
    return svc
