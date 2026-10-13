"""Плагин: проверки TLS/SSL (протоколы, сертификаты, шифры)."""
from __future__ import annotations

import re
from typing import List, Optional

from models import Finding, Host, Service
from netguard.plugins.base import Plugin, register


WEAK_CIPHER_RX = re.compile(
    r"(RC4|DES|3DES|EXPORT|NULL|MD5|anon)", re.I
)


@register
class WeakTLSProtocolPlugin(Plugin):
    id = "tls_weak_protocol"
    name = "Устаревшие версии протокола TLS/SSL"
    severity = "medium"
    cwe = "CWE-326"
    references = [
        "https://datatracker.ietf.org/doc/html/rfc8996",
        "https://owasp.org/www-project-web-security-testing-guide/",
    ]
    remediation = "Отключите SSLv3/TLS 1.0/1.1, оставьте TLS 1.2+ с AEAD-шифрами."

    def check(self, host: Host, svc: Service) -> Optional[List[Finding]]:
        proto = (svc.tls or {}).get("protocol", "")
        if not proto:
            return None
        p = proto.lower().replace(" ", "")
        bad = ("ssl" in p) or (p in ("tlsv1", "tlsv1.0", "tlsv1.1"))
        if not bad:
            return None
        sev = "high" if "ssl" in p else "medium"
        return [self.make_finding(
            svc, severity=sev,
            title=f"Сервис согласовал устаревший протокол {proto}",
            evidence=f"{host.ip}:{svc.port} → {proto}",
            description="RFC 8996 объявил TLS 1.0/1.1 устаревшими; SSLv3 уязвим к "
                        "POODLE, TLS 1.0 — к BEAST и downgrade-атакам.",
            cvss=7.4 if "ssl" in p else 5.9,
        )]


@register
class WeakCipherPlugin(Plugin):
    id = "tls_weak_cipher"
    name = "Слабый шифр TLS"
    severity = "medium"
    cwe = "CWE-327"
    references = ["https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-52r2.pdf"]
    remediation = "Оставьте только AEAD-шифры (AES-GCM / ChaCha20-Poly1305); исключите RC4/3DES/EXPORT/NULL."

    def check(self, host: Host, svc: Service) -> Optional[List[Finding]]:
        tls = svc.tls or {}
        cipher = tls.get("cipher", "")
        bits = tls.get("bits", 0)
        problems = []
        if cipher and WEAK_CIPHER_RX.search(cipher):
            problems.append(f"шифр {cipher}")
        if bits and bits < 112:
            problems.append(f"длина ключа {bits} бит")
        if not problems:
            return None
        return [self.make_finding(
            svc, severity="medium",
            title="Согласован криптографически слабый шифр TLS",
            evidence="; ".join(problems) + f" на {host.ip}:{svc.port}",
            cvss=5.9,
        )]


@register
class CertExpiryPlugin(Plugin):
    id = "cert_expiry"
    name = "Срок действия TLS-сертификата"
    severity = "medium"
    cwe = "CWE-298"
    references = ["https://www.rfc-editor.org/rfc/rfc5280#section-4.1.2.5"]
    remediation = "Замените сертификат до истечения срока; настройте мониторинг и ACME-обновление."

    def check(self, host: Host, svc: Service) -> Optional[List[Finding]]:
        tls = svc.tls or {}
        findings: List[Finding] = []
        if tls.get("expired"):
            findings.append(self.make_finding(
                svc, severity="high",
                title="Срок действия TLS-сертификата истёк",
                evidence=f"notAfter={tls.get('not_after')} на {host.ip}:{svc.port}",
                cvss=7.4,
                description="Клиенты получают ошибку доверия; канал может быть "
                            "использован для MITM-подмены.",
            ))
        elif tls.get("expiring_soon"):
            days = tls.get("expires_in_days", "?")
            findings.append(self.make_finding(
                svc, severity="low",
                title=f"TLS-сертификат истекает через {days} дн.",
                evidence=f"notAfter={tls.get('not_after')} на {host.ip}:{svc.port}",
                cvss=3.1,
            ))
        return findings or None


@register
class SelfSignedCertPlugin(Plugin):
    id = "cert_self_signed"
    name = "Самоподписанный TLS-сертификат"
    severity = "low"
    cwe = "CWE-295"
    references = ["https://owasp.org/www-community/vulnerabilities/Insufficient_Certificate_Validation"]
    remediation = "Выпустите сертификат внутренним CA (корень в доверенных хранилищах) или публичным CA."

    def check(self, host: Host, svc: Service) -> Optional[List[Finding]]:
        tls = svc.tls or {}
        if tls.get("self_signed"):
            return [self.make_finding(
                svc,
                title="Используется самоподписанный сертификат",
                evidence=f"CN={tls.get('subject_cn', '')} на {host.ip}:{svc.port}; issuer == subject",
                cvss=3.7,
            )]
        return None


@register
class WeakSignatureCertPlugin(Plugin):
    id = "cert_weak_signature"
    name = "Слабый алгоритм подписи сертификата"
    severity = "medium"
    cwe = "CWE-327"
    references = ["https://blog.cloudflare.com/web-sha-1-is-dead-and-we-dont-even-know-it-yet/"]
    remediation = "Перевыпустите сертификат с SHA-256 или лучше."

    def check(self, host: Host, svc: Service) -> Optional[List[Finding]]:
        tls = svc.tls or {}
        if tls.get("weak_signature"):
            algo = tls.get("signature_algorithm", "SHA-1/MD5")
            return [self.make_finding(
                svc,
                title=f"Сертификат подписан слабым алгоритмом ({algo})",
                evidence=f"{host.ip}:{svc.port}, fingerprint={tls.get('sha1_fingerprint', '')}",
                cvss=5.3,
            )]
        return None
