"""Плагин №1: открытые небезопасные протоколы (Telnet/FTP/r-сервисы).

Каждый плагин — декларативный класс с метаданными и методом check().
"""
from __future__ import annotations

from typing import List, Optional

from models import Finding, Host, Service
from netguard.plugins.base import Plugin, register


INSECURE_PROTOCOLS = {
    "telnet": dict(
        title="Telnet: передача учётных данных в открытом виде",
        severity="high", cvss=8.1, cwe="CWE-319",
        description="Telnet передаёт логин/пароль без шифрования; перехват в ЛС — "
                    "компрометация учётной записи.",
        remediation="Отключите telnetd, используйте SSH (порт 22) с ключевой "
                    "аутентификацией.",
        refs=["https://nvd.nist.gov/vuln/detail/CVE-1999-0563"],
    ),
    "ftp": dict(
        title="FTP: нешифрованная передача данных и учётных данных",
        severity="medium", cvss=5.9, cwe="CWE-319",
        description="FTP передаёт учётные данные и файлы в открытом виде.",
        remediation="Используйте SFTP/FTPS. Если FTP необходим — ограничьте доступ "
                    "по IP и включите TLS.",
        refs=["https://owasp.org/www-community/vulnerabilities/Use_of_Plain_Text_Protocols"],
    ),
    "exec": dict(
        title="r-services (rexec) доступны",
        severity="high", cvss=8.8, cwe="CWE-306",
        description="R-протоколы (rlogin/rsh/rexec) аутентифицируют по IP-адресу.",
        remediation="Отключите r-services, используйте SSH.",
        refs=["https://attack.mitre.org/techniques/T1078/"],
    ),
    "rlogin": dict(
        title="r-services (rlogin) доступны",
        severity="high", cvss=8.8, cwe="CWE-306",
        description="R-протоколы аутентифицируют по IP-адресу источника.",
        remediation="Отключите r-services, используйте SSH.",
        refs=[],
    ),
    "snmp": dict(
        title="SNMP доступен из сети",
        severity="low", cvss=3.7, cwe="CWE-200",
        description="SNMP может раскрывать конфигурацию оборудования/топологию, особенно "
                    "с community 'public'. Требуется дополнительная проверка.",
        remediation="Ограничьте SNMP ACL, замените public на сложное community, "
                    "перейдите на SNMPv3 с шифрованием.",
        refs=["https://www.us-cert.gov/ncas/alerts/TA14-256a"],
    ),
}


@register
class InsecureProtocolsPlugin(Plugin):
    id = "insecure_protocols"
    name = "Небезопасные протоколы управления"
    applies_to_services = list(INSECURE_PROTOCOLS.keys())

    def check(self, host: Host, svc: Service) -> Optional[List[Finding]]:
        meta = INSECURE_PROTOCOLS.get(svc.name)
        if not meta:
            return None
        f = self.make_finding(
            svc,
            title=meta["title"],
            severity=meta["severity"],
            description=meta["description"],
            evidence=f"{svc.name} на {host.ip}:{svc.port}; баннер: {svc.banner[:80]!r}",
            cvss=meta["cvss"],
            cwe=meta["cwe"],
            references=meta["refs"],
            remediation=meta["remediation"],
        )
        return [f]
