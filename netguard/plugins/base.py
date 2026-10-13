"""Интерфейс плагинов и реестр проверок.

Плагин = класс-наследник Plugin с декларативными атрибутами. Ядро вызывает
`check(host, service)` для каждой пары (хост, сервис); плагин может вернуть
Finding | None | список Finding.
"""
from __future__ import annotations

import abc
from typing import Dict, List, Optional, Type

from netguard.models import Finding, Host, Service


class Plugin(abc.ABC):
    id: str = "base"
    name: str = "Базовая проверка"
    description: str = ""
    severity: str = "informational"     # предлагаемая severity по умолчанию
    cwe: str = ""
    cvss: float = 0.0
    references: List[str] = []
    remediation: str = ""
    # порты/сервисы, на которых плагин имеет смысл; пусто = все
    applies_to_services: List[str] = []
    applies_to_ports: List[int] = []

    def applies(self, host: Host, svc: Service) -> bool:
        if self.applies_to_services and svc.name not in self.applies_to_services \
                and "*" not in self.applies_to_services:
            return False
        if self.applies_to_ports and svc.port not in self.applies_to_ports:
            return False
        return True

    @abc.abstractmethod
    def check(self, host: Host, svc: Service) -> Optional[List[Finding]]:
        """Возвращает находки или None."""

    def make_finding(self, svc: Service, *, severity: Optional[str] = None,
                     title: Optional[str] = None, evidence: str = "",
                     description: str = "", **kw) -> Finding:
        return Finding(
            plugin_id=self.id,
            title=title or self.name,
            severity=severity or self.severity,
            description=description or self.description,
            evidence=evidence,
            port=svc.port if svc else None,
            protocol=svc.protocol if svc else "tcp",
            cwe=self.cwe,
            cvss=kw.pop("cvss", self.cvss),
            references=list(kw.pop("references", self.references)),
            remediation=kw.pop("remediation", self.remediation),
        )


_REGISTRY: Dict[str, Type[Plugin]] = {}


def register(cls: Type[Plugin]) -> Type[Plugin]:
    if cls.id in _REGISTRY:
        raise ValueError(f"Дубликат id плагина: {cls.id}")
    _REGISTRY[cls.id] = cls
    return cls


def all_plugins() -> List[Plugin]:
    ensure_loaded()
    return [cls() for cls in _REGISTRY.values()]


def get_plugin(pid: str) -> Optional[Plugin]:
    ensure_loaded()
    cls = _REGISTRY.get(pid)
    return cls() if cls else None


def plugin_ids() -> List[str]:
    ensure_loaded()
    return sorted(_REGISTRY)


_loaded = False


def ensure_loaded() -> None:
    global _loaded
    if not _loaded:
        from netguard.plugins import (  # noqa: F401
            insecure_protocols, tls_checks, vulns,
        )
        _loaded = True
