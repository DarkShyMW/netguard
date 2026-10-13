"""Пакет плагинов NetGuard."""
from netguard.plugins.base import (  # noqa: F401
    Plugin, all_plugins, get_plugin, plugin_ids, register,
)

# Реестр пополняется импортом модулей; base.ensure_loaded() загружает все.

