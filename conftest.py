"""Корневой conftest: гарантирует импортируемость пакета netguard из исходников.

Позволяет запускать `python -m pytest tests` из корня репозитория без
предварительной установки пакета, и защищает от ситуации, когда в sys.path
оказывается путь ВНУТРЬ пакета (запуск из одноимённой папки), что приводит
к ModuleNotFoundError для модулей верхнего уровня (models, cli и т.п.).
"""
import os
import sys

_ROOT = os.path.dirname(os.path.abspath(__file__))
_PKG = os.path.join(_ROOT, "netguard")

# 1) корень проекта должен быть ПЕРВЫМ в sys.path (для `from netguard.x import y`).
#    Иначе при запуске изнутри папки пакета ''/CWD перекрывает пакет
#    «плоскими» модулями и тесты падают с ModuleNotFoundError: models.
if _ROOT in sys.path:
    sys.path.remove(_ROOT)
sys.path.insert(0, _ROOT)


# 2) удаляем ''/'.' и любые пути ВНУТРИ папки пакета — такой путь делает
#    пакет невидимым или подменяет его плоскими модулями (models, engine...).
def _inside_pkg(p: str) -> bool:
    if p in ("", "."):
        return True
    try:
        ap = os.path.abspath(p)
    except (OSError, ValueError):
        return False
    return ap == _PKG or ap.startswith(_PKG + os.sep)


sys.path[:] = [p for p in sys.path if not _inside_pkg(p)]
if _ROOT not in sys.path:
    sys.path.insert(0, _ROOT)

# 3) если пакет уже импортирован НЕ из этих исходников — сбрасываем кэш,
#    чтобы тесты гарантированно шли по рабочему дереву.
_mod = sys.modules.get("netguard")
if _mod is not None and os.path.dirname(os.path.abspath(getattr(_mod, "__file__", "") or "")) != _PKG:
    for _name in [n for n in list(sys.modules)
                  if n == "netguard" or n.startswith("netguard.")]:
        del sys.modules[_name]
