"""Точка входа NetGuard.

Работает во всех режимах запуска (Python 3.9+, Linux/macOS/Windows):
1) python -m netguard            — из корня проекта;
2) python -m netguard            — изнутри папки пакета (чинится через
   PYTHONPATH в activate-скриптах venv, см. hooks/activate_*);
3) python netguard/__main__.py   — прямой запуск файла из любой папки;
4) python netguard               — прямой запуск папки с пакетом.
"""
import os
import sys


def _bootstrap() -> None:
    """Делает пакет `netguard` импортируемым из любой директории."""
    here = os.path.dirname(os.path.abspath(__file__))   # папка пакета netguard/
    parent = os.path.dirname(here)                       # корень проекта

    # 1) Родительский каталог — для абсолютных импортов
    #    вида `from netguard.cli import main`.
    if parent not in sys.path:
        sys.path.insert(0, parent)

    # 2) Если CWD совпадает с папкой пакета, ''/'.' внутри sys.path
    #    указывает ВНУТРЬ пакета и обычный импорт не находит его.
    #    Регистрируем пакет явно по физическому пути.
    try:
        cwd = os.path.abspath(os.getcwd())
    except OSError:  # недоступная рабочая директория
        cwd = ""
    if cwd == here and "netguard" not in sys.modules:
        init_py = os.path.join(here, "__init__.py")
        if os.path.isfile(init_py):
            import importlib.util

            spec = importlib.util.spec_from_file_location(
                "netguard", init_py, submodule_search_locations=[here]
            )
            if spec and spec.loader:
                module = importlib.util.module_from_spec(spec)
                sys.modules["netguard"] = module
                spec.loader.exec_module(module)


_bootstrap()

from netguard.cli import main  # noqa: E402

if __name__ == "__main__":
    raise SystemExit(main())
