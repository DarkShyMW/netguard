#!/usr/bin/env python3
"""postinstall: добавляет корень проекта в PYTHONPATH активационных скриптов venv.

Решает проблему `ModuleNotFoundError: No module named 'netguard'` при запуске
`python -m netguard` изнутри папки пакета (частый сценарий на Windows):
activate-скрипты виртуального окружения после этого сами прописывают путь к
пакету, и интерпретатор находит его до разбора аргумента `-m`.

Запуск (из корня проекта, после создания .venv):
    python setup_hooks.py            # или py -3 setup_hooks.py на Windows
Скрипт безопасен для повторного запуска и работает на Linux/macOS/Windows.
"""
from __future__ import annotations

import os
import sys

MARK = "# netguard-path-hook"


def find_venv(root: str) -> str | None:
    """Ищет активированное venv рядом с проектом (bin/Activate.ps1 или Scripts/)."""
    for name in sorted(os.listdir(root)):
        cand = os.path.join(root, name)
        if not os.path.isdir(cand) or name in {"netguard"}:
            continue
        scripts = os.path.join(cand, "Scripts")   # Windows
        bin_ = os.path.join(cand, "bin")          # POSIX
        for d in (scripts, bin_):
            if os.path.isfile(os.path.join(d, "activate")):
                return d
    return None


def patch_file(path: str, project_root: str) -> bool:
    if not os.path.isfile(path):
        return False
    with open(path, "r", encoding="utf-8", errors="ignore") as f:
        content = f.read()
    if MARK in content:
        print(f"  уже настроен: {os.path.basename(path)}")
        return True

    base = os.path.basename(path)
    if base == "Activate.ps1":
        snippet = f'\n$env:PYTHONPATH = "{project_root};" + $env:PYTHONPATH  {MARK}\n'
    elif base.startswith("activate"):
        snippet = (
            f'\nif [ -n "$PYTHONPATH" ]; then export PYTHONPATH="{project_root}:$PYTHONPATH"; '
            f'else export PYTHONPATH="{project_root}"; fi  {MARK}\n'
        )
    else:
        return False

    with open(path, "a", encoding="utf-8") as f:
        f.write(snippet)
    print(f"  пропатчен: {base}")
    return True


def main() -> int:
    root = os.path.dirname(os.path.abspath(__file__))
    scripts_dir = find_venv(root)
    if not scripts_dir:
        print("Виртуальное окружение не найдено. Сначала выполните:")
        print("  python -m venv .venv")
        return 1

    print(f"Обнаружено venv: {os.path.dirname(scripts_dir)}")
    targets = ["activate", "activate.csh", "activate.fish", "Activate.ps1", "activate.bat"]
    patched = 0
    for t in targets:
        if patch_file(os.path.join(scripts_dir, t), root):
            patched += 1

    print("\nГотово. Перезапустите активацию окружения:")
    if os.name == "nt":
        print(r"  .\.venv\Scripts\Activate.ps1   (PowerShell)")
        print(r"  .venv\Scripts\activate.bat     (cmd.exe)")
    else:
        print("  source .venv/bin/activate")
    print('После этого `python -m netguard ...` будет работать из любой папки,\nвключая саму папку пакета "netguard".')
    return 0 if patched else 1


if __name__ == "__main__":
    sys.exit(main())
