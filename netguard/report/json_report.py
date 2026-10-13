"""JSON-отчёт."""
from __future__ import annotations

import json

from netguard.models import ScanResult


def write_json(result: ScanResult, path: str) -> str:
    with open(path, "w", encoding="utf-8") as f:
        f.write(result.to_json())
    return path


def to_string(result: ScanResult) -> str:
    return json.dumps(result.to_dict(), indent=2, ensure_ascii=False)
