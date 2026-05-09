import csv as _csv
import io
import json
import sys
from pathlib import Path
from typing import Any

from pydantic import BaseModel
from rich.table import Table

from .console import console
from .models import VulnerabilityStats
from .sarif import to_sarif_json


def to_serializable(data: Any) -> Any:
    if isinstance(data, BaseModel):
        return data.model_dump(by_alias=True)
    if isinstance(data, list) and data and isinstance(data[0], BaseModel):
        return [item.model_dump(by_alias=True) for item in data]
    return data


def _items_for_flat_format(data: Any) -> Any:
    serial = to_serializable(data)
    if (
        isinstance(serial, dict)
        and "items" in serial
        and "total" in serial
        and isinstance(serial["items"], list)
    ):
        return serial["items"]
    return serial


def _to_jsonl(data: Any) -> str:
    serial = _items_for_flat_format(data)
    if isinstance(serial, list):
        return "\n".join(json.dumps(item, ensure_ascii=False) for item in serial)
    return json.dumps(serial, ensure_ascii=False)


def _to_csv(data: Any) -> str:
    serial = _items_for_flat_format(data)
    rows = serial if isinstance(serial, list) else [serial]
    keys: list[str] = []
    seen: set[str] = set()
    for row in rows:
        if not isinstance(row, dict):
            continue
        for k in row:
            if k not in seen:
                seen.add(k)
                keys.append(k)
    if not keys:
        return ""
    out = io.StringIO()
    writer = _csv.DictWriter(out, fieldnames=keys, lineterminator="\n")
    writer.writeheader()
    for row in rows:
        if not isinstance(row, dict):
            continue
        flat: dict[str, Any] = {}
        for k in keys:
            v = row.get(k)
            if v is None:
                flat[k] = ""
            elif isinstance(v, (dict, list)):
                flat[k] = json.dumps(v, separators=(",", ":"), ensure_ascii=False)
            else:
                flat[k] = v
        writer.writerow(flat)
    return out.getvalue().rstrip("\n")


class OutputDependencyError(Exception):
    pass


def _to_toon(data: Any) -> str:
    try:
        from toon_format import encode
    except ImportError as exc:
        raise OutputDependencyError(
            'TOON output requires the optional "toon" extra: '
            'pip install "euvd-python-cli[toon]" --pre'
        ) from exc
    return encode(to_serializable(data)).rstrip("\n")


def format_data(data: Any, output_format: str) -> str:
    if output_format == "sarif":
        return to_sarif_json(data)
    if output_format == "jsonl":
        return _to_jsonl(data)
    if output_format == "csv":
        return _to_csv(data)
    if output_format == "toon":
        return _to_toon(data)
    return json.dumps(to_serializable(data), indent=2)


def print_data(data: Any, output_format: str) -> None:
    sys.stdout.write(format_data(data, output_format) + "\n")


def save_data(data: Any, output_format: str, filename: str) -> None:
    Path(filename).write_text(format_data(data, output_format), encoding="utf-8")


def render_stats(stats: VulnerabilityStats) -> None:
    table = Table(title="EUVD Vulnerability Statistics")
    table.add_column("Category", style="cyan", no_wrap=True)
    table.add_column("Count", style="white")

    table.add_row("Latest Vulnerabilities", str(stats.latest_count))
    table.add_row("Critical Vulnerabilities", str(stats.critical_count))
    table.add_row("Exploited Vulnerabilities", str(stats.exploited_count))

    console.print(table)
