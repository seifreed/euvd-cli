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


def format_data(data: Any, output_format: str) -> str:
    if output_format == "sarif":
        return to_sarif_json(data)
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
