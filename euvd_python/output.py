import json
from pathlib import Path
from typing import Any

import click
from pydantic import BaseModel
from rich.console import Console
from rich.json import JSON

from .sarif import to_sarif_json

console = Console()


def to_serializable(data: Any) -> Any:
    if isinstance(data, BaseModel):
        return data.model_dump()
    if isinstance(data, list) and data and isinstance(data[0], BaseModel):
        return [item.model_dump() for item in data]
    return data


def format_data(data: Any, output_format: str) -> str:
    if output_format == "sarif":
        return to_sarif_json(data)
    return json.dumps(to_serializable(data), indent=2)


def print_data(data: Any, output_format: str) -> None:
    if output_format == "sarif":
        click.echo(format_data(data, output_format))
    else:
        console.print(JSON.from_data(to_serializable(data)))


def save_data(data: Any, output_format: str, filename: str) -> None:
    Path(filename).write_text(format_data(data, output_format), encoding="utf-8")
