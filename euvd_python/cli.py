import functools
import json
import logging
import sys
from collections.abc import Callable
from datetime import datetime
from pathlib import Path
from typing import Any, NoReturn

import click
import requests.exceptions
from pydantic import BaseModel, ValidationError
from rich.console import Console
from rich.json import JSON
from rich.table import Table

from .api_client import APIResponseError, EUVDAPIClient
from . import __version__
from .models import SearchFilters
from .sarif import to_sarif_json
from .self_test import run_self_test

console = Console()

CVSS_MIN = 0.0
CVSS_MAX = 10.0
EPSS_MIN = 0.0
EPSS_MAX = 100.0


def print_banner() -> None:
    console.print()
    console.print(f"[bold cyan]EUVD Python CLI v{__version__}[/bold cyan]")
    console.print("[dim]ENISA EU Vulnerability Database Command Line Interface[/dim]")
    console.print(
        "[dim]Marc Rivero Lopez | API: https://euvd.enisa.europa.eu/apidoc[/dim]"
    )
    console.print()


def _to_serializable(data: Any) -> Any:
    if isinstance(data, BaseModel):
        return data.model_dump()
    if isinstance(data, list) and data and isinstance(data[0], BaseModel):
        return [item.model_dump() for item in data]
    return data


def _pretty_print(data: Any) -> None:
    console.print(JSON.from_data(_to_serializable(data)))


def output_data(data: Any, output_format: str) -> None:
    if output_format == "sarif":
        click.echo(to_sarif_json(data))
    else:
        _pretty_print(data)


def _output_format() -> str:
    return click.get_current_context().find_root().params.get("output_format", "json")


def _fetch_and_output(
    status_message: str,
    fetch_func: Callable[[EUVDAPIClient], Any],
    output_format: str,
    post_fetch: Callable[[Any], None] | None = None,
    renderer: Callable[[Any], None] | None = None,
) -> None:
    is_sarif = output_format == "sarif"
    if not is_sarif:
        print_banner()
    with EUVDAPIClient() as client:
        if not is_sarif:
            console.print(f"[yellow]{status_message}[/yellow]")
        data = fetch_func(client)
        if post_fetch and not is_sarif:
            post_fetch(data)
        if renderer and not is_sarif:
            renderer(data)
        else:
            output_data(data, output_format)


def _exit_with_error(message: str) -> NoReturn:
    console.print(f"[red]{message}[/red]")
    sys.exit(1)


def _validate_range(
    value: float | None, min_val: float, max_val: float, name: str
) -> None:
    if value is not None and (value < min_val or value > max_val):
        _exit_with_error(f"{name} must be between {min_val:.0f} and {max_val:.0f}")


def _save_to_file(data: Any, filename: str, sarif: bool) -> None:
    if sarif:
        content = to_sarif_json(data)
    else:
        content = json.dumps(_to_serializable(data), indent=2)

    Path(filename).write_text(content, encoding="utf-8")


def handle_api_error(func: Callable[..., Any]) -> Callable[..., Any]:
    @functools.wraps(func)
    def wrapper(*args: Any, **kwargs: Any) -> Any:
        try:
            return func(*args, **kwargs)
        except requests.RequestException as e:
            _exit_with_error(f"HTTP error: {e}")
        except ValidationError as e:
            _exit_with_error(f"Validation error: {e}")
        except APIResponseError as e:
            _exit_with_error(f"Error: {e}")

    return wrapper


@click.group(help="EUVD CLI tool for vulnerability lookup.")
@click.option("--verbose", "-v", is_flag=True, help="Enable verbose logging")
@click.option(
    "--format",
    "output_format",
    type=click.Choice(["json", "sarif"]),
    default="json",
    help="Output format",
)
@click.help_option("-h", "--help")
def cli(verbose: bool, output_format: str):
    if verbose:
        logging.getLogger().setLevel(logging.DEBUG)


@cli.command()
@handle_api_error
def latest():
    _fetch_and_output(
        "Fetching latest vulnerabilities...",
        lambda c: c.get_latest_vulnerabilities(),
        _output_format(),
    )


@cli.command()
@handle_api_error
def critical():
    _fetch_and_output(
        "Fetching critical vulnerabilities...",
        lambda c: c.get_critical_vulnerabilities(),
        _output_format(),
    )


@cli.command()
@handle_api_error
def exploited():
    _fetch_and_output(
        "Fetching exploited vulnerabilities...",
        lambda c: c.get_exploited_vulnerabilities(),
        _output_format(),
    )


@cli.command(help="Search vulnerability by ENISA ID.")
@click.argument("enisa_id")
@handle_api_error
def search_enisa(enisa_id: str):
    _fetch_and_output(
        f"Searching for ENISA ID: {enisa_id}...",
        lambda c: c.get_vulnerability_by_enisa_id(enisa_id),
        _output_format(),
    )


@cli.command(help="Search vulnerability by Advisory ID.")
@click.argument("advisory_id")
@handle_api_error
def search_advisory(advisory_id: str):
    _fetch_and_output(
        f"Searching for Advisory ID: {advisory_id}...",
        lambda c: c.get_advisory_by_id(advisory_id),
        _output_format(),
    )


@cli.command(help="Advanced search with flexible filters.")
@click.option("--text", help="Text search keywords")
@click.option("--vendor", help="Vendor name")
@click.option("--product", help="Product name")
@click.option("--assigner", help="Assigner")
@click.option("--from-score", type=float, help="Minimum CVSS score (0-10)")
@click.option("--to-score", type=float, help="Maximum CVSS score (0-10)")
@click.option("--from-epss", type=float, help="Minimum EPSS score (0-100)")
@click.option("--to-epss", type=float, help="Maximum EPSS score (0-100)")
@click.option("--from-date", help="Date filter start (YYYY-MM-DD)")
@click.option("--to-date", help="Date filter end (YYYY-MM-DD)")
@click.option(
    "--exploited/--not-exploited", default=None, help="Filter by exploitation status"
)
@click.option("--size", type=int, default=10, help="Results per page (max 100)")
@click.option("--page", type=int, default=0, help="Page number")
@handle_api_error
def search(
    text: str | None,
    vendor: str | None,
    product: str | None,
    assigner: str | None,
    from_score: float | None,
    to_score: float | None,
    from_epss: float | None,
    to_epss: float | None,
    from_date: str | None,
    to_date: str | None,
    exploited: bool | None,
    size: int,
    page: int,
):
    _validate_range(from_score, CVSS_MIN, CVSS_MAX, "from-score")
    _validate_range(to_score, CVSS_MIN, CVSS_MAX, "to-score")
    _validate_range(from_epss, EPSS_MIN, EPSS_MAX, "from-epss")
    _validate_range(to_epss, EPSS_MIN, EPSS_MAX, "to-epss")

    filters = SearchFilters(
        text=text,
        vendor=vendor,
        product=product,
        assigner=assigner,
        from_score=from_score,
        to_score=to_score,
        from_epss=from_epss,
        to_epss=to_epss,
        from_date=from_date,
        to_date=to_date,
        exploited=exploited,
        size=size,
        page=page,
    )
    _fetch_and_output(
        "Searching vulnerabilities...",
        lambda c: c.search_vulnerabilities(filters),
        _output_format(),
        post_fetch=lambda data: console.print(
            f"[green]Found {data.total} total vulnerabilities, showing {len(data.items)} results[/green]"
        ),
    )


def _render_stats(stats_data: Any) -> None:
    table = Table(title="EUVD Vulnerability Statistics")
    table.add_column("Category", style="cyan", no_wrap=True)
    table.add_column("Count", style="white")

    table.add_row("Latest Vulnerabilities", str(stats_data.latest_count))
    table.add_row("Critical Vulnerabilities", str(stats_data.critical_count))
    table.add_row("Exploited Vulnerabilities", str(stats_data.exploited_count))

    console.print(table)


@cli.command(help="Show vulnerability statistics.")
@handle_api_error
def stats():
    _fetch_and_output(
        "Fetching vulnerability statistics...",
        lambda c: c.get_vulnerability_stats(),
        _output_format(),
        renderer=_render_stats,
    )


def _render_kev_dump(data: Any) -> None:
    console.print(f"[green]{len(data)} KEV entries[/green]")
    output_data(data, "json")


@cli.command(help="Download KEV dump.")
@click.option("--output", "-o", "output_path", help="Save to file path")
@click.option("--save", is_flag=True, help="Save as kev_dump_YYYYMMDD_HHMMSS.json")
@handle_api_error
def kev_dump(output_path: str | None, save: bool):
    fmt = _output_format()
    is_sarif = fmt == "sarif"

    def _save_kev(client: EUVDAPIClient) -> Any:
        data = client.get_kev_dump()
        if output_path or save:
            if output_path:
                filename = output_path
            else:
                ext = ".sarif.json" if is_sarif else ".json"
                filename = f"kev_dump_{datetime.now().strftime('%Y%m%d_%H%M%S')}{ext}"
            _save_to_file(data, filename, is_sarif)
            if not is_sarif:
                console.print(f"[green]Saved to {filename}[/green]")
            return data
        return data

    renderer = None if (output_path or save) else _render_kev_dump
    _fetch_and_output(
        "Fetching KEV dump...",
        _save_kev,
        fmt,
        renderer=renderer,
    )


@cli.command(help="Run the self-test suite.")
@handle_api_error
def selftest():
    print_banner()
    if not run_self_test():
        sys.exit(1)
