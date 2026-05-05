import functools
import json
import logging
import sys
from contextlib import contextmanager
from datetime import datetime
from typing import Any

import click
import requests.exceptions
from pydantic import ValidationError
from rich.console import Console
from rich.json import JSON
from rich.table import Table

from .api_client import EUVDAPIClient
from .sarif import to_sarif_json
from .self_test import run_self_test

console = Console()
logger = logging.getLogger(__name__)


@contextmanager
def _api_client():
    client = EUVDAPIClient()
    try:
        yield client
    finally:
        client.close()


def print_banner():
    console.print()
    console.print("[bold cyan]EUVD Python CLI v1.0.0[/bold cyan]")
    console.print("[dim]ENISA EU Vulnerability Database Command Line Interface[/dim]")
    console.print(
        "[dim]Marc Rivero Lopez | API: https://euvd.enisa.europa.eu/apidoc[/dim]"
    )
    console.print()


def pretty_print_json(data: Any):
    if hasattr(data, "model_dump"):
        json_data = data.model_dump()
    elif isinstance(data, list) and data and hasattr(data[0], "model_dump"):
        json_data = [item.model_dump() for item in data]
    else:
        json_data = data

    json_obj = JSON.from_data(json_data)
    console.print(json_obj)


def output_data(data: Any, output_format: str):
    if output_format == "sarif":
        click.echo(to_sarif_json(data))
    else:
        pretty_print_json(data)


def _is_sarif() -> bool:
    return (
        click.get_current_context().find_root().params.get("output_format") == "sarif"
    )


def _fetch_and_output(label: str, fetch_func):
    sarif = _is_sarif()
    if not sarif:
        print_banner()
    with _api_client() as client:
        if not sarif:
            console.print(f"[yellow]{label}[/yellow]")
        data = fetch_func(client)
        output_data(data, "sarif" if sarif else "json")


def handle_api_error(func):
    @functools.wraps(func)
    def wrapper(*args, **kwargs):
        try:
            return func(*args, **kwargs)
        except requests.RequestException as e:
            console.print(f"[red]HTTP error: {e}[/red]")
            logger.error(f"HTTP error: {e}")
            return None
        except ValidationError as e:
            console.print(f"[red]Data validation error: {e}[/red]")
            logger.error(f"Data validation error: {e}")
            return None
        except ValueError as e:
            console.print(f"[red]Error: {e}[/red]")
            logger.error(f"Error: {e}")
            return None

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


@cli.command(help="Show latest vulnerabilities.")
@handle_api_error
def latest():
    _fetch_and_output(
        "Fetching latest vulnerabilities...",
        lambda c: c.get_latest_vulnerabilities(),
    )


@cli.command(help="Show critical vulnerabilities.")
@handle_api_error
def critical():
    _fetch_and_output(
        "Fetching critical vulnerabilities...",
        lambda c: c.get_critical_vulnerabilities(),
    )


@cli.command(help="Show exploited vulnerabilities.")
@handle_api_error
def exploited():
    _fetch_and_output(
        "Fetching exploited vulnerabilities...",
        lambda c: c.get_exploited_vulnerabilities(),
    )


@cli.command(help="Search vulnerability by ENISA ID.")
@click.argument("enisa_id")
@handle_api_error
def search_enisa(enisa_id: str):
    _fetch_and_output(
        f"Searching for ENISA ID: {enisa_id}...",
        lambda c: c.get_vulnerability_by_enisa_id(enisa_id),
    )


@cli.command(help="Search vulnerability by Advisory ID.")
@click.argument("advisory_id")
@handle_api_error
def search_advisory(advisory_id: str):
    _fetch_and_output(
        f"Searching for Advisory ID: {advisory_id}...",
        lambda c: c.get_advisory_by_id(advisory_id),
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
    sarif = _is_sarif()
    if not sarif:
        print_banner()
    with _api_client() as client:
        kwargs: dict[str, Any] = {}
        if text:
            kwargs["text"] = text
        if vendor:
            kwargs["vendor"] = vendor
        if product:
            kwargs["product"] = product
        if assigner:
            kwargs["assigner"] = assigner
        if from_score is not None:
            kwargs["from_score"] = from_score
        if to_score is not None:
            kwargs["to_score"] = to_score
        if from_epss is not None:
            kwargs["from_epss"] = from_epss
        if to_epss is not None:
            kwargs["to_epss"] = to_epss
        if from_date:
            kwargs["from_date"] = from_date
        if to_date:
            kwargs["to_date"] = to_date
        if exploited is not None:
            kwargs["exploited"] = exploited
        kwargs["size"] = size
        kwargs["page"] = page

        if not sarif:
            console.print(f"[yellow]Searching with filters: {kwargs}[/yellow]")
        data = client.search_vulnerabilities(**kwargs)
        if not sarif:
            console.print(
                f"[green]Found {data.total} total vulnerabilities, showing {len(data.items)} results[/green]"
            )
        output_data(data, "sarif" if sarif else "json")


@cli.command(help="Show vulnerability statistics.")
@handle_api_error
def stats():
    sarif = _is_sarif()
    if not sarif:
        print_banner()
    with _api_client() as client:
        if not sarif:
            console.print("[yellow]Fetching vulnerability statistics...[/yellow]")
        stats_data = client.get_vulnerability_stats()

        if sarif:
            click.echo(json.dumps(stats_data, indent=2))
            return

        table = Table(title="EUVD Vulnerability Statistics")
        table.add_column("Category", style="cyan", no_wrap=True)
        table.add_column("Count", style="white")

        table.add_row(
            "Latest Vulnerabilities", str(stats_data.get("latest_count", "N/A"))
        )
        table.add_row(
            "Critical Vulnerabilities", str(stats_data.get("critical_count", "N/A"))
        )
        table.add_row(
            "Exploited Vulnerabilities", str(stats_data.get("exploited_count", "N/A"))
        )

        console.print(table)


@cli.command(help="Download KEV dump.")
@click.option("--output", "-o", help="Save to file path")
@click.option("--save", is_flag=True, help="Save as kev_dump_YYYYMMDD_HHMMSS.json")
@handle_api_error
def kev_dump(output: str | None, save: bool):
    sarif = _is_sarif()
    if not sarif:
        print_banner()
    with _api_client() as client:
        if not sarif:
            console.print("[yellow]Fetching KEV dump...[/yellow]")
        data = client.get_kev_dump()
        if not sarif:
            console.print(f"[green]{len(data)} KEV entries[/green]")

        output_format = "sarif" if sarif else "json"
        if output or save:
            if output:
                filename = output
            else:
                ext = ".sarif.json" if sarif else ".json"
                filename = f"kev_dump_{datetime.now().strftime('%Y%m%d_%H%M%S')}{ext}"
            content = (
                to_sarif_json(data)
                if sarif
                else json.dumps([item.model_dump() for item in data], indent=2)
            )
            with open(filename, "w") as f:
                f.write(content)
            if not sarif:
                console.print(f"[green]Saved to {filename}[/green]")
        else:
            output_data(data, output_format)


@cli.command(help="Run the self-test suite.")
def selftest():
    print_banner()
    if not run_self_test():
        sys.exit(1)
