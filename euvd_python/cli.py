import functools
import logging
import sys
from collections.abc import Callable
from datetime import datetime
from pathlib import Path
from typing import Any, NoReturn

import click
from pydantic import ValidationError

from .api_client import API_ERRORS, EUVDAPIClient
from . import __version__
from .console import err_console
from .models import SearchFilters, VulnerabilityStats
from .output import print_data, render_stats, save_data
from .sarif import SARIFConversionError
from .self_test import run_self_test

# OSError covers filesystem failures during save (FileNotFoundError,
# PermissionError, IsADirectoryError, disk full) and BrokenPipeError when
# stdout's reader closes. Network OSErrors are wrapped by requests into
# RequestException so they go through API_ERRORS, not this catch.
_HANDLED_ERRORS = API_ERRORS + (SARIFConversionError, OSError)


def _format_validation_error(err: ValidationError) -> str:
    # Loc paths from SearchFilters always correspond to CLI flags; render them
    # as --kebab-case so users see the exact flag they typed.
    lines = []
    for item in err.errors():
        loc_parts = [str(part) for part in item["loc"]]
        if loc_parts:
            loc = "--" + loc_parts[0].replace("_", "-")
        else:
            loc = "<root>"
        lines.append(f"  {loc}: {item['msg']}")
    return "Invalid input:\n" + "\n".join(lines)


def _save_with_overwrite_warning(data: Any, output_format: str, path: str) -> None:
    # is_file() only matches regular files; directories or missing paths do
    # not warrant an overwrite warning (save_data will surface its own OSError
    # if the path is unwritable).
    if Path(path).is_file():
        err_console.print(f"[yellow]Warning: overwriting existing file {path}[/yellow]")
    save_data(data, output_format, path)


def print_banner() -> None:
    err_console.print()
    err_console.print(f"[bold cyan]EUVD Python CLI v{__version__}[/bold cyan]")
    err_console.print(
        "[dim]ENISA EU Vulnerability Database Command Line Interface[/dim]"
    )
    err_console.print(
        "[dim]Marc Rivero Lopez | API: https://euvd.enisa.europa.eu/apidoc[/dim]"
    )
    err_console.print()


def _output_format() -> str:
    return click.get_current_context().find_root().params.get("output_format", "json")


def _fetch_and_output(
    status_message: str,
    fetch_func: Callable[[EUVDAPIClient], Any],
    output_format: str,
    post_fetch: Callable[[Any], None] | None = None,
    renderer: Callable[[Any], None] | None = None,
    save_path: str | None = None,
) -> None:
    is_sarif = output_format == "sarif"
    if not is_sarif:
        print_banner()
    with EUVDAPIClient() as client:
        if not is_sarif:
            err_console.print(f"[yellow]{status_message}[/yellow]")
        data = fetch_func(client)
        if post_fetch and not is_sarif:
            post_fetch(data)

    if save_path:
        _save_with_overwrite_warning(data, output_format, save_path)
        if not is_sarif:
            err_console.print(f"[green]Saved to {save_path}[/green]")
    elif renderer and not is_sarif:
        renderer(data)
    else:
        print_data(data, output_format)


def _exit_with_error(message: str) -> NoReturn:
    err_console.print(f"[red]{message}[/red]")
    sys.exit(1)


def handle_cli_error(func: Callable[..., Any]) -> Callable[..., Any]:
    @functools.wraps(func)
    def wrapper(*args: Any, **kwargs: Any) -> Any:
        try:
            return func(*args, **kwargs)
        except ValidationError as e:
            _exit_with_error(_format_validation_error(e))
        except _HANDLED_ERRORS as e:
            _exit_with_error(f"{type(e).__name__}: {e}")

    return wrapper


@click.group(
    help="EUVD CLI tool for vulnerability lookup.",
    context_settings={"help_option_names": ["-h", "--help"]},
)
@click.option("--verbose", "-v", is_flag=True, help="Enable verbose logging")
@click.option(
    "--format",
    "output_format",
    type=click.Choice(["json", "sarif"]),
    default="json",
    help="Output format",
)
def cli(verbose: bool, output_format: str) -> None:
    if verbose:
        logging.getLogger().setLevel(logging.DEBUG)


@cli.command(help="Show latest vulnerabilities.")
@handle_cli_error
def latest() -> None:
    _fetch_and_output(
        "Fetching latest vulnerabilities...",
        lambda c: c.get_latest_vulnerabilities(),
        _output_format(),
    )


@cli.command(help="Show critical vulnerabilities.")
@handle_cli_error
def critical() -> None:
    _fetch_and_output(
        "Fetching critical vulnerabilities...",
        lambda c: c.get_critical_vulnerabilities(),
        _output_format(),
    )


@cli.command(help="Show exploited vulnerabilities.")
@handle_cli_error
def exploited() -> None:
    _fetch_and_output(
        "Fetching exploited vulnerabilities...",
        lambda c: c.get_exploited_vulnerabilities(),
        _output_format(),
    )


@cli.command(help="Search vulnerability by ENISA ID.")
@click.argument("enisa_id")
@handle_cli_error
def search_enisa(enisa_id: str) -> None:
    _fetch_and_output(
        f"Searching for ENISA ID: {enisa_id}...",
        lambda c: c.get_vulnerability_by_enisa_id(enisa_id),
        _output_format(),
    )


@cli.command(help="Search vulnerability by Advisory ID.")
@click.argument("advisory_id")
@handle_cli_error
def search_advisory(advisory_id: str) -> None:
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
@handle_cli_error
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
) -> None:
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
        post_fetch=lambda data: err_console.print(
            f"[green]Found {data.total} total vulnerabilities, showing {len(data.items)} results[/green]"
        ),
    )


@cli.command(help="Show vulnerability statistics.")
@handle_cli_error
def stats() -> None:
    if _output_format() == "sarif":
        _exit_with_error("SARIF format is not supported for statistics")
    print_banner()
    err_console.print("[yellow]Fetching vulnerability statistics...[/yellow]")
    with EUVDAPIClient() as client:
        latest = client.get_latest_vulnerabilities()
        critical = client.get_critical_vulnerabilities()
        exploited = client.get_exploited_vulnerabilities()
    render_stats(
        VulnerabilityStats(
            latest_count=len(latest),
            critical_count=len(critical),
            exploited_count=len(exploited),
        )
    )


@cli.command(help="Download KEV dump.")
@click.option("--output", "-o", "output_path", help="Save to file path")
@click.option("--save", is_flag=True, help="Save as kev_dump_YYYYMMDD_HHMMSS.json")
@handle_cli_error
def kev_dump(output_path: str | None, save: bool) -> None:
    fmt = _output_format()
    is_sarif = fmt == "sarif"
    ext = ".sarif.json" if is_sarif else ".json"
    save_path: str | None = None
    if output_path or save:
        save_path = (
            output_path or f"kev_dump_{datetime.now().strftime('%Y%m%d_%H%M%S')}{ext}"
        )

    _fetch_and_output(
        "Fetching KEV dump...",
        lambda c: c.get_kev_dump(),
        fmt,
        post_fetch=(
            None
            if save_path
            else lambda data: err_console.print(
                f"[green]{len(data)} KEV entries[/green]"
            )
        ),
        save_path=save_path,
    )


@cli.command(help="Run the self-test suite.")
def selftest() -> None:
    print_banner()
    if not run_self_test():
        sys.exit(1)
