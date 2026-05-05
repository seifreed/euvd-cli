import functools
import logging
from typing import Any

import click
from rich.console import Console
from rich.json import JSON
from rich.prompt import Prompt, Confirm
from rich.table import Table

from .api_client import EUVDAPIClient
from .self_test import run_self_test

console = Console()
logger = logging.getLogger(__name__)


def print_banner():
    console.print()
    console.print("[bold cyan]EUVD Python CLI v1.0.0[/bold cyan]")
    console.print("[dim]ENISA EU Vulnerability Database Command Line Interface[/dim]")
    console.print(
        "[dim]Author: Marc Rivero (@seifreed) | API: https://euvd.enisa.europa.eu/apidoc[/dim]"
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


def handle_api_error(func):
    @functools.wraps(func)
    def wrapper(*args, **kwargs):
        try:
            return func(*args, **kwargs)
        except Exception as e:
            console.print(f"[red]Error: {e}[/red]")
            logger.error(f"API error: {e}")
            return None

    return wrapper


class EUVDCLIApp:
    def __init__(self):
        self.client = EUVDAPIClient()

    def close(self):
        self.client.close()

    @handle_api_error
    def fetch_latest_vulnerabilities(self):
        console.print("[yellow]Fetching latest vulnerabilities...[/yellow]")
        data = self.client.get_latest_vulnerabilities()
        pretty_print_json(data)
        return data

    @handle_api_error
    def fetch_exploited_vulnerabilities(self):
        console.print("[yellow]Fetching exploited vulnerabilities...[/yellow]")
        data = self.client.get_exploited_vulnerabilities()
        pretty_print_json(data)
        return data

    @handle_api_error
    def fetch_critical_vulnerabilities(self):
        console.print("[yellow]Fetching critical vulnerabilities...[/yellow]")
        data = self.client.get_critical_vulnerabilities()
        pretty_print_json(data)
        return data

    @handle_api_error
    def search_by_enisa_id(self, enisa_id: str):
        console.print(f"[yellow]Searching for ENISA ID: {enisa_id}...[/yellow]")
        data = self.client.get_vulnerability_by_enisa_id(enisa_id)
        pretty_print_json(data)
        return data

    @handle_api_error
    def search_by_advisory_id(self, advisory_id: str):
        console.print(f"[yellow]Searching for Advisory ID: {advisory_id}...[/yellow]")
        data = self.client.get_advisory_by_id(advisory_id)
        pretty_print_json(data)
        return data

    @handle_api_error
    def show_vulnerability_stats(self):
        console.print("[yellow]Fetching vulnerability statistics...[/yellow]")
        stats = self.client.get_vulnerability_stats()

        table = Table(title="EUVD Vulnerability Statistics")
        table.add_column("Category", style="cyan", no_wrap=True)
        table.add_column("Count", style="white")

        table.add_row("Latest Vulnerabilities", str(stats.get("latest_count", "N/A")))
        table.add_row(
            "Critical Vulnerabilities", str(stats.get("critical_count", "N/A"))
        )
        table.add_row(
            "Exploited Vulnerabilities", str(stats.get("exploited_count", "N/A"))
        )

        console.print(table)
        return stats

    @handle_api_error
    def advanced_search_interactive(self):
        console.print("[cyan]Advanced Search with Flexible Filters[/cyan]")
        console.print("[yellow]Leave empty to skip any filter[/yellow]")

        text = Prompt.ask("Text search", default="")
        vendor = Prompt.ask("Vendor (e.g., Microsoft)", default="")
        product = Prompt.ask("Product (e.g., Windows)", default="")
        assigner = Prompt.ask("Assigner (e.g., mitre)", default="")

        from_score = Prompt.ask("Minimum CVSS score (0-10)", default="")
        to_score = Prompt.ask("Maximum CVSS score (0-10)", default="")

        from_epss = Prompt.ask("Minimum EPSS score (0-100)", default="")
        to_epss = Prompt.ask("Maximum EPSS score (0-100)", default="")

        exploited_str = Prompt.ask("Only exploited vulnerabilities? (y/n)", default="")
        exploited = None
        if exploited_str.lower() in ["y", "yes"]:
            exploited = True
        elif exploited_str.lower() in ["n", "no"]:
            exploited = False

        size = int(Prompt.ask("Results per page (max 100)", default="10"))

        kwargs = {}
        if text:
            kwargs["text"] = text
        if vendor:
            kwargs["vendor"] = vendor
        if product:
            kwargs["product"] = product
        if assigner:
            kwargs["assigner"] = assigner
        if from_score:
            kwargs["from_score"] = float(from_score)
        if to_score:
            kwargs["to_score"] = float(to_score)
        if from_epss:
            kwargs["from_epss"] = float(from_epss)
        if to_epss:
            kwargs["to_epss"] = float(to_epss)
        if exploited is not None:
            kwargs["exploited"] = exploited
        kwargs["size"] = size

        console.print(f"[yellow]Searching with filters: {kwargs}[/yellow]")
        data = self.client.search_vulnerabilities(**kwargs)

        console.print(
            f"[green]Found {data.total} total vulnerabilities, showing {len(data.items)} results[/green]"
        )
        pretty_print_json(data)
        return data

    def run_self_test_interactive(self):
        console.print("[yellow]Running self-test suite...[/yellow]")
        run_self_test()

    def run_interactive(self):
        print_banner()

        try:
            while True:
                console.print()

                table = Table(title="EUVD Tool Menu", show_header=False)
                table.add_column("Option", style="cyan", no_wrap=True)
                table.add_column("Description", style="white")

                menu_items = [
                    ("1", "Show Latest Vulnerabilities"),
                    ("2", "Show Exploited Vulnerabilities"),
                    ("3", "Show Critical Vulnerabilities"),
                    ("4", "Search by ENISA ID"),
                    ("5", "Search by Advisory ID"),
                    ("6", "Advanced Search with Filters"),
                    ("7", "Show Vulnerability Statistics"),
                    ("8", "Run self-test"),
                    ("9", "Exit"),
                ]

                for option, description in menu_items:
                    table.add_row(option, description)

                console.print(table)

                choice = Prompt.ask(
                    "Select an option",
                    choices=["1", "2", "3", "4", "5", "6", "7", "8", "9"],
                )

                if choice == "1":
                    self.fetch_latest_vulnerabilities()
                elif choice == "2":
                    self.fetch_exploited_vulnerabilities()
                elif choice == "3":
                    self.fetch_critical_vulnerabilities()
                elif choice == "4":
                    enisa_id = Prompt.ask("Enter ENISA ID")
                    self.search_by_enisa_id(enisa_id)
                elif choice == "5":
                    advisory_id = Prompt.ask("Enter Advisory ID")
                    self.search_by_advisory_id(advisory_id)
                elif choice == "6":
                    self.advanced_search_interactive()
                elif choice == "7":
                    self.show_vulnerability_stats()
                elif choice == "8":
                    self.run_self_test_interactive()
                elif choice == "9":
                    console.print("[yellow]Exiting...[/yellow]")
                    break

                if choice != "9":
                    console.print()
                    if not Confirm.ask("Continue?", default=True):
                        console.print("[yellow]Exiting...[/yellow]")
                        break

        except KeyboardInterrupt:
            console.print("\n[yellow]Interrupted by user. Exiting...[/yellow]")

        finally:
            self.close()


@click.group()
@click.option("--verbose", "-v", is_flag=True, help="Enable verbose logging")
@click.help_option("-h", "--help")
def cli(verbose):
    """EUVD CLI tool for vulnerability lookup."""
    if verbose:
        logging.basicConfig(level=logging.DEBUG)
    else:
        logging.basicConfig(level=logging.INFO)


@cli.command()
def interactive():
    """Run the interactive menu."""
    app = EUVDCLIApp()
    app.run_interactive()


@cli.command()
def latest():
    """Show latest vulnerabilities."""
    print_banner()
    app = EUVDCLIApp()
    try:
        app.fetch_latest_vulnerabilities()
    finally:
        app.close()


@cli.command()
def critical():
    """Show critical vulnerabilities."""
    print_banner()
    app = EUVDCLIApp()
    try:
        app.fetch_critical_vulnerabilities()
    finally:
        app.close()


@cli.command()
def exploited():
    """Show exploited vulnerabilities."""
    print_banner()
    app = EUVDCLIApp()
    try:
        app.fetch_exploited_vulnerabilities()
    finally:
        app.close()


@cli.command()
@click.argument("enisa_id")
def search_enisa(enisa_id):
    """Search vulnerability by ENISA ID."""
    print_banner()
    app = EUVDCLIApp()
    try:
        app.search_by_enisa_id(enisa_id)
    finally:
        app.close()


@cli.command()
@click.argument("advisory_id")
def search_advisory(advisory_id):
    """Search vulnerability by Advisory ID."""
    print_banner()
    app = EUVDCLIApp()
    try:
        app.search_by_advisory_id(advisory_id)
    finally:
        app.close()


@cli.command()
def stats():
    """Show vulnerability statistics."""
    print_banner()
    app = EUVDCLIApp()
    try:
        app.show_vulnerability_stats()
    finally:
        app.close()


@cli.command()
@click.option("--text", help="Text search keywords")
@click.option("--vendor", help="Vendor name (e.g., Microsoft)")
@click.option("--product", help="Product name (e.g., Windows)")
@click.option("--assigner", help="Assigner (e.g., mitre)")
@click.option("--from-score", type=float, help="Minimum CVSS score (0-10)")
@click.option("--to-score", type=float, help="Maximum CVSS score (0-10)")
@click.option("--from-epss", type=float, help="Minimum EPSS score (0-100)")
@click.option("--to-epss", type=float, help="Maximum EPSS score (0-100)")
@click.option("--exploited", type=bool, help="Filter by exploitation status")
@click.option("--size", type=int, default=10, help="Results per page (max 100)")
def search(
    text,
    vendor,
    product,
    assigner,
    from_score,
    to_score,
    from_epss,
    to_epss,
    exploited,
    size,
):
    """Advanced search with flexible filters."""
    print_banner()
    app = EUVDCLIApp()
    try:
        kwargs = {}
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
        if exploited is not None:
            kwargs["exploited"] = exploited
        kwargs["size"] = size

        console.print(f"[yellow]Searching with filters: {kwargs}[/yellow]")
        data = app.client.search_vulnerabilities(**kwargs)
        console.print(
            f"[green]Found {data.total} total vulnerabilities, showing {len(data.items)} results[/green]"
        )
        pretty_print_json(data)
    finally:
        app.close()


@cli.command()
def selftest():
    """Run the self-test suite."""
    print_banner()
    run_self_test()


if __name__ == "__main__":
    cli()
