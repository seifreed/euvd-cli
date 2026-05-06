from collections.abc import Callable

from rich.console import Console

from .api_client import EUVDAPIClient
from .models import SearchFilters

console = Console()


def _test_endpoint(
    label: str, func: Callable[..., object], *args: object, **kwargs: object
) -> bool:
    try:
        result = func(*args, **kwargs)
        if isinstance(result, list):
            console.print(f"[green]PASS[/green] {label} ({len(result)} items)")
        else:
            console.print(f"[green]PASS[/green] {label}")
        return True
    except Exception as e:
        console.print(f"[red]FAIL[/red] {label}: {e}")
        return False


def run_self_test() -> bool:
    client = EUVDAPIClient()

    try:
        console.print("Running self-test against official EUVD API endpoints...")

        results: list[tuple[str, bool]] = [
            (
                "Latest vulnerabilities",
                _test_endpoint(
                    "Latest vulnerabilities", client.get_latest_vulnerabilities
                ),
            ),
            (
                "Critical vulnerabilities",
                _test_endpoint(
                    "Critical vulnerabilities", client.get_critical_vulnerabilities
                ),
            ),
            (
                "Exploited vulnerabilities",
                _test_endpoint(
                    "Exploited vulnerabilities", client.get_exploited_vulnerabilities
                ),
            ),
            (
                "ENISA ID search",
                _test_endpoint(
                    "ENISA ID search",
                    client.get_vulnerability_by_enisa_id,
                    "EUVD-2025-4893",
                ),
            ),
            (
                "Advisory ID search",
                _test_endpoint(
                    "Advisory ID search",
                    client.get_advisory_by_id,
                    "oxas-adv-2024-0002",
                ),
            ),
            (
                "Advanced search (text)",
                _test_endpoint(
                    "Advanced search (text)",
                    client.search_vulnerabilities,
                    SearchFilters(text="vulnerability", size=2),
                ),
            ),
            (
                "Advanced search (exploited)",
                _test_endpoint(
                    "Advanced search (exploited)",
                    client.search_vulnerabilities,
                    SearchFilters(exploited=True, size=2),
                ),
            ),
            (
                "Advanced search (score filter)",
                _test_endpoint(
                    "Advanced search (score filter)",
                    client.search_vulnerabilities,
                    SearchFilters(from_score=9.0, size=2),
                ),
            ),
            (
                "Advanced search (date filter)",
                _test_endpoint(
                    "Advanced search (date filter)",
                    client.search_vulnerabilities,
                    SearchFilters(from_date="2024-01-01", size=2),
                ),
            ),
            ("KEV dump", _test_endpoint("KEV dump", client.get_kev_dump)),
        ]

        passed = sum(1 for _, ok in results if ok)
        total = len(results)
        console.print(f"\n{passed}/{total} tests passed.")

        if passed < total:
            console.print("[red]Failed tests:[/red]")
            for label, ok in results:
                if not ok:
                    console.print(f"  - {label}")

        return passed == total

    finally:
        client.close()


if __name__ == "__main__":
    import sys

    success = run_self_test()
    sys.exit(0 if success else 1)
