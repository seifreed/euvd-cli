from collections.abc import Callable

import requests.exceptions
from pydantic import ValidationError

from .api_client import APIResponseError, EUVDAPIClient
from .console import console
from .models import SearchFilters

_TEST_ENISA_ID = "EUVD-2025-4893"
_TEST_ADVISORY_ID = "oxas-adv-2024-0002"


def _test_endpoint(
    label: str, func: Callable[..., object], *args: object, **kwargs: object
) -> tuple[str, bool]:
    try:
        result = func(*args, **kwargs)
        if isinstance(result, list):
            console.print(f"[green]PASS[/green] {label} ({len(result)} items)")
        else:
            console.print(f"[green]PASS[/green] {label}")
        return label, True
    except (requests.RequestException, ValidationError, APIResponseError) as e:
        console.print(f"[red]FAIL[/red] {label}: {e}")
        return label, False


def run_self_test() -> bool:
    console.print("Running self-test against official EUVD API endpoints...")

    with EUVDAPIClient() as client:
        results = [
            _test_endpoint("Latest vulnerabilities", client.get_latest_vulnerabilities),
            _test_endpoint(
                "Critical vulnerabilities", client.get_critical_vulnerabilities
            ),
            _test_endpoint(
                "Exploited vulnerabilities", client.get_exploited_vulnerabilities
            ),
            _test_endpoint(
                "ENISA ID search",
                client.get_vulnerability_by_enisa_id,
                _TEST_ENISA_ID,
            ),
            _test_endpoint(
                "Advisory ID search",
                client.get_advisory_by_id,
                _TEST_ADVISORY_ID,
            ),
            _test_endpoint(
                "Advanced search (text)",
                client.search_vulnerabilities,
                SearchFilters(text="vulnerability", size=2),
            ),
            _test_endpoint(
                "Advanced search (exploited)",
                client.search_vulnerabilities,
                SearchFilters(exploited=True, size=2),
            ),
            _test_endpoint(
                "Advanced search (score filter)",
                client.search_vulnerabilities,
                SearchFilters(from_score=9.0, size=2),
            ),
            _test_endpoint(
                "Advanced search (date filter)",
                client.search_vulnerabilities,
                SearchFilters(from_date="2024-01-01", size=2),
            ),
            _test_endpoint("KEV dump", client.get_kev_dump),
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
