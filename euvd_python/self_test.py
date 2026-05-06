from collections.abc import Callable
from typing import NamedTuple

from rich.console import Console

from .api_client import EUVDAPIClient

console = Console()


class EndpointTest(NamedTuple):
    label: str
    func: Callable[..., object]
    args: tuple[object, ...]
    kwargs: dict[str, object]


def _test_endpoint(
    label: str, func: Callable[..., object], *args: object, **kwargs: object
) -> bool:
    try:
        result = func(*args, **kwargs)
        if isinstance(result, list):
            console.print(f"[green]PASS[/green] {label} ({len(result)} items)")
        elif isinstance(result, dict):
            console.print(f"[green]PASS[/green] {label} ({result})")
        else:
            console.print(f"[green]PASS[/green] {label}")
        return True
    except Exception as e:
        console.print(f"[red]FAIL[/red] {label}: {e}")
        return False


def run_self_test() -> bool:
    client = EUVDAPIClient()
    results: list[tuple[str, bool]] = []

    try:
        console.print("Running self-test against official EUVD API endpoints...")

        tests: list[EndpointTest] = [
            EndpointTest(
                "Latest vulnerabilities", client.get_latest_vulnerabilities, (), {}
            ),
            EndpointTest(
                "Critical vulnerabilities", client.get_critical_vulnerabilities, (), {}
            ),
            EndpointTest(
                "Exploited vulnerabilities",
                client.get_exploited_vulnerabilities,
                (),
                {},
            ),
            EndpointTest(
                "ENISA ID search",
                client.get_vulnerability_by_enisa_id,
                ("EUVD-2025-4893",),
                {},
            ),
            EndpointTest(
                "Advisory ID search",
                client.get_advisory_by_id,
                ("oxas-adv-2024-0002",),
                {},
            ),
            EndpointTest(
                "Advanced search (text)",
                client.search_vulnerabilities,
                (),
                {"text": "vulnerability", "size": 2},
            ),
            EndpointTest(
                "Advanced search (exploited)",
                client.search_vulnerabilities,
                (),
                {"exploited": True, "size": 2},
            ),
            EndpointTest(
                "Advanced search (score filter)",
                client.search_vulnerabilities,
                (),
                {"from_score": 9.0, "size": 2},
            ),
            EndpointTest(
                "Advanced search (date filter)",
                client.search_vulnerabilities,
                (),
                {"from_date": "2024-01-01", "size": 2},
            ),
            EndpointTest("KEV dump", client.get_kev_dump, (), {}),
        ]

        for test in tests:
            results.append(
                (
                    test.label,
                    _test_endpoint(test.label, test.func, *test.args, **test.kwargs),
                )
            )

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
