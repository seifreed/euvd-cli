import json
from collections.abc import Callable
from typing import Any

from .api_client import API_ERRORS, EUVDAPIClient
from .console import console
from .models import (
    AdvisoryByID,
    ENISAVulnerabilityByID,
    LatestVulnerability,
    SearchFilters,
)
from .sarif import SARIFConversionError, to_sarif_json

_TEST_ENISA_ID = "EUVD-2025-4893"
_TEST_ADVISORY_ID = "oxas-adv-2024-0002"


def _run_endpoint(
    label: str, func: Callable[..., object], *args: object, **kwargs: object
) -> tuple[str, bool, object | None]:
    try:
        result = func(*args, **kwargs)
        if isinstance(result, list):
            console.print(f"[green]PASS[/green] {label} ({len(result)} items)")
        else:
            console.print(f"[green]PASS[/green] {label}")
        return label, True, result
    except API_ERRORS as e:
        console.print(f"[red]FAIL[/red] {label}: {e}")
        return label, False, None


def _check(label: str, predicate: Callable[[], None]) -> tuple[str, bool]:
    try:
        predicate()
        console.print(f"[green]PASS[/green] {label}")
        return label, True
    except (AssertionError, TypeError, KeyError, ValueError) as e:
        console.print(f"[red]FAIL[/red] {label}: {e}")
        return label, False


def _assert_advisory_sarif_rule_id(advisory: AdvisoryByID, requested_id: str) -> None:
    sarif = json.loads(to_sarif_json(advisory))
    rule_id = sarif["runs"][0]["results"][0]["ruleId"]
    if rule_id != requested_id:
        raise AssertionError(f"expected ruleId={requested_id!r}, got {rule_id!r}")


def _assert_sarif_rules_unique(items: list[LatestVulnerability]) -> None:
    if not items:
        raise AssertionError("no items to validate SARIF rule uniqueness")
    sarif = json.loads(to_sarif_json(items))
    rules = sarif["runs"][0]["tool"]["driver"]["rules"]
    rule_ids = [r["id"] for r in rules]
    if len(rule_ids) != len(set(rule_ids)):
        raise AssertionError(f"duplicate rule ids: {rule_ids}")


def _assert_sarif_unsupported_raises() -> None:
    try:
        to_sarif_json({"not": "a model"})
    except SARIFConversionError:
        return
    raise AssertionError("expected SARIFConversionError for unsupported type")


def _assert_advisory_wire_id(advisory: AdvisoryByID, requested_id: str) -> None:
    if advisory.id != requested_id:
        raise AssertionError(
            f"advisory.id from wire != requested ({advisory.id!r} vs {requested_id!r})"
        )


def _assert_advisory_source_captured(advisory: AdvisoryByID) -> None:
    if advisory.source is None:
        raise AssertionError("advisory.source is None; expected populated from wire")
    if not advisory.source.name:
        raise AssertionError("advisory.source.name empty; expected populated from wire")


def _assert_enisa_vuln_cvss_metadata(vuln: ENISAVulnerabilityByID) -> None:
    if vuln.base_score_version is None:
        raise AssertionError("base_score_version is None; expected populated from wire")
    if vuln.base_score_vector is None:
        raise AssertionError("base_score_vector is None; expected populated from wire")


EndpointCall = tuple[str, Callable[..., object], tuple[Any, ...]]


def _build_endpoint_calls(client: EUVDAPIClient) -> list[EndpointCall]:
    return [
        ("Latest vulnerabilities", client.get_latest_vulnerabilities, ()),
        ("Critical vulnerabilities", client.get_critical_vulnerabilities, ()),
        ("Exploited vulnerabilities", client.get_exploited_vulnerabilities, ()),
        ("ENISA ID search", client.get_vulnerability_by_enisa_id, (_TEST_ENISA_ID,)),
        ("Advisory ID search", client.get_advisory_by_id, (_TEST_ADVISORY_ID,)),
        (
            "Advanced search (text)",
            client.search_vulnerabilities,
            (SearchFilters(text="vulnerability", size=2),),
        ),
        (
            "Advanced search (exploited)",
            client.search_vulnerabilities,
            (SearchFilters(exploited=True, size=2),),
        ),
        (
            "Advanced search (score filter)",
            client.search_vulnerabilities,
            (SearchFilters(from_score=9.0, size=2),),
        ),
        (
            "Advanced search (date filter)",
            client.search_vulnerabilities,
            (SearchFilters(from_date="2024-01-01", size=2),),
        ),
        ("KEV dump", client.get_kev_dump, ()),
    ]


def run_self_test() -> bool:
    console.print("Running self-test against official EUVD API endpoints...")

    results: list[tuple[str, bool]] = []
    captured: dict[str, object] = {}

    with EUVDAPIClient() as client:
        for label, func, args in _build_endpoint_calls(client):
            label, ok, value = _run_endpoint(label, func, *args)
            results.append((label, ok))
            if ok:
                captured[label] = value

    advisory = captured.get("Advisory ID search")
    if isinstance(advisory, AdvisoryByID):
        results.append(
            _check(
                "Advisory id populated from wire",
                lambda: _assert_advisory_wire_id(advisory, _TEST_ADVISORY_ID),
            )
        )
        results.append(
            _check(
                "Advisory source captured from wire",
                lambda: _assert_advisory_source_captured(advisory),
            )
        )
        results.append(
            _check(
                "SARIF advisory ruleId is requested id",
                lambda: _assert_advisory_sarif_rule_id(advisory, _TEST_ADVISORY_ID),
            )
        )

    enisa_vuln = captured.get("ENISA ID search")
    if isinstance(enisa_vuln, ENISAVulnerabilityByID):
        results.append(
            _check(
                "ENISA vulnerability CVSS metadata captured",
                lambda: _assert_enisa_vuln_cvss_metadata(enisa_vuln),
            )
        )

    latest = captured.get("Latest vulnerabilities")
    if isinstance(latest, list) and latest:
        results.append(
            _check(
                "SARIF rules deduplicated",
                lambda: _assert_sarif_rules_unique(latest),
            )
        )

    results.append(
        _check(
            "SARIF unsupported type raises SARIFConversionError",
            _assert_sarif_unsupported_raises,
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
