import io
import json
from collections.abc import Callable
from contextlib import redirect_stderr, redirect_stdout
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


def _assert_banner_to_stderr() -> None:
    from .cli import print_banner

    out_buf, err_buf = io.StringIO(), io.StringIO()
    with redirect_stdout(out_buf), redirect_stderr(err_buf):
        print_banner()
    if "EUVD Python CLI" in out_buf.getvalue():
        raise AssertionError("banner leaked to stdout; breaks JSON piping")
    if "EUVD Python CLI" not in err_buf.getvalue():
        raise AssertionError(f"banner missing from stderr; got {err_buf.getvalue()!r}")


def _assert_error_to_stderr() -> None:
    from .cli import _exit_with_error

    out_buf, err_buf = io.StringIO(), io.StringIO()
    marker = "regression_marker_xyz"
    with redirect_stdout(out_buf), redirect_stderr(err_buf):
        try:
            _exit_with_error(marker)
        except SystemExit:
            pass
    if marker in out_buf.getvalue():
        raise AssertionError("error message leaked to stdout")
    if marker not in err_buf.getvalue():
        raise AssertionError(
            f"error message missing from stderr; got {err_buf.getvalue()!r}"
        )


def _assert_print_data_clean_stdout() -> None:
    from .output import print_data

    buf = io.StringIO()
    with redirect_stdout(buf):
        print_data({"hello": "world", "n": 1}, "json")
    out = buf.getvalue()
    if "\x1b[" in out:
        raise AssertionError("ANSI escape detected in JSON stdout output")
    json.loads(out)


def _assert_subcommand_short_help_flag() -> None:
    from click.testing import CliRunner

    from .cli import cli as cli_group

    result = CliRunner().invoke(cli_group, ["latest", "-h"])
    if result.exit_code != 0:
        raise AssertionError(
            f"latest -h failed (exit={result.exit_code}); -h must propagate to subcommands"
        )
    if "Show latest vulnerabilities" not in result.output:
        raise AssertionError(
            f"subcommand help missing description; got: {result.output!r}"
        )


def _assert_sarif_rank_not_scaled() -> None:
    from .models import LatestVulnerability

    vuln = LatestVulnerability(id="EPSS-RANK-TEST", epss=64.28)
    sarif = json.loads(to_sarif_json(vuln))
    rank = sarif["runs"][0]["results"][0].get("rank")
    if rank != 64.28:
        raise AssertionError(
            f"SARIF rank should equal epss without scaling; got {rank}"
        )


def _assert_search_rejects_size_zero() -> None:
    from click.testing import CliRunner

    from .cli import cli as cli_group

    result = CliRunner().invoke(cli_group, ["search", "--text", "x", "--size", "0"])
    if result.exit_code == 0:
        raise AssertionError("search --size 0 should fail before hitting API")


def _assert_search_rejects_inverted_score_range() -> None:
    from click.testing import CliRunner

    from .cli import cli as cli_group

    result = CliRunner().invoke(
        cli_group,
        ["search", "--text", "x", "--from-score", "9", "--to-score", "5"],
    )
    if result.exit_code == 0:
        raise AssertionError(
            "search --from-score 9 --to-score 5 should fail before hitting API"
        )


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


def _assert_nested_vuln_data_processed(vuln: ENISAVulnerabilityByID) -> None:
    if not vuln.enisa_id_vulnerability:
        raise AssertionError(
            "enisa_id_vulnerability empty; cannot validate nested data_processed"
        )
    nested = vuln.enisa_id_vulnerability[0].vulnerability
    if nested.data_processed is None:
        raise AssertionError(
            "nested vulnerability.data_processed is None; expected populated from wire"
        )


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
        results.append(
            _check(
                "Nested vulnerability data_processed captured",
                lambda: _assert_nested_vuln_data_processed(enisa_vuln),
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

    results.append(
        _check(
            "Banner routes to stderr (preserves stdout for piping)",
            _assert_banner_to_stderr,
        )
    )

    results.append(
        _check(
            "Error messages route to stderr",
            _assert_error_to_stderr,
        )
    )

    results.append(
        _check(
            "JSON stdout is clean (no ANSI escapes)",
            _assert_print_data_clean_stdout,
        )
    )

    results.append(
        _check(
            "-h works on subcommand and shows description",
            _assert_subcommand_short_help_flag,
        )
    )

    results.append(
        _check(
            "SARIF rank equals epss without 100x scaling",
            _assert_sarif_rank_not_scaled,
        )
    )

    results.append(
        _check(
            "search rejects --size 0 before API call",
            _assert_search_rejects_size_zero,
        )
    )

    results.append(
        _check(
            "search rejects inverted --from-score/--to-score",
            _assert_search_rejects_inverted_score_range,
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
