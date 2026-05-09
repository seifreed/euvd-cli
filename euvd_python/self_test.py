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


def _assert_search_rejects_size_above_max() -> None:
    from click.testing import CliRunner

    from .cli import cli as cli_group

    result = CliRunner().invoke(cli_group, ["search", "--text", "x", "--size", "150"])
    if result.exit_code == 0:
        raise AssertionError(
            "search --size 150 should fail (max 100) instead of silently capping"
        )


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


def _assert_search_rejects_out_of_range_score() -> None:
    from click.testing import CliRunner

    from .cli import cli as cli_group

    result = CliRunner().invoke(
        cli_group, ["search", "--text", "x", "--from-score", "15"]
    )
    if result.exit_code == 0:
        raise AssertionError("search --from-score 15 should fail (out of 0-10 range)")


def _assert_search_rejects_bad_date_format() -> None:
    from click.testing import CliRunner

    from .cli import cli as cli_group

    result = CliRunner().invoke(
        cli_group, ["search", "--text", "x", "--from-date", "2024/01/01"]
    )
    if result.exit_code == 0:
        raise AssertionError(
            "search --from-date 2024/01/01 should fail (YYYY-MM-DD required)"
        )


def _assert_validation_error_formatted_compactly() -> None:
    from click.testing import CliRunner

    from .cli import cli as cli_group

    result = CliRunner().invoke(cli_group, ["search", "--text", "x", "--size", "0"])
    if result.exit_code == 0:
        raise AssertionError("expected non-zero exit on --size 0")
    if "pydantic.dev" in result.stderr:
        raise AssertionError(
            f"raw pydantic URL leaked to user output: {result.stderr!r}"
        )
    if "Invalid input" not in result.stderr:
        raise AssertionError(f"expected 'Invalid input' prefix; got: {result.stderr!r}")


def _assert_validation_error_uses_flag_form() -> None:
    from click.testing import CliRunner

    from .cli import cli as cli_group

    result = CliRunner().invoke(
        cli_group, ["search", "--text", "x", "--from-score", "15"]
    )
    if "--from-score" not in result.stderr:
        raise AssertionError(
            f"expected --from-score in error message; got: {result.stderr!r}"
        )


def _assert_search_rejects_inverted_date_range() -> None:
    from click.testing import CliRunner

    from .cli import cli as cli_group

    result = CliRunner().invoke(
        cli_group,
        [
            "search",
            "--text",
            "x",
            "--from-date",
            "2025-01-01",
            "--to-date",
            "2024-01-01",
        ],
    )
    if result.exit_code == 0:
        raise AssertionError(
            "search with from_date > to_date should fail before hitting API"
        )


def _assert_date_validator_strict_padding() -> None:
    from click.testing import CliRunner

    from .cli import cli as cli_group

    result = CliRunner().invoke(
        cli_group, ["search", "--text", "x", "--from-date", "2024-1-1"]
    )
    if result.exit_code == 0:
        raise AssertionError(
            "search --from-date 2024-1-1 should fail (strict YYYY-MM-DD padding)"
        )


def _assert_sigint_handler_bypasses_click() -> None:
    import signal

    from .main import _install_signal_handlers, _on_sigint

    # Install the handler in this process so getsignal observes it.
    _install_signal_handlers()
    installed = signal.getsignal(signal.SIGINT)
    if installed is not _on_sigint:
        raise AssertionError(
            f"_on_sigint not registered as SIGINT handler; got {installed!r}"
        )

    # The handler must raise SystemExit(130), not KeyboardInterrupt, so that
    # Click's `except KeyboardInterrupt` catch does not convert it to
    # "Aborted!" + exit 1.
    try:
        _on_sigint(signal.SIGINT, None)
    except SystemExit as exc:
        if exc.code != 130:
            raise AssertionError(f"expected exit 130, got {exc.code}")
        return
    except KeyboardInterrupt as exc:
        raise AssertionError(
            "handler raised KeyboardInterrupt; Click would convert to exit 1"
        ) from exc
    raise AssertionError("handler did not raise SystemExit")


def _assert_keyboard_interrupt_exits_130() -> None:
    from . import main as main_module

    original_cli = main_module.cli

    def _raise_keyboard_interrupt() -> None:
        raise KeyboardInterrupt

    setattr(main_module, "cli", _raise_keyboard_interrupt)
    try:
        try:
            main_module.main()
        except SystemExit as exc:
            if exc.code != 130:
                raise AssertionError(
                    f"expected exit 130 on KeyboardInterrupt, got {exc.code}"
                )
            return
        raise AssertionError("main() did not exit on KeyboardInterrupt")
    finally:
        setattr(main_module, "cli", original_cli)


def _assert_nested_validation_loc_formatted() -> None:
    from pydantic import BaseModel, ValidationError

    from .cli import _format_validation_error

    class _Inner(BaseModel):
        x: int

    class _Outer(BaseModel):
        inner: _Inner

    try:
        _Outer.model_validate({"inner": {"x": "not-int"}})
    except ValidationError as err:
        formatted = _format_validation_error(err)
    else:
        raise AssertionError("expected ValidationError for nested model")

    if "inner.x" not in formatted:
        raise AssertionError(
            f"nested loc not rendered as dotted path; got {formatted!r}"
        )
    if "--inner" in formatted:
        raise AssertionError(
            f"nested loc must not be prefixed with --; got {formatted!r}"
        )


def _assert_unknown_wire_fields_preserved() -> None:
    from .models import LatestVulnerability

    vuln = LatestVulnerability.model_validate(
        {"id": "EUVD-X", "futureField": "future-value", "epss": 1.0}
    )
    dump = vuln.model_dump(by_alias=True)
    if dump.get("futureField") != "future-value":
        raise AssertionError(
            f"unknown wire field dropped from model_dump; got {dump!r}"
        )


def _assert_oserror_handled_cleanly() -> None:
    from .cli import handle_cli_error

    @handle_cli_error
    def fail_with_oserror() -> None:
        raise FileNotFoundError(2, "No such file or directory", "bogus/path.json")

    err_buf = io.StringIO()
    raised: SystemExit | None = None
    with redirect_stderr(err_buf):
        try:
            fail_with_oserror()
        except SystemExit as exc:
            raised = exc
    if raised is None:
        raise AssertionError("handle_cli_error did not exit on OSError")
    if raised.code != 1:
        raise AssertionError(f"expected exit 1, got {raised.code}")
    if "FileNotFoundError" not in err_buf.getvalue():
        raise AssertionError(
            f"expected error name in stderr; got: {err_buf.getvalue()!r}"
        )


def _assert_save_warning_on_overwrite() -> None:
    import tempfile

    from .cli import _save_with_overwrite_warning

    with tempfile.NamedTemporaryFile(suffix=".json", mode="w", delete=False) as tmp:
        tmp.write("{}")
        tmp_path = tmp.name

    err_buf = io.StringIO()
    with redirect_stderr(err_buf):
        _save_with_overwrite_warning({"new": "data"}, "json", tmp_path)
    if "overwriting" not in err_buf.getvalue():
        raise AssertionError(f"expected overwrite warning; got: {err_buf.getvalue()!r}")


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
            "search rejects --size above max (no silent cap)",
            _assert_search_rejects_size_above_max,
        )
    )

    results.append(
        _check(
            "search rejects inverted --from-score/--to-score",
            _assert_search_rejects_inverted_score_range,
        )
    )

    results.append(
        _check(
            "search rejects --from-score out of 0-10 range",
            _assert_search_rejects_out_of_range_score,
        )
    )

    results.append(
        _check(
            "search rejects non-ISO --from-date format",
            _assert_search_rejects_bad_date_format,
        )
    )

    results.append(
        _check(
            "Validation errors formatted without pydantic.dev URL",
            _assert_validation_error_formatted_compactly,
        )
    )

    results.append(
        _check(
            "Validation error uses --kebab-case flag form",
            _assert_validation_error_uses_flag_form,
        )
    )

    results.append(
        _check(
            "search rejects inverted --from-date/--to-date",
            _assert_search_rejects_inverted_date_range,
        )
    )

    results.append(
        _check(
            "date validator rejects non-padded YYYY-M-D",
            _assert_date_validator_strict_padding,
        )
    )

    results.append(
        _check(
            "save warns when overwriting existing file",
            _assert_save_warning_on_overwrite,
        )
    )

    results.append(
        _check(
            "OSError handled cleanly (no traceback)",
            _assert_oserror_handled_cleanly,
        )
    )

    results.append(
        _check(
            "Unknown wire fields preserved in model_dump",
            _assert_unknown_wire_fields_preserved,
        )
    )

    results.append(
        _check(
            "Nested validation error rendered as dotted path",
            _assert_nested_validation_loc_formatted,
        )
    )

    results.append(
        _check(
            "KeyboardInterrupt exits 130 silently",
            _assert_keyboard_interrupt_exits_130,
        )
    )

    results.append(
        _check(
            "SIGINT handler bypasses Click and raises SystemExit(130)",
            _assert_sigint_handler_bypasses_click,
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
