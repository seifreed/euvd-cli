<p align="center">
  <img src="https://img.shields.io/badge/EUVD--CLI-EU%20Vulnerability%20Database-003399?style=for-the-badge" alt="EUVD-CLI">
</p>

<h1 align="center">EUVD CLI</h1>

<p align="center">
  <strong>Query the ENISA EU Vulnerability Database (EUVD) from the command line and from Python</strong>
</p>

<p align="center">
  <a href="https://pypi.org/project/euvd-python-cli/"><img src="https://img.shields.io/pypi/v/euvd-python-cli?style=flat-square&logo=pypi&logoColor=white&cacheSeconds=3600" alt="PyPI Version"></a>
  <a href="https://pypi.org/project/euvd-python-cli/"><img src="https://img.shields.io/pypi/pyversions/euvd-python-cli?style=flat-square&logo=python&logoColor=white&cacheSeconds=3600" alt="Python Versions"></a>
  <a href="https://github.com/seifreed/euvd-cli/blob/main/LICENSE"><img src="https://img.shields.io/github/license/seifreed/euvd-cli?style=flat-square&cacheSeconds=3600" alt="License"></a>
  <a href="https://github.com/seifreed/euvd-cli/actions"><img src="https://img.shields.io/github/actions/workflow/status/seifreed/euvd-cli/ci.yml?style=flat-square&logo=github&label=CI&cacheSeconds=3600" alt="CI Status"></a>
  <a href="https://pypi.org/project/euvd-python-cli/"><img src="https://img.shields.io/pypi/dm/euvd-python-cli?style=flat-square&logo=pypi&logoColor=white&cacheSeconds=3600" alt="Downloads"></a>
</p>

## Overview

EUVD CLI is both a command-line tool and a Python library that fetches vulnerabilities, advisories, and KEV entries from the ENISA EU Vulnerability Database, validates the responses with Pydantic, and emits JSON or SARIF 2.1 output. The same client and validation rules apply when used as a library.

### Current feature set

| Area | Capabilities |
| --- | --- |
| Endpoints | latest, critical, exploited, ENISA ID lookup, advisory lookup, search, KEV dump |
| Search filters | `--text`, `--vendor`, `--product`, `--assigner`, `--from-score`/`--to-score` (0-10), `--from-epss`/`--to-epss` (0-100), `--from-date`/`--to-date` (YYYY-MM-DD), `--exploited`/`--not-exploited`, `--size` (1-100), `--page` |
| Output | JSON (default), JSONL, CSV, TOON, and SARIF 2.1, written to stdout cleanly for piping |
| Save to file | `--output <path>` and `--save` (timestamped filename) for `kev-dump`, with overwrite warning |
| Validation | CVSS/EPSS bounds, strict ISO date format, `from_X <= to_X` cross-pair, page-size cap enforced via Pydantic before the request |
| Streams | banner/status/errors on stderr, machine-readable data on stdout, no ANSI escapes in JSON output |
| Errors | typed exceptions (`API_ERRORS`, `SARIFConversionError`, OSError) handled with a single-line user message; SIGINT exits 130, SIGPIPE exits cleanly |
| Library API | `from euvd_python import EUVDAPIClient, SearchFilters, to_sarif_json, ...` (32 public symbols) |
| Resilience | client-side rate limiter (1 request / 6 s) and 30-second HTTP timeout (calibrated for slow `/search?text=` queries) |
| Self-test | 39-check regression suite against the live API (`euvd-cli selftest`) |

### Supported endpoints

| Path | Subcommand |
| --- | --- |
| `/lastvulnerabilities` | `latest` |
| `/criticalvulnerabilities` | `critical` |
| `/exploitedvulnerabilities` | `exploited` |
| `/enisaid?id=` | `search-enisa` |
| `/advisory?id=` | `search-advisory` |
| `/search` | `search` |
| `/kev/dump` | `kev-dump` |

Base URL: `https://euvdservices.enisa.europa.eu/api`.

## Installation

### From PyPI

```bash
pip install euvd-python-cli
```

### From source

```bash
git clone https://github.com/seifreed/euvd-cli.git
cd euvd-cli
python3 -m venv venv
source venv/bin/activate
pip install -e .
```

### Development

```bash
pip install -e ".[dev]"
```

## Quick start

```bash
euvd-cli latest
euvd-cli critical
euvd-cli exploited
euvd-cli search-enisa EUVD-2025-4893
euvd-cli search-advisory oxas-adv-2024-0002
euvd-cli search --text "OpenSSL" --from-score 7.0 --size 20
euvd-cli stats
euvd-cli kev-dump --save
euvd-cli --format sarif latest > latest.sarif.json
```

## CLI usage

### Inputs

```bash
euvd-cli latest
euvd-cli critical
euvd-cli exploited
euvd-cli search-enisa EUVD-2025-4893
euvd-cli search-advisory oxas-adv-2024-0002
euvd-cli kev-dump
```

### Search

```bash
euvd-cli search --text "Windows" --size 10
euvd-cli search --exploited --size 5
euvd-cli search --from-score 9.0 --to-score 10.0
euvd-cli search --from-date 2024-01-01 --to-date 2024-12-31
euvd-cli search --from-epss 50 --to-epss 100
```

### Output formats

The `--format` flag is on the group, before the subcommand. Supported: `json` (default, indented), `jsonl` (one JSON object per line), `csv`, `toon` ([Token-Oriented Object Notation](https://github.com/toon-format/toon)), `sarif` (SARIF 2.1).

```bash
euvd-cli --format json  latest
euvd-cli --format jsonl latest
euvd-cli --format csv   latest
euvd-cli --format toon  latest
euvd-cli --format sarif search-advisory oxas-adv-2024-0002
```

For `search`, the `jsonl` and `csv` formats emit only the `items` (the `total` wrapper is dropped because flat formats can't represent it).

### Save to file

```bash
euvd-cli kev-dump -o kev.json
euvd-cli kev-dump --save                           # kev_dump_YYYYMMDD_HHMMSS.json
euvd-cli --format sarif kev-dump -o kev.sarif.json
```

### Statistics and self-test

```bash
euvd-cli stats
euvd-cli selftest
```

### Common options

| Option | Meaning |
| --- | --- |
| `-v`, `--verbose` | Enable DEBUG logging (rate-limiter timing) |
| `--format json\|sarif` | Output format. Group-level flag, before the subcommand |
| `-h`, `--help` | Help. Works on the group and on every subcommand |
| `-o`, `--output <path>` | Save destination for `kev-dump` |
| `--save` | Save with auto-generated timestamped filename |

## Python library

```python
from euvd_python import EUVDAPIClient, SearchFilters, to_sarif_json

with EUVDAPIClient() as client:
    latest = client.get_latest_vulnerabilities()
    advisory = client.get_advisory_by_id("oxas-adv-2024-0002")
    results = client.search_vulnerabilities(
        SearchFilters(text="OpenSSL", from_score=7.0, size=20)
    )

sarif_json = to_sarif_json(latest)
```

The same validation rules apply: `SearchFilters` rejects out-of-range CVSS/EPSS, non-ISO dates, inverted ranges, and out-of-bounds size before the request is made.

### Public API

```python
from euvd_python import (
    EUVDAPIClient,
    RateLimiter,
    APIResponseError,
    API_ERRORS,
    SearchFilters,
    LatestVulnerability,
    CriticalVulnerability,
    ExploitedVulnerability,
    SearchResultVulnerability,
    ENISAVulnerabilityByID,
    VulnerabilityByID,
    AdvisoryByID,
    AdvisorySource,
    KevEntry,
    VulnerabilityQueryResponse,
    to_sarif_json,
    SARIFConversionError,
    CVSS_CRITICAL_THRESHOLD,
    CVSS_HIGH_THRESHOLD,
    CVSS_MEDIUM_THRESHOLD,
)
```

Importing `euvd_python` does not load Click, does not load `rich.console`, and does not install signal handlers. Those are only loaded by `euvd_python.cli` and `euvd_python.main`, which library users have no reason to import.

## Output notes

- JSON: pretty-printed with `indent=2`, written via `sys.stdout.write` so the output is pipe-safe and free of ANSI escapes.
- SARIF: SARIF 2.1 with stable rule deduplication, EPSS mapped to `rank` on the API's native 0-100 scale, severity derived from CVSS thresholds.
- Diagnostics (banner, "Fetching...", "Saved to...", error messages) all go to stderr so stdout stays parseable.
- Models preserve unknown wire fields via Pydantic `extra="allow"`, so future EUVD additions show up in JSON output without a code change.

## Validation

`SearchFilters` enforces all input invariants in one place:

| Field | Rule |
| --- | --- |
| `from_score`, `to_score` | float in `[0, 10]` |
| `from_epss`, `to_epss` | float in `[0, 100]` |
| `from_date`, `to_date` | string matching `^\d{4}-\d{2}-\d{2}$`, valid calendar date |
| `from_X`, `to_X` | `from_X <= to_X` |
| `size` | int in `[1, 100]` |
| `page` | int `>= 0` |

Invalid input prints `Invalid input: --<flag>: <reason>` to stderr and exits 1, before any HTTP request.

## Testing

```bash
euvd-cli selftest
```

The self-test hits the live EUVD API. There are no mocks — a passing self-test means real usage works against the real endpoints. CVSS/EPSS bounds, ISO date parsing, SARIF correctness, stream routing, signal handling, and library re-exports are all locked by synthetic checks within the same suite.

Quality gates run with default rules and zero suppressions:

```bash
black --check euvd_python/
ruff check euvd_python/
mypy euvd_python/
bandit -r euvd_python/
pip-audit -r requirements.txt
```

## License

MIT — see [LICENSE](LICENSE).

Author: Marc Rivero Lopez · mriverolopez@gmail.com
