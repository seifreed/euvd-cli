# EUVD Python CLI

CLI for the ENISA EU Vulnerability Database (EUVD) API. Python >=3.13.

## Install

```bash
git clone https://github.com/seifreed/euvd-cli
cd euvd-cli
python -m venv venv
source venv/bin/activate
pip install -r requirements.txt
pip install -e .
```

## Usage

```bash
python euvd-cli.py latest                    # latest vulnerabilities
python euvd-cli.py critical                  # critical vulnerabilities
python euvd-cli.py exploited                 # exploited vulnerabilities
python euvd-cli.py search-enisa EUVD-2025-4893
python euvd-cli.py search-advisory oxas-adv-2024-0002
python euvd-cli.py search --text "Windows" --size 10
python euvd-cli.py search --exploited --size 5
python euvd-cli.py stats
python euvd-cli.py kev-dump
python euvd-cli.py kev-dump --save
python euvd-cli.py kev-dump -o kev.json
python euvd-cli.py selftest
```

Search params: `--text`, `--vendor`, `--product`, `--assigner`, `--from-score`, `--to-score`, `--from-epss`, `--to-epss`, `--from-date`, `--to-date`, `--exploited/--not-exploited`, `--size` (max 100), `--page`.

Output format (group-level flag, before the subcommand): `--format json` (default) or `--format sarif`.

```bash
python euvd-cli.py --format sarif latest
python euvd-cli.py --format sarif search-advisory oxas-adv-2024-0002
```

Note: vendor, product, CVSS score filters may return 403 from the API.

## As a library

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

The same rate limiter (1 request / 6s) and validation rules (`SearchFilters` enforces score 0-10, EPSS 0-100, ISO dates, `from_X <= to_X`) apply when used as a library.

## API

Base URL: `https://euvdservices.enisa.europa.eu/api`

| Endpoint | Description |
|----------|-------------|
| `/lastvulnerabilities` | Latest vulnerabilities |
| `/criticalvulnerabilities` | Critical vulnerabilities |
| `/exploitedvulnerabilities` | Exploited vulnerabilities |
| `/enisaid?id=` | Search by ENISA ID |
| `/advisory?id=` | Search by Advisory ID |
| `/search` | Search with filters |
| `/kev/dump` | KEV catalog dump |

## License

MIT

Author: Marc Rivero Lopez | mriverolopez@gmail.com