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
python euvd-cli.py                          # interactive menu
python euvd-cli.py latest                    # latest vulnerabilities
python euvd-cli.py critical                  # critical vulnerabilities
python euvd-cli.py exploited                 # exploited vulnerabilities
python euvd-cli.py search-enisa EUVD-2025-4893
python euvd-cli.py search-advisory oxas-adv-2024-0002
python euvd-cli.py search --text "Windows" --size 10
python euvd-cli.py search --exploited true --size 5
python euvd-cli.py stats
python euvd-cli.py selftest
```

Search params: `--text`, `--vendor`, `--product`, `--assigner`, `--from-score`, `--to-score`, `--from-epss`, `--to-epss`, `--exploited`, `--size` (max 100).

Note: vendor, product, CVSS score filters may return 403 from the API.

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

## License

MIT

Author: Marc Rivero Lopez | mriverolopez@gmail.com