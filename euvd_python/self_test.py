from .api_client import EUVDAPIClient


def _test_endpoint(label: str, func, *args, **kwargs) -> bool:
    try:
        result = func(*args, **kwargs)
        if isinstance(result, list):
            print(f"PASS {label} ({len(result)} items)")
        elif isinstance(result, dict):
            print(f"PASS {label} ({result})")
        else:
            print(f"PASS {label}")
        return True
    except Exception as e:
        print(f"FAIL {label}: {e}")
        return False


def run_self_test() -> bool:
    client = EUVDAPIClient()
    results: list[bool] = []

    try:
        print("Running self-test against official EUVD API endpoints...")

        results.append(
            _test_endpoint("Latest vulnerabilities", client.get_latest_vulnerabilities)
        )
        results.append(
            _test_endpoint(
                "Critical vulnerabilities", client.get_critical_vulnerabilities
            )
        )
        results.append(
            _test_endpoint(
                "Exploited vulnerabilities", client.get_exploited_vulnerabilities
            )
        )
        results.append(
            _test_endpoint(
                "ENISA ID search",
                client.get_vulnerability_by_enisa_id,
                "EUVD-2025-4893",
            )
        )
        results.append(
            _test_endpoint(
                "Advisory ID search",
                client.get_advisory_by_id,
                "oxas-adv-2024-0002",
            )
        )
        results.append(
            _test_endpoint(
                "Advanced search (text)",
                client.search_vulnerabilities,
                text="vulnerability",
                size=2,
            )
        )
        results.append(
            _test_endpoint(
                "Advanced search (exploited)",
                client.search_vulnerabilities,
                exploited=True,
                size=2,
            )
        )
        results.append(
            _test_endpoint(
                "Advanced search (score filter)",
                client.search_vulnerabilities,
                from_score=9.0,
                size=2,
            )
        )
        results.append(
            _test_endpoint(
                "Advanced search (date filter)",
                client.search_vulnerabilities,
                from_date="2024-01-01",
                size=2,
            )
        )
        results.append(_test_endpoint("KEV dump", client.get_kev_dump))

        passed = sum(results)
        total = len(results)
        print(f"\n{passed}/{total} tests passed.")

        if passed < total:
            print("Failed tests:")
            labels = [
                "Latest vulnerabilities",
                "Critical vulnerabilities",
                "Exploited vulnerabilities",
                "ENISA ID search",
                "Advisory ID search",
                "Advanced search (text)",
                "Advanced search (exploited)",
                "Advanced search (score filter)",
                "Advanced search (date filter)",
                "KEV dump",
            ]
            for label, result in zip(labels, results):
                if not result:
                    print(f"  - {label}")

        return passed == total

    finally:
        client.close()


if __name__ == "__main__":
    import sys

    success = run_self_test()
    sys.exit(0 if success else 1)
