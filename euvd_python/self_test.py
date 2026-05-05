from .api_client import EUVDAPIClient


def _test_endpoint(label: str, func, *args, **kwargs) -> bool:
    try:
        func(*args, **kwargs)
        print(f"PASS {label}")
        return True
    except Exception as e:
        print(f"FAIL {label}: {e}")
        return False


def run_self_test() -> bool:
    client = EUVDAPIClient()

    try:
        print("Running self-test against official EUVD API endpoints...")

        _test_endpoint("Latest vulnerabilities", client.get_latest_vulnerabilities)
        _test_endpoint("Critical vulnerabilities", client.get_critical_vulnerabilities)
        _test_endpoint(
            "Exploited vulnerabilities", client.get_exploited_vulnerabilities
        )
        _test_endpoint(
            "ENISA ID search", client.get_vulnerability_by_enisa_id, "EUVD-2025-4893"
        )
        _test_endpoint(
            "Advisory ID search", client.get_advisory_by_id, "oxas-adv-2024-0002"
        )
        _test_endpoint(
            "Advanced search (text)",
            client.search_vulnerabilities,
            text="vulnerability",
            size=2,
        )
        _test_endpoint(
            "Advanced search (exploited)",
            client.search_vulnerabilities,
            exploited=True,
            size=2,
        )
        _test_endpoint("Vulnerability statistics", client.get_vulnerability_stats)

        print("\nSelf-test completed.")
        return True

    finally:
        client.close()


if __name__ == "__main__":
    run_self_test()
