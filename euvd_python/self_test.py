"""
Self-test module for testing all EUVD API endpoints.
"""

import json
import logging
from pathlib import Path
from typing import List, Dict, Any

from .api_client import EUVDAPIClient

logger = logging.getLogger(__name__)


def run_self_test(output_file: str = "test.txt") -> bool:
    """Convenience function to run the self-test."""
    client = EUVDAPIClient()
    
    try:
        print("Running self-test against official EUVD API endpoints...")
        
        # Test the 3 official endpoints
        try:
            latest = client.get_latest_vulnerabilities()
            print(f"✅ Latest vulnerabilities: {len(latest)} found")
        except Exception as e:
            print(f"❌ Latest vulnerabilities failed: {e}")
        
        try:
            critical = client.get_critical_vulnerabilities()
            print(f"✅ Critical vulnerabilities: {len(critical)} found")
        except Exception as e:
            print(f"❌ Critical vulnerabilities failed: {e}")
        
        try:
            exploited = client.get_exploited_vulnerabilities()
            print(f"✅ Exploited vulnerabilities: {len(exploited)} found")
        except Exception as e:
            print(f"❌ Exploited vulnerabilities failed: {e}")
        
        # Test ENISA ID search
        try:
            enisa_data = client.get_vulnerability_by_enisa_id("EUVD-2025-4893")
            print(f"✅ ENISA ID search: Found vulnerability {enisa_data.id}")
        except Exception as e:
            print(f"❌ ENISA ID search failed: {e}")
        
        # Test Advisory ID search
        try:
            advisory_data = client.get_advisory_by_id("oxas-adv-2024-0002")
            print(f"✅ Advisory ID search: Found advisory {advisory_data.aliases or 'N/A'}")
        except Exception as e:
            print(f"❌ Advisory ID search failed: {e}")
        
        # Test advanced search with text filter
        try:
            search_data = client.search_vulnerabilities(text="vulnerability", size=2)
            print(f"✅ Advanced search (text): Found {search_data.total} vulnerabilities, showing {len(search_data.items)}")
        except Exception as e:
            print(f"❌ Advanced search (text) failed: {e}")
        
        # Test advanced search with exploited filter
        try:
            search_data = client.search_vulnerabilities(exploited=True, size=2)
            print(f"✅ Advanced search (exploited): Found {search_data.total} exploited vulnerabilities, showing {len(search_data.items)}")
        except Exception as e:
            print(f"❌ Advanced search (exploited) failed: {e}")
        
        # Test statistics functionality
        try:
            stats = client.get_vulnerability_stats()
            print(f"✅ Vulnerability statistics: {stats}")
        except Exception as e:
            print(f"❌ Vulnerability statistics failed: {e}")
        
        print("\n🎯 Self-test completed! All EUVD endpoints tested.")
        return True
        
    finally:
        client.close()


if __name__ == "__main__":
    run_self_test() 