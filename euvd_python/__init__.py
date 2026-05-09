from importlib.metadata import PackageNotFoundError, version

# Single source of truth for the version is setup.py (and the wheel/dist
# metadata produced from it). Reading it at runtime via importlib.metadata
# keeps the banner honest about what is actually installed; falls back to
# a sentinel when running from a non-installed checkout.
__version__: str
try:
    __version__ = version("euvd-python-cli")
except PackageNotFoundError:
    __version__ = "0.0.0+unknown"

from .api_client import (
    API_ERRORS,
    APIResponseError,
    EUVDAPIClient,
    RATE_LIMIT_INTERVAL,
    RateLimiter,
)
from .models import (
    CVSS_CRITICAL_THRESHOLD,
    CVSS_HIGH_THRESHOLD,
    CVSS_MEDIUM_THRESHOLD,
    AdvisoryByID,
    AdvisorySource,
    CriticalVulnerability,
    ENISAAdvisoryWrapper,
    ENISAVulnerability,
    ENISAVulnerabilityByID,
    ENISAVulnWrapper,
    EnisaProductInfo,
    EnisaVendorInfo,
    ExploitedVulnerability,
    KevEntry,
    LatestVulnerability,
    ProductName,
    SearchFilters,
    SearchResultVulnerability,
    VendorName,
    VulnerabilityAdvisory,
    VulnerabilityBase,
    VulnerabilityByID,
    VulnerabilityCore,
    VulnerabilityQueryResponse,
)
from .sarif import SARIFConversionError, to_sarif_json

__all__ = [
    "__version__",
    # client
    "EUVDAPIClient",
    "RateLimiter",
    "RATE_LIMIT_INTERVAL",
    "APIResponseError",
    "API_ERRORS",
    # search input
    "SearchFilters",
    # response models (top-level)
    "AdvisoryByID",
    "ENISAVulnerabilityByID",
    "KevEntry",
    "LatestVulnerability",
    "CriticalVulnerability",
    "ExploitedVulnerability",
    "SearchResultVulnerability",
    "VulnerabilityByID",
    "VulnerabilityQueryResponse",
    # response models (nested)
    "AdvisorySource",
    "ENISAAdvisoryWrapper",
    "ENISAVulnerability",
    "ENISAVulnWrapper",
    "EnisaProductInfo",
    "EnisaVendorInfo",
    "ProductName",
    "VendorName",
    "VulnerabilityAdvisory",
    "VulnerabilityBase",
    "VulnerabilityCore",
    # SARIF
    "to_sarif_json",
    "SARIFConversionError",
    # domain thresholds
    "CVSS_CRITICAL_THRESHOLD",
    "CVSS_HIGH_THRESHOLD",
    "CVSS_MEDIUM_THRESHOLD",
]
