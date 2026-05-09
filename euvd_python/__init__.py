from importlib.metadata import PackageNotFoundError, version

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
    "EUVDAPIClient",
    "RateLimiter",
    "RATE_LIMIT_INTERVAL",
    "APIResponseError",
    "API_ERRORS",
    "SearchFilters",
    "AdvisoryByID",
    "ENISAVulnerabilityByID",
    "KevEntry",
    "LatestVulnerability",
    "CriticalVulnerability",
    "ExploitedVulnerability",
    "SearchResultVulnerability",
    "VulnerabilityByID",
    "VulnerabilityQueryResponse",
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
    "to_sarif_json",
    "SARIFConversionError",
    "CVSS_CRITICAL_THRESHOLD",
    "CVSS_HIGH_THRESHOLD",
    "CVSS_MEDIUM_THRESHOLD",
]
