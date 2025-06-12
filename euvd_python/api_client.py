"""
API Client for EUVD API with rate limiting and error handling.
"""

import time
import logging
import requests
from typing import TypeVar, Type, List, Union
from urllib.parse import urljoin, quote
from pydantic import BaseModel, ValidationError

from .models import (
    LatestVulnerability,
    ExploitedVulnerability,
    CriticalVulnerability,
    ENISAVulnerabilityByID,
    AdvisoryByID,
    VulnerabilityQueryResponse
)

T = TypeVar('T', bound=BaseModel)

logger = logging.getLogger(__name__)


class RateLimiter:
    """Simple rate limiter to ensure 1 request per 6 seconds."""
    
    def __init__(self, interval: float = 6.0):
        self.interval = interval
        self.last_request = 0.0
    
    def wait_if_needed(self):
        """Wait if needed to respect rate limit."""
        current_time = time.time()
        time_since_last = current_time - self.last_request
        
        if time_since_last < self.interval:
            sleep_time = self.interval - time_since_last
            logger.debug(f"Rate limiting: sleeping for {sleep_time:.2f} seconds")
            time.sleep(sleep_time)
        
        self.last_request = time.time()


class EUVDAPIClient:
    """
    Client for interacting with the ENISA EUVD API.
    Includes automatic rate limiting and error handling.
    """
    
    BASE_URL = "https://euvdservices.enisa.europa.eu/api"
    TIMEOUT = 10.0
    
    def __init__(self):
        self.session = requests.Session()
        self.session.timeout = self.TIMEOUT
        self.rate_limiter = RateLimiter()
        
        # Set user agent
        self.session.headers.update({
            'User-Agent': 'EUVD-Python-CLI/1.0.0'
        })
    
    def _make_request(self, endpoint: str, model_class: Type[T]) -> T:
        """Make a rate-limited request to the API."""
        self.rate_limiter.wait_if_needed()
        
        # Ensure proper URL construction
        url = f"{self.BASE_URL}{endpoint}"
        logger.debug(f"Making request to: {url}")
        
        try:
            response = self.session.get(url)
            response.raise_for_status()
            
            data = response.json()
            return model_class.model_validate(data)
            
        except requests.exceptions.RequestException as e:
            logger.error(f"HTTP error for {url}: {e}")
            raise
        except ValidationError as e:
            logger.error(f"Data validation error for {url}: {e}")
            raise
        except Exception as e:
            logger.error(f"Unexpected error for {url}: {e}")
            raise
    
    def _make_list_request(self, endpoint: str, model_class: Type[T]) -> List[T]:
        """Make a rate-limited request that returns a list."""
        self.rate_limiter.wait_if_needed()
        
        # Ensure proper URL construction
        url = f"{self.BASE_URL}{endpoint}"
        logger.debug(f"Making list request to: {url}")
        
        try:
            response = self.session.get(url)
            response.raise_for_status()
            
            data = response.json()
            if not isinstance(data, list):
                raise ValueError(f"Expected list response, got {type(data)}")
            
            return [model_class.model_validate(item) for item in data]
            
        except requests.exceptions.RequestException as e:
            logger.error(f"HTTP error for {url}: {e}")
            raise
        except ValidationError as e:
            logger.error(f"Data validation error for {url}: {e}")
            raise
        except Exception as e:
            logger.error(f"Unexpected error for {url}: {e}")
            raise
    
    def get_latest_vulnerabilities(self) -> List[LatestVulnerability]:
        """Fetch latest vulnerabilities."""
        return self._make_list_request("/lastvulnerabilities", LatestVulnerability)
    
    def get_exploited_vulnerabilities(self) -> List[ExploitedVulnerability]:
        """Fetch exploited vulnerabilities."""
        return self._make_list_request("/exploitedvulnerabilities", ExploitedVulnerability)
    
    def get_critical_vulnerabilities(self) -> List[CriticalVulnerability]:
        """Fetch critical vulnerabilities."""
        return self._make_list_request("/criticalvulnerabilities", CriticalVulnerability)
    
    def get_vulnerability_by_enisa_id(self, enisa_id: str) -> ENISAVulnerabilityByID:
        """Fetch vulnerability by ENISA ID."""
        endpoint = f"/enisaid?id={quote(enisa_id)}"
        return self._make_request(endpoint, ENISAVulnerabilityByID)
    
    def get_advisory_by_id(self, advisory_id: str) -> AdvisoryByID:
        """Fetch advisory by ID."""
        endpoint = f"/advisory?id={quote(advisory_id)}"
        return self._make_request(endpoint, AdvisoryByID)
    
    def search_vulnerabilities(self, 
                                 from_score: float = None,
                                 to_score: float = None,
                                 from_epss: float = None,
                                 to_epss: float = None,
                                 from_date: str = None,
                                 to_date: str = None,
                                 product: str = None,
                                 vendor: str = None,
                                 assigner: str = None,
                                 exploited: bool = None,
                                 text: str = None,
                                 page: int = 0,
                                 size: int = 10) -> VulnerabilityQueryResponse:
        """
        Search vulnerabilities with flexible filters using /api/search endpoint.
        
        Args:
            from_score: Minimum CVSS score (0-10)
            to_score: Maximum CVSS score (0-10)
            from_epss: Minimum EPSS score (0-100)
            to_epss: Maximum EPSS score (0-100)
            from_date: Start date (YYYY-MM-DD)
            to_date: End date (YYYY-MM-DD)
            product: Product name filter
            vendor: Vendor name filter
            assigner: Assigner filter
            exploited: Filter by exploitation status (true/false)
            text: Text search keywords
            page: Page number (starts at 0)
            size: Results per page (max 100)
        """
        params = []
        
        if from_score is not None:
            params.append(f"fromScore={from_score}")
        if to_score is not None:
            params.append(f"toScore={to_score}")
        if from_epss is not None:
            params.append(f"fromEpss={from_epss}")
        if to_epss is not None:
            params.append(f"toEpss={to_epss}")
        if from_date:
            params.append(f"fromDate={from_date}")
        if to_date:
            params.append(f"toDate={to_date}")
        if product:
            params.append(f"product={quote(product)}")
        if vendor:
            params.append(f"vendor={quote(vendor)}")
        if assigner:
            params.append(f"assigner={quote(assigner)}")
        if exploited is not None:
            params.append(f"exploited={str(exploited).lower()}")
        if text:
            params.append(f"text={quote(text)}")
        
        params.append(f"page={page}")
        params.append(f"size={min(size, 100)}")  # Ensure max 100
        
        endpoint = f"/search?{'&'.join(params)}"
        return self._make_request(endpoint, VulnerabilityQueryResponse)
    
    def get_vulnerability_stats(self) -> dict:
        """Get basic statistics about vulnerabilities."""
        stats = {}
        try:
            latest = self.get_latest_vulnerabilities()
            stats['latest_count'] = len(latest)
        except Exception as e:
            stats['latest_count'] = f"Error: {e}"
        
        try:
            critical = self.get_critical_vulnerabilities()
            stats['critical_count'] = len(critical)
        except Exception as e:
            stats['critical_count'] = f"Error: {e}"
        
        try:
            exploited = self.get_exploited_vulnerabilities()
            stats['exploited_count'] = len(exploited)
        except Exception as e:
            stats['exploited_count'] = f"Error: {e}"
        
        return stats
    
    def close(self):
        """Close the session."""
        self.session.close() 