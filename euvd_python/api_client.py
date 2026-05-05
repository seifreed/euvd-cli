"""
API Client for EUVD API with rate limiting and error handling.
"""

import time
import logging
import requests
from typing import TypeVar, Type
from urllib.parse import quote
from pydantic import BaseModel, ValidationError

from .models import (
    LatestVulnerability,
    ExploitedVulnerability,
    CriticalVulnerability,
    ENISAVulnerabilityByID,
    AdvisoryByID,
    VulnerabilityQueryResponse,
)

T = TypeVar("T", bound=BaseModel)

logger = logging.getLogger(__name__)


class RateLimiter:
    def __init__(self, interval: float = 6.0):
        self.interval = interval
        self.last_request = 0.0

    def wait_if_needed(self):
        current_time = time.time()
        time_since_last = current_time - self.last_request

        if time_since_last < self.interval:
            sleep_time = self.interval - time_since_last
            logger.debug(f"Rate limiting: sleeping for {sleep_time:.2f} seconds")
            time.sleep(sleep_time)

        self.last_request = time.time()


class EUVDAPIClient:
    BASE_URL = "https://euvdservices.enisa.europa.eu/api"
    TIMEOUT = 10.0

    def __init__(self):
        self.session = requests.Session()
        self.session.timeout = self.TIMEOUT
        self.rate_limiter = RateLimiter()
        self.session.headers.update({"User-Agent": "EUVD-Python-CLI/1.0.0"})

    def _request(self, endpoint: str, model_class: Type[T]) -> T:
        self.rate_limiter.wait_if_needed()

        url = f"{self.BASE_URL}{endpoint}"
        logger.debug(f"Making request to: {url}")

        try:
            response = self.session.get(url)
            response.raise_for_status()
            return model_class.model_validate(response.json())
        except requests.exceptions.RequestException as e:
            logger.error(f"HTTP error for {url}: {e}")
            raise
        except ValidationError as e:
            logger.error(f"Data validation error for {url}: {e}")
            raise

    def _request_list(self, endpoint: str, model_class: Type[T]) -> list[T]:
        self.rate_limiter.wait_if_needed()

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

    def get_latest_vulnerabilities(self) -> list[LatestVulnerability]:
        return self._request_list("/lastvulnerabilities", LatestVulnerability)

    def get_exploited_vulnerabilities(self) -> list[ExploitedVulnerability]:
        return self._request_list("/exploitedvulnerabilities", ExploitedVulnerability)

    def get_critical_vulnerabilities(self) -> list[CriticalVulnerability]:
        return self._request_list("/criticalvulnerabilities", CriticalVulnerability)

    def get_vulnerability_by_enisa_id(self, enisa_id: str) -> ENISAVulnerabilityByID:
        endpoint = f"/enisaid?id={quote(enisa_id)}"
        return self._request(endpoint, ENISAVulnerabilityByID)

    def get_advisory_by_id(self, advisory_id: str) -> AdvisoryByID:
        endpoint = f"/advisory?id={quote(advisory_id)}"
        return self._request(endpoint, AdvisoryByID)

    def search_vulnerabilities(
        self,
        from_score: float | None = None,
        to_score: float | None = None,
        from_epss: float | None = None,
        to_epss: float | None = None,
        from_date: str | None = None,
        to_date: str | None = None,
        product: str | None = None,
        vendor: str | None = None,
        assigner: str | None = None,
        exploited: bool | None = None,
        text: str | None = None,
        page: int = 0,
        size: int = 10,
    ) -> VulnerabilityQueryResponse:
        params: list[str] = []

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
        params.append(f"size={min(size, 100)}")

        endpoint = f"/search?{'&'.join(params)}"
        return self._request(endpoint, VulnerabilityQueryResponse)

    def get_vulnerability_stats(self) -> dict[str, int]:
        return {
            "latest_count": len(self.get_latest_vulnerabilities()),
            "critical_count": len(self.get_critical_vulnerabilities()),
            "exploited_count": len(self.get_exploited_vulnerabilities()),
        }

    def close(self):
        self.session.close()
