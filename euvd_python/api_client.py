import time
import logging
import requests
from typing import TypeVar, Type
from pydantic import BaseModel

from .models import (
    LatestVulnerability,
    ExploitedVulnerability,
    CriticalVulnerability,
    ENISAVulnerabilityByID,
    AdvisoryByID,
    VulnerabilityQueryResponse,
    KevEntry,
    VulnerabilityStats,
)
from . import __version__

T = TypeVar("T", bound=BaseModel)

logger = logging.getLogger(__name__)

RATE_LIMIT_INTERVAL = 6.0


class RateLimiter:
    def __init__(self, interval: float = RATE_LIMIT_INTERVAL):
        self.interval = interval
        self.last_request = 0.0

    def wait_if_needed(self):
        current_time = time.time()
        time_since_last = current_time - self.last_request

        if time_since_last < self.interval:
            sleep_time = self.interval - time_since_last
            logger.debug("Rate limiting: sleeping for %.2f seconds", sleep_time)
            time.sleep(sleep_time)

        self.last_request = time.time()


class EUVDAPIClient:
    BASE_URL = "https://euvdservices.enisa.europa.eu/api"
    TIMEOUT = 10.0

    def __init__(self):
        self.session = requests.Session()
        self.session.timeout = self.TIMEOUT
        self.rate_limiter = RateLimiter()
        self.session.headers.update({"User-Agent": f"EUVD-Python-CLI/{__version__}"})

    def _fetch(
        self, endpoint: str, params: dict[str, str] | None = None
    ) -> dict | list:
        self.rate_limiter.wait_if_needed()
        url = f"{self.BASE_URL}{endpoint}"
        response = self.session.get(url, params=params)
        response.raise_for_status()
        return response.json()

    def _request(
        self, endpoint: str, model_class: Type[T], params: dict[str, str] | None = None
    ) -> T:
        data = self._fetch(endpoint, params=params)
        return model_class.model_validate(data)

    def _request_list(self, endpoint: str, model_class: Type[T]) -> list[T]:
        data = self._fetch(endpoint)
        if not isinstance(data, list):
            raise ValueError(f"Expected list response, got {type(data)}")
        return [model_class.model_validate(item) for item in data]

    def get_latest_vulnerabilities(self) -> list[LatestVulnerability]:
        return self._request_list("/lastvulnerabilities", LatestVulnerability)

    def get_exploited_vulnerabilities(self) -> list[ExploitedVulnerability]:
        return self._request_list("/exploitedvulnerabilities", ExploitedVulnerability)

    def get_critical_vulnerabilities(self) -> list[CriticalVulnerability]:
        return self._request_list("/criticalvulnerabilities", CriticalVulnerability)

    def get_vulnerability_by_enisa_id(self, enisa_id: str) -> ENISAVulnerabilityByID:
        return self._request(
            "/enisaid", ENISAVulnerabilityByID, params={"id": enisa_id}
        )

    def get_advisory_by_id(self, advisory_id: str) -> AdvisoryByID:
        return self._request("/advisory", AdvisoryByID, params={"id": advisory_id})

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
        params: dict[str, str] = {}

        if from_score is not None:
            params["fromScore"] = str(from_score)
        if to_score is not None:
            params["toScore"] = str(to_score)
        if from_epss is not None:
            params["fromEpss"] = str(from_epss)
        if to_epss is not None:
            params["toEpss"] = str(to_epss)
        if from_date:
            params["fromDate"] = from_date
        if to_date:
            params["toDate"] = to_date
        if product:
            params["product"] = product
        if vendor:
            params["vendor"] = vendor
        if assigner:
            params["assigner"] = assigner
        if exploited is not None:
            params["exploited"] = str(exploited).lower()
        if text:
            params["text"] = text

        params["page"] = str(page)
        params["size"] = str(min(size, 100))

        return self._request("/search", VulnerabilityQueryResponse, params=params)

    def get_kev_dump(self) -> list[KevEntry]:
        return self._request_list("/kev/dump", KevEntry)

    def get_vulnerability_stats(self) -> VulnerabilityStats:
        return VulnerabilityStats(
            latest_count=len(self.get_latest_vulnerabilities()),
            critical_count=len(self.get_critical_vulnerabilities()),
            exploited_count=len(self.get_exploited_vulnerabilities()),
        )

    def close(self):
        self.session.close()
