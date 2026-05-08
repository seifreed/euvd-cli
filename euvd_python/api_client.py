import time
import logging
import requests
import requests.exceptions
from typing import TypeVar, Type
from pydantic import BaseModel, ValidationError

from .models import (
    LatestVulnerability,
    ExploitedVulnerability,
    CriticalVulnerability,
    ENISAVulnerabilityByID,
    AdvisoryByID,
    VulnerabilityQueryResponse,
    KevEntry,
    SearchFilters,
)
from . import __version__

T = TypeVar("T", bound=BaseModel)

logger = logging.getLogger(__name__)

RATE_LIMIT_INTERVAL = 6.0
MAX_PAGE_SIZE = 100

_PARAM_ALIASES = {
    "from_score": "fromScore",
    "to_score": "toScore",
    "from_epss": "fromEpss",
    "to_epss": "toEpss",
    "from_date": "fromDate",
    "to_date": "toDate",
}


def _build_search_params(filters: SearchFilters) -> dict[str, str]:
    params = filters.model_dump(exclude_none=True)
    result: dict[str, str] = {}
    for key, value in params.items():
        api_key = _PARAM_ALIASES.get(key, key)
        if isinstance(value, bool):
            result[api_key] = str(value).lower()
        else:
            result[api_key] = str(value)
    result["size"] = str(min(filters.size, MAX_PAGE_SIZE))
    return result


class APIResponseError(Exception):
    pass


API_ERRORS = (requests.RequestException, ValidationError, APIResponseError)


class RateLimiter:
    def __init__(self, interval: float = RATE_LIMIT_INTERVAL):
        self.interval = interval
        self.last_request = 0.0

    def wait_if_needed(self) -> None:
        current_time = time.time()
        time_since_last = max(0.0, current_time - self.last_request)

        if time_since_last < self.interval:
            sleep_time = self.interval - time_since_last
            logger.debug("Rate limiting: sleeping for %.2f seconds", sleep_time)
            time.sleep(sleep_time)

        self.last_request = time.time()


class EUVDAPIClient:
    DEFAULT_BASE_URL = "https://euvdservices.enisa.europa.eu/api"
    DEFAULT_TIMEOUT = 10.0

    def __init__(
        self,
        base_url: str = DEFAULT_BASE_URL,
        timeout: float = DEFAULT_TIMEOUT,
    ):
        self.base_url = base_url
        self.timeout = timeout
        self.session = requests.Session()
        self.rate_limiter = RateLimiter()
        self.session.headers.update({"User-Agent": f"EUVD-Python-CLI/{__version__}"})

    def _get_json(
        self, endpoint: str, params: dict[str, str] | None = None
    ) -> dict | list:
        self.rate_limiter.wait_if_needed()
        url = f"{self.base_url}{endpoint}"
        response = self.session.get(url, params=params, timeout=self.timeout)
        response.raise_for_status()
        return response.json()

    def _get_model(
        self, endpoint: str, model_class: Type[T], params: dict[str, str] | None = None
    ) -> T:
        data = self._get_json(endpoint, params=params)
        return model_class.model_validate(data)

    def _get_model_list(self, endpoint: str, model_class: Type[T]) -> list[T]:
        data = self._get_json(endpoint)
        if not isinstance(data, list):
            raise APIResponseError(f"Expected list response, got {type(data)}")
        return [model_class.model_validate(item) for item in data]

    def get_latest_vulnerabilities(self) -> list[LatestVulnerability]:
        return self._get_model_list("/lastvulnerabilities", LatestVulnerability)

    def get_exploited_vulnerabilities(self) -> list[ExploitedVulnerability]:
        return self._get_model_list("/exploitedvulnerabilities", ExploitedVulnerability)

    def get_critical_vulnerabilities(self) -> list[CriticalVulnerability]:
        return self._get_model_list("/criticalvulnerabilities", CriticalVulnerability)

    def get_vulnerability_by_enisa_id(self, enisa_id: str) -> ENISAVulnerabilityByID:
        return self._get_model(
            "/enisaid", ENISAVulnerabilityByID, params={"id": enisa_id}
        )

    def get_advisory_by_id(self, advisory_id: str) -> AdvisoryByID:
        advisory = self._get_model(
            "/advisory", AdvisoryByID, params={"id": advisory_id}
        )
        advisory.advisory_id = advisory_id
        return advisory

    def search_vulnerabilities(
        self, filters: SearchFilters
    ) -> VulnerabilityQueryResponse:
        params = _build_search_params(filters)
        return self._get_model("/search", VulnerabilityQueryResponse, params=params)

    def get_kev_dump(self) -> list[KevEntry]:
        return self._get_model_list("/kev/dump", KevEntry)

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.close()

    def close(self) -> None:
        self.session.close()
