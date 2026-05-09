import re
from datetime import datetime
from typing import Self

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

_ISO_DATE_RE = re.compile(r"\d{4}-\d{2}-\d{2}")

CVSS_CRITICAL_THRESHOLD = 9.0
CVSS_HIGH_THRESHOLD = 7.0
CVSS_MEDIUM_THRESHOLD = 4.0

# extra="allow" preserves wire fields not declared in the model.
_WIRE_CONFIG = ConfigDict(populate_by_name=True, extra="allow")


class ProductName(BaseModel):
    model_config = _WIRE_CONFIG

    name: str


class EnisaProductInfo(BaseModel):
    model_config = _WIRE_CONFIG

    id: str
    product: ProductName
    product_version: str | None = None


class VendorName(BaseModel):
    model_config = _WIRE_CONFIG

    name: str


class EnisaVendorInfo(BaseModel):
    model_config = _WIRE_CONFIG

    id: str
    vendor: VendorName


class VulnerabilityCore(BaseModel):
    model_config = _WIRE_CONFIG

    id: str
    aliases: str | None = None
    assigner: str | None = None
    base_score: float | None = Field(alias="baseScore", default=None)
    date_published: str | None = Field(alias="datePublished", default=None)
    date_updated: str | None = Field(alias="dateUpdated", default=None)
    description: str | None = None
    enisa_id_product: list[EnisaProductInfo] | None = Field(
        alias="enisaIdProduct", default=None
    )
    enisa_id_vendor: list[EnisaVendorInfo] | None = Field(
        alias="enisaIdVendor", default=None
    )
    enisa_uuid: str | None = Field(alias="enisaUuid", default=None)
    epss: float | None = None
    references: str | None = None


class VulnerabilityBase(VulnerabilityCore):
    base_score_vector: str | None = Field(alias="baseScoreVector", default=None)
    base_score_version: str | None = Field(alias="baseScoreVersion", default=None)
    exploited_since: str | None = Field(alias="exploitedSince", default=None)


class LatestVulnerability(VulnerabilityBase):
    pass


class CriticalVulnerability(VulnerabilityBase):
    pass


class ExploitedVulnerability(VulnerabilityBase):
    pass


class SearchResultVulnerability(VulnerabilityBase):
    pass


class VulnerabilityQueryResponse(BaseModel):
    model_config = _WIRE_CONFIG

    items: list[SearchResultVulnerability]
    total: int


class VulnerabilityAdvisory(BaseModel):
    model_config = _WIRE_CONFIG

    id: str | None = None
    name: str | None = None
    url: str | None = None


# Distinct from VulnerabilityCore: this endpoint uses different field names.
class VulnerabilityByID(BaseModel):
    model_config = _WIRE_CONFIG

    id: str
    assigner: str | None = None
    base_score: float | None = Field(alias="baseScore", default=None)
    data_processed: str | None = Field(alias="dataProcessed", default=None)
    date_published: str | None = Field(alias="datePublished", default=None)
    date_updated: str | None = Field(alias="dateUpdated", default=None)
    description: str | None = None
    enisa_id: str | None = Field(alias="enisaId", default=None)
    epss: float | None = None
    references: str | None = None
    status: str | None = None
    vulnerability_advisory: list[VulnerabilityAdvisory] | None = Field(
        alias="vulnerabilityAdvisory", default=None
    )
    vulnerability_product: list[EnisaProductInfo] | None = Field(
        alias="vulnerabilityProduct", default=None
    )
    vulnerability_vendor: list[EnisaVendorInfo] | None = Field(
        alias="vulnerabilityVendor", default=None
    )


class ENISAVulnWrapper(BaseModel):
    model_config = _WIRE_CONFIG

    id: str
    vulnerability: VulnerabilityByID


class ENISAVulnerabilityByID(VulnerabilityCore):
    base_score_vector: str | None = Field(alias="baseScoreVector", default=None)
    base_score_version: str | None = Field(alias="baseScoreVersion", default=None)
    enisa_id_advisory: list[VulnerabilityAdvisory] | None = Field(
        alias="enisaIdAdvisory", default=None
    )
    enisa_id_vulnerability: list[ENISAVulnWrapper] | None = Field(
        alias="enisaIdVulnerability", default=None
    )


class ENISAVulnerability(VulnerabilityBase):
    pass


class ENISAAdvisoryWrapper(BaseModel):
    model_config = _WIRE_CONFIG

    id: str
    enisa_id: ENISAVulnerability = Field(alias="enisaId")


class AdvisorySource(BaseModel):
    model_config = _WIRE_CONFIG

    id: int
    name: str


class AdvisoryByID(BaseModel):
    model_config = _WIRE_CONFIG

    id: str
    advisory_product: list[EnisaProductInfo] | None = Field(
        alias="advisoryProduct", default=None
    )
    aliases: str | None = None
    base_score: float | None = Field(alias="baseScore", default=None)
    date_published: str | None = Field(alias="datePublished", default=None)
    date_updated: str | None = Field(alias="dateUpdated", default=None)
    description: str | None = None
    enisa_id_advisories: list[ENISAAdvisoryWrapper] | None = Field(
        alias="enisaIdAdvisories", default=None
    )
    references: str | None = None
    source: AdvisorySource | None = None
    vulnerability_advisory: list[VulnerabilityAdvisory] | None = Field(
        alias="vulnerabilityAdvisory", default=None
    )


class KevEntry(BaseModel):
    model_config = _WIRE_CONFIG

    cve_id: str = Field(alias="cveId")
    euvd_id: str = Field(alias="euvdId")
    date_added: str = Field(alias="dateAdded")
    sources: list[str]
    vendor_project: str | None = Field(alias="vendorProject", default=None)
    product: str | None = None


class SearchFilters(BaseModel):
    from_score: float | None = Field(default=None, ge=0.0, le=10.0)
    to_score: float | None = Field(default=None, ge=0.0, le=10.0)
    from_epss: float | None = Field(default=None, ge=0.0, le=100.0)
    to_epss: float | None = Field(default=None, ge=0.0, le=100.0)
    from_date: str | None = None
    to_date: str | None = None
    product: str | None = None
    vendor: str | None = None
    assigner: str | None = None
    exploited: bool | None = None
    text: str | None = None
    page: int = Field(default=0, ge=0)
    size: int = Field(default=10, ge=1, le=100)

    @field_validator("from_date", "to_date")
    @classmethod
    def _check_iso_date(cls, value: str | None) -> str | None:
        if value is None:
            return value
        if not _ISO_DATE_RE.fullmatch(value):
            raise ValueError("date must be in YYYY-MM-DD format")
        try:
            datetime.strptime(value, "%Y-%m-%d")
        except ValueError as exc:
            raise ValueError("date must be in YYYY-MM-DD format") from exc
        return value

    @model_validator(mode="after")
    def _check_range_pairs(self) -> Self:
        if (
            self.from_score is not None
            and self.to_score is not None
            and self.from_score > self.to_score
        ):
            raise ValueError("from_score must be <= to_score")
        if (
            self.from_epss is not None
            and self.to_epss is not None
            and self.from_epss > self.to_epss
        ):
            raise ValueError("from_epss must be <= to_epss")
        if (
            self.from_date is not None
            and self.to_date is not None
            and self.from_date > self.to_date
        ):
            raise ValueError("from_date must be <= to_date")
        return self


class VulnerabilityStats(BaseModel):
    latest_count: int
    critical_count: int
    exploited_count: int
