from pydantic import BaseModel, ConfigDict, Field

CVSS_CRITICAL_THRESHOLD = 9.0
CVSS_HIGH_THRESHOLD = 7.0
CVSS_MEDIUM_THRESHOLD = 4.0


class ProductName(BaseModel):
    name: str


class EnisaProductInfo(BaseModel):
    id: str
    product: ProductName
    product_version: str | None = None


class VendorName(BaseModel):
    name: str


class EnisaVendorInfo(BaseModel):
    id: str
    vendor: VendorName


class VulnerabilityCore(BaseModel):
    model_config = ConfigDict(populate_by_name=True)

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
    items: list[SearchResultVulnerability]
    total: int


class VulnerabilityAdvisory(BaseModel):
    id: str | None = None
    name: str | None = None
    url: str | None = None


# Does not inherit from VulnerabilityCore because the API returns different
# JSON field names (vulnerabilityAdvisory vs enisaIdAdvisory, etc.)
class VulnerabilityByID(BaseModel):
    model_config = ConfigDict(populate_by_name=True)

    id: str
    assigner: str | None = None
    base_score: float | None = Field(alias="baseScore", default=None)
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
    model_config = ConfigDict(populate_by_name=True)

    id: str
    enisa_id: ENISAVulnerability = Field(alias="enisaId")


class AdvisorySource(BaseModel):
    id: int
    name: str


class AdvisoryByID(BaseModel):
    model_config = ConfigDict(populate_by_name=True)

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
    model_config = ConfigDict(populate_by_name=True)

    cve_id: str = Field(alias="cveId")
    euvd_id: str = Field(alias="euvdId")
    date_added: str = Field(alias="dateAdded")
    sources: list[str]
    vendor_project: str | None = Field(alias="vendorProject", default=None)
    product: str | None = None


class SearchFilters(BaseModel):
    from_score: float | None = None
    to_score: float | None = None
    from_epss: float | None = None
    to_epss: float | None = None
    from_date: str | None = None
    to_date: str | None = None
    product: str | None = None
    vendor: str | None = None
    assigner: str | None = None
    exploited: bool | None = None
    text: str | None = None
    page: int = 0
    size: int = 10


class VulnerabilityStats(BaseModel):
    latest_count: int
    critical_count: int
    exploited_count: int
