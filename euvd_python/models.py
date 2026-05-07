from pydantic import BaseModel


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
    id: str
    aliases: str | None = None
    assigner: str | None = None
    baseScore: float | None = None
    datePublished: str | None = None
    dateUpdated: str | None = None
    description: str | None = None
    enisaIdProduct: list[EnisaProductInfo] | None = None
    enisaIdVendor: list[EnisaVendorInfo] | None = None
    enisaUuid: str | None = None
    epss: float | None = None
    references: str | None = None


class VulnerabilityBase(VulnerabilityCore):
    baseScoreVector: str | None = None
    baseScoreVersion: str | None = None


class LatestVulnerability(VulnerabilityBase):
    pass


class CriticalVulnerability(VulnerabilityBase):
    pass


class ExploitedVulnerability(VulnerabilityBase):
    exploitedSince: str | None = None


class VulnerabilityItem(VulnerabilityBase):
    pass


class VulnerabilityQueryResponse(BaseModel):
    items: list[VulnerabilityItem]
    total: int


class VulnerabilityAdvisory(BaseModel):
    id: str | None = None
    name: str | None = None
    url: str | None = None


# Does not inherit from VulnerabilityCore because the API returns different
# JSON field names (vulnerabilityAdvisory vs enisaIdAdvisory, etc.)
class VulnerabilityByID(BaseModel):
    assigner: str | None = None
    baseScore: float | None = None
    datePublished: str | None = None
    dateUpdated: str | None = None
    description: str | None = None
    enisa_id: str | None = None
    epss: float | None = None
    id: str
    references: str | None = None
    status: str | None = None
    vulnerabilityAdvisory: list[VulnerabilityAdvisory] | None = None
    vulnerabilityProduct: list[EnisaProductInfo] | None = None
    vulnerabilityVendor: list[EnisaVendorInfo] | None = None


class ENISAVulnWrapper(BaseModel):
    id: str
    vulnerability: VulnerabilityByID


class ENISAVulnerabilityByID(VulnerabilityCore):
    enisaIdAdvisory: list[VulnerabilityAdvisory] | None = None
    enisaIdVulnerability: list[ENISAVulnWrapper] | None = None


class ENISAVulnerability(VulnerabilityBase):
    pass


class ENISAAdvisoryWrapper(BaseModel):
    id: str
    enisaId: ENISAVulnerability


class AdvisoryByID(BaseModel):
    advisoryProduct: list[EnisaProductInfo] | None = None
    aliases: str | None = None
    baseScore: float | None = None
    datePublished: str | None = None
    dateUpdated: str | None = None
    description: str | None = None
    enisaIdAdvisories: list[ENISAAdvisoryWrapper] | None = None


class KevEntry(BaseModel):
    cveId: str
    euvdId: str
    dateAdded: str
    sources: list[str]
    vendorProject: str | None = None
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

    def to_params(self) -> dict[str, str]:
        params: dict[str, str] = {}
        if self.from_score is not None:
            params["fromScore"] = str(self.from_score)
        if self.to_score is not None:
            params["toScore"] = str(self.to_score)
        if self.from_epss is not None:
            params["fromEpss"] = str(self.from_epss)
        if self.to_epss is not None:
            params["toEpss"] = str(self.to_epss)
        if self.from_date:
            params["fromDate"] = self.from_date
        if self.to_date:
            params["toDate"] = self.to_date
        if self.product:
            params["product"] = self.product
        if self.vendor:
            params["vendor"] = self.vendor
        if self.assigner:
            params["assigner"] = self.assigner
        if self.exploited is not None:
            params["exploited"] = str(self.exploited).lower()
        if self.text:
            params["text"] = self.text
        params["page"] = str(self.page)
        params["size"] = str(self.size)
        return params


class VulnerabilityStats(BaseModel):
    latest_count: int
    critical_count: int
    exploited_count: int
