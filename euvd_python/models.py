from typing import Any
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


class VulnerabilityBase(BaseModel):
    aliases: str | None = None
    assigner: str | None = None
    baseScore: float | None = None
    baseScoreVector: str | None = None
    baseScoreVersion: str | None = None
    datePublished: str | None = None
    dateUpdated: str | None = None
    description: str | None = None
    enisaIdProduct: list[EnisaProductInfo] | None = None
    enisaIdVendor: list[EnisaVendorInfo] | None = None
    enisaUuid: str | None = None
    epss: float | None = None
    id: str
    references: str | None = None


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
    vulnerabilityAdvisory: list[Any] | None = None
    vulnerabilityProduct: list[EnisaProductInfo] | None = None
    vulnerabilityVendor: list[EnisaVendorInfo] | None = None


class ENISAVulnWrapper(BaseModel):
    id: str
    vulnerability: VulnerabilityByID


class ENISAVulnerabilityByID(BaseModel):
    aliases: str | None = None
    assigner: str | None = None
    baseScore: float | None = None
    datePublished: str | None = None
    dateUpdated: str | None = None
    description: str | None = None
    enisaIdAdvisory: list[Any] | None = None
    enisaIdProduct: list[EnisaProductInfo] | None = None
    enisaIdVendor: list[EnisaVendorInfo] | None = None
    enisaIdVulnerability: list[ENISAVulnWrapper] | None = None
    enisaUuid: str | None = None
    epss: float | None = None
    id: str
    references: str | None = None


class ENISAVulnerability(BaseModel):
    aliases: str | None = None
    assigner: str | None = None
    baseScore: float | None = None
    baseScoreVector: str | None = None
    baseScoreVersion: str | None = None
    datePublished: str | None = None
    dateUpdated: str | None = None
    description: str | None = None
    enisaIdProduct: list[EnisaProductInfo] | None = None
    enisaIdVendor: list[EnisaVendorInfo] | None = None
    enisaUuid: str | None = None
    epss: float | None = None
    id: str
    references: str | None = None


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
