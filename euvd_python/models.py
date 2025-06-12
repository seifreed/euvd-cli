"""
Data models for EUVD API responses using Pydantic.
"""

from typing import List, Optional, Any
from pydantic import BaseModel, Field


class ProductName(BaseModel):
    name: str


class EnisaProductInfo(BaseModel):
    id: str
    product: ProductName
    product_version: Optional[str] = None


class VendorName(BaseModel):
    name: str


class EnisaVendorInfo(BaseModel):
    id: str
    vendor: VendorName


class ExploitedVulnerability(BaseModel):
    aliases: str
    assigner: str
    baseScore: float
    baseScoreVector: str
    baseScoreVersion: str
    datePublished: str
    dateUpdated: str
    description: str
    enisaIdProduct: List[EnisaProductInfo]
    enisaIdVendor: List[EnisaVendorInfo]
    epss: float
    exploitedSince: str
    id: str
    references: str


class CriticalVulnerability(BaseModel):
    aliases: str
    assigner: str
    baseScore: float
    baseScoreVector: str
    baseScoreVersion: str
    datePublished: str
    dateUpdated: str
    description: str
    enisaIdProduct: List[EnisaProductInfo]
    enisaIdVendor: List[EnisaVendorInfo]
    epss: float
    id: str
    references: str


class LatestVulnerability(BaseModel):
    aliases: str
    assigner: str
    baseScore: float
    baseScoreVector: str
    baseScoreVersion: str
    datePublished: str
    dateUpdated: str
    description: str
    enisaIdProduct: List[EnisaProductInfo]
    enisaIdVendor: List[EnisaVendorInfo]
    epss: float
    id: str
    references: str


class VulnerabilityItem(BaseModel):
    aliases: str
    assigner: str
    baseScore: float
    baseScoreVector: str
    baseScoreVersion: str
    datePublished: str
    dateUpdated: str
    description: str
    enisaIdProduct: List[EnisaProductInfo]
    enisaIdVendor: List[EnisaVendorInfo]
    epss: float
    id: str
    references: str


class VulnerabilityQueryResponse(BaseModel):
    items: List[VulnerabilityItem]
    total: int


class VulnerabilityByID(BaseModel):
    assigner: Optional[str] = None
    baseScore: Optional[float] = None
    datePublished: Optional[str] = None
    dateUpdated: Optional[str] = None
    description: Optional[str] = None
    enisa_id: Optional[str] = None
    epss: Optional[float] = None
    id: str
    references: Optional[str] = None
    status: Optional[str] = None
    vulnerabilityAdvisory: Optional[List[Any]] = None  # Empty array in sample
    vulnerabilityProduct: Optional[List[EnisaProductInfo]] = None
    vulnerabilityVendor: Optional[List[EnisaVendorInfo]] = None


class ENISAVulnWrapper(BaseModel):
    id: str
    vulnerability: VulnerabilityByID


class ENISAVulnerabilityByID(BaseModel):
    aliases: Optional[str] = None
    assigner: Optional[str] = None
    baseScore: Optional[float] = None
    datePublished: Optional[str] = None
    dateUpdated: Optional[str] = None
    description: Optional[str] = None
    enisaIdAdvisory: Optional[List[Any]] = None
    enisaIdProduct: Optional[List[EnisaProductInfo]] = None
    enisaIdVendor: Optional[List[EnisaVendorInfo]] = None
    enisaIdVulnerability: Optional[List[ENISAVulnWrapper]] = None
    epss: Optional[float] = None
    id: str
    references: Optional[str] = None


class ENISAVulnerability(BaseModel):
    aliases: str
    assigner: str
    baseScore: float
    baseScoreVector: str
    baseScoreVersion: str
    datePublished: str
    dateUpdated: str
    description: str
    enisaIdVendor: List[EnisaVendorInfo]
    epss: float
    id: str
    references: str


class ENISAAdvisoryWrapper(BaseModel):
    id: str
    enisaId: ENISAVulnerability


class AdvisoryByID(BaseModel):
    advisoryProduct: Optional[List[EnisaProductInfo]] = None
    aliases: Optional[str] = None
    baseScore: Optional[float] = None
    datePublished: Optional[str] = None
    dateUpdated: Optional[str] = None
    description: Optional[str] = None
    enisaIdAdvisories: Optional[List[ENISAAdvisoryWrapper]] = None 