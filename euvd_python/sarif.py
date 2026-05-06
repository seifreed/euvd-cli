import json
from typing import Any

from . import __version__ as _pkg_version
from .models import (
    AdvisoryByID,
    EnisaProductInfo,
    EnisaVendorInfo,
    ENISAVulnerabilityByID,
    ExploitedVulnerability,
    KevEntry,
    VulnerabilityBase,
    VulnerabilityCore,
    VulnerabilityQueryResponse,
    VulnerabilityStats,
)

SARIF_VERSION = "2.1.0"
SARIF_SCHEMA = (
    "https://docs.oasis-open.org/sarif/sarif/v2.1.0/errata01/os/schemas"
    "/sarif-schema-2.1.0.json"
)
TOOL_NAME = "EUVD CLI"
TOOL_VERSION = _pkg_version
TOOL_URI = "https://euvd.enisa.europa.eu"

CVSS_CRITICAL_THRESHOLD = 9.0
CVSS_HIGH_THRESHOLD = 7.0
CVSS_MEDIUM_THRESHOLD = 4.0
EPSS_PERCENT_FACTOR = 100


def _score_to_level(base_score: float | None) -> str:
    if base_score is None:
        return "none"
    if base_score >= CVSS_CRITICAL_THRESHOLD:
        return "error"
    if base_score >= CVSS_HIGH_THRESHOLD:
        return "warning"
    if base_score >= CVSS_MEDIUM_THRESHOLD:
        return "note"
    return "none"


def _build_fingerprints(uuid: str | None) -> dict[str, str]:
    if uuid:
        return {"enisaUuid/v1": uuid}
    return {}


def _build_products(
    products: list[EnisaProductInfo] | None,
) -> list[dict[str, Any]] | None:
    if not products:
        return None
    return [
        {"id": p.id, "name": p.product.name, "version": p.product_version}
        for p in products
    ]


def _build_vendors(
    vendors: list[EnisaVendorInfo] | None,
) -> list[dict[str, Any]] | None:
    if not vendors:
        return None
    return [{"id": v.id, "name": v.vendor.name} for v in vendors]


def _optional_fields(fields: dict[str, Any]) -> dict[str, Any]:
    return {k: v for k, v in fields.items() if v is not None and v is not False}


def _build_common_properties(
    vuln: VulnerabilityCore,
) -> dict[str, Any]:
    products = _build_products(vuln.enisaIdProduct)
    vendors = _build_vendors(vuln.enisaIdVendor)
    return _optional_fields(
        {
            "baseScore": vuln.baseScore,
            "aliases": vuln.aliases,
            "references": vuln.references,
            "assigner": vuln.assigner,
            "datePublished": vuln.datePublished,
            "dateUpdated": vuln.dateUpdated,
            "epss": vuln.epss,
            "products": products,
            "vendors": vendors,
        }
    )


def _build_vulnerability_result(
    vuln: VulnerabilityCore,
    extra_properties: dict[str, Any] | None = None,
) -> dict[str, Any]:
    result: dict[str, Any] = {
        "ruleId": vuln.id,
        "level": _score_to_level(vuln.baseScore),
        "kind": "fail",
        "message": {"text": vuln.description or vuln.id},
    }

    fingerprints = _build_fingerprints(vuln.enisaUuid)
    properties = _build_common_properties(vuln)
    if extra_properties:
        properties.update(extra_properties)

    if vuln.epss is not None:
        result["rank"] = vuln.epss * EPSS_PERCENT_FACTOR

    if fingerprints:
        result["fingerprints"] = fingerprints
    if properties:
        result["properties"] = properties

    return result


def vulnerability_to_result(vuln: VulnerabilityBase) -> dict[str, Any]:
    extra: dict[str, Any] = {}
    if vuln.baseScoreVector:
        extra["baseScoreVector"] = vuln.baseScoreVector
    if vuln.baseScoreVersion:
        extra["baseScoreVersion"] = vuln.baseScoreVersion
    if isinstance(vuln, ExploitedVulnerability) and vuln.exploitedSince:
        extra["exploitedSince"] = vuln.exploitedSince
    return _build_vulnerability_result(vuln, extra_properties=extra or None)


def enisa_vulnerability_to_result(vuln: ENISAVulnerabilityByID) -> dict[str, Any]:
    return _build_vulnerability_result(vuln)


def advisory_to_result(advisory: AdvisoryByID) -> dict[str, Any]:
    result: dict[str, Any] = {
        "ruleId": advisory.description or "unknown-advisory",
        "level": _score_to_level(advisory.baseScore),
        "kind": "review",
        "message": {"text": advisory.description or "Advisory lookup"},
    }

    products = _build_products(advisory.advisoryProduct)
    related_ids = (
        [a.id for a in advisory.enisaIdAdvisories]
        if advisory.enisaIdAdvisories
        else None
    )
    properties = _optional_fields(
        {
            "baseScore": advisory.baseScore,
            "aliases": advisory.aliases,
            "datePublished": advisory.datePublished,
            "dateUpdated": advisory.dateUpdated,
            "products": products,
            "relatedVulnerabilityIds": related_ids,
        }
    )

    if properties:
        result["properties"] = properties

    return result


def kev_entry_to_result(entry: KevEntry) -> dict[str, Any]:
    result: dict[str, Any] = {
        "ruleId": entry.cveId,
        "level": "error",
        "kind": "fail",
        "message": {
            "text": f"Known exploited vulnerability: {entry.cveId} (EUVD: {entry.euvdId})"
        },
        "fingerprints": {"euvdId/v1": entry.euvdId},
    }

    properties = _optional_fields(
        {
            "euvdId": entry.euvdId,
            "dateAdded": entry.dateAdded,
            "sources": entry.sources,
            "vendorProject": entry.vendorProject,
            "product": entry.product,
        }
    )

    if properties:
        result["properties"] = properties

    return result


def build_sarif_log(
    results: list[dict[str, Any]],
    tool_name: str = TOOL_NAME,
    tool_version: str = TOOL_VERSION,
    run_properties: dict[str, Any] | None = None,
) -> dict[str, Any]:
    run: dict[str, Any] = {
        "tool": {
            "driver": {
                "name": tool_name,
                "version": tool_version,
                "informationUri": TOOL_URI,
                "rules": [{"id": r["ruleId"]} for r in results],
            }
        },
        "results": results,
    }

    if run_properties:
        run["properties"] = run_properties

    return {
        "$schema": SARIF_SCHEMA,
        "version": SARIF_VERSION,
        "runs": [run],
    }


def to_sarif_json(data: Any) -> str:
    if isinstance(data, list) and data and isinstance(data[0], VulnerabilityBase):
        results = [vulnerability_to_result(v) for v in data]
        return json.dumps(build_sarif_log(results), indent=2)

    if isinstance(data, VulnerabilityBase):
        results = [vulnerability_to_result(data)]
        return json.dumps(build_sarif_log(results), indent=2)

    if isinstance(data, ENISAVulnerabilityByID):
        results = [enisa_vulnerability_to_result(data)]
        return json.dumps(build_sarif_log(results), indent=2)

    if isinstance(data, AdvisoryByID):
        results = [advisory_to_result(data)]
        return json.dumps(build_sarif_log(results), indent=2)

    if isinstance(data, VulnerabilityQueryResponse):
        results = [vulnerability_to_result(v) for v in data.items]
        sarif = build_sarif_log(
            results,
            run_properties={"totalResults": data.total},
        )
        return json.dumps(sarif, indent=2)

    if isinstance(data, list) and data and isinstance(data[0], KevEntry):
        results = [kev_entry_to_result(e) for e in data]
        return json.dumps(build_sarif_log(results), indent=2)

    if isinstance(data, VulnerabilityStats):
        return json.dumps(data.model_dump(), indent=2)

    raise TypeError(f"Cannot convert {type(data).__name__} to SARIF")
