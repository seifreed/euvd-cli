import json
from typing import Any

from .models import (
    AdvisoryByID,
    ENISAVulnerabilityByID,
    ExploitedVulnerability,
    KevEntry,
    VulnerabilityBase,
)

SARIF_VERSION = "2.1.0"
SARIF_SCHEMA = (
    "https://docs.oasis-open.org/sarif/sarif/v2.1.0/errata01/os/schemas"
    "/sarif-schema-2.1.0.json"
)
TOOL_NAME = "EUVD CLI"
TOOL_VERSION = "1.0.0"
TOOL_URI = "https://euvd.enisa.europa.eu"


def _score_to_level(base_score: float | None) -> str:
    if base_score is None:
        return "none"
    if base_score >= 9.0:
        return "error"
    if base_score >= 7.0:
        return "warning"
    if base_score >= 4.0:
        return "note"
    return "none"


def _build_fingerprints(uuid: str | None) -> dict[str, str]:
    if uuid:
        return {"enisaUuid/v1": uuid}
    return {}


def _build_products(
    products: list[Any] | None,
) -> list[dict[str, Any]] | None:
    if not products:
        return None
    return [
        {"id": p.id, "name": p.product.name, "version": p.product_version}
        for p in products
    ]


def _build_vendors(vendors: list[Any] | None) -> list[dict[str, Any]] | None:
    if not vendors:
        return None
    return [{"id": v.id, "name": v.vendor.name} for v in vendors]


def _build_common_properties(
    vuln: VulnerabilityBase | ENISAVulnerabilityByID,
) -> dict[str, Any]:
    properties: dict[str, Any] = {}
    if vuln.baseScore is not None:
        properties["baseScore"] = vuln.baseScore
    if vuln.aliases:
        properties["aliases"] = vuln.aliases
    if vuln.references:
        properties["references"] = vuln.references
    if vuln.assigner:
        properties["assigner"] = vuln.assigner
    if vuln.datePublished:
        properties["datePublished"] = vuln.datePublished
    if vuln.dateUpdated:
        properties["dateUpdated"] = vuln.dateUpdated
    if vuln.epss is not None:
        properties["epss"] = vuln.epss
    products = _build_products(getattr(vuln, "enisaIdProduct", None))
    if products:
        properties["products"] = products
    vendors = _build_vendors(getattr(vuln, "enisaIdVendor", None))
    if vendors:
        properties["vendors"] = vendors
    return properties


def vulnerability_to_result(vuln: VulnerabilityBase) -> dict[str, Any]:
    result: dict[str, Any] = {
        "ruleId": vuln.id,
        "level": _score_to_level(vuln.baseScore),
        "kind": "fail",
        "message": {"text": vuln.description or vuln.id},
    }

    fingerprints = _build_fingerprints(vuln.enisaUuid)
    properties = _build_common_properties(vuln)

    if vuln.baseScoreVector:
        properties["baseScoreVector"] = vuln.baseScoreVector
    if vuln.baseScoreVersion:
        properties["baseScoreVersion"] = vuln.baseScoreVersion
    if vuln.epss is not None:
        result["rank"] = vuln.epss * 100
    if isinstance(vuln, ExploitedVulnerability) and vuln.exploitedSince:
        properties["exploitedSince"] = vuln.exploitedSince

    if fingerprints:
        result["fingerprints"] = fingerprints
    if properties:
        result["properties"] = properties

    return result


def enisa_vulnerability_to_result(vuln: ENISAVulnerabilityByID) -> dict[str, Any]:
    result: dict[str, Any] = {
        "ruleId": vuln.id,
        "level": _score_to_level(vuln.baseScore),
        "kind": "fail",
        "message": {"text": vuln.description or vuln.id},
    }

    fingerprints = _build_fingerprints(vuln.enisaUuid)
    properties = _build_common_properties(vuln)

    if vuln.epss is not None:
        result["rank"] = vuln.epss * 100

    if fingerprints:
        result["fingerprints"] = fingerprints
    if properties:
        result["properties"] = properties

    return result


def advisory_to_result(advisory: AdvisoryByID) -> dict[str, Any]:
    result: dict[str, Any] = {
        "ruleId": advisory.description or "unknown-advisory",
        "level": _score_to_level(advisory.baseScore),
        "kind": "review",
        "message": {"text": advisory.description or "Advisory lookup"},
    }

    properties: dict[str, Any] = {}
    if advisory.baseScore is not None:
        properties["baseScore"] = advisory.baseScore
    if advisory.aliases:
        properties["aliases"] = advisory.aliases
    if advisory.datePublished:
        properties["datePublished"] = advisory.datePublished
    if advisory.dateUpdated:
        properties["dateUpdated"] = advisory.dateUpdated
    products = _build_products(advisory.advisoryProduct)
    if products:
        properties["products"] = products
    if advisory.enisaIdAdvisories:
        properties["relatedVulnerabilityIds"] = [
            a.id for a in advisory.enisaIdAdvisories
        ]

    if properties:
        result["properties"] = properties

    return result


def kev_entry_to_result(entry: KevEntry) -> dict[str, Any]:
    return {
        "ruleId": entry.cveId,
        "level": "error",
        "kind": "fail",
        "message": {
            "text": f"Known exploited vulnerability: {entry.cveId} (EUVD: {entry.euvdId})"
        },
        "fingerprints": {"euvdId/v1": entry.euvdId},
        "properties": {
            "euvdId": entry.euvdId,
            "dateAdded": entry.dateAdded,
            "sources": entry.sources,
            "vendorProject": entry.vendorProject,
            "product": entry.product,
        },
    }


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

    from .models import VulnerabilityQueryResponse

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

    if isinstance(data, dict):
        return json.dumps(data, indent=2)

    if hasattr(data, "model_dump"):
        return json.dumps(data.model_dump(), indent=2)
    if isinstance(data, list) and data and hasattr(data[0], "model_dump"):
        return json.dumps([item.model_dump() for item in data], indent=2)

    return json.dumps(data, indent=2, default=str)
