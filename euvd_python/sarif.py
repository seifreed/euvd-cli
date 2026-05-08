import json
from typing import Any

from . import __version__
from .models import (
    AdvisoryByID,
    EnisaProductInfo,
    EnisaVendorInfo,
    ENISAVulnerabilityByID,
    KevEntry,
    VulnerabilityBase,
    VulnerabilityCore,
    VulnerabilityQueryResponse,
    CVSS_CRITICAL_THRESHOLD,
    CVSS_HIGH_THRESHOLD,
    CVSS_MEDIUM_THRESHOLD,
)

SARIF_VERSION = "2.1.0"
SARIF_SCHEMA = (
    "https://docs.oasis-open.org/sarif/sarif/v2.1.0/errata01/os/schemas"
    "/sarif-schema-2.1.0.json"
)
TOOL_NAME = "EUVD CLI"
TOOL_VERSION = __version__
TOOL_URI = "https://euvd.enisa.europa.eu"

EPSS_PERCENT_FACTOR = 100


def _cvss_to_sarif_level(base_score: float | None) -> str:
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


def _strip_none_and_false(fields: dict[str, Any]) -> dict[str, Any]:
    return {k: v for k, v in fields.items() if v is not None and v is not False}


def _build_common_properties(
    vuln: VulnerabilityCore,
) -> dict[str, Any]:
    products = _build_products(vuln.enisa_id_product)
    vendors = _build_vendors(vuln.enisa_id_vendor)
    return _strip_none_and_false(
        {
            "baseScore": vuln.base_score,
            "aliases": vuln.aliases,
            "references": vuln.references,
            "assigner": vuln.assigner,
            "datePublished": vuln.date_published,
            "dateUpdated": vuln.date_updated,
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
        "level": _cvss_to_sarif_level(vuln.base_score),
        "kind": "fail",
        "message": {"text": vuln.description or vuln.id},
    }

    fingerprints = _build_fingerprints(vuln.enisa_uuid)
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
    if vuln.base_score_vector:
        extra["baseScoreVector"] = vuln.base_score_vector
    if vuln.base_score_version:
        extra["baseScoreVersion"] = vuln.base_score_version
    if vuln.exploited_since:
        extra["exploitedSince"] = vuln.exploited_since
    return _build_vulnerability_result(vuln, extra_properties=extra if extra else None)


def enisa_vulnerability_to_result(vuln: ENISAVulnerabilityByID) -> dict[str, Any]:
    return _build_vulnerability_result(vuln)


def _advisory_rule_id(advisory: AdvisoryByID) -> str:
    if advisory.advisory_id:
        return advisory.advisory_id
    if advisory.enisa_id_advisories:
        return advisory.enisa_id_advisories[0].id
    return "unknown-advisory"


def advisory_to_result(advisory: AdvisoryByID) -> dict[str, Any]:
    result: dict[str, Any] = {
        "ruleId": _advisory_rule_id(advisory),
        "level": _cvss_to_sarif_level(advisory.base_score),
        "kind": "review",
        "message": {"text": advisory.description or "Advisory lookup"},
    }

    products = _build_products(advisory.advisory_product)
    related_ids = (
        [a.id for a in advisory.enisa_id_advisories]
        if advisory.enisa_id_advisories
        else None
    )
    properties = _strip_none_and_false(
        {
            "baseScore": advisory.base_score,
            "aliases": advisory.aliases,
            "datePublished": advisory.date_published,
            "dateUpdated": advisory.date_updated,
            "products": products,
            "relatedVulnerabilityIds": related_ids,
        }
    )

    if properties:
        result["properties"] = properties

    return result


def kev_entry_to_result(entry: KevEntry) -> dict[str, Any]:
    result: dict[str, Any] = {
        "ruleId": entry.cve_id,
        "level": "error",
        "kind": "fail",
        "message": {
            "text": f"Known exploited vulnerability: {entry.cve_id} (EUVD: {entry.euvd_id})"
        },
        "fingerprints": {"euvdId/v1": entry.euvd_id},
    }

    properties = _strip_none_and_false(
        {
            "euvdId": entry.euvd_id,
            "dateAdded": entry.date_added,
            "sources": entry.sources,
            "vendorProject": entry.vendor_project,
            "product": entry.product,
        }
    )

    if properties:
        result["properties"] = properties

    return result


def build_sarif_log(
    results: list[dict[str, Any]],
    run_properties: dict[str, Any] | None = None,
) -> dict[str, Any]:
    unique_rule_ids = list(dict.fromkeys(r["ruleId"] for r in results))
    run: dict[str, Any] = {
        "tool": {
            "driver": {
                "name": TOOL_NAME,
                "version": TOOL_VERSION,
                "informationUri": TOOL_URI,
                "rules": [{"id": rid} for rid in unique_rule_ids],
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


_SINGLE_CONVERTERS: list[tuple[type, Any]] = [
    (
        VulnerabilityQueryResponse,
        lambda d: (
            [vulnerability_to_result(v) for v in d.items],
            {"totalResults": d.total},
        ),
    ),
    (ENISAVulnerabilityByID, lambda d: ([enisa_vulnerability_to_result(d)], None)),
    (AdvisoryByID, lambda d: ([advisory_to_result(d)], None)),
    (VulnerabilityBase, lambda d: ([vulnerability_to_result(d)], None)),
]

_LIST_CONVERTERS: list[tuple[type, Any]] = [
    (VulnerabilityBase, lambda items: [vulnerability_to_result(v) for v in items]),
    (KevEntry, lambda items: [kev_entry_to_result(e) for e in items]),
]


def _to_sarif_results(data: Any) -> tuple[list[dict[str, Any]], dict[str, Any] | None]:
    for data_type, converter in _SINGLE_CONVERTERS:
        if isinstance(data, data_type):
            return converter(data)

    if isinstance(data, list):
        if not data:
            return [], None
        first_type = type(data[0])
        for item_type, converter in _LIST_CONVERTERS:
            if issubclass(first_type, item_type):
                return converter(data), None

    raise TypeError(f"Cannot convert {type(data).__name__} to SARIF")


def to_sarif_json(data: Any) -> str:
    results, run_properties = _to_sarif_results(data)
    sarif = build_sarif_log(results, run_properties=run_properties)
    return json.dumps(sarif, indent=2)
