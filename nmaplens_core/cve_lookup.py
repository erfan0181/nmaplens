from __future__ import annotations

from urllib.parse import quote


NVD_CPE_SEARCH_URL = "https://nvd.nist.gov/products/cpe/search/results"
NVD_CVE_SEARCH_URL = "https://nvd.nist.gov/vuln/search/results"


def enrich_cpe_references(hosts: list[dict[str, object]]) -> None:
    for host in hosts:
        references: list[dict[str, str]] = []
        for port in host["open_ports"]:
            cpe_values = list(port.get("cpe_values", []))
            port_references = []
            for cpe_value in cpe_values:
                reference = build_cpe_reference(cpe_value)
                port_references.append(reference)
                if reference not in references:
                    references.append(reference)
            port["cve_references"] = port_references
        host["cve_references"] = references


def build_cpe_reference(cpe_value: str) -> dict[str, str]:
    normalized = cpe_value.strip()
    return {
        "cpe": normalized,
        "nvd_cpe_url": f"{NVD_CPE_SEARCH_URL}?namingFormat=2.3&keyword={quote(normalized)}",
        "nvd_cve_url": f"{NVD_CVE_SEARCH_URL}?query={quote(normalized)}&search_type=all",
    }
