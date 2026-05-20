from __future__ import annotations

from urllib.parse import quote


NVD_CPE_SEARCH_URL = "https://nvd.nist.gov/products/cpe/search/results"
NVD_CVE_SEARCH_URL = "https://nvd.nist.gov/vuln/search/results"
CVE_SEARCH_URL = "https://www.cve.org/CVERecord/SearchResults"
EXPLOIT_DB_SEARCH_URL = "https://www.exploit-db.com/search"


def enrich_cpe_references(hosts: list[dict[str, object]]) -> None:
    for host in hosts:
        references: list[dict[str, str]] = []
        for port in host["open_ports"]:
            port_references = _build_port_references(port)
            port["cve_references"] = port_references
            for reference in port_references:
                if reference not in references:
                    references.append(reference)
        host["cve_references"] = references


def _build_port_references(port: dict[str, object]) -> list[dict[str, str]]:
    cpe_values = [str(value).strip() for value in port.get("cpe_values", []) if str(value).strip()]
    if cpe_values:
        references = [build_cpe_reference(cpe_value) for cpe_value in cpe_values]
        return [reference for reference in references if not _is_low_value_reference(reference)]

    fallback_query = build_fallback_query(port)
    if not fallback_query:
        return []
    reference = build_keyword_reference(fallback_query)
    return [] if _is_low_value_reference(reference) else [reference]


def build_cpe_reference(cpe_value: str) -> dict[str, str]:
    normalized = cpe_value.strip()
    cve_query = build_cpe_keyword_query(normalized)
    return {
        "label": cve_query,
        "query_type": "cpe",
        "cpe": normalized,
        "nvd_cpe_url": f"{NVD_CPE_SEARCH_URL}?namingFormat=2.3&keyword={quote(normalized)}",
        "nvd_cve_url": f"{NVD_CVE_SEARCH_URL}?query={quote(normalized)}&search_type=all",
        "cve_search_url": f"{CVE_SEARCH_URL}?query={quote(cve_query)}",
        "exploit_db_url": f"{EXPLOIT_DB_SEARCH_URL}?q={quote(cve_query)}",
    }


def build_keyword_reference(query: str) -> dict[str, str]:
    normalized = " ".join(query.split())
    return {
        "label": normalized,
        "query_type": "keyword",
        "cpe": normalized,
        "nvd_cpe_url": f"{NVD_CPE_SEARCH_URL}?keyword={quote(normalized)}",
        "nvd_cve_url": f"{NVD_CVE_SEARCH_URL}?query={quote(normalized)}&search_type=all",
        "cve_search_url": f"{CVE_SEARCH_URL}?query={quote(normalized)}",
        "exploit_db_url": f"{EXPLOIT_DB_SEARCH_URL}?q={quote(normalized)}",
    }


def build_fallback_query(port: dict[str, object]) -> str:
    service = str(port.get("service", "")).strip()
    product = str(port.get("product", "")).strip()
    version = str(port.get("version", "")).strip()

    service_aliases = {
        "ms-wbt-server": "Microsoft RDP",
        "msmq": "Microsoft Message Queuing",
        "kpasswd5": "Kerberos kpasswd5",
        "kerberos-sec": "Microsoft Kerberos",
        "ms-sql-s": "Microsoft SQL Server",
        "microsoft-ds": "SMB Microsoft DS",
        "netbios-ssn": "NetBIOS SMB",
        "domain": "DNS",
    }

    parts = [part for part in [product, version] if part]
    normalized_service = service_aliases.get(service.lower(), service)
    if not parts and normalized_service:
        parts.append(normalized_service)
    elif normalized_service and normalized_service.lower() not in " ".join(parts).lower():
        parts.append(normalized_service)
    return " ".join(parts)


def build_cpe_keyword_query(cpe_value: str) -> str:
    parts = cpe_value.split(":")
    if len(parts) < 4:
        return cpe_value

    vendor = parts[2].replace("_", " ").strip()
    product = parts[3].replace("_", " ").strip()
    version = parts[4].replace("_", " ").strip() if len(parts) > 4 else ""

    normalized_product = {
        "internet information services": "IIS",
        "sql server": "SQL Server",
        "simple dns plus": "Simple DNS Plus",
        "kerberos": "Kerberos",
        "windows": "Windows",
        "openssh": "OpenSSH",
    }.get(product.lower(), product)

    normalized_vendor = {
        "jh software": "JH Software",
        "microsoft": "Microsoft",
        "openbsd": "OpenBSD",
    }.get(vendor.lower(), vendor.title() if vendor else "")

    words = [normalized_vendor, normalized_product, version]
    return " ".join(part for part in words if part and part != "*")


def _is_low_value_reference(reference: dict[str, str]) -> bool:
    label = reference["label"].strip().lower()
    if not label:
        return True
    if label in {"tcpwrapped", "microsoft windows", "windows"}:
        return True
    return False
