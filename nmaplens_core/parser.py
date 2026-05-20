from __future__ import annotations

import xml.etree.ElementTree as ET
from pathlib import Path


def parse_nmap_xml(file_path: str | Path) -> dict[str, object]:
    path = Path(file_path)
    if not path.exists():
        raise FileNotFoundError(path)
    if not path.is_file():
        raise ValueError(f"Input path is not a file: {path}")

    try:
        root = ET.parse(path).getroot()
    except ET.ParseError as exc:
        raise ValueError(f"Invalid XML: {exc}") from exc

    if root.tag != "nmaprun":
        raise ValueError("Invalid Nmap XML: root element must be 'nmaprun'")

    hosts = [_parse_host(host_node) for host_node in root.findall("host")]
    if not hosts:
        raise ValueError("No hosts found in the scan")

    return {
        "scan_metadata": {
            "scanner": root.attrib.get("scanner", "unknown"),
            "version": root.attrib.get("version", "unknown"),
            "start_time": root.attrib.get("startstr") or root.attrib.get("start", "unknown"),
            "xml_path": str(path),
        },
        "hosts": hosts,
    }


def _parse_host(host_node: ET.Element) -> dict[str, object]:
    ip_address = "unknown"
    mac_address = None
    vendor = None

    for address in host_node.findall("address"):
        addrtype = address.attrib.get("addrtype", "")
        if addrtype in {"ipv4", "ipv6"} and ip_address == "unknown":
            ip_address = address.attrib.get("addr", "unknown")
        if addrtype == "mac":
            mac_address = address.attrib.get("addr")
            vendor = address.attrib.get("vendor")

    hostnames = [
        node.attrib.get("name", "")
        for node in host_node.findall("./hostnames/hostname")
        if node.attrib.get("name")
    ]
    status_node = host_node.find("status")
    os_match = host_node.find("./os/osmatch")

    open_ports = []
    for port_node in host_node.findall("./ports/port"):
        state_node = port_node.find("state")
        state = state_node.attrib.get("state", "unknown") if state_node is not None else "unknown"
        if state != "open":
            continue

        service_node = port_node.find("service")
        cpe_values = [
            cpe.text.strip()
            for cpe in port_node.findall("./service/cpe")
            if cpe.text and cpe.text.strip()
        ]
        open_ports.append(
            {
                "protocol": port_node.attrib.get("protocol", "unknown"),
                "port": int(port_node.attrib.get("portid", "0")),
                "service": _service_name(service_node, port_node.attrib.get("portid", "")),
                "product": service_node.attrib.get("product", "") if service_node is not None else "",
                "version": service_node.attrib.get("version", "") if service_node is not None else "",
                "extra_info": service_node.attrib.get("extrainfo", "") if service_node is not None else "",
                "cpe_values": cpe_values,
            }
        )

    service_details = [
        {
            "port": port["port"],
            "service": port["service"],
            "product": port["product"],
            "version": port["version"],
            "extra_info": port["extra_info"],
        }
        for port in open_ports
    ]
    cpe_values = [cpe for port in open_ports for cpe in port["cpe_values"]]

    return {
        "ip_address": ip_address,
        "hostname": hostnames[0] if hostnames else None,
        "all_hostnames": hostnames,
        "status": status_node.attrib.get("state", "unknown") if status_node is not None else "unknown",
        "mac_address": mac_address,
        "vendor": vendor,
        "os_guess": os_match.attrib.get("name") if os_match is not None else None,
        "open_ports": open_ports,
        "service_details": service_details,
        "cpe_values": cpe_values,
        "risk_score": 0,
        "risk_level": "Low",
        "risk_reasons": [],
        "recommendations": [],
        "cve_references": [],
    }


def _service_name(service_node: ET.Element | None, fallback_port: str) -> str:
    if service_node is not None and service_node.attrib.get("name"):
        return service_node.attrib["name"].lower()

    return {
        "21": "ftp",
        "22": "ssh",
        "23": "telnet",
        "80": "http",
        "443": "https",
        "445": "microsoft-ds",
        "3389": "ms-wbt-server",
        "5900": "vnc",
        "3306": "mysql",
        "5432": "postgresql",
        "6379": "redis",
        "27017": "mongodb",
        "9200": "elasticsearch",
    }.get(fallback_port, "unknown")
