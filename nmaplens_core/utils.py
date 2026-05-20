from __future__ import annotations

from collections import Counter
from pathlib import Path


DISCLAIMER = (
    "This tool is intended for educational and authorized security testing only. "
    "Only scan systems you own or have explicit permission to test."
)


def ensure_output_path(raw_path: str) -> Path:
    path = Path(raw_path)
    if path.exists() and path.is_dir():
        raise ValueError(f"Invalid output path: {path} is a directory")
    path.parent.mkdir(parents=True, exist_ok=True)
    return path


def build_summary(hosts: list[dict[str, object]]) -> dict[str, object]:
    online_hosts = sum(1 for host in hosts if host["status"] == "up")
    total_open_ports = sum(len(host["open_ports"]) for host in hosts)
    risk_counts = {"Low": 0, "Medium": 0, "High": 0, "Critical": 0}
    port_counter: Counter[str] = Counter()
    service_counter: Counter[str] = Counter()

    for host in hosts:
        risk_counts[str(host["risk_level"])] += 1
        for port in host["open_ports"]:
            port_counter[str(port["port"])] += 1
            service_counter[str(port["service"])] += 1

    return {
        "total_hosts": len(hosts),
        "online_hosts": online_hosts,
        "total_open_ports": total_open_ports,
        "risk_counts": risk_counts,
        "most_common_open_ports": port_counter.most_common(5),
        "most_common_services": service_counter.most_common(5),
    }


def format_console_summary(scan_data: dict[str, object], *, verbose: bool, summary_only: bool) -> str:
    metadata = scan_data["scan_metadata"]
    summary = scan_data["summary"]
    hosts = scan_data["hosts"]

    lines = [
        "NmapLens Summary",
        f"Scanner: {metadata['scanner']} {metadata['version']}",
        f"Scan start: {metadata['start_time']}",
        f"Total hosts: {summary['total_hosts']}",
        f"Online hosts: {summary['online_hosts']}",
        f"Total open ports: {summary['total_open_ports']}",
        (
            "Risk counts: "
            f"Low={summary['risk_counts']['Low']}, "
            f"Medium={summary['risk_counts']['Medium']}, "
            f"High={summary['risk_counts']['High']}, "
            f"Critical={summary['risk_counts']['Critical']}"
        ),
    ]

    if summary_only:
        lines.extend(["", DISCLAIMER])
        return "\n".join(lines)

    if verbose:
        for host in hosts:
            port_summary = ", ".join(
                f"{port['port']}/{port['protocol']} {port['service']}" for port in host["open_ports"]
            ) or "None"
            lines.extend(
                [
                    "",
                    f"Host: {host['ip_address']}",
                    f"  Hostname: {host['hostname'] or 'N/A'}",
                    f"  Status: {host['status']}",
                    f"  OS guess: {host['os_guess'] or 'N/A'}",
                    f"  Risk: {host['risk_level']} ({host['risk_score']})",
                    f"  Open ports: {port_summary}",
                ]
            )

    lines.extend(["", DISCLAIMER])
    return "\n".join(lines)
