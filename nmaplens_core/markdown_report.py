from __future__ import annotations


DISCLAIMER = (
    "This tool is intended for educational and authorized security testing only. "
    "Only scan systems you own or have explicit permission to test."
)


def build_markdown_report(scan_data: dict[str, object]) -> str:
    metadata = scan_data["scan_metadata"]
    summary = scan_data["summary"]
    hosts = scan_data["hosts"]

    lines = [
        "# NmapLens Report",
        "",
        "## Scan Summary",
        "",
        f"- Scanner: {metadata['scanner']} {metadata['version']}",
        f"- Scan start: {metadata['start_time']}",
        f"- Total hosts: {summary['total_hosts']}",
        f"- Online hosts: {summary['online_hosts']}",
        f"- Total open ports: {summary['total_open_ports']}",
        f"- Low risk hosts: {summary['risk_counts']['Low']}",
        f"- Medium risk hosts: {summary['risk_counts']['Medium']}",
        f"- High risk hosts: {summary['risk_counts']['High']}",
        f"- Critical risk hosts: {summary['risk_counts']['Critical']}",
        "",
        "## Host List",
        "",
    ]

    for host in hosts:
        lines.append(f"- {host['ip_address']} ({host['risk_level']}, score {host['risk_score']})")

    lines.extend(
        [
            "",
            "## Risk Table",
            "",
            "| Host | Status | Risk Score | Risk Level | Open Ports |",
            "| --- | --- | ---: | --- | ---: |",
        ]
    )
    for host in hosts:
        lines.append(
            f"| {host['ip_address']} | {host['status']} | {host['risk_score']} | {host['risk_level']} | {len(host['open_ports'])} |"
        )

    lines.extend(["", "## Detailed Host Findings", ""])

    for host in hosts:
        lines.extend(
            [
                f"### {host['ip_address']}",
                "",
                f"- Hostname: {host['hostname'] or 'N/A'}",
                f"- MAC address: {host['mac_address'] or 'N/A'}",
                f"- Vendor: {host['vendor'] or 'N/A'}",
                f"- OS guess: {host['os_guess'] or 'N/A'}",
                f"- Risk score: {host['risk_score']}",
                f"- Risk level: {host['risk_level']}",
                "",
                "#### Risk Reasons",
                "",
            ]
        )
        for reason in host["risk_reasons"]:
            lines.append(f"- {reason}")

        lines.extend(["", "#### Open Ports", ""])
        if host["open_ports"]:
            for port in host["open_ports"]:
                details = " ".join(part for part in [port["product"], port["version"], port["extra_info"]] if part).strip()
                lines.append(
                    f"- `{port['port']}/{port['protocol']}` {port['service']}"
                    + (f" ({details})" if details else "")
                )
                if port["cpe_values"]:
                    lines.append(f"  - CPE: {', '.join(port['cpe_values'])}")
        else:
            lines.append("- No open ports found.")

        lines.extend(["", "#### Recommended Next Commands", ""])
        for command in host["recommendations"]:
            lines.append(f"- `{command.replace('TARGET', host['ip_address'])}`")
        lines.append("")

    lines.extend(["## Disclaimer", "", DISCLAIMER, ""])
    return "\n".join(lines)
