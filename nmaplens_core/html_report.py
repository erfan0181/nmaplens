from __future__ import annotations

from html import escape


DISCLAIMER = (
    "This tool is intended for educational and authorized security testing only. "
    "Only scan systems you own or have explicit permission to test."
)


def build_html_report(scan_data: dict[str, object]) -> str:
    metadata = scan_data["scan_metadata"]
    summary = scan_data["summary"]
    hosts = scan_data["hosts"]
    comparison = scan_data.get("comparison")

    summary_cards = "".join(
        _summary_card(title, value)
        for title, value in [
            ("Total Hosts", summary["total_hosts"]),
            ("Online Hosts", summary["online_hosts"]),
            ("Open Ports", summary["total_open_ports"]),
            ("Critical Hosts", summary["risk_counts"]["Critical"]),
            ("High Hosts", summary["risk_counts"]["High"]),
            ("Medium Hosts", summary["risk_counts"]["Medium"]),
            ("Low Hosts", summary["risk_counts"]["Low"]),
        ]
    )
    host_sections = "".join(_build_host_section(host) for host in hosts)
    common_ports = ", ".join(f"{port} ({count})" for port, count in summary["most_common_open_ports"]) or "None"
    common_services = ", ".join(f"{service} ({count})" for service, count in summary["most_common_services"]) or "None"
    comparison_panel = _build_comparison_panel(comparison)

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>NmapLens Report</title>
  <style>
    :root {{
      --bg: #09111b;
      --panel: #111927;
      --panel-alt: #182230;
      --border: #2b3848;
      --text: #edf2f7;
      --muted: #9fb0c3;
    }}
    * {{ box-sizing: border-box; }}
    body {{
      margin: 0;
      font-family: "Segoe UI", Tahoma, Geneva, Verdana, sans-serif;
      color: var(--text);
      background:
        radial-gradient(circle at top left, rgba(76, 201, 240, 0.18), transparent 28%),
        radial-gradient(circle at top right, rgba(255, 77, 109, 0.12), transparent 22%),
        var(--bg);
    }}
    .container {{
      width: min(1180px, calc(100% - 32px));
      margin: 0 auto;
      padding: 32px 0 48px;
    }}
    .panel {{
      background: rgba(17, 25, 39, 0.92);
      border: 1px solid var(--border);
      border-radius: 18px;
      padding: 24px;
      box-shadow: 0 20px 60px rgba(0, 0, 0, 0.28);
    }}
    .hero h1 {{ margin: 0 0 8px; }}
    .meta {{ color: var(--muted); margin: 6px 0; }}
    .grid {{
      display: grid;
      grid-template-columns: repeat(auto-fit, minmax(150px, 1fr));
      gap: 16px;
      margin: 22px 0;
    }}
    .card {{
      background: linear-gradient(180deg, rgba(255,255,255,0.03), rgba(76,201,240,0.10));
      border: 1px solid var(--border);
      border-radius: 16px;
      padding: 16px;
    }}
    .label {{ color: var(--muted); font-size: 0.9rem; }}
    .value {{ font-size: 1.8rem; font-weight: 700; margin-top: 8px; }}
    details {{
      background: var(--panel-alt);
      border: 1px solid var(--border);
      border-radius: 14px;
      padding: 16px;
      margin-top: 14px;
    }}
    summary {{ cursor: pointer; font-weight: 700; }}
    table {{ width: 100%; border-collapse: collapse; margin-top: 12px; }}
    th, td {{ text-align: left; padding: 10px 12px; border-bottom: 1px solid var(--border); vertical-align: top; }}
    .badge {{ display: inline-block; padding: 4px 10px; border-radius: 999px; font-size: 0.85rem; font-weight: 700; }}
    .Low {{ background: rgba(46,160,67,0.18); color: #7ee787; }}
    .Medium {{ background: rgba(210,153,34,0.18); color: #f2cc60; }}
    .High {{ background: rgba(248,81,73,0.18); color: #ff938a; }}
    .Critical {{ background: rgba(255,77,109,0.18); color: #ff92a8; }}
    code {{ background: rgba(159,176,195,0.12); border-radius: 8px; padding: 2px 6px; }}
    .footer {{ color: var(--muted); margin-top: 20px; }}
  </style>
</head>
<body>
  <div class="container">
    <section class="panel hero">
      <h1>NmapLens Report</h1>
      <p class="meta">Scanner: {escape(str(metadata["scanner"]))} {escape(str(metadata["version"]))}</p>
      <p class="meta">Scan start: {escape(str(metadata["start_time"]))}</p>
      <p class="meta">Most common open ports: {escape(common_ports)}</p>
      <p class="meta">Most common services: {escape(common_services)}</p>
    </section>
    <section class="grid">{summary_cards}</section>
    <section class="panel">
      <h2>Host Findings</h2>
      {host_sections}
    </section>
    {comparison_panel}
    <p class="footer">{escape(DISCLAIMER)}</p>
  </div>
</body>
</html>
"""


def _summary_card(title: str, value: object) -> str:
    return f'<div class="card"><div class="label">{escape(str(title))}</div><div class="value">{escape(str(value))}</div></div>'


def _build_host_section(host: dict[str, object]) -> str:
    rows = []
    for port in host["open_ports"]:
        cpes = ", ".join(port["cpe_values"]) if port["cpe_values"] else "N/A"
        details = " ".join(part for part in [port["product"], port["version"], port["extra_info"]] if part).strip() or "N/A"
        rows.append(
            "<tr>"
            f"<td>{escape(str(port['port']))}/{escape(str(port['protocol']))}</td>"
            f"<td>{escape(str(port['service']))}</td>"
            f"<td>{escape(details)}</td>"
            f"<td>{escape(cpes)}</td>"
            "</tr>"
        )
    ports_table = (
        "<table><thead><tr><th>Port</th><th>Service</th><th>Details</th><th>CPE</th></tr></thead>"
        f"<tbody>{''.join(rows) or '<tr><td colspan=\"4\">No open ports found.</td></tr>'}</tbody></table>"
    )
    reasons = "".join(f"<li>{escape(reason)}</li>" for reason in host["risk_reasons"])
    recommendations = "".join(
        f"<li><code>{escape(command.replace('TARGET', str(host['ip_address'])))}</code></li>"
        for command in host["recommendations"]
    )
    return f"""
<details>
  <summary>{escape(str(host['ip_address']))} - <span class="badge {escape(str(host['risk_level']))}">{escape(str(host['risk_level']))}</span></summary>
  <p class="meta">Hostname: {escape(str(host['hostname'] or 'N/A'))}</p>
  <p class="meta">Status: {escape(str(host['status']))}</p>
  <p class="meta">MAC address: {escape(str(host['mac_address'] or 'N/A'))}</p>
  <p class="meta">Vendor: {escape(str(host['vendor'] or 'N/A'))}</p>
  <p class="meta">OS guess: {escape(str(host['os_guess'] or 'N/A'))}</p>
  <p class="meta">Risk score: {escape(str(host['risk_score']))}</p>
  {ports_table}
  <h3>Risk Reasons</h3>
  <ul>{reasons}</ul>
  <h3>Recommended Next Steps</h3>
  <ul>{recommendations}</ul>
</details>
"""


def _build_comparison_panel(comparison: dict[str, object] | None) -> str:
    if not comparison:
        return ""

    changed_rows = []
    for host in comparison["changed_hosts"]:
        added = ", ".join(
            f"{port['port']}/{port['protocol']} {port['service']}" for port in host["added_ports"]
        ) or "None"
        removed = ", ".join(
            f"{port['port']}/{port['protocol']} {port['service']}" for port in host["removed_ports"]
        ) or "None"
        service_changes = ", ".join(
            f"{item['port']}/{item['protocol']}: {item['before']} -> {item['after']}"
            for item in host["service_changes"]
        ) or "None"
        changed_rows.append(
            "<tr>"
            f"<td>{escape(str(host['ip_address']))}</td>"
            f"<td>{escape(added)}</td>"
            f"<td>{escape(removed)}</td>"
            f"<td>{escape(service_changes)}</td>"
            "</tr>"
        )

    return f"""
    <section class="panel">
      <h2>Scan Comparison</h2>
      <p class="meta">Added hosts: {escape(', '.join(comparison['added_hosts']) or 'None')}</p>
      <p class="meta">Removed hosts: {escape(', '.join(comparison['removed_hosts']) or 'None')}</p>
      <table>
        <thead>
          <tr><th>Host</th><th>Added Ports</th><th>Removed Ports</th><th>Service Changes</th></tr>
        </thead>
        <tbody>{''.join(changed_rows) or '<tr><td colspan="4">No host-level port changes detected.</td></tr>'}</tbody>
      </table>
    </section>
"""
