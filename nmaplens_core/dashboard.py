from __future__ import annotations

import json
from html import escape
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer


def build_dashboard_html(scan_data: dict[str, object]) -> str:
    payload = json.dumps(scan_data).replace("</", "<\\/")
    html = """<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>NmapLens Dashboard</title>
  <style>
    :root {{
      --bg: #081018;
      --panel: #101a26;
      --panel-alt: #142131;
      --border: #2b3848;
      --text: #edf2f7;
      --muted: #9fb0c3;
      --accent: #4cc9f0;
      --good: #7ee787;
      --warn: #f2cc60;
      --bad: #ff938a;
      --critical: #ff92a8;
    }}
    * {{ box-sizing: border-box; }}
    body {{
      margin: 0;
      font-family: "Segoe UI", Tahoma, Geneva, Verdana, sans-serif;
      background:
        radial-gradient(circle at top left, rgba(76, 201, 240, 0.14), transparent 28%),
        radial-gradient(circle at bottom right, rgba(255, 77, 109, 0.10), transparent 26%),
        var(--bg);
      color: var(--text);
    }}
    .wrap {{ width: min(1220px, calc(100% - 28px)); margin: 0 auto; padding: 24px 0 40px; }}
    .panel {{
      background: rgba(16, 26, 38, 0.94);
      border: 1px solid var(--border);
      border-radius: 18px;
      padding: 20px;
      box-shadow: 0 18px 60px rgba(0, 0, 0, 0.24);
    }}
    .hero {{ display: grid; gap: 10px; }}
    .hero h1 {{ margin: 0; font-size: 2rem; }}
    .muted {{ color: var(--muted); }}
    .grid {{
      display: grid;
      grid-template-columns: repeat(auto-fit, minmax(150px, 1fr));
      gap: 14px;
      margin: 18px 0 22px;
    }}
    .card {{
      background: linear-gradient(180deg, rgba(255,255,255,0.03), rgba(76,201,240,0.08));
      border: 1px solid var(--border);
      border-radius: 16px;
      padding: 16px;
    }}
    .card strong {{ display: block; font-size: 1.7rem; margin-top: 8px; }}
    .toolbar {{
      display: flex;
      gap: 12px;
      flex-wrap: wrap;
      align-items: center;
      margin: 18px 0;
    }}
    input, select {{
      background: #0d1520;
      color: var(--text);
      border: 1px solid var(--border);
      border-radius: 10px;
      padding: 10px 12px;
      min-width: 180px;
    }}
    .section-title {{ margin: 0 0 14px; }}
    .host-grid {{
      display: grid;
      grid-template-columns: repeat(auto-fit, minmax(320px, 1fr));
      gap: 16px;
    }}
    .host-card {{
      background: var(--panel-alt);
      border: 1px solid var(--border);
      border-radius: 16px;
      padding: 16px;
    }}
    .host-card h3 {{ margin: 0 0 8px; }}
    .badge {{
      display: inline-block;
      padding: 4px 10px;
      border-radius: 999px;
      font-size: 0.82rem;
      font-weight: 700;
    }}
    .Low {{ background: rgba(46,160,67,0.18); color: var(--good); }}
    .Medium {{ background: rgba(210,153,34,0.18); color: var(--warn); }}
    .High {{ background: rgba(248,81,73,0.18); color: var(--bad); }}
    .Critical {{ background: rgba(255,77,109,0.18); color: var(--critical); }}
    .ports {{ margin: 10px 0 0; padding-left: 18px; }}
    .ports li, .list li {{ margin: 6px 0; }}
    .list {{ padding-left: 18px; }}
    .comparison {{
      margin-top: 22px;
      display: none;
    }}
    .comparison.show {{ display: block; }}
    .table-wrap {{ overflow: auto; }}
    table {{ width: 100%; border-collapse: collapse; }}
    th, td {{ text-align: left; padding: 10px 12px; border-bottom: 1px solid var(--border); vertical-align: top; }}
    @media (max-width: 720px) {{
      .hero h1 {{ font-size: 1.55rem; }}
      .wrap {{ width: min(100% - 18px, 1220px); }}
    }}
  </style>
</head>
<body>
  <div class="wrap">
    <section class="panel hero">
      <h1>NmapLens Dashboard</h1>
      <div class="muted" id="meta-line"></div>
      <div class="muted" id="common-line"></div>
    </section>

    <section class="grid" id="summary-grid"></section>

    <section class="panel">
      <h2 class="section-title">Host Explorer</h2>
      <div class="toolbar">
        <input id="search" type="search" placeholder="Search by IP, hostname, service">
        <select id="risk-filter">
          <option value="">All risk levels</option>
          <option value="Critical">Critical</option>
          <option value="High">High</option>
          <option value="Medium">Medium</option>
          <option value="Low">Low</option>
        </select>
      </div>
      <div class="host-grid" id="host-grid"></div>
    </section>

    <section class="panel comparison" id="comparison-panel">
      <h2 class="section-title">Comparison</h2>
      <div class="muted" id="comparison-summary"></div>
      <div class="table-wrap">
        <table>
          <thead>
            <tr><th>Host</th><th>Added Ports</th><th>Removed Ports</th><th>Service Changes</th></tr>
          </thead>
          <tbody id="comparison-body"></tbody>
        </table>
      </div>
    </section>
  </div>

  <script>
    const scanData = __PAYLOAD__;

    const summaryGrid = document.getElementById("summary-grid");
    const hostGrid = document.getElementById("host-grid");
    const searchInput = document.getElementById("search");
    const riskFilter = document.getElementById("risk-filter");
    const metaLine = document.getElementById("meta-line");
    const commonLine = document.getElementById("common-line");
    const comparisonPanel = document.getElementById("comparison-panel");
    const comparisonSummary = document.getElementById("comparison-summary");
    const comparisonBody = document.getElementById("comparison-body");

    function escapeHtml(value) {{
      return String(value)
        .replaceAll("&", "&amp;")
        .replaceAll("<", "&lt;")
        .replaceAll(">", "&gt;");
    }}

    function renderSummary() {{
      const summary = scanData.summary;
      const cards = [
        ["Total Hosts", summary.total_hosts],
        ["Online Hosts", summary.online_hosts],
        ["Open Ports", summary.total_open_ports],
        ["Critical", summary.risk_counts.Critical],
        ["High", summary.risk_counts.High],
        ["Medium", summary.risk_counts.Medium],
        ["Low", summary.risk_counts.Low],
      ];
      summaryGrid.innerHTML = cards.map(([label, value]) => `
        <div class="card">
          <div class="muted">${{escapeHtml(label)}}</div>
          <strong>${{escapeHtml(value)}}</strong>
        </div>
      `).join("");

      const metadata = scanData.scan_metadata;
      metaLine.textContent = `Scanner: ${{metadata.scanner}} ${{metadata.version}} | Scan start: ${{metadata.start_time}}`;

      const ports = summary.most_common_open_ports.map(([port, count]) => `${{port}} (${{count}})`).join(", ") || "None";
      const services = summary.most_common_services.map(([service, count]) => `${{service}} (${{count}})`).join(", ") || "None";
      commonLine.textContent = `Most common ports: ${{ports}} | Most common services: ${{services}}`;
    }}

    function hostMatches(host, query, risk) {{
      const haystack = [
        host.ip_address,
        host.hostname || "",
        ...(host.all_hostnames || []),
        ...host.open_ports.map((port) => `${{port.port}} ${{port.service}} ${{port.product}}`)
      ].join(" ").toLowerCase();
      if (query && !haystack.includes(query)) return false;
      if (risk && host.risk_level !== risk) return false;
      return true;
    }}

    function renderHosts() {{
      const query = searchInput.value.trim().toLowerCase();
      const risk = riskFilter.value;
      const hosts = scanData.hosts.filter((host) => hostMatches(host, query, risk));

      hostGrid.innerHTML = hosts.map((host) => `
        <article class="host-card">
          <h3>${{escapeHtml(host.ip_address)}} <span class="badge ${{escapeHtml(host.risk_level)}}">${{escapeHtml(host.risk_level)}}</span></h3>
          <div class="muted">Hostname: ${{escapeHtml(host.hostname || "N/A")}}</div>
          <div class="muted">OS guess: ${{escapeHtml(host.os_guess || "N/A")}}</div>
          <div class="muted">Risk score: ${{escapeHtml(host.risk_score)}}</div>
          <h4>Open Ports</h4>
          <ul class="ports">
            ${(host.open_ports.length ? host.open_ports : [null]).map((port) => port
              ? `<li><strong>${{escapeHtml(port.port)}}/${{escapeHtml(port.protocol)}}</strong> ${{escapeHtml(port.service)}}${{port.product ? ` (${{escapeHtml(port.product)}} ${{escapeHtml(port.version || "")}})` : ""}}</li>`
              : "<li>No open ports found.</li>").join("")}
          </ul>
          <h4>Risk Reasons</h4>
          <ul class="list">
            ${host.risk_reasons.map((reason) => `<li>${{escapeHtml(reason)}}</li>`).join("")}
          </ul>
          <h4>Recommended Commands</h4>
          <ul class="list">
            ${host.recommendations.map((command) => `<li><code>${{escapeHtml(command.replaceAll("TARGET", host.ip_address))}}</code></li>`).join("")}
          </ul>
          <h4>CVE References</h4>
          <ul class="list">
            ${(host.cve_references && host.cve_references.length ? host.cve_references : [null]).map((reference) => reference
              ? `<li>
                  <strong>${{escapeHtml(reference.label)}}</strong><br>
                  <a href="${{escapeHtml(reference.cve_search_url || reference.nvd_cve_url)}}" target="_blank" rel="noreferrer">CVE</a>
                  ·
                  <a href="${{escapeHtml(reference.exploit_db_url)}}" target="_blank" rel="noreferrer">Exploit-DB</a>
                </li>`
              : "<li>No CPE or product-based CVE references found.</li>").join("")}
          </ul>
        </article>
      `).join("");
    }}

    function renderComparison() {{
      const comparison = scanData.comparison;
      if (!comparison) return;
      comparisonPanel.classList.add("show");
      comparisonSummary.textContent =
        `Baseline hosts: ${{comparison.baseline_host_count}} | Current hosts: ${{comparison.current_host_count}} | ` +
        `Added hosts: ${{comparison.added_hosts.join(", ") || "None"}} | Removed hosts: ${{comparison.removed_hosts.join(", ") || "None"}}`;

      comparisonBody.innerHTML = (comparison.changed_hosts.length ? comparison.changed_hosts : [null]).map((host) => {{
        if (!host) return '<tr><td colspan="4">No host-level changes detected.</td></tr>';
        const added = host.added_ports.map((port) => `${{port.port}}/${{port.protocol}} ${{port.service}}`).join(", ") || "None";
        const removed = host.removed_ports.map((port) => `${{port.port}}/${{port.protocol}} ${{port.service}}`).join(", ") || "None";
        const changes = host.service_changes.map((item) => `${{item.port}}/${{item.protocol}}: ${{item.before}} -> ${{item.after}}`).join(", ") || "None";
        return `<tr>
          <td>${{escapeHtml(host.ip_address)}}</td>
          <td>${{escapeHtml(added)}}</td>
          <td>${{escapeHtml(removed)}}</td>
          <td>${{escapeHtml(changes)}}</td>
        </tr>`;
      }}).join("");
    }}

    searchInput.addEventListener("input", renderHosts);
    riskFilter.addEventListener("change", renderHosts);

    renderSummary();
    renderHosts();
    renderComparison();
  </script>
</body>
</html>
"""
    return html.replace("{{", "{").replace("}}", "}").replace("__PAYLOAD__", payload)


def serve_dashboard(scan_data: dict[str, object], host: str, port: int) -> None:
    html = build_dashboard_html(scan_data).encode("utf-8")

    class DashboardHandler(BaseHTTPRequestHandler):
        def do_GET(self) -> None:  # noqa: N802
            if self.path not in {"/", "/index.html"}:
                self.send_error(404, "Not Found")
                return
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Content-Length", str(len(html)))
            self.end_headers()
            self.wfile.write(html)

        def log_message(self, format: str, *args: object) -> None:
            return

    server = ThreadingHTTPServer((host, port), DashboardHandler)
    try:
        print(f"Dashboard running at http://{host}:{port}")
        server.serve_forever()
    finally:
        server.server_close()
