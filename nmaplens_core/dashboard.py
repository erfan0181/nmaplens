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
    .graph-shell {{
      display: grid;
      grid-template-columns: minmax(0, 1fr) 260px;
      gap: 16px;
      align-items: start;
    }}
    .graph-wrap {{
      background: linear-gradient(180deg, rgba(255,255,255,0.02), rgba(76,201,240,0.05));
      border: 1px solid var(--border);
      border-radius: 16px;
      padding: 14px;
      overflow: auto;
    }}
    .graph-legend {{
      display: grid;
      gap: 12px;
    }}
    .legend-card {{
      background: var(--panel-alt);
      border: 1px solid var(--border);
      border-radius: 16px;
      padding: 14px;
    }}
    .legend-card h3 {{
      margin: 0 0 10px;
      font-size: 1rem;
    }}
    .legend-list {{
      list-style: none;
      margin: 0;
      padding: 0;
      display: grid;
      gap: 8px;
    }}
    .legend-list li {{
      display: flex;
      align-items: center;
      gap: 10px;
      color: var(--muted);
      font-size: 0.95rem;
    }}
    .swatch {{
      width: 14px;
      height: 14px;
      border-radius: 999px;
      display: inline-block;
      border: 1px solid rgba(255,255,255,0.08);
    }}
    .graph-note {{
      color: var(--muted);
      margin: 0 0 14px;
    }}
    #network-graph {{
      width: 100%;
      min-width: 760px;
      height: 520px;
      display: block;
    }}
    .graph-node {{
      cursor: pointer;
      transition: opacity 0.18s ease, transform 0.18s ease;
    }}
    .graph-node text {{
      pointer-events: none;
      fill: var(--text);
      font-size: 13px;
      font-weight: 600;
    }}
    .graph-node circle,
    .graph-node rect {{
      stroke: rgba(255,255,255,0.12);
      stroke-width: 1.2;
    }}
    .graph-edge {{
      stroke: rgba(159, 176, 195, 0.45);
      stroke-width: 1.5;
      transition: opacity 0.18s ease, stroke-width 0.18s ease;
    }}
    .graph-node.is-dim,
    .graph-edge.is-dim {{
      opacity: 0.18;
    }}
    .graph-node.is-active circle,
    .graph-node.is-active rect {{
      stroke: var(--accent);
      stroke-width: 2;
    }}
    .graph-edge.is-active {{
      stroke: var(--accent);
      stroke-width: 2.6;
      opacity: 1;
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
    @media (max-width: 980px) {{
      .graph-shell {{ grid-template-columns: 1fr; }}
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

    <section class="panel">
      <h2 class="section-title">Network Graph</h2>
      <p class="graph-note">Click a host or service node to highlight related exposure paths.</p>
      <div class="graph-shell">
        <div class="graph-wrap">
          <svg id="network-graph" viewBox="0 0 980 520" role="img" aria-label="Network exposure graph"></svg>
        </div>
        <div class="graph-legend">
          <div class="legend-card">
            <h3>Risk Levels</h3>
            <ul class="legend-list">
              <li><span class="swatch" style="background:#7ee787"></span> Low</li>
              <li><span class="swatch" style="background:#f2cc60"></span> Medium</li>
              <li><span class="swatch" style="background:#ff938a"></span> High</li>
              <li><span class="swatch" style="background:#ff92a8"></span> Critical</li>
            </ul>
          </div>
          <div class="legend-card">
            <h3>How To Read</h3>
            <ul class="legend-list">
              <li>Rounded blocks are hosts.</li>
              <li>Circles are grouped services.</li>
              <li>Lines connect each host to its exposed services.</li>
            </ul>
          </div>
        </div>
      </div>
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
    const graphSvg = document.getElementById("network-graph");
    const graphNamespace = "http://www.w3.org/2000/svg";

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

    function serviceKey(port) {{
      const service = (port.service || "unknown").trim() || "unknown";
      return service.toLowerCase();
    }}

    function serviceLabel(port) {{
      const service = (port.service || "unknown").trim() || "unknown";
      return service;
    }}

    function riskColor(level) {{
      return {{
        Low: "#7ee787",
        Medium: "#f2cc60",
        High: "#ff938a",
        Critical: "#ff92a8",
      }}[level] || "#4cc9f0";
    }}

    function createSvg(tag, attributes = {{}}, text = "") {{
      const node = document.createElementNS(graphNamespace, tag);
      Object.entries(attributes).forEach(([key, value]) => node.setAttribute(key, String(value)));
      if (text) node.textContent = text;
      return node;
    }}

    function buildGraphData() {{
      const noisyServices = new Set(["msrpc", "ncacn_http", "tcpwrapped"]);
      const hostNodes = scanData.hosts.map((host, index) => ({{
        id: `host-${{index}}`,
        type: "host",
        label: host.hostname ? `${{host.ip_address}} (${{host.hostname}})` : host.ip_address,
        shortLabel: host.ip_address,
        riskLevel: host.risk_level,
        raw: host,
      }}));
      const serviceMap = new Map();
      const edges = [];

      scanData.hosts.forEach((host, hostIndex) => {{
        host.open_ports.forEach((port) => {{
          const normalizedService = (port.service || "unknown").trim().toLowerCase();
          if (noisyServices.has(normalizedService)) return;
          const key = serviceKey(port);
          if (!serviceMap.has(key)) {{
            serviceMap.set(key, {{
              id: `service-${{serviceMap.size}}`,
              type: "service",
              label: serviceLabel(port),
              service: normalizedService || "unknown",
              products: new Set(),
              ports: [],
              hosts: new Set(),
            }});
          }}
          const service = serviceMap.get(key);
          service.ports.push(port.port);
          service.hosts.add(host.ip_address);
          if (port.product) service.products.add(port.product);
          edges.push({{
            id: `edge-${{hostIndex}}-${{service.id}}-${{port.port}}`,
            from: `host-${{hostIndex}}`,
            to: service.id,
            title: `${{host.ip_address}} -> ${{service.label}} on port ${{port.port}}`,
          }});
        }});
      }});

      const serviceNodes = Array.from(serviceMap.values()).map((service) => ({{
        ...service,
        shortLabel: service.label,
        portList: Array.from(new Set(service.ports)).sort((left, right) => left - right).join(", "),
        hostCount: service.hosts.size,
        productList: Array.from(service.products).sort().join(", "),
      }}));

      return {{ hostNodes, serviceNodes, edges }};
    }}

    function resetGraphState() {{
      graphSvg.querySelectorAll(".graph-node, .graph-edge").forEach((node) => {{
        node.classList.remove("is-active", "is-dim");
      }});
    }}

    function attachGraphInteractions() {{
      const nodes = Array.from(graphSvg.querySelectorAll(".graph-node"));
      const edges = Array.from(graphSvg.querySelectorAll(".graph-edge"));

      nodes.forEach((node) => {{
        node.addEventListener("click", () => {{
          const targetId = node.getAttribute("data-node-id");
          resetGraphState();
          nodes.forEach((item) => item.classList.add("is-dim"));
          edges.forEach((item) => item.classList.add("is-dim"));

          node.classList.remove("is-dim");
          node.classList.add("is-active");

          edges
            .filter((edge) => edge.getAttribute("data-from") === targetId || edge.getAttribute("data-to") === targetId)
            .forEach((edge) => {{
              edge.classList.remove("is-dim");
              edge.classList.add("is-active");
              const from = edge.getAttribute("data-from");
              const to = edge.getAttribute("data-to");
              nodes
                .filter((item) => {{
                  const nodeId = item.getAttribute("data-node-id");
                  return nodeId === from || nodeId === to;
                }})
                .forEach((item) => {{
                  item.classList.remove("is-dim");
                  item.classList.add("is-active");
                }});
            }});
        }});
      }});

      graphSvg.addEventListener("mouseleave", resetGraphState);
      graphSvg.addEventListener("dblclick", resetGraphState);
    }}

    function renderGraph() {{
      const {{ hostNodes, serviceNodes, edges }} = buildGraphData();
      graphSvg.innerHTML = "";

      if (!hostNodes.length || !serviceNodes.length) {{
        const message = createSvg("text", {{ x: 40, y: 80, fill: "#9fb0c3", "font-size": 18 }}, "No graph data available.");
        graphSvg.appendChild(message);
        return;
      }}

      const hostSpacing = 520 / (hostNodes.length + 1);
      const serviceSpacing = 520 / (serviceNodes.length + 1);
      const positions = new Map();

      hostNodes.forEach((host, index) => {{
        positions.set(host.id, {{ x: 210, y: Math.round(hostSpacing * (index + 1)) }});
      }});
      serviceNodes.forEach((service, index) => {{
        positions.set(service.id, {{ x: 760, y: Math.round(serviceSpacing * (index + 1)) }});
      }});

      edges.forEach((edge) => {{
        const from = positions.get(edge.from);
        const to = positions.get(edge.to);
        const path = createSvg("path", {{
          d: `M ${{from.x + 86}} ${{from.y}} C 460 ${{from.y}}, 510 ${{to.y}}, ${{to.x - 34}} ${{to.y}}`,
          class: "graph-edge",
          fill: "none",
          "data-from": edge.from,
          "data-to": edge.to,
        }});
        const title = createSvg("title", {{}}, edge.title);
        path.appendChild(title);
        graphSvg.appendChild(path);
      }});

      hostNodes.forEach((host) => {{
        const pos = positions.get(host.id);
        const group = createSvg("g", {{
          class: "graph-node",
          "data-node-id": host.id,
          tabindex: 0,
        }});
        const rect = createSvg("rect", {{
          x: pos.x - 86,
          y: pos.y - 26,
          rx: 16,
          ry: 16,
          width: 172,
          height: 52,
          fill: "#162232",
        }});
        const accent = createSvg("rect", {{
          x: pos.x - 86,
          y: pos.y - 26,
          rx: 16,
          ry: 16,
          width: 9,
          height: 52,
          fill: riskColor(host.riskLevel),
        }});
        const label = createSvg("text", {{ x: pos.x - 64, y: pos.y + 5 }}, host.shortLabel);
        const title = createSvg("title", {{}}, `${{host.label}} | Risk: ${{host.riskLevel}}`);
        group.append(rect, accent, label, title);
        graphSvg.appendChild(group);
      }});

      serviceNodes.forEach((service) => {{
        const pos = positions.get(service.id);
        const group = createSvg("g", {{
          class: "graph-node",
          "data-node-id": service.id,
          tabindex: 0,
        }});
        const circle = createSvg("circle", {{
          cx: pos.x,
          cy: pos.y,
          r: 26,
          fill: "#203248",
        }});
        const label = createSvg("text", {{ x: pos.x + 42, y: pos.y - 2 }}, service.service.toUpperCase());
        const meta = createSvg("text", {{
          x: pos.x + 42,
          y: pos.y + 17,
          fill: "#9fb0c3",
          "font-size": 11,
          "font-weight": 500,
        }}, `Ports: ${{service.portList}}`);
        const detail = service.productList ? ` | Products: ${{service.productList}}` : "";
        const title = createSvg("title", {{}}, `${{service.label}} | Ports: ${{service.portList}} | Hosts: ${{service.hostCount}}${{detail}}`);
        group.append(circle, label, meta, title);
        graphSvg.appendChild(group);
      }});

      attachGraphInteractions();
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
    renderGraph();
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
