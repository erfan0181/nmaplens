# NmapLens Roadmap

This roadmap is based on the current repository state and focuses on realistic, incremental improvements. It is intended to help contributors understand what already works, what should be stabilized first, and where the project can grow next without breaking existing strengths.

## 1. Current Project Status

NmapLens is already a functional attack-surface review tool for offline Nmap XML analysis. It currently supports:

- Nmap XML parsing for hosts, ports, service metadata, hostnames, MAC/vendor data, OS guesses, and CPE values
- Rule-based risk scoring and plain-language risk reasons
- Recommended follow-up Nmap commands grouped by detected service
- CVE reference generation using detected CPE values, plus fallback keyword-based CVE and Exploit-DB search links
- Console summaries and detailed structured output
- HTML, JSON, Markdown, and PDF report generation
- Baseline comparison between two scans, including host and port-level changes
- A local dashboard with host explorer, CVE references, comparison view, and built-in network graph visualization
- Docker packaging for local execution
- Automated CI test runs on multiple Python versions
- Project documentation, screenshots, contribution guide, and release history

The project is beyond prototype stage, but it is still closer to a polished single-user CLI/reporting tool than a production-grade attack surface platform.

## 2. Current Strengths

- Nmap XML parsing is already implemented and reliable for the current sample and real-world workflows.
- The dashboard is useful today, not just a placeholder. It includes host exploration, CVE links, and graph visualization.
- Graph visualization already gives a meaningful host-to-service exposure view without adding external frontend dependencies.
- Reporting is broad for a small project: console, HTML, JSON, Markdown, and PDF are all supported.
- Baseline comparison is implemented and already useful for simple scan drift detection.
- Docker support makes local execution easier and reduces environment friction.
- CI exists and runs the test suite across supported Python versions.
- Documentation is stronger than most early-stage tools, including screenshots and contributor-facing files.
- The codebase stays lightweight and dependency-minimal, which makes local setup simple.

## 3. Known Limitations

- The overall structure is still partially monolithic.
- The CLI orchestrates the full pipeline directly, and several modules rely on untyped nested dictionaries instead of explicit domain models.
- The dashboard is implemented as a large inline HTML/CSS/JavaScript template, which makes long-term maintenance harder.
- The risk engine is intentionally simple and service-based, so it does not yet model exposure context, service versions, authentication posture, or host criticality.
- Web fingerprinting is limited to what Nmap already exposes plus follow-up command suggestions.
- Historical intelligence is limited to one baseline comparison and does not store scan history over time.
- Search and filtering in the dashboard are useful but still basic.
- There is no AI explanation layer for turning raw findings into prioritized remediation narratives.
- There is no real-time scan mode or streaming workflow; analysis starts after an XML file already exists.
- There is no public API, no persistent storage layer, and no normalized internal schema versioning.
- Test coverage is useful but still narrow compared with the feature surface, especially around rendering behavior and edge-case scans.
- Packaging is still lightweight. The project currently lacks stronger distribution structure such as a formal installable package workflow.

## 4. Roadmap Phases

### Phase 1: Architecture Refactor

**Goal**

Stabilize the internal structure before the project grows further.

**Why it matters**

Most future features will become harder to add safely if the project continues to depend on large dictionary payloads, string-based templates, and tightly coupled CLI orchestration.

**Tasks**

- [ ] Introduce explicit internal data models for scan, host, port, comparison, and reference objects.
- [ ] Separate pipeline stages more clearly: parse, enrich, compare, render, and serve.
- [ ] Split the dashboard template into smaller render helpers or static template assets.
- [ ] Reduce duplicated presentation logic across console, HTML, Markdown, and dashboard outputs.
- [ ] Add a lightweight configuration layer for reusable defaults.
- [ ] Review file layout and move toward a cleaner installable package structure.

**Complexity:** High  
**Priority:** Critical  
**Expected user impact:** Higher reliability, safer feature growth, fewer regressions, easier contributions

### Phase 2: Risk Engine Upgrade

**Goal**

Make risk scoring more defensible and more useful for prioritization.

**Why it matters**

The current score is helpful for simple triage, but it is still mostly a static per-service heuristic. That limits trust in the output for larger or more varied environments.

**Tasks**

- [ ] Separate service risk, host exposure risk, and business impact scoring concepts.
- [ ] Incorporate contextual factors such as remote access exposure, insecure legacy protocols, and database exposure patterns.
- [ ] Use version-aware bonuses or penalties where service metadata is strong enough to justify them.
- [ ] Add weighted scoring rules for domain controller, database, admin interface, and web surface patterns.
- [ ] Improve explanation text so every risk score maps to clearer reasoning.
- [ ] Add focused tests for scoring edge cases.

**Complexity:** High  
**Priority:** High  
**Expected user impact:** Better prioritization, more credible findings, stronger practical value

### Phase 3: Attack Surface Visualization

**Goal**

Expand the current graph and dashboard views into a more useful exposure analysis interface.

**Why it matters**

The graph already proves the concept. The next step is to make it more informative for dense environments instead of only visually interesting.

**Tasks**

- [ ] Add graph filtering by host, service, and risk level.
- [ ] Add optional grouping views for web, Windows/AD, remote access, and database services.
- [ ] Show host counts, shared services, and high-risk clusters more clearly.
- [ ] Add graph tooltips or side-panel details for selected nodes.
- [ ] Support rendering larger scans without the graph becoming unreadable.
- [ ] Keep the graph dependency-light unless scale clearly requires a dedicated frontend library.

**Complexity:** Medium  
**Priority:** High  
**Expected user impact:** Faster understanding of exposure relationships and service concentration

### Phase 4: Historical Scan Intelligence

**Goal**

Move from one-off diffing toward time-based scan intelligence.

**Why it matters**

Baseline comparison exists today, but real operational value comes from tracking trends, repeated changes, and recurring risky exposure over time.

**Tasks**

- [ ] Introduce a simple local history format for storing normalized scan snapshots.
- [ ] Add commands for comparing the current scan against the latest saved scan automatically.
- [ ] Track recurring changes such as newly opened ports, disappearing services, and repeated risky hosts.
- [ ] Generate trend summaries for open ports and risk counts across scans.
- [ ] Add dashboard sections for recent changes and scan history summaries.

**Complexity:** High  
**Priority:** Medium  
**Expected user impact:** Better operational awareness and stronger repeated-use value

### Phase 5: Web Intelligence Layer

**Goal**

Improve analysis depth for HTTP and HTTPS services.

**Why it matters**

Web services are often the largest exposed surface in real scans, and current logic mostly stops at Nmap-discovered banners plus recommended follow-up commands.

**Tasks**

- [ ] Expand HTTP/HTTPS classification in the internal model.
- [ ] Add lightweight parsing for titles, headers, auth indicators, redirects, and common web fingerprints when available in scan results.
- [ ] Improve report summaries for web stacks such as IIS, Apache, Nginx, and generic HTTP APIs.
- [ ] Add optional screenshot capture planning hooks without making screenshots a hard dependency yet.
- [ ] Keep this phase scoped to enrichment and reporting, not full web crawling.

**Complexity:** Medium  
**Priority:** Medium  
**Expected user impact:** Better insight into web-exposed hosts without leaving NmapLens immediately

### Phase 6: Search and Filtering

**Goal**

Make the existing dashboard and output more usable for larger scans.

**Why it matters**

Current search and filtering are enough for small scans, but larger host counts will quickly outgrow the current interface.

**Tasks**

- [ ] Add dashboard filters for service name, open port, hostname, vendor, and operating system.
- [ ] Add sorting controls for risk score, host count, and open port count.
- [ ] Add quick filters for web, database, remote access, and Windows/AD-related hosts.
- [ ] Add compare-focused filtering for added, removed, and changed hosts.
- [ ] Consider search normalization for aliases such as `rdp`, `ms-wbt-server`, and `microsoft-ds`.

**Complexity:** Medium  
**Priority:** Medium  
**Expected user impact:** Faster navigation and less manual scanning of large host lists

### Phase 7: AI Explanation Layer

**Goal**

Add optional higher-level explanation and remediation guidance on top of the structured findings.

**Why it matters**

The project already has useful raw findings, but users still need to translate those findings into action. AI assistance can help summarize, explain, and prioritize when used carefully.

**Tasks**

- [ ] Design a clean optional interface for AI-generated summaries rather than tightly coupling to a single provider.
- [ ] Generate host-level remediation summaries from structured scan data.
- [ ] Generate executive summaries and analyst summaries separately.
- [ ] Clearly separate deterministic findings from AI-generated interpretation.
- [ ] Add privacy and redaction controls before any external AI integration is considered.

**Complexity:** High  
**Priority:** Low  
**Expected user impact:** Better readability and prioritization, especially for mixed-skill teams

### Phase 8: Real-Time Scan Mode

**Goal**

Allow NmapLens to participate earlier in the workflow instead of only after XML export.

**Why it matters**

Today NmapLens begins after scan completion. A real-time mode would make the tool more interactive and more useful during active assessment.

**Tasks**

- [ ] Add a controlled mode that runs Nmap directly and captures XML output.
- [ ] Support incremental status updates while scans are running.
- [ ] Preserve the current offline analysis mode as the default and safest path.
- [ ] Ensure clear warnings around authorized usage remain visible.
- [ ] Keep real-time mode optional so the project does not become dependent on one workflow.

**Complexity:** High  
**Priority:** Low  
**Expected user impact:** Smoother workflow for repeat users and less manual handoff between tools

### Phase 9: UI/UX Polish

**Goal**

Make the interface more polished without replacing the lightweight architecture.

**Why it matters**

The dashboard is already useful, but better hierarchy, spacing, interaction detail, and reporting consistency will make it feel much more mature.

**Tasks**

- [ ] Improve dashboard spacing, responsive behavior, and visual hierarchy for dense host cards.
- [ ] Add clearer selected-state feedback in the network graph.
- [ ] Align terminology across console, dashboard, HTML, Markdown, and PDF outputs.
- [ ] Improve empty states and error states for sparse or unusual scans.
- [ ] Add a more intentional information architecture for host details, commands, and references.

**Complexity:** Medium  
**Priority:** Medium  
**Expected user impact:** Better readability, lower cognitive load, more professional presentation

### Phase 10: Open Source Professionalization

**Goal**

Strengthen project operations so outside contributors can trust and extend the codebase.

**Why it matters**

The repository already looks serious. The next step is to make the maintenance workflow match that appearance.

**Tasks**

- [ ] Expand test coverage beyond core happy paths.
- [ ] Add more scan fixtures representing Windows, Linux, mixed web, and edge-case XML structures.
- [ ] Add release notes discipline tied to tagged versions.
- [ ] Add developer setup guidance for local verification of dashboard, Docker, and report outputs.
- [ ] Add issue labels, contribution examples, and triage workflow notes.
- [ ] Consider packaging and distribution improvements once the internal structure is more stable.

**Complexity:** Medium  
**Priority:** High  
**Expected user impact:** Better contributor confidence, safer releases, and easier long-term maintenance

## 5. Quick Wins

These improvements can likely be delivered quickly without major architectural disruption:

- [ ] Add `ROADMAP.md` links from the README for contributor visibility
- [ ] Add more dashboard filters for service and port
- [ ] Add compare-specific filter chips in the dashboard
- [ ] Improve graph node labeling for large host sets
- [ ] Add more scan fixtures to the test suite
- [ ] Refine recommendation text for web, LDAP, MSSQL, and RDP-heavy hosts
- [ ] Add safer validation around empty or malformed service metadata
- [ ] Add simple report metadata such as baseline file name when comparison mode is used
- [ ] Clean up tracked sample output policy and document which generated outputs are intentionally versioned

## 6. Long-Term Vision

NmapLens can become a serious open-source attack surface analysis tool by staying focused on what it already does well:

- turn raw Nmap XML into structured, explainable security findings
- make host and service exposure easier to understand visually
- support repeated scan review, not just one-time reporting
- remain lightweight enough for local analyst workflows
- grow toward deeper intelligence without losing transparency

The strongest long-term path is not to become a generic scanner replacement. The stronger path is to become a reliable analysis and reporting layer on top of Nmap:

- dependable offline analysis
- useful risk-based prioritization
- meaningful historical comparison
- clearer exposure visualization
- optional AI-assisted explanation

If the project first strengthens its internal architecture and testability, it can reasonably grow into a mature open-source tool for attack surface review, change tracking, and reporting without abandoning its current simplicity.
