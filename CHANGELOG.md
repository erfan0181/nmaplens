# Changelog

All notable changes to this project will be documented in this file.

## [0.2.0] - Unreleased

### Added

- Baseline scan comparison with `--baseline`
- Compare-only mode with `--compare-only`
- CPE-based NVD CVE reference generation
- Dockerfile and container usage documentation
- Simple PDF export with `--pdf`
- Local web dashboard with `--dashboard`
- Built-in dashboard network graph for host-to-service visualization
- Console, JSON, HTML, and Markdown comparison summaries
- Sample baseline XML and automated tests for scan diffs

## [0.1.0] - 2026-05-20

### Added

- Initial NmapLens CLI implementation
- Nmap XML parsing for metadata, hosts, ports, services, and CPE values
- Risk scoring and plain-language risk reasons
- Recommended follow-up Nmap commands per detected service
- Offline HTML, JSON, and Markdown report generation
- Sample scan file and generated example outputs
- Local test suite with `unittest`
- GitHub Actions CI workflow
