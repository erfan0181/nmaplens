# Changelog

All notable changes to this project will be documented in this file.

## [0.8.0] - 2026-05-20

### Added

- Built-in dashboard network graph for host-to-service visualization
- Interactive SVG graph highlighting for related host and service exposure paths

## [0.7.2] - 2026-05-20

### Changed

- Updated README preview images with real dashboard screenshots

## [0.7.1] - 2026-05-20

### Changed

- Improved dashboard CVE references with cleaner labels and Exploit-DB links
- Reduced noisy recommended commands for large Windows and Active Directory hosts
- Hardened `.gitignore` to avoid committing local scan artifacts and generated files

## [0.6.0] - 2026-05-20

### Added

- Simple offline PDF export with `--pdf`

## [0.5.0] - 2026-05-20

### Added

- Dockerfile and container usage documentation

## [0.4.0] - 2026-05-20

### Added

- CPE-based CVE reference generation
- Fallback product-based CVE search references for services without usable CPE data

## [0.3.0] - 2026-05-20

### Added

- Compare-only mode with `--compare-only`
- JSON, HTML, and Markdown comparison summaries

## [0.2.0] - 2026-05-20

### Added

- Baseline scan comparison with `--baseline`
- Sample baseline XML and automated tests for scan diffs
- Open source community files including license, contribution guide, and issue templates

### Changed

- Removed internal project notes file from the repository

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
