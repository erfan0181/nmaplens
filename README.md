# NmapLens

NmapLens is a beginner-friendly but professional Python command-line tool that reads Nmap XML scan results and generates HTML, JSON, and Markdown security reports.

## Features

- Parse Nmap XML scan results
- Extract scan metadata, host details, open ports, services, versions, and CPE values
- Score host exposure based on risky services
- Explain risk reasons in plain language
- Suggest useful next-step Nmap commands
- Generate offline HTML, JSON, and Markdown reports
- Produce a summary of common ports and services
- Use Python standard library only

## Installation

```bash
git clone https://github.com/your-name/nmaplens.git
cd nmaplens
python3 nmaplens.py --help
```

## Usage

Basic summary:

```bash
python3 nmaplens.py --input examples/sample_scan.xml
```

Generate all report formats:

```bash
python3 nmaplens.py \
  --input examples/sample_scan.xml \
  --html output/report.html \
  --json output/report.json \
  --markdown output/report.md
```

Summary only:

```bash
python3 nmaplens.py --input examples/sample_scan.xml --summary-only
```

Verbose console output:

```bash
python3 nmaplens.py --input examples/sample_scan.xml --verbose
```

## Example Nmap Scan Command

```bash
nmap -sV -O -oX scan.xml TARGET
```

## Example Output

```text
NmapLens Summary
Scanner: nmap 7.95
Scan start: 2026-05-20 12:00 UTC
Total hosts: 2
Online hosts: 2
Total open ports: 6
Risk counts: Low=0, Medium=1, High=1, Critical=0
```

## Output Files

- `output/report.html`: dark-theme offline dashboard
- `output/report.json`: structured machine-readable report
- `output/report.md`: Markdown report for notes and Git repositories

## Project Structure

```text
nmaplens/
├── nmaplens.py
├── README.md
├── requirements.txt
├── examples/
│   └── sample_scan.xml
├── output/
│   ├── report.html
│   ├── report.json
│   └── report.md
└── nmaplens_core/
    ├── __init__.py
    ├── parser.py
    ├── risk.py
    ├── recommendations.py
    ├── html_report.py
    ├── json_report.py
    ├── markdown_report.py
    └── utils.py
```

## Roadmap

- CVE lookup using CPE
- Web dashboard
- Compare two scans
- PDF export
- Network graph
- Screenshot capture for web services
- Docker support
- Nessus and Burp import

## Security Disclaimer

This tool is intended for educational and authorized security testing only. Only scan systems you own or have explicit permission to test.

## License Suggestion

MIT
