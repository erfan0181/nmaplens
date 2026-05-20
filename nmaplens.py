from __future__ import annotations

import argparse
import sys

from nmaplens_core.html_report import build_html_report
from nmaplens_core.json_report import build_json_report
from nmaplens_core.markdown_report import build_markdown_report
from nmaplens_core.compare import build_scan_diff
from nmaplens_core.parser import parse_nmap_xml
from nmaplens_core.recommendations import enrich_recommendations
from nmaplens_core.risk import enrich_risk
from nmaplens_core.utils import build_summary, ensure_output_path, format_console_summary


def build_argument_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Generate HTML, JSON, and Markdown reports from Nmap XML scan results."
    )
    parser.add_argument("--input", required=True, help="Path to the Nmap XML scan file")
    parser.add_argument("--html", help="Path to write the HTML report")
    parser.add_argument("--json", help="Path to write the JSON report")
    parser.add_argument("--markdown", help="Path to write the Markdown report")
    parser.add_argument(
        "--baseline",
        help="Path to an older Nmap XML scan file for comparison against the current scan",
    )
    parser.add_argument(
        "--compare-only",
        action="store_true",
        help="Show only scan differences when used with --baseline",
    )
    parser.add_argument("--verbose", action="store_true", help="Print host details to the console")
    parser.add_argument(
        "--summary-only",
        action="store_true",
        help="Print the summary only without host-by-host console details",
    )
    return parser


def main() -> int:
    parser = build_argument_parser()
    args = parser.parse_args()

    try:
        scan_data = parse_nmap_xml(args.input)
        enrich_risk(scan_data["hosts"])
        enrich_recommendations(scan_data["hosts"])
        scan_data["summary"] = build_summary(scan_data["hosts"])
        if args.baseline:
            baseline_data = parse_nmap_xml(args.baseline)
            scan_data["comparison"] = build_scan_diff(baseline_data["hosts"], scan_data["hosts"])
        if args.compare_only:
            if not args.baseline:
                raise ValueError("--compare-only requires --baseline")
            scan_data["comparison_only"] = True
    except FileNotFoundError:
        print(f"Error: Input file not found: {args.input}", file=sys.stderr)
        return 1
    except PermissionError as exc:
        print(f"Error: Permission denied: {exc}", file=sys.stderr)
        return 1
    except ValueError as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 1

    if args.html:
        try:
            output_path = ensure_output_path(args.html)
            output_path.write_text(build_html_report(scan_data), encoding="utf-8")
        except (OSError, ValueError) as exc:
            print(f"Error writing HTML report: {exc}", file=sys.stderr)
            return 1

    if args.json:
        try:
            output_path = ensure_output_path(args.json)
            output_path.write_text(build_json_report(scan_data), encoding="utf-8")
        except (OSError, ValueError) as exc:
            print(f"Error writing JSON report: {exc}", file=sys.stderr)
            return 1

    if args.markdown:
        try:
            output_path = ensure_output_path(args.markdown)
            output_path.write_text(build_markdown_report(scan_data), encoding="utf-8")
        except (OSError, ValueError) as exc:
            print(f"Error writing Markdown report: {exc}", file=sys.stderr)
            return 1

    print(format_console_summary(scan_data, verbose=args.verbose, summary_only=args.summary_only))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
