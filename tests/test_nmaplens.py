from __future__ import annotations

import json
import subprocess
import tempfile
import unittest
from pathlib import Path

from nmaplens_core.compare import build_scan_diff
from nmaplens_core.cve_lookup import enrich_cpe_references
from nmaplens_core.parser import parse_nmap_xml
from nmaplens_core.pdf_report import build_pdf_report
from nmaplens_core.recommendations import enrich_recommendations
from nmaplens_core.risk import enrich_risk
from nmaplens_core.utils import build_summary


PROJECT_ROOT = Path(__file__).resolve().parents[1]
SAMPLE_SCAN = PROJECT_ROOT / "examples" / "sample_scan.xml"
BASELINE_SCAN = PROJECT_ROOT / "examples" / "sample_scan_baseline.xml"


class NmapLensTests(unittest.TestCase):
    def test_parser_extracts_metadata_and_hosts(self) -> None:
        scan_data = parse_nmap_xml(SAMPLE_SCAN)

        self.assertEqual(scan_data["scan_metadata"]["scanner"], "nmap")
        self.assertEqual(len(scan_data["hosts"]), 2)
        self.assertEqual(scan_data["hosts"][0]["ip_address"], "192.168.1.10")
        self.assertEqual(scan_data["hosts"][0]["hostname"], "gateway.local")

    def test_risk_and_summary_are_calculated(self) -> None:
        scan_data = parse_nmap_xml(SAMPLE_SCAN)
        enrich_risk(scan_data["hosts"])
        enrich_recommendations(scan_data["hosts"])
        enrich_cpe_references(scan_data["hosts"])
        summary = build_summary(scan_data["hosts"])

        self.assertEqual(scan_data["hosts"][0]["risk_level"], "Medium")
        self.assertEqual(scan_data["hosts"][1]["risk_level"], "High")
        self.assertEqual(summary["total_open_ports"], 6)
        self.assertEqual(summary["risk_counts"]["Medium"], 1)
        self.assertEqual(summary["risk_counts"]["High"], 1)
        self.assertTrue(scan_data["hosts"][0]["cve_references"])

    def test_cli_generates_json_report(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            output_path = Path(tmpdir) / "report.json"
            result = subprocess.run(
                [
                    "python3",
                    str(PROJECT_ROOT / "nmaplens.py"),
                    "--input",
                    str(SAMPLE_SCAN),
                    "--json",
                    str(output_path),
                    "--summary-only",
                ],
                cwd=PROJECT_ROOT,
                capture_output=True,
                text=True,
                check=False,
            )

            self.assertEqual(result.returncode, 0, msg=result.stderr)
            self.assertTrue(output_path.exists())

            payload = json.loads(output_path.read_text(encoding="utf-8"))
            self.assertEqual(payload["summary"]["total_hosts"], 2)
            self.assertEqual(payload["hosts"][1]["risk_score"], 65)
            self.assertIn("cve_references", payload["hosts"][0]["open_ports"][0])

    def test_compare_detects_host_and_port_changes(self) -> None:
        baseline_data = parse_nmap_xml(BASELINE_SCAN)
        current_data = parse_nmap_xml(SAMPLE_SCAN)

        comparison = build_scan_diff(baseline_data["hosts"], current_data["hosts"])

        self.assertEqual(comparison["added_hosts"], ["192.168.1.20"])
        self.assertEqual(comparison["removed_hosts"], [])
        self.assertEqual(len(comparison["changed_hosts"]), 1)
        self.assertEqual(comparison["changed_hosts"][0]["ip_address"], "192.168.1.10")
        self.assertEqual(comparison["changed_hosts"][0]["added_ports"][0]["port"], 445)

    def test_compare_only_requires_baseline(self) -> None:
        result = subprocess.run(
            [
                "python3",
                str(PROJECT_ROOT / "nmaplens.py"),
                "--input",
                str(SAMPLE_SCAN),
                "--compare-only",
            ],
            cwd=PROJECT_ROOT,
            capture_output=True,
            text=True,
            check=False,
        )

        self.assertNotEqual(result.returncode, 0)
        self.assertIn("--compare-only requires --baseline", result.stderr)

    def test_compare_only_json_includes_comparison_flag(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            output_path = Path(tmpdir) / "diff.json"
            result = subprocess.run(
                [
                    "python3",
                    str(PROJECT_ROOT / "nmaplens.py"),
                    "--baseline",
                    str(BASELINE_SCAN),
                    "--input",
                    str(SAMPLE_SCAN),
                    "--compare-only",
                    "--json",
                    str(output_path),
                ],
                cwd=PROJECT_ROOT,
                capture_output=True,
                text=True,
                check=False,
            )

            self.assertEqual(result.returncode, 0, msg=result.stderr)
            payload = json.loads(output_path.read_text(encoding="utf-8"))
            self.assertTrue(payload["comparison_only"])
            self.assertEqual(payload["comparison"]["added_hosts"], ["192.168.1.20"])

    def test_cpe_lookup_builds_nvd_links(self) -> None:
        scan_data = parse_nmap_xml(SAMPLE_SCAN)
        enrich_cpe_references(scan_data["hosts"])

        references = scan_data["hosts"][0]["cve_references"]
        self.assertTrue(references)
        self.assertIn("nvd.nist.gov", references[0]["nvd_cve_url"])

    def test_pdf_report_starts_with_pdf_header(self) -> None:
        scan_data = parse_nmap_xml(SAMPLE_SCAN)
        enrich_risk(scan_data["hosts"])
        enrich_recommendations(scan_data["hosts"])
        enrich_cpe_references(scan_data["hosts"])
        scan_data["summary"] = build_summary(scan_data["hosts"])

        payload = build_pdf_report(scan_data)

        self.assertTrue(payload.startswith(b"%PDF-1.4"))

    def test_cli_generates_pdf_report(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            output_path = Path(tmpdir) / "report.pdf"
            result = subprocess.run(
                [
                    "python3",
                    str(PROJECT_ROOT / "nmaplens.py"),
                    "--input",
                    str(SAMPLE_SCAN),
                    "--pdf",
                    str(output_path),
                    "--summary-only",
                ],
                cwd=PROJECT_ROOT,
                capture_output=True,
                text=True,
                check=False,
            )

            self.assertEqual(result.returncode, 0, msg=result.stderr)
            self.assertTrue(output_path.exists())
            self.assertTrue(output_path.read_bytes().startswith(b"%PDF-1.4"))


if __name__ == "__main__":
    unittest.main()
