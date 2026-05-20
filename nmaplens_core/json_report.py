from __future__ import annotations

import json


def build_json_report(scan_data: dict[str, object]) -> str:
    return json.dumps(scan_data, indent=2)
