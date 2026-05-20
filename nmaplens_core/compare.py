from __future__ import annotations


def build_scan_diff(
    baseline_hosts: list[dict[str, object]],
    current_hosts: list[dict[str, object]],
) -> dict[str, object]:
    baseline_map = {str(host["ip_address"]): host for host in baseline_hosts}
    current_map = {str(host["ip_address"]): host for host in current_hosts}

    added_hosts = sorted(ip for ip in current_map if ip not in baseline_map)
    removed_hosts = sorted(ip for ip in baseline_map if ip not in current_map)
    changed_hosts: list[dict[str, object]] = []

    for ip in sorted(set(baseline_map) & set(current_map)):
        baseline_host = baseline_map[ip]
        current_host = current_map[ip]
        baseline_ports = _port_map(baseline_host)
        current_ports = _port_map(current_host)

        added_ports = sorted(key for key in current_ports if key not in baseline_ports)
        removed_ports = sorted(key for key in baseline_ports if key not in current_ports)
        service_changes = []

        for key in sorted(set(baseline_ports) & set(current_ports)):
            before_service = str(baseline_ports[key].get("service", "unknown"))
            after_service = str(current_ports[key].get("service", "unknown"))
            if before_service != after_service:
                service_changes.append(
                    {
                        "port": baseline_ports[key]["port"],
                        "protocol": baseline_ports[key]["protocol"],
                        "before": before_service,
                        "after": after_service,
                    }
                )

        if added_ports or removed_ports or service_changes:
            changed_hosts.append(
                {
                    "ip_address": ip,
                    "added_ports": [_port_snapshot(current_ports[key]) for key in added_ports],
                    "removed_ports": [_port_snapshot(baseline_ports[key]) for key in removed_ports],
                    "service_changes": service_changes,
                }
            )

    return {
        "baseline_host_count": len(baseline_hosts),
        "current_host_count": len(current_hosts),
        "added_hosts": added_hosts,
        "removed_hosts": removed_hosts,
        "changed_hosts": changed_hosts,
    }


def _port_map(host: dict[str, object]) -> dict[tuple[str, int], dict[str, object]]:
    return {
        (str(port["protocol"]), int(port["port"])): port
        for port in host["open_ports"]
    }


def _port_snapshot(port: dict[str, object]) -> dict[str, object]:
    return {
        "port": port["port"],
        "protocol": port["protocol"],
        "service": port["service"],
    }
