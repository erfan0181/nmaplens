from __future__ import annotations


SERVICE_RISK = {
    "telnet": 30,
    "microsoft-ds": 25,
    "netbios-ssn": 25,
    "smb": 25,
    "ms-wbt-server": 20,
    "rdp": 20,
    "ftp": 15,
    "vnc": 15,
    "mysql": 10,
    "postgresql": 10,
    "mongodb": 15,
    "redis": 15,
    "elasticsearch": 15,
    "http": 5,
    "https": 3,
    "ssh": 5,
}

RISK_REASONS = {
    "telnet": "Telnet is exposed and uses clear-text communication.",
    "microsoft-ds": "SMB exposure can increase lateral movement risk.",
    "netbios-ssn": "SMB exposure can increase lateral movement risk.",
    "smb": "SMB exposure can increase lateral movement risk.",
    "ms-wbt-server": "RDP should be protected with VPN, MFA, and strict access control.",
    "rdp": "RDP should be protected with VPN, MFA, and strict access control.",
    "ftp": "FTP may expose credentials if not protected.",
    "vnc": "VNC exposure may allow remote desktop access if weakly protected.",
    "mysql": "Database services should not be exposed to untrusted networks.",
    "postgresql": "Database services should not be exposed to untrusted networks.",
    "mongodb": "Database services should not be exposed to untrusted networks.",
    "redis": "Database services should not be exposed to untrusted networks.",
    "elasticsearch": "Database services should not be exposed to untrusted networks.",
    "http": "HTTP traffic is not encrypted.",
    "https": "HTTPS still requires certificate and access-control validation.",
    "ssh": "SSH should be restricted to trusted administrative networks.",
}


def enrich_risk(hosts: list[dict[str, object]]) -> None:
    for host in hosts:
        score = 0
        reasons: list[str] = []
        for port in host["open_ports"]:
            service = str(port.get("service", "")).lower()
            score += SERVICE_RISK.get(service, 0)
            reason = RISK_REASONS.get(service)
            if reason and reason not in reasons:
                reasons.append(reason)
        host["risk_score"] = score
        host["risk_level"] = classify_risk(score)
        host["risk_reasons"] = reasons or ["No major risky services matched the built-in rules."]


def classify_risk(score: int) -> str:
    if score >= 70:
        return "Critical"
    if score >= 40:
        return "High"
    if score >= 15:
        return "Medium"
    return "Low"
