from __future__ import annotations


SERVICE_RECOMMENDATIONS = {
    "microsoft-ds": "nmap --script smb-enum-shares,smb-os-discovery,smb-protocols -p445 TARGET",
    "smb": "nmap --script smb-enum-shares,smb-os-discovery,smb-protocols -p445 TARGET",
    "http": "nmap --script http-title,http-headers,http-methods -p80 TARGET",
    "https": "nmap --script http-title,http-headers,http-methods -p443 TARGET",
    "ssh": "nmap --script ssh2-enum-algos -p22 TARGET",
    "ftp": "nmap --script ftp-anon,ftp-syst -p21 TARGET",
    "ms-wbt-server": "nmap --script rdp-enum-encryption -p3389 TARGET",
    "rdp": "nmap --script rdp-enum-encryption -p3389 TARGET",
    "telnet": "nmap -sV -p23 TARGET",
    "vnc": "nmap -sV -p5900 TARGET",
    "mysql": "nmap -sV -p3306 TARGET",
    "postgresql": "nmap -sV -p5432 TARGET",
    "mongodb": "nmap -sV -p27017 TARGET",
    "redis": "nmap -sV -p6379 TARGET",
    "elasticsearch": "nmap -sV -p9200 TARGET",
}


def enrich_recommendations(hosts: list[dict[str, object]]) -> None:
    for host in hosts:
        commands: list[str] = []
        for port in host["open_ports"]:
            service = str(port.get("service", "")).lower()
            command = SERVICE_RECOMMENDATIONS.get(service, f"nmap -sV -p{port.get('port', 'PORT')} TARGET")
            if command not in commands:
                commands.append(command)
        host["recommendations"] = commands or ["nmap -sV TARGET"]
