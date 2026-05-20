from __future__ import annotations


SERVICE_SCRIPT_GROUPS = {
    "microsoft-ds": [
        "nmap --script smb-enum-shares,smb-os-discovery,smb-protocols -p{ports} TARGET",
        "nmap --script smb-security-mode,smb2-security-mode -p{ports} TARGET",
        "nmap --script smb-vuln* -p{ports} TARGET",
    ],
    "smb": [
        "nmap --script smb-enum-shares,smb-os-discovery,smb-protocols -p{ports} TARGET",
        "nmap --script smb-security-mode,smb2-security-mode -p{ports} TARGET",
        "nmap --script smb-vuln* -p{ports} TARGET",
    ],
    "netbios-ssn": [
        "nmap --script smb-enum-shares,smb-os-discovery,smb-protocols -p{ports} TARGET",
    ],
    "http": [
        "nmap --script http-title,http-headers,http-methods,http-enum -p{ports} TARGET",
        "nmap --script http-auth-finder,http-server-header,http-robots.txt -p{ports} TARGET",
    ],
    "https": [
        "nmap --script http-title,http-headers,http-methods,ssl-cert,ssl-enum-ciphers -p{ports} TARGET",
        "nmap --script ssl-heartbleed,ssl-known-key -p{ports} TARGET",
    ],
    "ssh": [
        "nmap --script ssh2-enum-algos,ssh-hostkey -p{ports} TARGET",
        "nmap --script ssh-auth-methods -p{ports} TARGET",
    ],
    "ftp": [
        "nmap --script ftp-anon,ftp-syst,ftp-bounce -p{ports} TARGET",
        "nmap --script ftp-proftpd-backdoor,ftp-vsftpd-backdoor -p{ports} TARGET",
    ],
    "ms-wbt-server": [
        "nmap --script rdp-enum-encryption,rdp-ntlm-info -p{ports} TARGET",
        "nmap --script rdp-vuln-ms12-020 -p{ports} TARGET",
    ],
    "rdp": [
        "nmap --script rdp-enum-encryption,rdp-ntlm-info -p{ports} TARGET",
        "nmap --script rdp-vuln-ms12-020 -p{ports} TARGET",
    ],
    "telnet": [
        "nmap -sV --version-all -p{ports} TARGET",
        "nmap --script banner,telnet-encryption -p{ports} TARGET",
    ],
    "vnc": [
        "nmap -sV --version-all -p{ports} TARGET",
        "nmap --script vnc-info,vnc-title -p{ports} TARGET",
    ],
    "mysql": [
        "nmap -sV --version-all -p{ports} TARGET",
        "nmap --script mysql-info,mysql-empty-password,mysql-variables -p{ports} TARGET",
    ],
    "postgresql": [
        "nmap -sV --version-all -p{ports} TARGET",
        "nmap --script pgsql-brute -p{ports} TARGET",
    ],
    "mongodb": [
        "nmap -sV --version-all -p{ports} TARGET",
        "nmap --script mongodb-info -p{ports} TARGET",
    ],
    "redis": [
        "nmap -sV --version-all -p{ports} TARGET",
        "nmap --script redis-info -p{ports} TARGET",
    ],
    "elasticsearch": [
        "nmap -sV --version-all -p{ports} TARGET",
        "nmap --script http-title,http-headers -p{ports} TARGET",
    ],
    "ldap": [
        "nmap --script ldap-rootdse,ldap-search -p{ports} TARGET",
    ],
    "kerberos-sec": [
        "nmap --script krb5-enum-users -p{ports} TARGET",
    ],
    "ms-sql-s": [
        "nmap --script ms-sql-info,ms-sql-empty-password,ms-sql-config -p{ports} TARGET",
        "nmap --script ms-sql-dump-hashes,ms-sql-xp-cmdshell -p{ports} TARGET",
    ],
    "domain": [
        "nmap --script dns-recursion,dns-service-discovery -p{ports} TARGET",
        "nmap -sU -sV -p53 TARGET",
    ],
}

LOW_VALUE_SERVICES = {
    "msrpc",
    "ncacn_http",
    "tcpwrapped",
}


def enrich_recommendations(hosts: list[dict[str, object]]) -> None:
    for host in hosts:
        commands: list[str] = []
        ports = sorted(int(port["port"]) for port in host["open_ports"])
        if ports:
            port_list = ",".join(str(port) for port in ports)
            _add_command(commands, f"nmap -sV -sC -O -p{port_list} TARGET")
            _add_command(commands, f"nmap -Pn --reason --version-all -p{port_list} TARGET")
        else:
            host["recommendations"] = ["nmap -sV TARGET"]
            continue

        service_groups = _group_ports_by_service(host["open_ports"])
        for service, grouped_ports in service_groups.items():
            _add_group_recommendations(commands, service, grouped_ports)

        host["recommendations"] = commands or ["nmap -sV TARGET"]


def _group_ports_by_service(open_ports: list[dict[str, object]]) -> dict[str, list[dict[str, object]]]:
    groups: dict[str, list[dict[str, object]]] = {}
    for port in open_ports:
        service = str(port.get("service", "")).lower()
        groups.setdefault(service, []).append(port)
    return groups


def _add_group_recommendations(commands: list[str], service: str, ports: list[dict[str, object]]) -> None:
    port_list = ",".join(str(int(port["port"])) for port in sorted(ports, key=lambda item: int(item["port"])))
    products = " ".join(str(port.get("product", "")).lower() for port in ports)
    cpe_values = " ".join(
        str(cpe).lower()
        for port in ports
        for cpe in port.get("cpe_values", [])
    )

    for template in SERVICE_SCRIPT_GROUPS.get(service, []):
        _add_command(commands, template.format(ports=port_list))

    if service in {"http", "https"}:
        if "nginx" in products or "nginx" in cpe_values:
            _add_command(commands, f"nmap --script http-title,http-server-header,http-vhosts -p{port_list} TARGET")
        if "apache" in products or "apache" in cpe_values:
            _add_command(commands, f"nmap --script http-title,http-server-header,http-passwd -p{port_list} TARGET")
        if "iis" in products or "internet_information_services" in cpe_values:
            _add_command(commands, f"nmap --script http-iis-webdav-vuln,http-iis-short-name-brute -p{port_list} TARGET")

    if cpe_values and service not in LOW_VALUE_SERVICES:
        _add_command(commands, f"nmap -sV --version-all --script vulners -p{port_list} TARGET")

    if service not in SERVICE_SCRIPT_GROUPS and service not in LOW_VALUE_SERVICES:
        _add_command(commands, f"nmap -sV --version-all -p{port_list} TARGET")
        _add_command(commands, f"nmap --script banner -p{port_list} TARGET")


def _add_command(commands: list[str], command: str) -> None:
    if command not in commands:
        commands.append(command)
