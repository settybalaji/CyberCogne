"""
Level 1 - Network Vulnerability Assessment
Scans ONLY loopback / private (RFC1918) addresses: your own VirtualBox/VMware lab.
Uses Nmap if installed (service/version detection), otherwise a built-in TCP connect scanner.
"""
import argparse, concurrent.futures, datetime, ipaddress, json, shutil, socket, subprocess, sys, tempfile
import xml.etree.ElementTree as ET
from pathlib import Path
from report_generator import write_reports

# port: (service, risk note, severity, recommendation)
KNOWLEDGE = {
    21:  ("FTP", "Cleartext credentials; anonymous login often enabled", "High", "Disable FTP; use SFTP/FTPS"),
    22:  ("SSH", "Brute-force target if password auth is enabled", "Low", "Use key auth, disable root login, add fail2ban"),
    23:  ("Telnet", "Cleartext remote shell", "Critical", "Disable Telnet; use SSH"),
    25:  ("SMTP", "Open relay / user enumeration risk", "Medium", "Restrict relay, require auth/TLS"),
    53:  ("DNS", "Zone transfer / amplification risk", "Medium", "Restrict recursion and zone transfers"),
    80:  ("HTTP", "Unencrypted web traffic", "Medium", "Redirect to HTTPS, add security headers"),
    110: ("POP3", "Cleartext mail credentials", "High", "Use POP3S or disable"),
    139: ("NetBIOS", "Legacy SMB exposure", "High", "Block at firewall"),
    143: ("IMAP", "Cleartext mail credentials", "Medium", "Use IMAPS"),
    443: ("HTTPS", "Check TLS version/cert validity", "Low", "Enforce TLS 1.2+"),
    445: ("SMB", "Wormable SMB flaws (e.g. EternalBlue) on unpatched hosts", "High", "Patch, disable SMBv1, firewall"),
    3306: ("MySQL", "Database exposed to network", "High", "Bind to localhost / firewall"),
    3389: ("RDP", "Brute-force & BlueKeep-type exposure", "High", "VPN + NLA + MFA"),
    5432: ("PostgreSQL", "Database exposed to network", "High", "Bind to localhost / firewall"),
    5900: ("VNC", "Weak/no authentication common", "High", "Tunnel over SSH, strong password"),
    8080: ("HTTP-alt", "Dev/admin panels often exposed", "Medium", "Restrict access, review app"),
}
TOP_PORTS = sorted(KNOWLEDGE) + [111, 135, 161, 389, 1433, 1521, 5000, 6379, 8000, 8443, 9200, 27017]

def check_scope(target: str):
    """Refuse anything that is not loopback/private."""
    net = ipaddress.ip_network(target, strict=False)
    if not (net.is_private or net.is_loopback):
        sys.exit(f"[!] {target} is not a private/loopback address. Scan only your authorized lab.")
    if net.num_addresses > 256:
        sys.exit("[!] Range too large (max /24).")
    return [str(h) for h in (net.hosts() if net.num_addresses > 1 else [net.network_address])]

def socket_scan(host, ports, timeout=0.6):
    def probe(p):
        try:
            with socket.create_connection((host, p), timeout=timeout) as s:
                banner = ""
                try:
                    s.settimeout(0.4); banner = s.recv(80).decode(errors="ignore").strip()
                except Exception:
                    pass
                return p, banner
        except Exception:
            return None
    with concurrent.futures.ThreadPoolExecutor(64) as ex:
        return [{"port": r[0], "proto": "tcp", "service": KNOWLEDGE.get(r[0], ("unknown",))[0],
                 "version": r[1]} for r in ex.map(probe, ports) if r]

def nmap_scan(host):
    out = Path(tempfile.mkdtemp()) / "scan.xml"
    subprocess.run(["nmap", "-sV", "-T4", "--top-ports", "1000", "-oX", str(out), host],
                   check=True, capture_output=True)
    results = []
    for p in ET.parse(out).getroot().iter("port"):
        if p.find("state").get("state") != "open":
            continue
        svc = p.find("service")
        ver = " ".join(filter(None, [svc.get("product"), svc.get("version")])) if svc is not None else ""
        results.append({"port": int(p.get("portid")), "proto": p.get("protocol"),
                        "service": svc.get("name") if svc is not None else "unknown", "version": ver})
    return results

def assess(open_ports):
    findings = []
    for o in open_ports:
        svc, risk, sev, fix = KNOWLEDGE.get(o["port"], (o["service"], "Unrecognised service - verify it is needed", "Info", "Close if unused"))
        findings.append({**o, "risk": risk, "severity": sev, "recommendation": fix})
    order = {"Critical": 0, "High": 1, "Medium": 2, "Low": 3, "Info": 4}
    return sorted(findings, key=lambda f: order[f["severity"]])

def main():
    ap = argparse.ArgumentParser(description="Lab-only network vulnerability assessment")
    ap.add_argument("target", help="e.g. 127.0.0.1, 192.168.56.101 or 192.168.56.0/24")
    ap.add_argument("--no-nmap", action="store_true", help="force built-in scanner")
    a = ap.parse_args()
    results = {}
    for host in check_scope(a.target):
        print(f"[*] Scanning {host} ...")
        try:
            ports = socket_scan(host, TOP_PORTS) if a.no_nmap or not shutil.which("nmap") else nmap_scan(host)
        except subprocess.CalledProcessError as e:
            sys.exit(f"nmap failed: {e}")
        if ports:
            results[host] = assess(ports)
            print(f"    {len(ports)} open port(s)")
    meta = {"target": a.target, "date": datetime.datetime.now().isoformat(timespec="seconds"),
            "engine": "nmap" if shutil.which("nmap") and not a.no_nmap else "python-socket"}
    write_reports(results, meta, Path(__file__).parent / "reports")

if __name__ == "__main__":
    main()
