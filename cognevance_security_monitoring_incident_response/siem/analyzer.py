"""Detection engine: parses logs, applies rules, returns alerts (mapped to MITRE ATT&CK)."""
import re
from collections import defaultdict
from datetime import datetime

AUTH_RE = re.compile(r"^(\S+) (\S+) sshd\[\d+\]: (Failed|Accepted) password for (\S+) from (\S+)")
WEB_RE = re.compile(r'^(\S+) \S+ \S+ \[([^\]]+)\] "(\S+) (\S+) [^"]*" (\d{3}) (\d+)')
SQLI = re.compile(r"(union\s+select|or\s+'?1'?='?1|--|;\s*drop\s|sleep\()", re.I)
XSS = re.compile(r"(<script|onerror=|javascript:)", re.I)
TRAVERSAL = re.compile(r"(\.\./|%2e%2e)", re.I)
SENSITIVE = ("/.env", "/.git", "/phpmyadmin", "/wp-admin", "/admin")

def parse_auth(path):
    for line in open(path):
        m = AUTH_RE.match(line.strip())
        if m:
            yield dict(ts=datetime.fromisoformat(m[1]), host=m[2], result=m[3], user=m[4], ip=m[5])

def parse_web(path):
    for line in open(path):
        m = WEB_RE.match(line.strip())
        if m:
            yield dict(ip=m[1], ts=datetime.strptime(m[2].split()[0], "%d/%b/%Y:%H:%M:%S"), method=m[3], url=m[4], status=int(m[5]))

def detect(auth_path, web_path):
    alerts, auth, web = [], list(parse_auth(auth_path)), list(parse_web(web_path))
    def add(sev, rule, ip, desc, ts, mitre, count=1):
        alerts.append(dict(severity=sev, rule=rule, src_ip=ip, description=desc, first_seen=ts.isoformat(timespec="seconds"), mitre=mitre, count=count))

    fails = defaultdict(list)
    for e in auth:
        if e["result"] == "Failed":
            fails[e["ip"]].append(e["ts"])
    for ip, times in fails.items():
        if len(times) >= 5:
            success = [e for e in auth if e["ip"] == ip and e["result"] == "Accepted"]
            if success:
                add("Critical", "SSH brute force followed by success", ip,
                    f"{len(times)} failed logins then successful login as '{success[0]['user']}' - probable compromise", times[0], "T1110 Brute Force", len(times))
            else:
                add("High", "SSH brute force", ip, f"{len(times)} failed logins", times[0], "T1110 Brute Force", len(times))
    for e in auth:
        if e["result"] == "Accepted" and 0 <= e["ts"].hour < 5:
            add("Low", "Off-hours login", e["ip"], f"{e['user']} logged in at {e['ts']:%H:%M}", e["ts"], "T1078 Valid Accounts")

    notfound = defaultdict(list)
    for e in web:
        if e["status"] == 404:
            notfound[e["ip"]].append(e)
        if SQLI.search(e["url"]):
            add("High", "SQL injection attempt", e["ip"], e["url"], e["ts"], "T1190 Exploit Public-Facing App")
        if XSS.search(e["url"]):
            add("Medium", "XSS attempt", e["ip"], e["url"], e["ts"], "T1059.007 JavaScript")
        if TRAVERSAL.search(e["url"]):
            add("High", "Path traversal attempt", e["ip"], e["url"], e["ts"], "T1083 File and Directory Discovery")
        if e["url"].startswith(SENSITIVE):
            add("Medium", "Sensitive path probe", e["ip"], e["url"], e["ts"], "T1595 Active Scanning")
    for ip, evs in notfound.items():
        if len(evs) >= 10:
            add("Medium", "Web scanning / forced browsing", ip, f"{len(evs)} 404 responses", evs[0]["ts"], "T1595 Active Scanning", len(evs))

    order = {"Critical": 0, "High": 1, "Medium": 2, "Low": 3}
    alerts.sort(key=lambda a: (order[a["severity"]], a["first_seen"]))
    for i, a in enumerate(alerts, 1):
        a["id"] = f"ALR-{i:03d}"
    return alerts, auth, web
