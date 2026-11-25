"""
Lab-only web security tester: security headers, SQL injection and reflected XSS checks.
Only http(s)://localhost / 127.0.0.1 / private-IP targets are allowed.
"""
import argparse, datetime, ipaddress, json, sys
from pathlib import Path
from urllib.parse import urlparse
import requests

HEADERS_EXPECTED = {
    "Content-Security-Policy": "Mitigates XSS and data injection",
    "X-Content-Type-Options": "Stops MIME sniffing",
    "X-Frame-Options": "Prevents clickjacking",
    "Referrer-Policy": "Limits referrer leakage",
}
SQLI_LOGIN = [("' OR '1'='1' --", "x"), ("admin' --", "x")]
SQLI_ERROR = ["'", "\""]
XSS_MARK = "<script>alert('XSS-TEST')</script>"
DB_ERRORS = ["sql syntax", "sqlite", "unrecognized token", "database error", "mysql", "odbc"]

def check_scope(url):
    host = urlparse(url).hostname or ""
    if host != "localhost":
        try:
            ip = ipaddress.ip_address(host)
            ok = ip.is_loopback or ip.is_private
        except ValueError:
            ok = False
        if not ok:
            sys.exit(f"[!] {host} is not localhost/private. Test only authorized lab targets.")

def run(base):
    findings, s = [], requests.Session()
    try:
        r = s.get(base, timeout=5)
    except requests.RequestException as e:
        sys.exit(f"[!] Cannot reach {base}: {e}")
    for h, why in HEADERS_EXPECTED.items():
        if h not in r.headers:
            findings.append(dict(type="Missing security header", severity="Low", url=base, detail=f"{h} missing - {why}",
                                 fix=f"Add the {h} response header"))
    # SQLi: authentication bypass
    for u, p in SQLI_LOGIN:
        resp = s.post(f"{base}/login", data={"username": u, "password": p}, timeout=5)
        if resp.status_code == 200 and "Welcome" in resp.text:
            findings.append(dict(type="SQL Injection (auth bypass)", severity="Critical", url=f"{base}/login",
                                 detail=f"Payload {u!r} logged in: {resp.text[:60]!r}",
                                 fix="Use parameterized queries / ORM; hash passwords; add rate limiting"))
            break
    # SQLi: error based
    for q in SQLI_ERROR:
        resp = s.post(f"{base}/login", data={"username": q, "password": "x"}, timeout=5)
        if any(e in resp.text.lower() for e in DB_ERRORS):
            findings.append(dict(type="SQL error disclosure", severity="Medium", url=f"{base}/login",
                                 detail=f"Database error leaked for payload {q!r}", fix="Return generic errors; log details server-side"))
            break
    # Reflected XSS
    resp = s.get(f"{base}/search", params={"q": XSS_MARK}, timeout=5)
    if XSS_MARK in resp.text:
        findings.append(dict(type="Reflected XSS", severity="High", url=f"{base}/search?q=",
                             detail="Script payload reflected without encoding", fix="Context-aware output encoding + CSP"))
    return findings

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("target", help="e.g. http://127.0.0.1:5000")
    ap.add_argument("--out", default=str(Path(__file__).parent.parent / "reports"))
    a = ap.parse_args()
    check_scope(a.target)
    base = a.target.rstrip("/")
    findings = run(base)
    out = Path(a.out); out.mkdir(exist_ok=True)
    name = "secure" if base.endswith("5001") else "vulnerable" if base.endswith("5000") else "target"
    (out / f"findings_{name}.json").write_text(json.dumps(findings, indent=2))
    md = ["# Web Application Security Assessment", "", f"- Target: {base}", f"- Date: {datetime.datetime.now():%Y-%m-%d %H:%M}",
          f"- Findings: {len(findings)}", "", "| # | Severity | Type | Location | Detail | Mitigation |", "|---|---|---|---|---|---|"]
    md += [f"| {i} | {f['severity']} | {f['type']} | {f['url']} | {f['detail']} | {f['fix']} |" for i, f in enumerate(findings, 1)]
    (out / f"report_{name}.md").write_text("\n".join(md))
    for f in findings:
        print(f"[{f['severity']}] {f['type']} @ {f['url']}")
    print(f"[+] {len(findings)} finding(s). Report: {out}/report_{name}.md")

if __name__ == "__main__":
    main()
