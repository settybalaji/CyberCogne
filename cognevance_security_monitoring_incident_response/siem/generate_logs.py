"""Generates synthetic auth + web logs (with embedded attack patterns) for SIEM practice. No real systems involved."""
import random
from datetime import datetime, timedelta
from pathlib import Path

random.seed(7)
OUT = Path(__file__).parent.parent / "data"
OUT.mkdir(exist_ok=True)
start = datetime.now().replace(minute=0, second=0, microsecond=0) - timedelta(hours=6)
users = ["alice", "bob", "carol", "dave"]
normal_ips = [f"10.0.1.{i}" for i in range(10, 30)]
attacker_bf, attacker_scan, attacker_web = "203.0.113.45", "198.51.100.23", "192.0.2.77"   # documentation IP ranges
auth, web = [], []

def t(minutes): return start + timedelta(minutes=minutes, seconds=random.randint(0, 59))
def A(ts, msg): auth.append((ts, f"{ts.isoformat(timespec='seconds')} srv01 sshd[{random.randint(1000, 9999)}]: {msg}"))
def W(ts, ip, req, code, size=512):
    web.append((ts, f'{ip} - - [{ts.strftime("%d/%b/%Y:%H:%M:%S")} +0000] "{req} HTTP/1.1" {code} {size}'))

for m in range(0, 360, 3):                       # normal traffic
    ip, u = random.choice(normal_ips), random.choice(users)
    A(t(m), f"Accepted password for {u} from {ip} port {random.randint(30000, 60000)} ssh2")
    W(t(m), ip, f"GET {random.choice(['/', '/products', '/about', '/contact', '/cart'])}", 200)
for _ in range(6):                               # a few typos
    A(t(random.randint(0, 359)), f"Failed password for {random.choice(users)} from {random.choice(normal_ips)} port 4444 ssh2")
for i in range(14):                              # SSH brute force then success
    A(t(120 + i // 4), f"Failed password for root from {attacker_bf} port {40000 + i} ssh2")
A(t(125), f"Accepted password for root from {attacker_bf} port 40999 ssh2")
for i in range(25):                              # directory/port probing
    W(t(200 + i // 8), attacker_scan, f"GET /{random.choice(['phpmyadmin', 'backup.zip', 'test', 'old', 'cgi-bin', 'x'])}{i}", 404, 200)
W(t(205), attacker_scan, "GET /.env", 404, 200)
for p in ["/search?q=' OR '1'='1' --", "/search?q=1 UNION SELECT username,password FROM users",
          "/search?q=<script>alert(1)</script>", "/login?user=admin'--", "/download?file=../../etc/passwd"]:
    W(t(300), attacker_web, f"GET {p}", 200 if "UNION" in p else 500)
A(datetime.now().replace(hour=2, minute=14, second=0) - timedelta(days=0), "Accepted password for dave from 10.0.1.99 port 51000 ssh2")
(OUT / "auth.log").write_text("\n".join(l for _, l in sorted(auth)))
(OUT / "access.log").write_text("\n".join(l for _, l in sorted(web)))
print(f"[+] Wrote {len(auth)} auth events and {len(web)} web events to {OUT}")
