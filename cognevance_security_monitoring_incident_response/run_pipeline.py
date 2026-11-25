"""Run the full pipeline: generate logs -> detect -> respond -> dashboard + JSON alerts."""
import json, subprocess, sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent / "siem"))
from analyzer import detect
from response import respond
from dashboard import build

root = Path(__file__).parent
if not (root / "data" / "auth.log").exists() or "--regen" in sys.argv:
    subprocess.run([sys.executable, str(root / "siem" / "generate_logs.py")], check=True)
alerts, auth, web = detect(root / "data" / "auth.log", root / "data" / "access.log")
out = root / "output"
out.mkdir(exist_ok=True)
(out / "alerts.json").write_text(json.dumps(alerts, indent=2))
blocked = respond(alerts, out)
build(alerts, auth, web, blocked, out / "dashboard.html")
print(f"[+] {len(alerts)} alerts, {len(blocked)} IPs added to simulated blocklist")
for a in alerts[:8]:
    print(f"  {a['id']} [{a['severity']}] {a['rule']} <- {a['src_ip']}")
print(f"[+] Open {out / 'dashboard.html'} in your browser")
