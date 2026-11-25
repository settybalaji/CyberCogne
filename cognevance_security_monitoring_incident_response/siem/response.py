"""Automated incident response (SIMULATED): blocklist file + incident reports. Does not touch real firewalls."""
from pathlib import Path

PLAYBOOK = {
    "Critical": ["Isolate host from network", "Block source IP", "Reset credentials of affected account", "Collect logs/forensic image", "Escalate to IR lead"],
    "High": ["Block source IP", "Review related logs for 24h", "Patch/validate vulnerable component"],
    "Medium": ["Monitor source IP", "Verify WAF / rate-limit rules"],
    "Low": ["Log and review with user"],
}

def respond(alerts, outdir: Path):
    outdir.mkdir(exist_ok=True)
    (outdir / "incidents").mkdir(exist_ok=True)
    blocked = sorted({a["src_ip"] for a in alerts if a["severity"] in ("Critical", "High")})
    (outdir / "blocklist.txt").write_text("\n".join(blocked))
    for a in alerts:
        if a["severity"] in ("Critical", "High"):
            steps = "\n".join(f"{n}. {s}" for n, s in enumerate(PLAYBOOK[a["severity"]], 1))
            (outdir / "incidents" / f"{a['id']}.md").write_text(
                f"# Incident {a['id']} - {a['rule']}\n\n- Severity: {a['severity']}\n- Source IP: {a['src_ip']}\n"
                f"- First seen: {a['first_seen']}\n- MITRE ATT&CK: {a['mitre']}\n- Details: {a['description']}\n\n## Response actions\n{steps}\n\n## Status\nOpen\n")
    return blocked
