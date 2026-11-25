import json
from collections import Counter
from pathlib import Path

def write_reports(results, meta, outdir: Path):
    outdir.mkdir(exist_ok=True)
    (outdir / "scan_results.json").write_text(json.dumps({"meta": meta, "results": results}, indent=2))
    sev = Counter(f["severity"] for fs in results.values() for f in fs)
    lines = ["# Vulnerability Assessment Report", "",
             f"- **Target:** {meta['target']}", f"- **Date:** {meta['date']}", f"- **Scan engine:** {meta['engine']}", "",
             "## Summary", "", "| Severity | Count |", "|---|---|"]
    lines += [f"| {s} | {sev.get(s, 0)} |" for s in ["Critical", "High", "Medium", "Low", "Info"]]
    for host, fs in results.items():
        lines += ["", f"## Host {host}", "", "| Port | Service | Version/Banner | Severity | Risk | Recommendation |", "|---|---|---|---|---|---|"]
        lines += [f"| {f['port']}/{f['proto']} | {f['service']} | {f['version'] or '-'} | {f['severity']} | {f['risk']} | {f['recommendation']} |" for f in fs]
    if not results:
        lines += ["", "_No open ports found._"]
    lines += ["", "## Methodology", "1. Scope check (private/lab ranges only)", "2. Host/port discovery and service detection",
              "3. Mapping services to known risks", "4. Prioritised remediation", "",
              "> Testing performed only in an authorized lab environment."]
    (outdir / "vulnerability_report.md").write_text("\n".join(lines))
    print(f"[+] Reports written to {outdir}/")
