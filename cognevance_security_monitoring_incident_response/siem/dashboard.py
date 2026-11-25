"""Builds a self-contained HTML security dashboard (no external libraries)."""
from collections import Counter
from html import escape
from pathlib import Path

COLORS = {"Critical": "#b91c1c", "High": "#ea580c", "Medium": "#ca8a04", "Low": "#2563eb"}

def bar(label, value, maxv, color="#334155"):
    w = int(100 * value / maxv) if maxv else 0
    return f"<div class=row><span class=l>{escape(str(label))}</span><div class=b><i style='width:{w}%;background:{color}'></i></div><span>{value}</span></div>"

def build(alerts, auth, web, blocked, out: Path):
    sev = Counter(a["severity"] for a in alerts)
    ips = Counter(a["src_ip"] for a in alerts).most_common(5)
    rules = Counter(a["rule"] for a in alerts).most_common()
    hours = Counter(e["ts"].strftime("%H:00") for e in web)
    rows = "".join(f"<tr><td>{a['id']}</td><td style='color:{COLORS[a['severity']]}'><b>{a['severity']}</b></td><td>{escape(a['rule'])}</td>"
                   f"<td>{a['src_ip']}</td><td>{escape(a['description'][:80])}</td><td>{escape(a['mitre'])}</td></tr>" for a in alerts)
    html = f"""<!doctype html><meta charset=utf-8><title>Security Dashboard</title>
<style>body{{font-family:system-ui;margin:24px;background:#f8fafc;color:#0f172a}}h1{{margin:0}}.cards{{display:flex;gap:12px;margin:16px 0}}
.card{{background:#fff;border-radius:8px;padding:14px 20px;box-shadow:0 1px 3px #0002}}.card b{{font-size:28px;display:block}}
.panel{{background:#fff;border-radius:8px;padding:16px;margin:12px 0;box-shadow:0 1px 3px #0002}}.row{{display:flex;align-items:center;gap:8px;margin:4px 0}}
.l{{width:260px;font-size:13px}}.b{{flex:1;background:#e2e8f0;height:12px;border-radius:6px}}.b i{{display:block;height:12px;border-radius:6px}}
table{{border-collapse:collapse;width:100%;font-size:13px}}td,th{{border-bottom:1px solid #e2e8f0;padding:6px;text-align:left}}</style>
<h1>Security Monitoring Dashboard</h1>
<div class=cards><div class=card><b>{len(auth)+len(web)}</b>events analysed</div><div class=card><b>{len(alerts)}</b>alerts</div>
<div class=card><b style='color:#b91c1c'>{sev.get('Critical',0)}</b>critical</div><div class=card><b>{len(blocked)}</b>IPs blocked (simulated)</div></div>
<div class=panel><h3>Alerts by severity</h3>{''.join(bar(s, sev.get(s,0), max(sev.values() or [1]), COLORS[s]) for s in COLORS)}</div>
<div class=panel><h3>Top source IPs</h3>{''.join(bar(i, c, ips[0][1]) for i, c in ips)}</div>
<div class=panel><h3>Detections by rule</h3>{''.join(bar(r, c, rules[0][1]) for r, c in rules)}</div>
<div class=panel><h3>Web requests per hour</h3>{''.join(bar(h, c, max(hours.values())) for h, c in sorted(hours.items()))}</div>
<div class=panel><h3>Alert log</h3><table><tr><th>ID<th>Severity<th>Rule<th>Source<th>Details<th>MITRE</tr>{rows}</table></div>"""
    out.write_text(html)
