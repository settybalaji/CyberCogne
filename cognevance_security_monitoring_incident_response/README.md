# cognevance_security_monitoring_incident_response
Level 3 – Enterprise Security Monitoring & Incident Response System (Cognevance Technologies)

## Quick start (no dependencies)
```bash
python run_pipeline.py            # generates sample logs, detects attacks, builds dashboard
python run_pipeline.py --regen    # regenerate logs
```
Outputs in `output/`: `alerts.json`, `dashboard.html`, `blocklist.txt` (simulated), `incidents/*.md`.

## Components
| File | Purpose |
|---|---|
| `siem/generate_logs.py` | Synthetic auth/web logs with embedded attacks |
| `siem/analyzer.py` | Detection rules (brute force, SQLi, XSS, traversal, scanning, off-hours) mapped to MITRE ATT&CK |
| `siem/response.py` | Automated response playbooks (simulated blocking + incident reports) |
| `siem/dashboard.py` | HTML dashboard |
| `elk/` | Optional ELK Stack via Docker (Elasticsearch, Kibana, Filebeat) |
| `docs/architecture.md` | Network architecture diagram, risk assessment, hardening |

## ELK (optional)
`cd elk && docker compose up -d` → open http://localhost:5601 → create data view `filebeat-*`, build dashboards, add alert rules (e.g. >5 failed SSH logins in 5 min).
For Splunk: install Splunk Free, add `data/` as a monitored directory, and recreate the same searches.

## Safety
All data is synthetic (IPs from documentation ranges). Nothing touches real firewalls or networks.
