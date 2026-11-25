# Web Application Security Assessment

- Target: http://127.0.0.1:5000
- Date: 2026-11-25 06:08
- Findings: 4

| # | Severity | Type | Location | Detail | Mitigation |
|---|---|---|---|---|---|
| 1 | Low | Missing security header | http://127.0.0.1:5000 | Content-Security-Policy missing - Mitigates XSS and data injection | Add the Content-Security-Policy response header |
| 2 | Low | Missing security header | http://127.0.0.1:5000 | X-Content-Type-Options missing - Stops MIME sniffing | Add the X-Content-Type-Options response header |
| 3 | Low | Missing security header | http://127.0.0.1:5000 | X-Frame-Options missing - Prevents clickjacking | Add the X-Frame-Options response header |
| 4 | Low | Missing security header | http://127.0.0.1:5000 | Referrer-Policy missing - Limits referrer leakage | Add the Referrer-Policy response header |