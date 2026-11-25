# cognevance_web_application_security_testing
Level 2 – Web Application Security Testing (Cognevance Technologies)

## Setup
```bash
python -m venv .venv && source .venv/bin/activate      # Windows: .venv\Scripts\activate
pip install -r requirements.txt
```
## Targets
| Target | How |
|---|---|
| Built-in vulnerable demo | `python vulnerable_app/app.py` → http://127.0.0.1:5000 |
| Fixed version (after mitigation) | `python vulnerable_app/secure_app.py` → http://127.0.0.1:5001 |
| DVWA | `docker run --rm -p 8081:80 vulnerables/web-dvwa` → http://127.0.0.1:8081 |
| OWASP Juice Shop | `docker run --rm -p 3000:3000 bkimminich/juice-shop` |

## Workflow
1. Start the vulnerable app, then run: `python tester/web_tester.py http://127.0.0.1:5000`
2. Start the secure app, run: `python tester/web_tester.py http://127.0.0.1:5001` (should report only fewer/no findings) – before/after comparison.
3. Manual testing (screenshots in `screenshots/`):
   - **Burp Suite Community**: set browser proxy to 127.0.0.1:8080, intercept `/login`, send to Repeater, try `' OR '1'='1' --`; on `/search` try `<script>alert(1)</script>`.
   - **Nikto**: `nikto -h http://127.0.0.1:5000`
4. Fill findings and mitigation into the reports in `reports/`.

## Mitigations summary
Parameterized queries, output encoding, CSP and security headers, generic error messages, password hashing, rate limiting, WAF, regular dependency updates.

## Safety
The tester only accepts localhost/private targets. Never test systems you do not own or have written permission to test.
