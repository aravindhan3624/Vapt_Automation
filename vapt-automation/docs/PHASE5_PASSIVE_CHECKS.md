# Phase 5 — Passive checks (CKYC 7.0 dev environment)

**Passive only.** The checks read traffic that your own session already produced. They send no
requests, change nothing and replay nothing. Active testing is Phase 6 and needs your separate
written approval.

## How to run
**Recorder (recommended): always on, nothing extra to do.**
```powershell
cd vapt-automation
.\tools\record.ps1 -Project "CKYC-7.0" -Role Maker -StartUrl "https://<approved-dev-host>/"
```
Every recording now also writes `<base>-passive-checks.html/.csv/.json` in `C:\captures\CKYC-7.0\`.
- Without `-Zap`: all checks, **including TLS** (protocol and certificate, read from the browser's own connection).
- With `-Zap`: all checks except TLS (the browser then sees ZAP's certificate), plus the ZAP report.
  For full coverage, record each role once without `-Zap`, then once with it.

**Offline from a HAR file**
```powershell
.\tools\passive-checks-har.ps1 -Project "CKYC-7.0" -Hosts "<approved-dev-host>" -Har "C:\captures\ckyc-maker.har"
```
HAR files have no TLS details, and CKYC bodies in a HAR are encrypted. Use the recorder for those checks.

## Checks
| Check | What it looks for | Checklist |
|---|---|---|
| P5-H01 | CSP missing, report-only, or weak (`unsafe-inline`, `unsafe-eval`, any-source, inline styles, no `default-src`) on pages. Reads the header **and** `<meta http-equiv>` tags and combines them the way the browser enforces them | VAPT-010 |
| P5-H02 | No X-Frame-Options DENY/SAMEORIGIN and no CSP `frame-ancestors` on pages | VAPT-025 |
| P5-H03 | HSTS missing or max-age < 180 days | VAPT-001 |
| P5-H04 | `X-Content-Type-Options: nosniff` missing | VAPT-023 |
| P5-H05 | Server / X-Powered-By / X-AspNet-Version reveal product and version | VAPT-008 |
| P5-H06 | 2xx API responses without `Cache-Control: no-store` | VAPT-063, VAPT-012 |
| P5-H07 | `Access-Control-Allow-Origin: *` (worse with credentials) | VAPT-023 |
| P5-C01 | Cookies missing Secure / HttpOnly / SameSite | VAPT-014 |
| P5-D01 | Unmasked PAN, Aadhaar (Verhoeff), card (Luhn), mobile, email in **decrypted** responses; masked values are counted as good | VAPT-043, VAPT-052 |
| P5-D02 | Password / PIN / OTP / CVV / secret-key fields returned to the browser | VAPT-052, VAPT-017 |
| P5-D03 | Credentials or personal data in URL query strings | VAPT-017, VAPT-002 |
| P5-E01 | Stack traces, exception class names (e.g. `MailConnectException`), SQL errors, framework error pages, internal paths / IPs | VAPT-041, VAPT-042 |
| P5-E02 | HTTP 5xx during normal use | VAPT-041 |
| P5-T01 | Plain http:// to the application | VAPT-001, VAPT-039 |
| P5-T02 | TLS below 1.2 | VAPT-001, VAPT-023 |
| P5-T03 | Certificate expired or expiring within 30 days | VAPT-023 |
| P5-T04 | HTTPS page loading http:// resources (mixed content) | VAPT-001 |

## Reading the report
- **Lead - to verify**: the check fired. Not a confirmed finding yet: reproduce it and keep the
  request/response before raising it. Each lead lists names (header / cookie / JSON field path /
  query parameter), reason counts, up to 15 endpoints, and how to verify it.
- **No issue observed**: the check ran on real traffic and found nothing. The endpoints checked are
  listed as closure evidence for PASS items.
- **Not observed**: no traffic of that kind (e.g. no cookies were set).
- **Not checked**: the data wasn't available (e.g. TLS via a proxy or from a HAR), with the reason.

Leads first, then no-issue checks: the same order as the customer report.

## What is never written
Header values (except Server / X-Powered-By style version banners), cookie values, body values,
personal data and query values. Data checks look at values in memory and write only the field
path (e.g. `responseObject.customer.panNo`) and the type found. Everything also passes MaskUtil.

## Verified (2026-11-10, local only)
- `PassiveChecksTest` (3): every check fires on synthetic data, including TLS 1.1, a certificate
  expiring in 10 days, mixed content, `MailConnectException` and an internal IP. 8 of 8 fake values
  absent from HTML/CSV/JSON; false-positive guards (ids, postal PIN code, company names) hold.
- `HarPassiveChecksTest`: base64 HAR bodies decoded; the out-of-scope host is ignored; TLS "Not checked".
- `RecorderLocalIT`: on the local fake app with WebCrypto encryption, 6 leads, including the
  `password` field in a response; no fake secret in any output.
