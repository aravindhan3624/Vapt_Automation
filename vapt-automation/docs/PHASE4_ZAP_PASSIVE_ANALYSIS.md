# Phase 4 — ZAP passive analysis (CKYC 7.0 dev environment)

**Passive only.** OWASP ZAP reads traffic that already exists: your own browsing (live) or an
exported HAR file (offline). It sends no requests of its own. No spider, no active scan, no
fuzzing, and nothing is replayed or changed. Active testing is Phase 6 and needs your separate
written approval.

Target: the CKYC 7.0 **development** environment (not UAT, not production). `ConfigLoader` still
refuses any environment named PROD.

## Option A (recommended): live, together with the recorder
```powershell
cd vapt-automation
.\tools\record.ps1 -Project "CKYC-7.0" -Role Maker -StartUrl "https://<approved-dev-host>/" -Zap
```
1. The recorder starts a local ZAP (127.0.0.1 only, random API key, protected mode, about a
   minute), then opens Edge with a fresh profile routed through it.
2. Log in yourself and walk the modules as usual (type the module name in the "VAPT module" box).
3. Close the window. The recorder waits for ZAP's passive rules to finish, writes the report and
   shuts ZAP down. ZAP's session, which held the raw traffic (cookies, tokens), is deleted.

## Option B: offline, from a HAR file
Export from Edge/Chrome DevTools (Network tab → Export HAR) or Burp, save it outside OneDrive
(e.g. `C:\captures\`), then:
```powershell
.\tools\zap-passive-har.ps1 -Project "CKYC-7.0" -Hosts "<approved-dev-host>" -Har "C:\captures\ckyc-maker.har"
```
ZAP only imports the file. It does not contact the application.

## Output (in `C:\captures\CKYC-7.0\`, outside OneDrive and git)
| File | Content |
|---|---|
| `*-zap-passive.html` | Report: summary by risk, one row per ZAP rule, details with redacted evidence |
| `*-zap-passive.csv` | Same rows for Excel |
| `*-zap-passive.json` | Full data |

- **Every row is a lead with status "To verify"**, never a confirmed finding. Confirm it with a
  request/response pair before raising it.
- Each ZAP rule is linked to the related banking-checklist item (e.g. CSP → VAPT-010, cookie
  flags → VAPT-014, error disclosure → VAPT-041/042). Mapping file:
  `zap-integration/src/main/resources/zap/zap-catalog-map.yaml` (override with `-Dvapt.zap.map=<file>`).
- Only approved hosts are reported (ZAP's passive scanner is also limited to them).
- Removed from every output: tokens, cookies, passwords, OTP, PAN/Aadhaar/card numbers, JWTs,
  long secret-looking strings and URL query **values** (names are kept).

## What it can and cannot see on CKYC 7.0
CKYC encrypts API bodies, so ZAP sees ciphertext there. Header, cookie, TLS/transport, status and
error-page rules still work. Rules that read body content cannot see the plain fields. The
recorder's own capture has the decrypted, redacted bodies for that. A ZAP bridge for the
encryption is a later, separate step.

## Verified (2026-11-09, local only)
- HAR import of a synthetic walk (fake host, fake cookie, token, password, OTP): 11 leads, linked to
  checklist items; **0 requests** reached the listening fake target; out-of-scope host not
  reported; 0 of 5 fake secrets in any output; ZAP run session deleted.
- Recorder + live ZAP against a local fake app (headless Edge): 8 leads; the app received exactly
  the page's own 2 requests (ZAP added none); 0 of 2 fake secrets in any output.
