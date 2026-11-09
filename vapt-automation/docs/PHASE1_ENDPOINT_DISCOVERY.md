# Phase 1 — Passive endpoint discovery (CKYC 7.0 dev environment)

**Passive only.** You use the application normally; Burp Suite records the traffic; this
tool reads the exported file and builds an endpoint inventory. The tool itself sends **no**
requests and runs **no** security tests. Active testing is a later phase and needs separate
written confirmation.

## Before you start
- Approved CKYC 7.0 **dev environment** only, with the written approval reference recorded.
- Use **test accounts** only. You type passwords yourself into the CKYC login page.
  Never paste them in chat, a file or a ticket.
- Burp Suite running; browser proxy set to Burp (default `127.0.0.1:8080`), Burp CA
  certificate installed in that browser so HTTPS loads.
- In Burp, add the dev host to **Target > Scope** and turn on "show only in-scope items",
  so traffic from other sites isn't captured.
- **Do not** use Burp Scanner, Intruder or active scan in this phase.

## Option A (recommended): the recorder — no Burp export needed
One command per role. Edge opens with a **fresh, empty profile** (nothing from your own Edge);
you log in yourself and use the application; closing the window ends the session.
```powershell
cd vapt-automation
.\tools\record.ps1 -Project "CKYC-7.0" -Role Maker -StartUrl "https://<approved-dev-host>/"
```
- Captures only XHR/fetch API calls to the start URL's host (add more with `-Hosts h1,h2`).
- **CKYC encrypted bodies are saved as plain JSON** (read inside the page from WebCrypto, matched
  exactly to each call), with passwords, tokens, OTP, CSRF/session values, PAN/Aadhaar redacted.
  Header values are never stored.
- Type the module name in the small **"VAPT module"** box (bottom right) before each module.
- Optional: `-Proxy 127.0.0.1:8080` also sends the traffic through Burp Community.
- Add `-Zap` for Phase 4 ZAP passive analysis of the same session (see `PHASE4_ZAP_PASSIVE_ANALYSIS.md`).
- Output in `C:\captures\CKYC-7.0\`: `*.capture.jsonl` (redacted calls), `*-endpoints.redacted.csv/json`
  and `*-endpoint-discovery.html`.
- Verified 2026-11-07 on a local fake app that encrypts with WebCrypto AES-GCM: 2 in-scope calls
  captured, static file + out-of-scope host ignored, both encrypted bodies read as plain text,
  0 of 3 fake secrets in any output file.

## Option B: Burp export
## 1. Capture (manual, per role)
1. Clear Burp **Proxy > HTTP history** (so each file holds one role's walk).
2. Log in to CKYC 7.0 dev as one test role (e.g. Maker).
3. Walk every module and action normally: menus, search, view, create, edit, approve/reject,
   upload/download, reports. Use test data only; don't do final submissions to external
   registries.
4. Log out.
5. In **HTTP history**: filter to in-scope items, select all (Ctrl+A), right-click
   **Save items**, keep "Base64-encode requests and responses" ticked, save as e.g.
   `ckyc-maker-walk.xml`.
6. Repeat 1–5 for each role (Maker A, Maker B, Checker, Admin).

Keep these raw files in a local folder such as `C:\captures\` (outside OneDrive). They contain
live cookies and tokens; the project `.gitignore` also blocks `*.har`, `burp-*.xml` and
`captures/`.

## 2. Run discovery
From `vapt-automation`:
```powershell
.\tools\run-discovery.ps1 -Project "CKYC-7.0" -Capture "C:\captures\ckyc-maker-walk.xml","C:\captures\ckyc-checker-walk.xml"
```
HAR files (Burp or browser DevTools export) work too.

Output in `reports\output\discovery\` (git-ignored):
| File | Content |
|---|---|
| `CKYC-7.0-endpoints.redacted.json` | Full inventory + metadata |
| `CKYC-7.0-endpoints.redacted.csv` | One row per endpoint, for Excel |
| `CKYC-7.0-endpoint-discovery.html` | Report grouped by module |

## What is stored (and what is not)
| Stored | Never stored |
|---|---|
| Method, normalized path (`/customer/{id}`), module, host | Header / cookie values, bearer tokens |
| Query-parameter **names**, body-parameter **names** | Any query or body **value** (passwords, OTP, PAN, Aadhaar…) |
| Status codes seen, content types, call count | Response bodies |

Same endpoint called with different ids is merged into one row (`{id}`, `{uuid}`, `{hash}`).
CKYC bodies are encrypted, so Burp sees only `{"payload": ...}`; these rows are marked
**encrypted body**. Method, path, query params and status are still discovered. Reading the
decrypted fields needs the browser-hook recorder (later phase).

## Verified
Synthetic captures (fake host, fake token, cookie, password, OTP, PAN) on 2026-11-05: 8 calls →
6 unique endpoints, correct modules, and none of the 8 fake secret values appear in any output
file.
