# Phase 6 — Active checks (CKYC 7.0 dev environment)

**Approval-gated. Read-only. Dev only.** Phase 6 is the first phase that sends requests of its
own. Every request is a **re-send of a call you already made** in your authorized session, with the
authorization weakened, to see whether the server correctly denies it. It **never** creates,
updates, approves, rejects, deletes, submits, uploads or logs in. There is no brute force, no
injection of destructive payloads, and no data extraction beyond confirming a single leaked field.

## The safety gate (fails closed)
The run is refused unless **all** of these hold:
1. The project config has a real authorization `scope:` (approver + approval reference, no placeholders).
2. The environment is not production (`ConfigLoader` and the gate both check).
3. `-Approval` matches the `approvalReference` in the config **and** the `VAPT_ACTIVE_APPROVAL`
   environment variable — so an active run always needs a deliberate, out-of-band step.
4. At least one approved host and one check are enabled.
5. In code, `ActiveChecks` cannot even be constructed without the gate's token, only approved hosts
   are contacted, and only endpoints the **non-destructive guard** rates read-only are ever re-sent.

The guard refuses, by name, anything whose path looks state-changing (create, update, delete,
approve, reject, lock, unlock, revoke, submit, login, crud, bulk, upload, …) and anything it cannot
classify. A wrongly-refused safe endpoint just means one fewer check; the default is always refuse.

## The checks (all read-only)
| Check | What it does | Secure result | Checklist |
|---|---|---|---|
| `UNAUTH_DOCUMENT_ACCESS` (default) | Fetch each recorded document/image URL with **no session** | 401/403 | VAPT-049/017 |
| `UNAUTHENTICATED_ACCESS` | Re-send a read API call with **no session** | 401/403 | VAPT-050 |
| `IDOR_BOLA` | Re-send a read for **another object id** (`-OtherIds`) | 403/404 | VAPT-049 |
| `JWT_TAMPER` | Re-send with an alg:none / unsigned token | rejected | VAPT-051 |

A result is **CONFIRMED** only when the weakened request actually succeeds (2xx with a real body);
otherwise it is **Secure** (closure evidence) or **Inconclusive** (verify by hand).

## Before you run — prerequisites
1. **Written approval.** Record the approver, approval reference and date in the project config
   `scope:` block (`projects/ckyc/config/ckyc-config.yaml`). The reference is your real ticket id.
2. **A capture** of the area to test, made with `tools/record.ps1`.
3. **Your session (optional, for baseline only).** For the non-document checks, set the env vars so
   the baseline request uses your logged-in session. Get the Cookie from DevTools → Network → any
   request → Request Headers → `Cookie`. It is used only to compare and is never stored:
   ```powershell
   $env:VAPT_SESSION_HEADER = "Cookie"
   $env:VAPT_SESSION_VALUE  = "ckyc_session=...; ckyc_refresh=..."
   ```

## How to run
```powershell
cd vapt-automation
$env:VAPT_ACTIVE_APPROVAL = "ISOLVE-VAPT-CKYC-2026-001"      # your approval reference
.\tools\active-checks.ps1 `
    -Config "projects\ckyc\config\ckyc-config.yaml" `
    -Capture "C:\captures\CKYC-7.0\CKYC-7.0-Maker-20261110-185959.capture.jsonl" `
    -Approval "ISOLVE-VAPT-CKYC-2026-001"
```
- Default check: `UNAUTH_DOCUMENT_ACCESS` — directly tests whether the customer Photo/POI/POA URLs
  from your capture can be opened with no login. This is the active confirmation of the Phase 5
  document lead, and it needs no session and no encryption.
- Add more with `-Checks "UNAUTH_DOCUMENT_ACCESS,UNAUTHENTICATED_ACCESS,IDOR_BOLA"` and
  `-OtherIds "<another test customer ref>"` for IDOR.
- Pacing is 1 request/second by default (`-DelayMs`), with a hard cap (`-Max 200`).

## Encrypted API checks (the encryption bridge)
The CKYC API read endpoints (e.g. `getCustomerDetailsV2`) encrypt their request and response. The
runner re-encrypts the (id-swapped) plain body into CKYC's envelope
(RSA-OAEP-SHA256 + AES-256-GCM), sends it, and decrypts the reply — including the inner
`statusCode` — so the no-login and IDOR checks work on those endpoints too.

To enable them you need two things, both supplied at run time and never stored:
1. **The CKYC server public key** (public material) via `-ServerKey` — a `.pem`/base64 string or a
   file path. Get it from the app's login/config response or its front-end JS, or ask the dev team.
   Set the env var equivalently with `VAPT_SERVER_PUBLIC_KEY`.
2. **Your session**, for the baseline comparison only: `VAPT_SESSION_VALUE` (the `Cookie` value from
   DevTools). The no-login check deliberately sends no session; IDOR uses your session with another
   customer's id.

```powershell
$env:VAPT_ACTIVE_APPROVAL = "ISOLVE-VAPT-CKYC-2026-001"
$env:VAPT_SESSION_VALUE   = "__Host-ckyc_session=...; __Host-ckyc_refresh=..."
.\tools\active-checks.ps1 -Config "projects\ckyc\config\ckyc-config.yaml" `
    -Capture "C:\captures\CKYC-7.0\...capture.jsonl" -Approval "ISOLVE-VAPT-CKYC-2026-001" `
    -ServerKey "C:\captures\ckyc-server-public-key.pem" -OtherIds "<another test customer ref>" `
    -Checks "UNAUTHENTICATED_ACCESS,IDOR_BOLA"
```
Without `-ServerKey`, only the document check runs; the encrypted checks are refused with a clear
message (nothing is sent).

## Output (in `C:\captures\CKYC-7.0\`)
`*-active-*.html/.csv/.json` — confirmed weaknesses first, then securely-denied checks (closure
evidence), then inconclusive. It records the approval reference and environment, lists each
endpoint and the weakened-vs-baseline HTTP status, and writes no session values or response bodies.

## Verified (2026-11-11, local only)
- `ActivePhase6Test` (9): the gate refuses without confirmation, in PROD, without the env var, on a
  reference mismatch; the guard refuses approve/update/lock/login/crud/DELETE; the engine confirms an
  unauth endpoint, marks a protected one secure, never re-sends a state-changing call, and never
  contacts an out-of-scope host.
- `HttpActiveTargetLocalTest`: end-to-end on loopback — a document served with no auth is CONFIRMED,
  a protected API is Secure, the approve/update endpoints in the capture are never fetched, the
  no-auth re-send carries no cookie, and no session value reaches the report.
- `CkycEnvelopeActiveIT` (projects/ckyc): end-to-end through the encryption bridge against a fake
  CKYC-envelope server — the no-login re-send is denied (inner 401 → Secure), the IDOR re-send for
  another id is denied (inner 403 → Secure), a public endpoint is CONFIRMED, the swapped id really
  travelled inside the encrypted body, and the approve/reject endpoint was never sent.
