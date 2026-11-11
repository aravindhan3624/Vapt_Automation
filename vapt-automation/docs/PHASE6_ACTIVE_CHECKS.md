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
- Add more with `-Checks "UNAUTH_DOCUMENT_ACCESS,UNAUTHENTICATED_ACCESS"` and `-OtherIds "999"` for
  IDOR. The API read endpoints are encrypted on the wire; re-sending those with a modified body
  needs the encryption bridge (next step) and is skipped until then — the document and
  unauthenticated-GET checks run today.
- Pacing is 1 request/second by default (`-DelayMs`), with a hard cap (`-Max 200`).

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
