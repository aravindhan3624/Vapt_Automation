# iSolve VAPT Automation Framework

A **dynamic, project-independent** QA + Authorized VAPT automation framework.
One core engine; CKYC / CAO / CCM / any future banking application is onboarded
through **configuration only** (`projects/<name>/config/*.yaml`) — never by
rewriting Java.

```
vapt-automation/
├── core-engine/                 # reusable engine — NO project-specific logic
│   └── src/main/java/com/isolve/vapt/
│       ├── config/              # ProjectConfig model + ConfigLoader (safety guardrails)
│       ├── catalog/              # Banking-domain VAPT catalog (64 findings) + loader
│       ├── engine/                # AuthEngine, ApiEngine(+ZAP), header/cookie/JWT/IDOR/fuzz
│       ├── report/                # FindingResult model + ReportEngine (VAPT/Retest/Closure)
│       └── util/                  # MaskUtil — secrets/PII masking before anything is written
│   └── src/main/resources/catalog/vapt-banking-catalog.yaml   # generated from your xlsx
├── projects/
│   ├── ckyc/                    # CKYC onboarding: config + feature files + thin step-defs
│   └── cao/                      # placeholder — same pattern, config not yet filled in
└── reports/
    ├── templates/                # reference HTML/Excel templates (see below)
    ├── output/                   # generated VAPT / Retest reports + Closure trackers land here
    └── evidence/                 # masked screenshots / request-response logs per run
```

## What's already built

1. **Catalog** — your `VAPT_Banking Domain check list_Final (1).xlsx` (64 checklist
   items) is parsed into [`vapt-banking-catalog.yaml`](core-engine/src/main/resources/catalog/vapt-banking-catalog.yaml):
   id, title, CWE, severity, remediation, "Done By" (AI/Manual/AI+Manual), test steps,
   expected secure result. Every automated check in the suite is tagged with its
   catalog id (`@VAPT-046`, etc.) so results roll straight into the reports below.
2. **Core engine** — config loading with mandatory safety guardrails (see below),
   REST Assured `ApiEngine` with optional OWASP ZAP proxy routing, `AuthEngine`
   (env-var-only credentials), `SecurityHeaderValidator`, `CookieValidator`,
   `JwtValidator`, `IdorValidator`, and `InputFuzzEngine` (safe, non-destructive
   SQLi/XSS/path-traversal detection payloads).
3. **Reporting** — `ReportEngine` generates:
   - **VAPT Report** (HTML) — executive summary + full findings detail + evidence links
   - **Retest Report** (HTML) — original FAIL vs retest result → CLOSED / REOPENED
   - **Closure Tracker** (XLSX) — one row per finding with sign-off columns, for
     your standard defect-closure sign-off process
   All three run every string through `MaskUtil` first — no password/OTP/bearer
   token/PAN/Aadhaar/card number is ever written to a report in the clear.
4. **CKYC project skeleton** — `projects/ckyc/config/ckyc-config.yaml` (placeholders
   marked `<<FILL ME>>`) and a sample feature file covering headers, cookies, auth
   bypass, JWT tampering, IDOR, SQLi/XSS probes and one Maker/Checker business rule.

## Built-in safety guardrails (`ConfigLoader`)

The engine **refuses to run** against a project config unless:
- a `scope:` block names who authorized the engagement and under what reference, and
- `environment:` does not contain "PROD".

Credentials are **never** stored in YAML — only the *name* of an environment
variable is configured (`usernameEnvVar`/`passwordEnvVar`); you export the real
value before running Maven.

## What I still need from you to actually run this against CKYC UAT

I will not fabricate or guess at CKYC's real endpoints, locators or test accounts.
To move from "scaffold" to "running," please provide:

**1. Install (one-time, on the machine that will run the suite):**
```bash
# Java 17+, Maven, and (optional but recommended) OWASP ZAP
java -version
mvn -version
```
If OWASP ZAP is wanted for the UI-spidering/active-scan pieces, install it and start
it listening on a port (default 8080) — tell me the host/port if different.

**2. Fill in `projects/ckyc/config/ckyc-config.yaml`:**
   - `baseUrl` / `apiBaseUrl` for the CKYC **UAT** environment
   - `openApiSpecUrl` (Swagger/OpenAPI), if CKYC exposes one — this alone would let
     me auto-generate most of the `endpoints:` list instead of you typing it by hand
   - The real `endpoints:` list (path/method/role) if no Swagger exists
   - Document Master (POI/POA codes) if file-upload/document checks are in scope
   - The `scope:` block — who approved this testing and the approval reference

**3. Test accounts (as environment variables, never typed into chat or committed):**
```bash
# PowerShell, before running mvn test
$env:CKYC_MAKER_USER   = "<uat maker test username>"
$env:CKYC_MAKER_PASS   = "<uat maker test password>"
$env:CKYC_CHECKER_USER = "<uat checker test username>"
$env:CKYC_CHECKER_PASS = "<uat checker test password>"
$env:CKYC_ADMIN_USER   = "<uat admin test username>"
$env:CKYC_ADMIN_PASS   = "<uat admin test password>"
```
These must be dedicated **test** accounts in UAT, not real employee/customer
credentials — I will never ask you to paste real passwords into this chat, and I
will not enter credentials anywhere myself (see the assistant's own safety rules).

**4. Network reachability** — this sandbox needs a route to the CKYC UAT host. If
it's on your internal corporate network only, the suite will need to run from a
machine that has that access (your laptop, a CI runner, a jump box) rather than
from here — I can hand you the finished Maven project to run there, and read back
whatever report/log output you paste or upload.

**5. Written authorization** — standard practice before any pentest: confirm you
have management/application-owner sign-off to run security tests (even safe,
non-destructive ones) against CKYC UAT, and record the reference in the `scope:`
block above. I won't run anything without that block populated — `ConfigLoader`
enforces it.

## Running once configured

```bash
cd vapt-automation
mvn -pl core-engine install
mvn -pl projects/ckyc test
```

Reports land in `reports/output/`:
`CKYC_VAPT_Report_<date>.html`, `CKYC_Closure_Tracker_<date>.xlsx`, and the raw
Cucumber HTML report.

## Onboarding the next project (CAO, CCM, ...)

1. Copy `projects/ckyc/` to `projects/cao/`, rename the pom artifactId.
2. Write `projects/cao/config/cao-config.yaml` using the exact same schema —
   different URLs, roles, endpoints, business rules, document master.
3. Write CAO's own feature file(s) tagging each scenario with the catalog finding
   id it exercises (the catalog is shared — 64 findings apply to any banking app).
4. **Zero changes to `core-engine`.** If you find yourself editing core-engine
   Java to make CAO work, that's the signal something was accidentally
   CKYC-specific and needs to move into config instead.

## What's intentionally NOT automated (manual, per the catalog's "Done By" column)

Findings tagged `Manual` in the catalog (OTP entropy/bypass, CAPTCHA bypass,
DoS/load testing, race conditions, shoulder-surfing/UI masking, HTTP request
smuggling) need a human with Burp Suite / physical device access. The catalog
still tracks them — `VaptCatalogLoader.manualOnly()` — so they show up as
`SKIPPED` with their steps/expected-result in the report rather than silently
disappearing, prompting the manual tester to pick them up.
