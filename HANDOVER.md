# HANDOVER.md — VAPT_Codes

_Last verified: 2026-11-05. Read this alongside CLAUDE.md before continuing work._

## 2026-11-07 — Recorder (Phase 3, passive)
- New module **`recorder`** (Playwright **1.64.0**, `channel=msedge` = installed Edge 156, no browser
  download; fresh empty profile). `Recorder` / `RecorderMain` / `RecorderConfig` / `CaptureRecord` /
  `JsonRedactor` + `resources/recorder/crypto-hook.js`; run with `tools/record.ps1`.
- Captures XHR/fetch to approved hosts only; header names only; bodies redacted by key
  (password/otp/token/secret/csrf/session/cookie/authorization/api key...) + MaskUtil.
- In-page hook observes WebCrypto AES-GCM encrypt/decrypt and reports plain text with
  base64(iv||ciphertext), which equals the wire `payload` / `responseObject`, so plain bodies are
  matched exactly. Raw bodies live in memory only until redacted. If an app uses a JS crypto
  library instead of WebCrypto, bodies stay encrypted (still discovered as endpoints).
- `RecorderLocalIT` (Edge headless, loopback fake app with real WebCrypto encryption): **pass** —
  2 in-scope calls, static + out-of-scope ignored, request+response decrypted, 0/3 fake secrets in
  output. Full `mvn install`: 6 modules SUCCESS, CKYC dry run 13/13.
- Not yet run on CKYC UAT. Unverified until then: that CKYC's front end uses WebCrypto
  (`crypto.subtle`) for AES-GCM (API_Automation notes say its algorithm matches the app's
  `src/utils/crypto.ts`). The first real run will show it: `requestDecrypted: true` in the capture.

## 2026-11-07 — Phase 2: shared crypto + ZAP integration (local only)
- `zap-clientapi` 1.15.0 -> **1.17.0** (parent pom). New modules, build order
  `crypto -> core-engine -> zap-integration -> projects/ckyc`.
- **`crypto`**: `EnvelopeCrypto` (ported from API_Automation; same RSA-OAEP-SHA256 + AES-256-GCM wire
  format, server public key passed in, one ephemeral key pair per instance) and
  `EnvelopeCryptoFilter` (REST Assured: encrypts plain JSON out, decrypts reply; one-shot modes
  `PLAIN_BODY` / `CORRUPT_KEY` for later approval-gated integrity tests).
  `EnvelopeCryptoTest`: **5/5 pass** against a loopback stand-in server with its own key pair.
- **`zap-integration`**: `ZapDaemon` (starts `C:\Tools\ZAP_2.17.0` headless, `-host 127.0.0.1`,
  `-silent`, random per-run API key in memory, sets **protect** mode, shuts down via API) and
  `ZapPassiveSession` (context limited to approved hosts, wait for passive scan, redacted alerts,
  ZAP HTML report). **No active-scan method exists.**
  `ZapPassiveLocalIT` (runs only with `-Dzap.install.dir=...`): loopback fake server without
  security headers -> 1 request via ZAP proxy -> **6 passive alerts** (anti-clickjacking, CSP,
  X-Content-Type-Options, cookie HttpOnly, cookie SameSite, session info), report written, ZAP
  stopped, 0 leftover processes. **Pass**, about 15 s.
  First attempt failed: overriding `api.addrs` removed ZAP's default `zap` virtual host that the
  Java client uses ("host header zap not permitted"); override removed. Log of that attempt kept
  at `C:\Tools\zap-home\zap-daemon-console.first-attempt.log`.
- Full build `mvn install` (CKYC dry run): all 5 modules SUCCESS, CKYC 13/13 discovered.
- Burp edition confirmed by user: **Community** -> manual workbench only (no scanner/API).
- Nothing was sent to CKYC UAT. Next: recorder (Playwright + Edge), then CKYC encryption bridge
  for ZAP (so ZAP's passive rules see plain JSON), all tested on the local fake target first.

## 2026-11-05 — tool plan + ZAP installed
- Tool evaluation, Burp vs ZAP decision, module structure and phase plan:
  `vapt-automation/docs/VAPT_PRODUCT_PLAN.md` (ZAP = automation engine, Burp = manual workbench).
- **ZAP 2.17.0 installed** (user-approved) from the official GitHub release, SHA-256 verified,
  unzipped to `C:\Tools\ZAP_2.17.0\`, home dir `C:\Tools\zap-home\`. Version check OK on JDK 21.
  Not yet started as a daemon, no scan run.
- Burp Suite 2026.4.3 is installed at `%LOCALAPPDATA%\Programs\BurpSuite`; edition not yet confirmed.
- Next (Phase 2): update `zap-clientapi` to 1.17.0, add shared `crypto` module (from API_Automation
  `EnvelopeCrypto`), ZAP daemon start/stop script tested against the local fake target only.

## 2026-11-05 — git + Phase 1 passive endpoint discovery
- `git init` at `VAPT_Codes` root (user-approved; no repo existed). Baseline commit `ea3c16e`.
  Root `.gitignore` keeps credentials, keys and raw captures out.
- New package `core-engine/src/main/java/com/isolve/vapt/discovery/` (`CaptureParsers`,
  `EndpointInventory`, `DiscoveryReport`, `EndpointDiscovery` + 2 models) and
  `tools/run-discovery.ps1`. Reads a Burp "Save items" XML or HAR the user exported, normalizes
  ids, de-duplicates, guesses the module, writes redacted JSON/CSV/HTML to
  `reports/output/discovery/`. Sends no requests. Stores names/status codes only.
- Verified on synthetic captures only (fake host + fake secrets): 8 calls -> 6 endpoints,
  modules correct, 0 of 8 fake secret values in output. **Not yet run on a real CKYC capture.**
- Next: user captures CKYC 7.0 UAT per role with Burp (guide:
  `vapt-automation/docs/PHASE1_ENDPOINT_DISCOVERY.md`) and runs the script; then Phase 2
  (endpoint classification + review). No active testing until the user confirms in writing.
- Credentials: the user pasted test-account credentials in chat on 2026-11-05. They were not
  stored anywhere; the user was asked to rotate them and use env vars.

## Location (changed 2026-11-05, user's decision)
**The only working copy is now** `C:\Users\da14294\OneDrive - isolve Technologies\Desktop\Automation_Testing_Projects\VAPT_Codes`.
The old `D:\IntelliJ_Projects\VAPT_Codes` was compared first (OneDrive had every D: file plus
`Reviews/`; only the regenerable `target/` folders were missing), then **moved, not deleted**, to
`D:\IntelliJ_Projects_Archive\VAPT_Codes_moved-to-OneDrive_2026-11-05` so the nightly
`IntelliJ-OneDrive-Backup` task (D:\IntelliJ_Projects -> OneDrive) no longer creates `.conflict-*`
copies for this project. Paths "D:\IntelliJ_Projects\VAPT_Codes" in older sections below are historical.

## Current state in one line
**Both modules compile and Surefire discovers the CKYC runner** (verified
2026-10-31, see below); still **never pointed at a real system**. All CKYC values
are placeholders.

## 2026-10-31 — first real build (Claude, with user's OK; work on D: copy)
Commands run in `D:\IntelliJ_Projects\VAPT_Codes\vapt-automation` with
`C:\Program Files\Maven\apache-maven-3.10.0\bin\mvn.cmd` (JDK 21.0.10, target 17):
1. `mvn -B -ntp -pl core-engine install -DskipTests` → **BUILD SUCCESS**, 23 sources
   compiled with zero errors; missing deps downloaded from Maven Central.
2. `mvn -B -ntp -pl projects/ckyc -am test-compile` → **BUILD SUCCESS** (2 test sources).
3. `mvn -pl projects/ckyc test` (without `-am`) → **FAILS**: parent POM
   `vapt-automation-parent:1.0.0` is not installed in `.m2`. Always build through the
   reactor (`-am`), or run `mvn -N install` once from `vapt-automation`.
4. Added Surefire `<includes>**/*TestRunner.java</includes>` to
   `projects/ckyc/pom.xml` (the only source change) — default patterns did not
   match `CkycTestRunner`.
5. `mvn -B -ntp -pl projects/ckyc -am test -Dcucumber.execution.dry-run=true
   -Dsurefire.failIfNoSpecifiedTests=false` → **Tests run: 13, Failures 0, Errors 0**
   in `CkycTestRunner`; every step bound to a Java method (no undefined steps).
   Dry run = step bodies NOT executed, no network request sent. `@AfterSuite` still
   wrote (empty-result) `CKYC_VAPT_Report_2026-10-31.html`,
   `CKYC_Closure_Tracker_2026-10-31.xlsx`, `ckyc-cucumber-report.html` to
   `reports/output/` — proves the report pipeline runs, not that results are right.

## 2026-10-31 — code fixes (user approved "fix them")
| File | Fix |
|---|---|
| `core-engine/.../catalog/VaptCatalogLoader.java` | **Latent bug found:** catalog YAML is snake_case but POJOs are camelCase, so `load()` threw `UnrecognizedPropertyException` (confirmed in jshell). Added `PropertyNamingStrategies.SNAKE_CASE`. |
| `core-engine/.../engine/InputFuzzEngine.java` | `List.of((Object) null)` → `Collections.singletonList(null)` (NPE). |
| `projects/ckyc/.../CkycApiSecuritySteps.java` | JWT tamper step now uses the token returned by `AuthEngine.loginAs` (field `currentToken`; asserts a login ran first). VAPT-050/051 recorded under their real ids instead of "N/A". `recordResult` fills severity + CWE from the catalog and module from the endpoint config. |
| `projects/ckyc/config/ckyc-config.yaml` | Added `testData.foreignCustomerId` (placeholder) so the IDOR step no longer fails on a null map. |
Verified: `mvn -pl projects/ckyc -am install -DskipTests` exit 0; jshell against
the built classes: catalog loads 64 findings (23 automatable / 41 manual), e.g.
VAPT-050 severity Medium CWE 287; `genericMutations("INTEGER")` returns a null entry
without error; `ConfigLoader` loads ckyc config with `testData` key. Dry run again
13/13, 0 failures. No request sent to any host.

## 2026-10-31 — guardrail tightened (user approved "Yes, tighten it")
`ConfigLoader.validate` now also throws `SecurityException` if `scope.authorizedBy`,
`approvalReference` or `approvalDate` contains `<<` or `FILL ME`. Verified in jshell:
shipped `ckyc-config.yaml` → REFUSED (placeholder message); scratch copy with dummy
scope values → LOADED; same copy with `environment: PROD` → REFUSED (prod message).
Consequence: **a real run is impossible until the user records the genuine
approval in `scope:`** — intended. URL fields are not placeholder-checked (a
`<<FILL ME>>` baseUrl simply fails at request time).

## 2026-10-31 — local mock dry run (user approved)
**What was added**
- `projects/ckyc/src/test/java/com/isolve/vapt/ckyc/mock/MockTargetHooks.java` — FAKE
  target (JDK `HttpServer`, loopback only, inside the test JVM) started by a Cucumber
  `@BeforeAll` only when `-Dvapt.mock.port` is set. Deliberately vulnerable: IDOR on
  `/customer/MOCK-FOREIGN-002`, DB-error string for ids containing `'`. Secure otherwise.
- `projects/ckyc/config/ckyc-mock-config.yaml` — copy of ckyc config: project
  `CKYC-MOCK`, env `LOCAL-MOCK`, URLs `http://localhost:18089`, env-var names
  `MOCK_MAKER_USER/PASS`, scope = local mock only.
- Step defs: `-Dvapt.config=` overrides the config path; runner glue includes the mock
  package; runner labels reports from the loaded project/env (no more hardcoded CKYC/UAT).

**Bugs the mock run exposed and fixed**
1. `{id}` in endpoint paths was never substituted for headers / no-auth / tampered-token
   steps → REST Assured threw "Invalid number of path parameters" (would have hit real
   CKYC too). `resolvePath` now fills every `{param}` from `testData` (key = param name);
   added `testData.id` placeholder to `ckyc-config.yaml`.
2. XSS check flagged correctly encoded output as reflected (matched `onerror=alert`
   inside `&lt;img …&gt;`). Now FAIL only if the exact raw payload is in the body.
3. Header/cookie evidence printed `HeaderCheck@hash` → added `toString()` to
   `SecurityHeaderValidator.HeaderCheck` and `CookieValidator.CookieVerdict`.

**Result (actual)** — command (PowerShell, dummy values only for the mock):
```
$env:MOCK_MAKER_USER="mock-user"; $env:MOCK_MAKER_PASS="mock-pass"
mvn -B -pl projects/ckyc -am test -Dvapt.mock.port=18089 -Dvapt.config=config/ckyc-mock-config.yaml "-Dcucumber.filter.tags=@ckyc and not @cookies and not @business-logic" -Dsurefire.failIfNoSpecifiedTests=false
```
Tests run 11, failures 0 (the two PendingException scenarios excluded by tag).
`reports/output/CKYC-MOCK_VAPT_Report_2026-10-31.html`: PASS 8 / FAIL 3 — FAIL =
VAPT-049 IDOR (High, CWE 639) + 2× VAPT-046 SQLi (Medium, CWE 89), exactly the planted
flaws; headers, VAPT-050, 3× VAPT-051, VAPT-046 boolean probe, 2× VAPT-045 PASS.
`CKYC-MOCK_Closure_Tracker_2026-10-31.xlsx`: header + 11 rows. Only localhost traffic.
Note: security-check Then steps record FAIL in the report but don't fail the test —
the build stays green when findings exist. **Decision 2026-10-31 (user): keep
report-only** — findings go to the VAPT report / closure tracker, the build does not
fail on them. Don't add assertions to the security Then steps without asking.

Still open: 3 PendingException stubs; IDOR Then-step records but never asserts
(same as headers/SQLi/XSS steps — they record, don't fail); "expired" JWT variant is
a malformed placeholder, not a genuinely expired token; tags VAPT-045 (generic input
validation) vs catalog VAPT-022 (XSS); endpoint `method` ignored (always GET).

## Work completed this session
1. Parsed `VAPT_Banking Domain check list_Final (1).xlsx` (64 rows) into
   `vapt-automation/core-engine/src/main/resources/catalog/vapt-banking-catalog.yaml`.
2. Built the Maven multi-module skeleton: parent `pom.xml`, `core-engine` module,
   `projects/ckyc` module, `projects/cao` placeholder.
3. Implemented `core-engine`: config model (`ProjectConfig` + 7 nested config
   classes), `ConfigLoader` with mandatory authorization-scope + non-PROD
   guardrails, catalog model + loader, engine classes (`ApiEngine`, `AuthEngine`,
   `SecurityHeaderValidator`, `CookieValidator`, `JwtValidator`, `IdorValidator`,
   `InputFuzzEngine`), `MaskUtil`, and `ReportEngine` (VAPT/Retest HTML reports +
   Closure Tracker XLSX).
4. Built `projects/ckyc`: `ckyc-config.yaml` (placeholders), one feature file with
   8 scenarios tagged to catalog finding ids, `CkycApiSecuritySteps` step defs
   (3 of them deliberately `PendingException` stubs), `CkycTestRunner` (TestNG +
   Cucumber, generates reports in `@AfterSuite`).
5. Wrote `vapt-automation/README.md`, `reports/evidence/README.md`,
   `projects/cao/config/README.md`, `.gitignore`.
6. Set up the user's requested cross-project memory system in
   `OneDrive/.../Automation_Testing_Projects/` (`MASTER_PROMPT.md`,
   `MASTER_MEMORY.md`, `PROJECT_INDEX.md`, and `Projects/<id>/PROJECT_MEMORY.md`
   for all 9 discovered projects, including this one).
7. This file + `CLAUDE.md`, per the user's explicit request for project
   documentation — completes a task that was interrupted mid-way earlier in this
   session.

## Files created/modified (this session)
All new files — nothing pre-existing was overwritten.
```
VAPT_Codes/CLAUDE.md                                               (new)
VAPT_Codes/HANDOVER.md                                             (new)
VAPT_Codes/vapt-automation/pom.xml                                 (new)
VAPT_Codes/vapt-automation/.gitignore                               (new)
VAPT_Codes/vapt-automation/README.md                                (new)
VAPT_Codes/vapt-automation/core-engine/pom.xml                      (new)
VAPT_Codes/vapt-automation/core-engine/src/main/java/com/isolve/vapt/**  (new, 16 files)
VAPT_Codes/vapt-automation/core-engine/src/main/resources/catalog/vapt-banking-catalog.yaml  (new, generated)
VAPT_Codes/vapt-automation/projects/ckyc/pom.xml                    (new)
VAPT_Codes/vapt-automation/projects/ckyc/config/ckyc-config.yaml    (new, placeholders)
VAPT_Codes/vapt-automation/projects/ckyc/src/test/**                (new, feature+stepdefs+runner)
VAPT_Codes/vapt-automation/projects/cao/config/README.md            (new, placeholder note)
VAPT_Codes/vapt-automation/reports/evidence/README.md               (new)
```

## Important decisions made
- Config-driven onboarding (see CLAUDE.md §8) — the non-negotiable architectural
  constraint going forward.
- Hard safety guardrails in `ConfigLoader` (authorization scope mandatory, PROD
  environments refused) — do not loosen these without the user explicitly asking.
- `ReportEngine` masks everything before writing — treat as mandatory for any new
  report/evidence code path.

## Known issues / blockers
1. ~~Never compiled~~ — resolved 2026-10-31: compiles cleanly; build with `-am`
   (see section above).
2. **CKYC config is 100% placeholder.** No real base URL, API URL, Swagger,
   endpoints, business rules, document master, or test accounts. The suite cannot
   run until the user supplies these (see `vapt-automation/README.md` §"What I
   still need from you").
3. **Three step defs are `PendingException` stubs**: `loginViaUi` (needs real CKYC
   login page locators for a Selenium-based UI engine, which doesn't exist yet —
   only the API engine is implemented), `createdTestTransaction` and
   `sameMakerAttemptsApproval` (need CKYC's real transaction/approval endpoints).
4. **`reports/templates/` is empty** — the README mentions "reference HTML/Excel
   templates" there but none were ever created; either populate it or fix the
   README to stop promising it.
5. **No UI engine exists yet** — `ApiEngine`/`AuthEngine` only cover API-level
   testing. Selenium is a declared dependency but unused. Cookie-based checks
   (`@VAPT-014`) need a UI login flow to capture `Set-Cookie` headers, which is
   exactly the blocked `loginViaUi` step above.
6. **No `.git` repository** in `D:\IntelliJ_Projects\VAPT_Codes` — consider
   initializing one before this grows further, so changes are tracked.
7. **Dual-copy ambiguity**: an apparent mirror of this project exists at
   `OneDrive/.../Automation_Testing_Projects/VAPT_Codes/` — not confirmed whether
   it auto-syncs with `D:\IntelliJ_Projects\VAPT_Codes` or is a stale snapshot.
   Confirm with the user which is canonical before editing both.
8. **ExtentReports is a declared Maven dependency but unused** — `ReportEngine`
   writes HTML/XLSX directly. Either wire it in or drop the dependency.

## Next recommended actions (in order)
1. Confirm canonical project location (D: vs OneDrive) with the user.
2. Get CKYC real connection details from the user (see README §"What I still need
   from you") — base URL, API URL, Swagger if any, test account env vars, written
   authorization reference.
3. Open in IntelliJ, resolve Maven deps, compile, fix any errors.
4. Fill `ckyc-config.yaml` with real values; export the test-account env vars.
5. Run `mvn -pl projects/ckyc test`; fix whatever breaks on first real contact
   with a live API (field names, auth flow shape, etc. will almost certainly need
   adjustment from the placeholder assumptions).
6. Decide whether to build the UI engine now (needed for cookie/session/UI-based
   checklist items) or defer those items as manual.
7. Once CKYC runs cleanly, onboard CAO next using
   `Projects/SURAT_CAO_WEB_AUTOMATION/PROJECT_MEMORY.md` (in the OneDrive master
   memory) as the source for CAO's real endpoints/roles instead of guessing.

## Test/validation results
- 2026-10-31: compile OK (both modules); Cucumber dry run 13/13 discovered, all
  steps bound. That is the only execution so far.
- Nothing has been executed against a real environment. Do not report otherwise in
  a future session.
