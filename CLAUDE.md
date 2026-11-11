# CLAUDE.md — VAPT_Codes

Guidance for any Claude session working in this repository.

## 1. Purpose & Architecture
A **dynamic, project-independent QA + authorized-VAPT automation framework** for
banking back-office applications (CKYC, and in future CAO/CCM). The design goal:
one reusable core engine, with each application onboarded purely through YAML
configuration — never by writing new Java per application.

```
NEW PROJECT → YAML config → core engine (auth, API client, validators) → reports
```

See [vapt-automation/README.md](vapt-automation/README.md) for the full
architecture writeup (this file summarizes; that file is authoritative on design
rationale).

## 2. Folder structure
**Working copy (since 2026-11-05):** `C:\Users\da14294\OneDrive - isolve Technologies\Desktop\Automation_Testing_Projects\VAPT_Codes`.
The old `D:\IntelliJ_Projects\VAPT_Codes` is archived at `D:\IntelliJ_Projects_Archive\VAPT_Codes_moved-to-OneDrive_2026-11-05` - don't edit it.
```
VAPT_Codes/
├── VAPT_Banking Domain check list_Final (1).xlsx   # source: 64-item banking VAPT checklist
├── API automation Prompt with security.txt          # a *planning prompt* for a SEPARATE,
│                                                       not-yet-started "DailyAds" API
│                                                       automation project — not implemented here
├── CLAUDE.md                                         # this file
├── HANDOVER.md                                       # latest verified status, read this too
└── vapt-automation/                                  # the actual Maven project
    ├── pom.xml                                       # parent POM (dependency versions)
    ├── core-engine/                                  # reusable engine, NO project-specific code
    │   └── src/main/java/com/isolve/vapt/
    │       ├── config/    ProjectConfig model + ConfigLoader (safety guardrails)
    │       ├── catalog/    VaptFinding/VaptCatalog + VaptCatalogLoader
    │       ├── engine/      ApiEngine, AuthEngine, SecurityHeaderValidator,
    │       │                CookieValidator, JwtValidator, IdorValidator, InputFuzzEngine
    │       ├── report/      FindingResult + ReportEngine (VAPT/Retest/Closure)
    │       └── util/        MaskUtil (secret/PII masking)
    │   └── src/main/resources/catalog/vapt-banking-catalog.yaml   # generated from the xlsx
    ├── projects/
    │   ├── ckyc/            # CKYC onboarding: config + feature file + step defs + runner
    │   └── cao/              # placeholder only — config not filled in yet
    └── reports/
        ├── templates/        # EMPTY — referenced in README but never actually populated (gap)
        ├── output/            # generated reports land here (empty — never run yet)
        └── evidence/          # README.md documents the evidence-folder convention; no runs yet
```

## 3. Frameworks, libraries, dependencies
Defined in `vapt-automation/pom.xml` (parent, dependencyManagement):
- Java 17, Maven multi-module
- Selenium 4.23.0 (UI — not yet wired to any step def)
- REST Assured 5.4.0 (+ json-schema-validator)
- Cucumber 7.18.0 + TestNG 7.10.2 (BDD execution)
- OWASP ZAP client API 1.17.0; the ZAP 2.17.0 application itself is installed separately at
  `C:\Tools\ZAP_2.17.0` (home `C:\Tools\zap-home`) and driven by the `zap-integration` module
- Modules (build order): `crypto` (CKYC envelope encryption + REST Assured filter) ->
  `core-engine` -> `zap-integration` (ZAP daemon + passive session, no active scan) ->
  `recorder` (Playwright 1.64 + installed Edge; passive capture, plain CKYC bodies via WebCrypto
  hook, redacted) -> `projects/ckyc`. Selenium is declared but unused (Playwright replaces it).
- Jackson YAML + SnakeYAML (config/catalog parsing)
- Apache POI 5.3.0 (closure-tracker XLSX generation)
- ExtentReports 5.1.2 (declared as a dependency; not yet actually used by any class —
  `ReportEngine` currently writes plain HTML/XLSX directly, not through ExtentReports)
- Log4j2 / SLF4J

**Compiles (verified 2026-10-31)** with Maven 3.10.0
(`C:\Program Files\Maven\apache-maven-3.10.0\bin\mvn.cmd`, may not be on PATH) and
JDK 21 targeting 17. core-engine has 23 Java files.

## 4. Existing features and how they work
- **Catalog**: `VaptCatalogLoader.load()` reads the bundled
  `catalog/vapt-banking-catalog.yaml` (64 findings, each with id/title/CWE/
  severity/remediation/testSteps/expectedSecureResult/automatable flag) from the
  classpath. `automatable()`/`manualOnly()`/`findById()` helpers exist.
- **Config loading**: `ConfigLoader.load(File)` deserializes a project YAML into
  `ProjectConfig` and **refuses to proceed** (throws `SecurityException`) unless a
  `scope:` block with `authorizedBy`/`approvalReference` is present, and the
  `environment:` string does not contain "PROD". This is the framework's main
  safety control — do not remove or weaken it without discussing with the user.
- **Auth**: `AuthEngine.loginAs(roleName)` reads credentials strictly from OS
  environment variables named in the role config (`usernameEnvVar`/
  `passwordEnvVar`) — never from YAML or Java literals — POSTs to the configured
  login endpoint, extracts a bearer token via the configured JSON path, and sets it
  on `ApiEngine`. Only `API_LOGIN` is implemented; `FORM_LOGIN`/`OAUTH2`/
  `BEARER_STATIC` are declared in `AuthConfig.type` but not yet handled (will throw
  `UnsupportedOperationException`).
- **API calls**: `ApiEngine` wraps REST Assured. `baseRequest()` attaches the
  current bearer token; `unauthenticatedRequest()` and `requestWithToken(String)`
  exist for negative auth tests. If `zap.enabled: true` in project config, all
  REST Assured traffic is routed through the configured ZAP host/port.
- **Validators** (all stateless, pure functions over a REST Assured `Response`):
  `SecurityHeaderValidator.evaluate()` (CSP/HSTS/X-Frame-Options/etc. →
  SECURE/WEAK/MISSING), `CookieValidator.evaluate()` (Secure/HttpOnly/SameSite on
  session-looking cookies), `JwtValidator` (decode + alg:none/signature-stripped
  tamper variants — detection only, never forges a validly-signed token),
  `IdorValidator.evaluate()` (asserts 401/403/404 on cross-object access).
- **InputFuzzEngine**: static payload lists only (no live traffic) —
  `sqlInjectionProbes()`, `sqlErrorSignatures()`, `xssProbes()`,
  `pathTraversalProbes()`, plus `genericMutations(dataType)` for boundary/null/
  type fuzzing. Deliberately excludes destructive payloads (no DROP/UPDATE/stacked
  queries, no UNION-based data extraction) — SQLi verdicts require an observed
  error signature or boolean-based behavioural delta, never "HTTP 500 alone".
- **Reporting**: `ReportEngine` has three methods —
  `generateVaptReportHtml(...)`, `generateRetestReportHtml(...)`,
  `generateClosureTrackerXlsx(...)`. All route every string through `MaskUtil.mask()`
  first (strips Bearer tokens, Authorization headers, password/OTP JSON fields,
  PAN/Aadhaar/card-number-shaped strings) before writing to the output file.
- **CKYC project**: `projects/ckyc/config/ckyc-config.yaml` has placeholder values
  (`<<FILL ME>>`) for base/API URLs, a few example endpoints, two example business
  rules, and an empty-ish document master — **none of this is real CKYC data**, it
  was written as a template, not discovered from an actual CKYC system.
  `api_security_regression.feature` has 8 scenarios tagged with catalog finding
  ids (`@VAPT-010`, `@VAPT-014`, `@VAPT-050`, `@VAPT-051`, `@VAPT-049`, `@VAPT-046`,
  `@VAPT-045`, plus `@BR-CKYC-001`). `CkycApiSecuritySteps` implements most of
  these against the config's placeholder endpoints; three steps are deliberately
  `PendingException` stubs (`loginViaUi`, `createdTestTransaction`,
  `sameMakerAttemptsApproval`) marked TODO pending real CKYC UI locators and
  transaction/approval endpoints.

## 5. Important classes/methods — quick index
| Class | Key methods | Notes |
|---|---|---|
| `ConfigLoader` | `load(File)` | throws `SecurityException` if scope/env guardrail fails |
| `VaptCatalogLoader` | `load()`, `findById()`, `automatable()`, `manualOnly()` | cached singleton after first load |
| `ApiEngine` | `baseRequest()`, `unauthenticatedRequest()`, `requestWithToken()` | ZAP proxy wired in constructor if enabled |
| `AuthEngine` | `loginAs(role)` | env-var credentials only; API_LOGIN only so far |
| `ReportEngine` | `generateVaptReportHtml`, `generateRetestReportHtml`, `generateClosureTrackerXlsx` | all mask via `MaskUtil` |
| `CkycApiSecuritySteps` | step defs | `RESULTS` static list is read by `CkycTestRunner`'s `@AfterSuite` hook |

## 6. Build, run, test, debug
**Compiles and dry-runs; not yet run against a target** — see HANDOVER.md.
```bash
cd vapt-automation
mvn -pl projects/ckyc -am test-compile                          # compile only
mvn -pl projects/ckyc -am test -Dcucumber.execution.dry-run=true -Dsurefire.failIfNoSpecifiedTests=false   # safe: no requests sent
mvn -pl projects/ckyc -am test -Dvapt.mock.port=18089 -Dvapt.config=config/ckyc-mock-config.yaml "-Dcucumber.filter.tags=@ckyc and not @cookies and not @business-logic"   # local FAKE target (MockTargetHooks); needs MOCK_MAKER_USER/PASS set to any dummy value
mvn -pl crypto -am test                                         # crypto round trip vs loopback stand-in server
mvn -pl zap-integration -am test -Dzap.install.dir=C:\Tools\ZAP_2.17.0 -Dzap.home.dir=C:\Tools\zap-home   # starts ZAP locally, loopback fake target only
.\tools\record.ps1 -Project "CKYC-7.0" -Role Maker -StartUrl "https://<approved-dev-host>/" -Zap   # Phase 4: tester browses CKYC dev, ZAP passive only
.\tools\zap-passive-har.ps1 -Project "CKYC-7.0" -Hosts "<dev-host>" -Har C:\captures\x.har   # Phase 4 offline: HAR import, sends nothing
.\tools\passive-checks-har.ps1 -Project "CKYC-7.0" -Hosts "<dev-host>" -Har C:\captures\x.har   # Phase 5 offline checks (recorder runs them automatically)
.\tools\active-checks.ps1 -Config projects\ckyc\config\ckyc-config.yaml -Capture C:\captures\CKYC-7.0\x.capture.jsonl -Approval <ref>   # Phase 6: approval-gated, read-only (needs VAPT_ACTIVE_APPROVAL=<ref> + filled scope)
mvn -pl projects/ckyc -am test                                  # REAL run: only with filled scope + user's go
```
Always use `-am`: the parent POM is not installed in `.m2`, so `-pl projects/ckyc`
alone fails dependency resolution. Surefire picks up `**/*TestRunner.java` (set in
`projects/ckyc/pom.xml`).
Reports land in `reports/output/`. Required env vars (never commit real values):
`CKYC_MAKER_USER`, `CKYC_MAKER_PASS`, `CKYC_CHECKER_USER`, `CKYC_CHECKER_PASS`,
`CKYC_ADMIN_USER`, `CKYC_ADMIN_PASS` (and `CKYC_ZAP_API_KEY` / DB vars if those
features are turned on).

## 7. Completed / known issues / pending / next steps
See **HANDOVER.md** — kept separate and more volatile than this file so it can be
updated after every meaningful change without churning this architecture doc.

## 8. Important implementation decisions & constraints
- **Config-driven, not code-driven onboarding** is the central design constraint —
  resist the temptation to add CKYC-specific `if` branches into `core-engine`; if a
  new project needs that, the config schema (`ProjectConfig` and friends) should
  grow instead.
- **Credentials never in YAML or Java** — only env-var *names* are configured.
  Don't break this even for convenience/testing.
- **Non-destructive only** — `InputFuzzEngine` payloads and `ConfigLoader`'s
  PROD-environment refusal exist specifically so this framework can't accidentally
  be pointed at a live production banking system. Preserve both when extending.
- **MaskUtil runs before every report write** — if you add a new report field or
  evidence type, run it through `MaskUtil.mask()` too.
- The `API automation Prompt with security.txt` file at the repo root is a
  **planning prompt for an unrelated future project** ("DailyAds" third-party API
  integration) — don't confuse it with this VAPT framework; nothing has been built
  from it yet.
- **Git** was initialized on 2026-11-05 at the `VAPT_Codes` root (user-approved). The root
  `.gitignore` blocks credentials, key files and raw proxy captures (`*.har`, `burp-*.xml`,
  `captures/`); never commit those.
- **Target environment**: CKYC 7.0 **dev** environment (user, 2026-11-09), not UAT/production.
- **Phase 4 ZAP passive analysis** (`ZapPassiveAnalysis`, `PassiveAnalysisReport`, recorder `--zap`):
  ZAP only watches the tester's traffic or imports a HAR; no spider/active scan. Every lead is
  "To verify"; the per-run ZAP session (raw traffic) is deleted on close. See
  `vapt-automation/docs/PHASE4_ZAP_PASSIVE_ANALYSIS.md`.
- **Phase 5 passive checks** (`core-engine/.../passive`, always on in the recorder): headers, cookies,
  personal data / secrets in decrypted responses, data in URLs, error leakage, TLS. Values are inspected
  in memory only; reports hold names, counts and endpoints. See `vapt-automation/docs/PHASE5_PASSIVE_CHECKS.md`.
- **Phase 6 encryption bridge** (`projects/ckyc/.../active`: `CkycEnvelopeBridge`, `CkycActiveRunner`):
  re-encrypts the (id-swapped) plain body into CKYC's envelope and decrypts the reply, so the no-login
  and IDOR checks also work on encrypted API endpoints. Server key via `VAPT_SERVER_PUBLIC_KEY` / `-ServerKey`.
- **Phase 6 active checks** (`core-engine/.../active`, run via `tools/active-checks.ps1`): read-only
  re-sends of recorded calls with weakened auth (no token / another id / tampered token). Fails closed:
  `ActiveTestGate` needs config scope + non-PROD + approvalReference matching the config AND the
  `VAPT_ACTIVE_APPROVAL` env var; `NonDestructiveGuard` re-sends only read-only endpoints. Never
  creates/updates/approves/deletes/submits. See `vapt-automation/docs/PHASE6_ACTIVE_CHECKS.md`.
- **Phase 1 discovery** (`core-engine/.../discovery`, run via `tools/run-discovery.ps1`) is
  passive: it only reads a capture file the user exported and stores names/status codes, never
  values. Active testing needs the user's separate written go-ahead. See
  `vapt-automation/docs/PHASE1_ENDPOINT_DISCOVERY.md`.
