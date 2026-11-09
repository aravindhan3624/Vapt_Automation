# VAPT Automation Product — Tool Evaluation, Architecture and Plan

_Prepared 2026-11-05 for the authorized CKYC 7.0 engagement (target: the CKYC 7.0 **dev** environment, confirmed by the user 2026-11-09; not UAT, not production). Versions below were checked
the same day against Maven Central metadata and the official ZAP GitHub releases API._

## 1. Environment found on this PC
| Item | Found | Notes |
|---|---|---|
| JDK | 21.0.10 LTS | Project compiles for Java 17 |
| Maven | 3.10.0 | Maven Central reachable (HTTP 200, no proxy errors) |
| Burp Suite | 2026.4.3 installed (`%LOCALAPPDATA%\Programs\BurpSuite`) | One installer for both editions; Community vs Professional depends on the licence |
| OWASP ZAP | **Not installed** | Needs a separate install (see section 4) |
| Docker | Not installed | Not needed |
| Playwright for Java | 1.42.0 cached | Latest 1.64.0 |
| CKYC crypto client | `API_Automation\...\security\EnvelopeCrypto.java` + `SessionFilter.java` | JDK `AES/GCM/NoPadding` + `RSA/ECB/OAEPPadding`; to be moved into a shared module |

## 2. Tool evaluation
| Tool | Purpose in this product | Integration | Licence / cost | Latest checked | Decision |
|---|---|---|---|---|---|
| **REST Assured** | Engine for API test traffic; a filter encrypts/decrypts CKYC bodies | Maven library (already used) | Apache 2.0, free | 6.3.0 (project uses 5.4.0) | **Required** (keep 5.4.0 for now; upgrade later after testing) |
| **OWASP ZAP** (application) | Proxy + passive scan rules + controlled scanning + reports, all driven by API / Automation Framework YAML | Separate Java application run in **daemon (headless) mode**, controlled over its REST API | Apache 2.0, free | 2.17.0 | **Required** for automation |
| **ZAP Java client** `org.zaproxy:zap-clientapi` | Java calls to the ZAP API (start sessions, import traffic, read alerts, set scope, generate reports) | Maven library — **does not contain ZAP itself** | Apache 2.0, free | 1.17.0 (project declares 1.15.0) | **Required** (upgrade to 1.17.0) |
| **Burp Suite** | Tester's manual workbench: proxy capture, Repeater for manual confirmation of findings | Installed desktop app; extensions via Montoya API | Community free; Professional paid (annual) | 2026.4.3 installed | **Required for manual work**; not the automation engine (Community has no scanner or REST API) |
| **Burp Montoya API** `net.portswigger.burp.extensions:montoya-api` | Optional Burp extension that shows CKYC bodies decrypted and re-encrypts edits in Repeater | Maven, `provided` scope; built as a jar loaded into Burp | Free to use | 2026.7 | **Optional** (only if manual Burp work on CKYC needs plain bodies) |
| **Playwright for Java** | Recorder browser: tester logs in and browses; every call captured automatically, plain body read before client-side encryption | Maven library; downloads its browser builds on first run | Apache 2.0, free | 1.64.0 | **Required** for the recorder |
| **Selenium WebDriver** | Browser automation | Declared, unused | Apache 2.0 | 4.23.0 declared | **Unnecessary** once Playwright is in (remove later) |
| **OWASP Dependency-Check** Maven plugin | Scans **our own framework's** dependencies for known CVEs | Maven plugin; needs a free NVD API key; first run downloads the NVD data (large, slow) | Apache 2.0, free | 13.0.0 | **Optional** (supply-chain hygiene for the product) |
| **CycloneDX Maven plugin** | SBOM of the product for customers/auditors | Maven plugin | Apache 2.0, free | 2.9.3 | **Optional** |
| **Nuclei** | Template-based scanner | Separate Go binary, no Java API | MIT, free | not evaluated further | **Unnecessary** now — overlaps with ZAP, templates are mostly infra/CVE oriented, adds a second scanner to govern |
| **testssl.sh / sslyze** | TLS configuration review | CLI tools (bash / Python) | GPL-2 / AGPL-3 | not evaluated further | **Optional** later; ZAP passive rules plus a Java TLS handshake check cover the basics |

## 3. Burp Suite vs OWASP ZAP — decision
**Use both, for different jobs.** The user's Burp edition is **Community** (confirmed 2026-11-07),
so Burp is used only for manual work and all automated scanning goes through ZAP.
- **ZAP = automation engine.** Headless daemon, full REST API, Automation Framework YAML plans,
  passive rules, scan policies we control, HTML/JSON/XML reports. Fits CI and unattended runs.
- **Burp = tester's manual workbench.** Capture, look, and confirm findings by hand in Repeater
  before they go in a customer report. Burp Community can't be driven by API and has no scanner,
  so it is not used for unattended automation.
- **Our framework = the brain.** Endpoint inventory, roles, ownership, business rules, proof-based
  verdicts, false-positive handling and the customer report format. ZAP alerts are *inputs* to
  our verdict engine, never auto-confirmed findings.
- **CKYC encryption:** ZAP and Burp both see only `{"payload": ...}`. So the framework sends its
  own traffic through ZAP with the shared crypto module (plain JSON in our code, encrypted on the
  wire), and the recorder captures plain bodies in the browser.

### Research notes (official docs, 2026-11-05)
- **ZAP needs Java 17+** (JDK 21 OK). Headless modes: `-daemon` (API server) or
  `-cmd -autorun plan.yaml` (exit 0 ok / 1 errors / 2 warnings; `-autocheck` validates a plan).
  Source: zaproxy.org/download, zaproxy.org/docs/desktop/addons/automation-framework/
- **CKYC encryption in ZAP:** an **HTTP Sender script** runs on every request/response (proxy,
  scanner, fuzzer), so it can decrypt responses and re-encrypt requests and let ZAP's rules see
  plain JSON. **Script Input Vector** scripts limit exactly which fields are tested.
  Source: zaproxy.org/docs/desktop/addons/script-console/
- **Burp Montoya:** `HttpHandler` can modify traffic from any Burp tool, and custom request/
  response editor tabs can show decrypted bodies in Proxy/Repeater. Burp Pro is about
  US$399/user/year (portswigger.net/pricing; confirm before buying). Not needed by the framework.
- **Playwright:** browsers download to `%LOCALAPPDATA%\ms-playwright` (Chromium about 281 MB),
  **or** use `setChannel("msedge")` to drive the already-installed Edge with no download.
  Source: playwright.dev/java/docs/browsers
- **Selenium 4.52:** BiDi network interception is still marked internal, so it's not a good
  recorder; removing Selenium avoids two UI stacks.
- **REST Assured 6.x** needs Java 17+ and moves to Groovy 5 / Jackson 3; upgrade only after tests.
- **Dependency-Check 13.0.0:** first run can take 20+ minutes; an NVD API key is strongly advised.
- **TLS:** SSLyze 6.3.1 (AGPL-3.0) runs natively on Windows with JSON output, so it's preferred
  over testssl.sh (needs WSL/MSYS2). Call as a separate CLI; don't bundle it in the product.
- **Nuclei v3.11.1** (MIT): no Java SDK, community templates include intrusive checks, and it
  can't see through CKYC encryption, so it stays out.

## 4. Dependencies and installation plan
| # | Item | Source | Action | Needs |
|---|---|---|---|---|
| 1 | `zap-clientapi` 1.15.0 → **1.17.0** | Maven Central | Update version in parent `pom.xml` | Nothing |
| 2 | `playwright` 1.42.0 → **1.64.0** | Maven Central | Add to new `recorder` module | Use installed **Edge** (`channel=msedge`): no browser download. Chromium (about 281 MB) only if needed |
| 3 | `montoya-api` **2026.7** | Maven Central | Add to optional `burp-extension` module (`provided`) | Nothing |
| 4 | **ZAP 2.17.0 application** | Official GitHub release: `ZAP_2.17.0_Crossplatform.zip` (273 MB) | Unzip to `C:\Tools\ZAP_2.17.0\` — no installer, no admin rights; runs on the installed JDK 21 | **Your OK to download** |
| 5 | Dependency-Check / CycloneDX plugins | Maven Central | Add later as optional `verify` profile | Free NVD API key (you register) |

Not downloaded: Nuclei, testssl.sh, sslyze, Selenium upgrades.

### ZAP install record (done 2026-11-05, user-approved)
| Item | Value |
|---|---|
| Source | `https://github.com/zaproxy/zaproxy/releases/download/v2.17.0/ZAP_2.17.0_Crossplatform.zip` (official release) |
| Size | 286,652,857 bytes |
| SHA-256 | `94c8f767b1c2e94f0db66b3ae56514d5e3f5a728ee1b6c798e0c8fe2d61fbff0`, matching both GitHub's asset digest and the release notes |
| Installed to | `C:\Tools\ZAP_2.17.0\` (unzipped; no installer, no admin rights). Original zip kept in `C:\Tools\_downloads\` |
| ZAP home (config, sessions, add-ons) | `C:\Tools\zap-home\` (always start ZAP with `-dir C:\Tools\zap-home`) |
| Check | `java -jar zap-2.17.0.jar -cmd -version -dir C:\Tools\zap-home` printed `2.17.0`, exit 0, on JDK 21.0.10 |
| Not done yet | ZAP not started as a daemon; no API key set; no scan or proxy run against any host |

## 5. Proposed module structure
```
vapt-automation/
├── core-engine/            existing: config + guardrails, catalog, validators, report, MaskUtil,
│                           discovery (Phase 1, done)
├── crypto/                 NEW: shared EnvelopeCrypto + REST Assured encrypt/decrypt filter
├── recorder/               NEW: Playwright recorder browser (capture per role + module)
├── zap-integration/        NEW: ZAP daemon control, scope/context, passive alerts import,
│                           controlled scan policy, ZAP report export
├── burp-extension/         NEW (optional): Montoya extension for plain-text CKYC in Burp
├── checks/                 LATER: active check modules (each gated by approval)
├── projects/ckyc|cao/      project config, feature files, runners
├── config/                 environment settings (no secrets; env-var names only)
├── tools/                  run-discovery.ps1, start-zap.ps1, record.ps1 ...
└── docs/                   this plan, Phase 1 guide, onboarding
```

Component mapping (requested names → where they live):
| Component | Module / package |
|---|---|
| ApplicationLauncher, BrowserManager | `recorder` |
| BurpProxyIntegration | `discovery` (Burp XML/HAR import, done) + optional `burp-extension` |
| ZapIntegration | `zap-integration` |
| EndpointDiscovery, EndpointInventory | `core-engine/discovery` (done) |
| AuthenticationManager, SessionAnalyzer | `core-engine/engine` (AuthEngine + new session checks) |
| SecurityHeaderAnalyzer, CookieSecurityAnalyzer | `core-engine/engine` (existing validators) + ZAP passive rules |
| ApiSecurityScanner, AccessControlValidator, InputValidationTester | `checks` (later, approval-gated) |
| VulnerabilityAnalyzer | `checks/verdict` (proof-based; merges ZAP alerts + our checks; false-positive register) |
| EvidenceCollector | `core-engine/report` (redacted request/response, screenshots from recorder) |
| VaptReportGenerator | `core-engine/report` (HTML / Excel / JSON, customer format) |
| ExecutionLogger | `core-engine/util` (Log4j2, per-run log file) |

## 6. Phase plan
| Phase | Scope | Traffic to the target? | Status |
|---|---|---|---|
| 1 | Inspect project, evaluate tools, this plan | No | **Done** |
| 2 | Architecture + dependency updates, shared `crypto` module, ZAP daemon + passive session | No (local fake target only) | **Done 2026-11-07** (crypto 5/5, ZAP local IT pass) |
| 3 | Recorder (Playwright) + discovery from recordings | Only your own browsing | **Done 2026-11-07** (local IT pass); first CKYC dev recording pending (tester) |
| 4 | ZAP passive analysis: live through the recorder (`-Zap`) or offline HAR import; scope = approved host only; leads "To verify" linked to checklist items; redacted reports ([PHASE4](PHASE4_ZAP_PASSIVE_ANALYSIS.md)) | Passive only (no extra requests) | **Done 2026-11-09** (local ITs pass); first CKYC dev run pending (tester) |
| 5 | Passive analysis: headers, cookies, sensitive data, error leakage, TLS basics | No extra traffic | |
| 6 | Active modules, each separately approved by you in writing | **Yes — only after approval** | Not started |
| 7 | Customer report: findings first, closure evidence for every item, false-positive register | No | Format exists (02 Nov report) |
| 8 | Validate everything on the local fake target before any run on the target | Local only | Fake target exists |

## 7. Safety rules built into the product
- ConfigLoader refuses PROD environments and placeholder approvals.
- ZAP context/scope is limited to the approved host (CKYC 7.0 dev environment); out-of-scope requests are dropped.
- Active modules are off by default and need an explicit per-run approval reference.
- No brute force, no destructive or data-changing tests unless you approve them on test records.
- Credentials only through environment variables; never in config, code, logs, reports or git.
- Every report string is redacted (MaskUtil); ZAP findings are "to verify" until proven.

## 8. Missing prerequisites (yours)
1. OK to download `ZAP_2.17.0_Crossplatform.zip` (273 MB) from the official ZAP GitHub release.
2. Burp edition: Community or Professional.
3. Approval reference + test-account environment variables (set by you).
4. Optional: NVD API key, if you want Dependency-Check.
