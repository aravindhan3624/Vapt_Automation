# Run wizard (no code editing)

A local web form that saves the project config and launches record / passive / active runs, and
lets you review and label the captured endpoints — so you never edit YAML or type long commands.

## Launch
```powershell
cd vapt-automation
.\tools\vapt-wizard.ps1
```
It starts a localhost-only server (127.0.0.1, random port, random one-time token) and opens the
wizard in your browser. Leave the PowerShell window open while you use it; Ctrl+C there stops it.

## Steps
1. **Project** — project name, environment (production is blocked), approved host.
2. **Authorization** — approver, approval reference, date. Saved into the project config `scope:`.
3. **Action** — pick one:
   - **Record** — role + start URL (+ optional ZAP). Opens Edge; you log in and walk the app.
   - **Passive** — a HAR file to check offline.
   - **Active** — pick a capture file; the wizard loads its **endpoints** and lets you edit the
     module name and add a comment per endpoint (updates live as you type; **Save labels** writes
     `<capture>.labels.json` next to the capture). Choose the read-only checks, an "other id" for
     IDOR, a server public key for encrypted apps, and (optionally) your session cookie for the
     baseline. The session is passed to the run in memory and **never written to disk**.
4. **Review & run** — shows the exact config and command, then runs it and shows the report path.

## How it stays safe
- The server binds to 127.0.0.1 only, with a random port and a one-time token required on every
  `/api/*` call. Captures are only read from under `C:\captures\`.
- The config the wizard writes holds only non-secret values (scope reference, host, environment).
- Active runs still pass the full Phase 6 safety gate (approval reference must match the config and
  the `VAPT_ACTIVE_APPROVAL` env var, which the wizard sets for the child run only; non-production;
  read-only guard). The session cookie and server key are set as child-process env vars and removed
  after the run.

## Running from IntelliJ instead (IDE runner classes)
If you work in the IDE, each tool also has a TestNG launcher you run from the green ▶ gutter — the
IDE equivalent of the wizard. You set the host/options as **VM options** in the run configuration
(not in the YAML), so you still don't hand-edit the config file.

| Launcher (Run ▶) | Module | Example VM options |
|---|---|---|
| `RunRecorder` | recorder | `-Dvapt.project=CKYC-7.0 -Dvapt.role=Maker -Dvapt.startUrl=https://<dev-host>/ -Dvapt.zap=true` |
| `RunPassiveChecks` | core-engine | `-Dvapt.project=CKYC-7.0 -Dvapt.hosts=<dev-host> -Dvapt.har=C:\captures\walk.har` |
| `RunActiveChecks` | projects/ckyc | `-Dvapt.config=projects/ckyc/config/ckyc-config.yaml -Dvapt.capture=C:\captures\...jsonl -Dvapt.approval=<ref>` + env `VAPT_ACTIVE_APPROVAL=<ref>` |

These are deliberately named to avoid each module's surefire pattern, so a plain `mvn` build never
runs them, and each skips (does nothing) unless you supply its parameters. For `RunActiveChecks` the
Phase 6 gate still applies (approval reference must match the config and the `VAPT_ACTIVE_APPROVAL`
env var; non-production; read-only).

## Verified (2026-11-11, local)
- `vapt-wizard.ps1` parses clean; endpoint extraction returns 22 unique endpoints from a real
  CKYC capture. The page renders and navigates with no console errors; the Active step shows the
  dynamic capture dropdown, the read-only checks, and the per-endpoint label/comment editor.
