<#
.SYNOPSIS
  Phase 6: APPROVAL-GATED active checks. READ-ONLY re-sends of calls you already made, to confirm
  access-control weaknesses. It never creates, updates, approves, rejects, deletes or submits.

.DESCRIPTION
  Refuses to run unless ALL of these hold (the safety gate):
    - the project config has a real authorization scope and the environment is not production;
    - -Approval matches the approvalReference in the config AND the VAPT_ACTIVE_APPROVAL env var;
    - at least one approved host and one check are set.
  The default check is UNAUTH_DOCUMENT_ACCESS (fetch recorded document URLs with no session and
  see whether they are served). Your current session, used only for baseline comparison, is read
  from the env vars VAPT_SESSION_HEADER / VAPT_SESSION_VALUE and never stored.

  Only run this against the approved CKYC 7.0 DEV environment, with written approval, using test
  data. Record a capture first with tools/record.ps1.

.EXAMPLE
  $env:VAPT_ACTIVE_APPROVAL = "ISOLVE-VAPT-CKYC-2026-001"
  .\tools\active-checks.ps1 -Config "projects\ckyc\config\ckyc-config.yaml" `
      -Capture "C:\captures\CKYC-7.0\CKYC-7.0-Maker-20261110-185959.capture.jsonl" `
      -Approval "ISOLVE-VAPT-CKYC-2026-001"
#>
param(
    [Parameter(Mandatory = $true)][string]$Config,
    [Parameter(Mandatory = $true)][string]$Capture,
    [Parameter(Mandatory = $true)][string]$Approval,
    [string]$Hosts = "",
    [string]$Checks = "UNAUTH_DOCUMENT_ACCESS",
    [string]$OtherIds = "",
    [string]$Out = "",
    [int]$DelayMs = 1000,
    [int]$Max = 200
)
$ErrorActionPreference = 'Stop'
if (-not $env:VAPT_ACTIVE_APPROVAL) {
    throw "VAPT_ACTIVE_APPROVAL is not set. Set it to your approval reference first:  `$env:VAPT_ACTIVE_APPROVAL = '$Approval'"
}
if (-not (Test-Path -LiteralPath $Capture)) { throw "Capture file not found: $Capture" }

$root = Split-Path -Parent $PSScriptRoot
$mvn  = 'C:\Program Files\Maven\apache-maven-3.10.0\bin\mvn.cmd'
if (-not (Test-Path $mvn)) { $mvn = 'mvn' }

Push-Location $root
try {
    $cfg = if ([System.IO.Path]::IsPathRooted($Config)) { $Config } else { Join-Path $root $Config }
    Write-Host "Building core engine..."
    & $mvn -B -ntp -q -pl core-engine -am install -DskipTests
    if ($LASTEXITCODE -ne 0) { throw "Build failed" }
    $cpFile = Join-Path $root 'core-engine\target\active-classpath.txt'
    & $mvn -B -ntp -q -pl core-engine dependency:build-classpath "-Dmdep.outputFile=$cpFile"
    if ($LASTEXITCODE -ne 0) { throw "Could not resolve classpath" }
    $cp = (Join-Path $root 'core-engine\target\classes') + ';' + (Get-Content -Raw $cpFile).Trim()

    $javaArgs = @('-cp', $cp, 'com.isolve.vapt.active.ActiveRunnerMain',
                  '--config', $cfg, '--capture', (Resolve-Path -LiteralPath $Capture).Path,
                  '--approval', $Approval, '--checks', $Checks, '--delay-ms', "$DelayMs", '--max', "$Max")
    if ($Hosts)    { $javaArgs += @('--hosts', $Hosts) }
    if ($OtherIds) { $javaArgs += @('--other-ids', $OtherIds) }
    if ($Out)      { $javaArgs += @('--out', $Out) }
    & java @javaArgs
    $code = $LASTEXITCODE
    if ($code -eq 2) { Write-Warning "The safety gate refused the run (see the message above). Nothing was sent."; exit 2 }
    if ($code -ne 0) { throw "Active runner failed (exit $code)" }
} finally {
    Pop-Location
}
