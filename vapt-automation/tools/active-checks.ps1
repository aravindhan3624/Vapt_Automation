<#
.SYNOPSIS
  Phase 6: APPROVAL-GATED active checks for CKYC. READ-ONLY re-sends of calls you already made, to
  confirm access-control weaknesses. It never creates, updates, approves, rejects, deletes or submits.

.DESCRIPTION
  Refuses to run unless ALL of these hold (the safety gate):
    - the project config has a real authorization scope and the environment is not production;
    - -Approval matches the approvalReference in the config AND the VAPT_ACTIVE_APPROVAL env var;
    - at least one approved host and one check are set.
  The default check is UNAUTH_DOCUMENT_ACCESS (fetch recorded document URLs with no session).
  The encrypted API checks (UNAUTHENTICATED_ACCESS / IDOR_BOLA / JWT_TAMPER) also need the CKYC
  server public key, via -ServerKey (a PEM/base64 string or a file path); the runner re-encrypts the
  (id-swapped) body into CKYC's envelope and decrypts the reply.
  Your current session, used only for baseline comparison, is read from VAPT_SESSION_HEADER /
  VAPT_SESSION_VALUE and never stored.

  Only run this against the approved CKYC 7.0 DEV environment, with written approval, using test data.

.EXAMPLE
  # Documents only (no key needed)
  $env:VAPT_ACTIVE_APPROVAL = "ISOLVE-VAPT-CKYC-2026-001"
  .\tools\active-checks.ps1 -Config "projects\ckyc\config\ckyc-config.yaml" `
      -Capture "C:\captures\CKYC-7.0\CKYC-7.0-Maker-...capture.jsonl" -Approval "ISOLVE-VAPT-CKYC-2026-001"

.EXAMPLE
  # Encrypted API checks too (no-login + IDOR), with the server key and your session for baseline
  $env:VAPT_ACTIVE_APPROVAL = "ISOLVE-VAPT-CKYC-2026-001"
  $env:VAPT_SESSION_VALUE   = "__Host-ckyc_session=...; __Host-ckyc_refresh=..."
  .\tools\active-checks.ps1 -Config "projects\ckyc\config\ckyc-config.yaml" `
      -Capture "C:\captures\CKYC-7.0\...capture.jsonl" -Approval "ISOLVE-VAPT-CKYC-2026-001" `
      -ServerKey "C:\captures\ckyc-server-public-key.pem" -OtherIds "IN29100124" `
      -Checks "UNAUTH_DOCUMENT_ACCESS,UNAUTHENTICATED_ACCESS,IDOR_BOLA"
#>
param(
    [Parameter(Mandatory = $true)][string]$Config,
    [Parameter(Mandatory = $true)][string]$Capture,
    [Parameter(Mandatory = $true)][string]$Approval,
    [string]$Hosts = "",
    [string]$Checks = "UNAUTH_DOCUMENT_ACCESS",
    [string]$OtherIds = "",
    [string]$ServerKey = "",
    [string]$Out = "",
    [int]$DelayMs = 1000,
    [int]$Max = 200
)
$ErrorActionPreference = 'Stop'
if (-not $env:VAPT_ACTIVE_APPROVAL) {
    throw "VAPT_ACTIVE_APPROVAL is not set. Set it to your approval reference first:  `$env:VAPT_ACTIVE_APPROVAL = '$Approval'"
}
if (-not (Test-Path -LiteralPath $Capture)) { throw "Capture file not found: $Capture" }
if ($ServerKey) { $env:VAPT_SERVER_PUBLIC_KEY = $ServerKey }

$root = Split-Path -Parent $PSScriptRoot
$mvn  = 'C:\Program Files\Maven\apache-maven-3.10.0\bin\mvn.cmd'
if (-not (Test-Path $mvn)) { $mvn = 'mvn' }

Push-Location $root
try {
    $cfg = if ([System.IO.Path]::IsPathRooted($Config)) { $Config } else { Join-Path $root $Config }
    Write-Host "Building CKYC active runner..."
    & $mvn -B -ntp -q -pl projects/ckyc -am install -DskipTests
    if ($LASTEXITCODE -ne 0) { throw "Build failed" }
    $cpFile = Join-Path $root 'projects\ckyc\target\active-classpath.txt'
    & $mvn -B -ntp -q -pl projects/ckyc dependency:build-classpath "-Dmdep.outputFile=$cpFile"
    if ($LASTEXITCODE -ne 0) { throw "Could not resolve classpath" }
    $cp = (Join-Path $root 'projects\ckyc\target\classes') + ';' + (Get-Content -Raw $cpFile).Trim()

    $javaArgs = @('-cp', $cp, 'com.isolve.vapt.ckyc.active.CkycActiveRunner',
                  '--config', $cfg, '--capture', (Resolve-Path -LiteralPath $Capture).Path,
                  '--approval', $Approval, '--checks', $Checks, '--delay-ms', "$DelayMs", '--max', "$Max")
    if ($Hosts)    { $javaArgs += @('--hosts', $Hosts) }
    if ($OtherIds) { $javaArgs += @('--other-ids', $OtherIds) }
    if ($Out)      { $javaArgs += @('--out', $Out) }
    & java @javaArgs
    $code = $LASTEXITCODE
    if ($code -eq 2) { Write-Warning "The safety gate refused the run (see the message above). Nothing was sent."; exit 2 }
    if ($code -eq 3) { Write-Warning "Encrypted checks need -ServerKey (the CKYC server public key). See the message above."; exit 3 }
    if ($code -ne 0) { throw "Active runner failed (exit $code)" }
} finally {
    Pop-Location
}
