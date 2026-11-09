<#
.SYNOPSIS
  Phase 4 (offline): ZAP passive analysis of an exported HAR file. Sends NO requests.

.DESCRIPTION
  Starts a local OWASP ZAP, imports the HAR file(s) into a fresh ZAP session, lets ZAP's passive
  rules read them, and writes a redacted report of leads (status "To verify") for the approved
  hosts only. The ZAP session (raw traffic) is deleted afterwards. Keep HAR files outside
  OneDrive and git (e.g. C:\captures\); they contain live cookies and tokens.

.EXAMPLE
  .\tools\zap-passive-har.ps1 -Project "CKYC-7.0" -Hosts "<approved-dev-host>" -Har "C:\captures\ckyc-maker.har"
#>
param(
    [Parameter(Mandatory = $true)][string]$Project,
    [Parameter(Mandatory = $true)][string]$Hosts,
    [Parameter(Mandatory = $true)][string[]]$Har,
    [string]$Out = "",
    [string]$ZapDir = "C:\Tools\ZAP_2.17.0",
    [string]$ZapHome = "C:\Tools\zap-home"
)
$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent $PSScriptRoot          # ...\vapt-automation
$mvn  = 'C:\Program Files\Maven\apache-maven-3.10.0\bin\mvn.cmd'
if (-not (Test-Path $mvn)) { $mvn = 'mvn' }

$harPaths = @()
foreach ($h in $Har) {
    if (-not (Test-Path -LiteralPath $h)) { throw "HAR file not found: $h" }
    $harPaths += (Resolve-Path -LiteralPath $h).Path
}

Push-Location $root
try {
    Write-Host "Building ZAP integration..."
    & $mvn -B -ntp -q -pl zap-integration -am install -DskipTests
    if ($LASTEXITCODE -ne 0) { throw "Build failed" }
    $cpFile = Join-Path $root 'zap-integration\target\zap-classpath.txt'
    & $mvn -B -ntp -q -pl zap-integration dependency:build-classpath "-Dmdep.outputFile=$cpFile"
    if ($LASTEXITCODE -ne 0) { throw "Could not resolve classpath" }
    $cp = (Join-Path $root 'zap-integration\target\classes') + ';' + (Get-Content -Raw $cpFile).Trim()

    $javaArgs = @('-cp', $cp, 'com.isolve.vapt.zap.ZapPassiveAnalysis',
                  '--project', $Project, '--hosts', $Hosts, '--har', ($harPaths -join ','),
                  '--zap-dir', $ZapDir, '--zap-home', $ZapHome)
    if ($Out) { $javaArgs += @('--out', $Out) }
    & java @javaArgs
    if ($LASTEXITCODE -ne 0) { throw "ZAP passive analysis failed" }
} finally {
    Pop-Location
}
