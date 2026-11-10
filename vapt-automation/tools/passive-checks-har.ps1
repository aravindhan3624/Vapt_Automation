<#
.SYNOPSIS
  Phase 5 (offline): passive checks on an exported HAR file. Reads the file only; sends NO requests.

.DESCRIPTION
  Checks security headers, cookie flags, personal data / secrets in responses, sensitive data in
  URLs, error leakage and transport for the approved hosts only. The report holds names, counts
  and endpoints, never values. HAR files have no TLS details, and CKYC bodies in a HAR are
  encrypted, so prefer the recorder (record.ps1), which runs the same checks on decrypted bodies.
  Keep HAR files outside OneDrive and git (e.g. C:\captures\).

.EXAMPLE
  .\tools\passive-checks-har.ps1 -Project "CKYC-7.0" -Hosts "<approved-dev-host>" -Har "C:\captures\ckyc-maker.har"
#>
param(
    [Parameter(Mandatory = $true)][string]$Project,
    [Parameter(Mandatory = $true)][string]$Hosts,
    [Parameter(Mandatory = $true)][string[]]$Har,
    [string]$Out = ""
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
    Write-Host "Building core engine..."
    & $mvn -B -ntp -q -pl core-engine -am install -DskipTests
    if ($LASTEXITCODE -ne 0) { throw "Build failed" }
    $cpFile = Join-Path $root 'core-engine\target\core-classpath.txt'
    & $mvn -B -ntp -q -pl core-engine dependency:build-classpath "-Dmdep.outputFile=$cpFile"
    if ($LASTEXITCODE -ne 0) { throw "Could not resolve classpath" }
    $cp = (Join-Path $root 'core-engine\target\classes') + ';' + (Get-Content -Raw $cpFile).Trim()

    $javaArgs = @('-cp', $cp, 'com.isolve.vapt.passive.HarPassiveChecks',
                  '--project', $Project, '--hosts', $Hosts, '--har', ($harPaths -join ','))
    if ($Out) { $javaArgs += @('--out', $Out) }
    & java @javaArgs
    if ($LASTEXITCODE -ne 0) { throw "Passive checks failed" }
} finally {
    Pop-Location
}
