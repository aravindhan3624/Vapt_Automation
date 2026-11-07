<#
.SYNOPSIS
  Phase 1 - PASSIVE endpoint discovery from a Burp Suite / HAR capture you exported.

.DESCRIPTION
  Builds core-engine (if needed) and runs com.isolve.vapt.discovery.EndpointDiscovery.
  This script sends NO requests to any application. It only reads the capture file(s)
  and writes redacted JSON / CSV / HTML to reports\output\discovery (git-ignored).

.EXAMPLE
  .\tools\run-discovery.ps1 -Project "CKYC-7.0" -Capture "C:\captures\ckyc-maker-walk.xml"

.EXAMPLE
  .\tools\run-discovery.ps1 -Project "CKYC-7.0" -Capture "C:\captures\maker.xml","C:\captures\checker.xml"
#>
param(
    [Parameter(Mandatory = $true)][string]$Project,
    [Parameter(Mandatory = $true)][string[]]$Capture,
    [string]$Out = "",
    [string]$Skip = ""
)
$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent $PSScriptRoot          # ...\vapt-automation
$mvn  = 'C:\Program Files\Maven\apache-maven-3.10.0\bin\mvn.cmd'
if (-not (Test-Path $mvn)) { $mvn = 'mvn' }
if (-not $Out) { $Out = Join-Path $root 'reports\output\discovery' }

foreach ($c in $Capture) { if (-not (Test-Path -LiteralPath $c)) { throw "Capture file not found: $c" } }

Push-Location $root
try {
    Write-Host "Building core-engine..."
    & $mvn -B -ntp -q -pl core-engine -am install -DskipTests
    if ($LASTEXITCODE -ne 0) { throw "Build failed" }
    $cpFile = Join-Path $root 'core-engine\target\discovery-classpath.txt'
    & $mvn -B -ntp -q -pl core-engine dependency:build-classpath "-Dmdep.outputFile=$cpFile"
    if ($LASTEXITCODE -ne 0) { throw "Could not resolve classpath" }
    $cp = (Join-Path $root 'core-engine\target\classes') + ';' + (Get-Content -Raw $cpFile).Trim()

    $javaArgs = @('-cp', $cp, 'com.isolve.vapt.discovery.EndpointDiscovery', '--project', $Project, '--out', $Out)
    if ($Skip) { $javaArgs += @('--skip', $Skip) }
    $javaArgs += $Capture
    & java @javaArgs
    if ($LASTEXITCODE -ne 0) { throw "Discovery failed" }
    Write-Host ""
    Write-Host "Done. Open the HTML report in: $Out"
} finally {
    Pop-Location
}
