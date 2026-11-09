<#
.SYNOPSIS
  Passive recorder: opens Microsoft Edge (fresh empty profile), you log in and use the app,
  API calls to the approved host are captured (redacted) and an endpoint report is written.
  With -Zap, a local OWASP ZAP also watches the same traffic and writes a passive-analysis
  report (Phase 4). ZAP only watches: no spider, no active scan, no extra requests.

.DESCRIPTION
  The recorder sends no requests of its own and never reads or fills the login form.
  You type your test-account password into the application's own login page.
  Close the browser window to finish. Output goes to C:\captures\<Project>\ by default
  (outside OneDrive and git).

.EXAMPLE
  .\tools\record.ps1 -Project "CKYC-7.0" -Role Maker -StartUrl "https://<approved-dev-host>/"

.EXAMPLE
  # Phase 4: recorder + local ZAP passive analysis (ZAP from C:\Tools\ZAP_2.17.0)
  .\tools\record.ps1 -Project "CKYC-7.0" -Role Maker -StartUrl "https://<approved-dev-host>/" -Zap

.EXAMPLE
  # Also send the traffic through Burp (Community) running on 127.0.0.1:8080
  .\tools\record.ps1 -Project "CKYC-7.0" -Role Checker -StartUrl "https://<approved-dev-host>/" -Proxy "127.0.0.1:8080"
#>
param(
    [Parameter(Mandatory = $true)][string]$Project,
    [Parameter(Mandatory = $true)][string]$Role,
    [Parameter(Mandatory = $true)][string]$StartUrl,
    [string]$Hosts = "",
    [string]$Out = "",
    [string]$Proxy = "",
    [switch]$NoOverlay,
    [switch]$NoBodies,
    [switch]$Zap,
    [string]$ZapDir = "C:\Tools\ZAP_2.17.0",
    [string]$ZapHome = "C:\Tools\zap-home"
)
$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent $PSScriptRoot          # ...\vapt-automation
$mvn  = 'C:\Program Files\Maven\apache-maven-3.10.0\bin\mvn.cmd'
if (-not (Test-Path $mvn)) { $mvn = 'mvn' }

Push-Location $root
try {
    Write-Host "Building recorder..."
    & $mvn -B -ntp -q -pl recorder -am install -DskipTests
    if ($LASTEXITCODE -ne 0) { throw "Build failed" }
    $cpFile = Join-Path $root 'recorder\target\recorder-classpath.txt'
    & $mvn -B -ntp -q -pl recorder dependency:build-classpath "-Dmdep.outputFile=$cpFile"
    if ($LASTEXITCODE -ne 0) { throw "Could not resolve classpath" }
    $cp = (Join-Path $root 'recorder\target\classes') + ';' + (Get-Content -Raw $cpFile).Trim()

    $javaArgs = @('-cp', $cp, 'com.isolve.vapt.recorder.RecorderMain',
                  '--project', $Project, '--role', $Role, '--start-url', $StartUrl)
    if ($Hosts)     { $javaArgs += @('--hosts', $Hosts) }
    if ($Out)       { $javaArgs += @('--out', $Out) }
    if ($Proxy)     { $javaArgs += @('--proxy', $Proxy) }
    if ($NoOverlay) { $javaArgs += '--no-overlay' }
    if ($NoBodies)  { $javaArgs += '--no-bodies' }
    if ($Zap) {
        if ($Proxy) { throw "Use either -Zap or -Proxy, not both" }
        $javaArgs += @('--zap', $ZapDir, '--zap-home', $ZapHome)
    }
    & java @javaArgs
    if ($LASTEXITCODE -ne 0) { throw "Recorder failed" }
} finally {
    Pop-Location
}
