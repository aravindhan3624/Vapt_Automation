<#
.SYNOPSIS
  Passive recorder: opens Microsoft Edge (fresh empty profile), you log in and use the app,
  API calls to the approved host are captured (redacted) and an endpoint report is written.

.DESCRIPTION
  The recorder sends no requests of its own and never reads or fills the login form.
  You type your test-account password into the application's own login page.
  Close the browser window to finish. Output goes to C:\captures\<Project>\ by default
  (outside OneDrive and git).

.EXAMPLE
  .\tools\record.ps1 -Project "CKYC-7.0" -Role Maker -StartUrl "https://<approved-uat-host>/"

.EXAMPLE
  # Also send the traffic through Burp (Community) running on 127.0.0.1:8080
  .\tools\record.ps1 -Project "CKYC-7.0" -Role Checker -StartUrl "https://<approved-uat-host>/" -Proxy "127.0.0.1:8080"
#>
param(
    [Parameter(Mandatory = $true)][string]$Project,
    [Parameter(Mandatory = $true)][string]$Role,
    [Parameter(Mandatory = $true)][string]$StartUrl,
    [string]$Hosts = "",
    [string]$Out = "",
    [string]$Proxy = "",
    [switch]$NoOverlay,
    [switch]$NoBodies
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
    & java @javaArgs
    if ($LASTEXITCODE -ne 0) { throw "Recorder failed" }
} finally {
    Pop-Location
}
