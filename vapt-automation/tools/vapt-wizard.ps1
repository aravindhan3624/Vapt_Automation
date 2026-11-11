<#
.SYNOPSIS
  Local wizard for the VAPT framework: a styled web form (no code editing) that saves a project
  config and launches record / passive / active runs, and lets you review and label the captured
  endpoints dynamically.

.DESCRIPTION
  Starts a localhost-only web server (127.0.0.1, random port, random one-time token) and opens the
  wizard in your default browser. The browser form talks back to this script, which writes the
  project config, reads your capture files and endpoints, saves your per-endpoint comments, and
  runs the chosen tool. Secrets you type (session cookie) are passed to the child run in memory and
  never written to disk.

.EXAMPLE
  .\tools\vapt-wizard.ps1
#>
param([int]$Port = 0)
$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent $PSScriptRoot                 # ...\vapt-automation
$wizardHtml = Join-Path $PSScriptRoot 'wizard\index.html'
$capturesRoot = 'C:\captures'
if (-not (Test-Path $wizardHtml)) { throw "Wizard page not found: $wizardHtml" }

# ---------- helpers ----------
function New-Token { -join ((48..57)+(97..122) | Get-Random -Count 32 | ForEach-Object {[char]$_}) }

function Get-FreePort {
    $l = [System.Net.Sockets.TcpListener]::new([System.Net.IPAddress]::Loopback, 0)
    $l.Start(); $p = $l.LocalEndpoint.Port; $l.Stop(); return $p
}

function Read-Body($ctx) {
    $r = [System.IO.StreamReader]::new($ctx.Request.InputStream, [System.Text.Encoding]::UTF8)
    try { $txt = $r.ReadToEnd() } finally { $r.Dispose() }
    if ([string]::IsNullOrWhiteSpace($txt)) { return @{} }
    return $txt | ConvertFrom-Json
}

function Send-Json($ctx, $obj, [int]$code = 200) {
    $json = ($obj | ConvertTo-Json -Depth 8)
    $bytes = [System.Text.Encoding]::UTF8.GetBytes($json)
    $ctx.Response.StatusCode = $code
    $ctx.Response.ContentType = 'application/json; charset=utf-8'
    $ctx.Response.OutputStream.Write($bytes, 0, $bytes.Length)
    $ctx.Response.OutputStream.Close()
}

function Send-Html($ctx, $html) {
    $bytes = [System.Text.Encoding]::UTF8.GetBytes($html)
    $ctx.Response.StatusCode = 200
    $ctx.Response.ContentType = 'text/html; charset=utf-8'
    $ctx.Response.Headers.Add('Cache-Control', 'no-store')
    $ctx.Response.OutputStream.Write($bytes, 0, $bytes.Length)
    $ctx.Response.OutputStream.Close()
}

function Test-SafeName([string]$s) { return $s -match '^[A-Za-z0-9._-]{1,64}$' }

function Save-VaptConfig($p) {
    if (-not (Test-SafeName $p.project)) { throw "Invalid project name." }
    if (($p.environment).ToUpper() -like '*PROD*') { throw "Production is not allowed." }
    $dir = Join-Path $root ("projects\{0}\config" -f $p.project)
    New-Item -ItemType Directory -Force -Path $dir | Out-Null
    $path = Join-Path $dir ("{0}-config.yaml" -f $p.project)
    # Write the YAML exactly as previewed in the wizard (non-secret: scope ref, hosts, env).
    [System.IO.File]::WriteAllText($path, [string]$p.configYaml, (New-Object System.Text.UTF8Encoding($false)))
    return $path
}

function Get-CaptureList([string]$project) {
    $dir = Join-Path $capturesRoot $project
    if (-not (Test-Path $dir)) { return @() }
    Get-ChildItem -LiteralPath $dir -Filter '*.capture.jsonl' -File |
        Sort-Object LastWriteTime -Descending |
        ForEach-Object { @{ name = $_.Name; path = $_.FullName } }
}

function Get-Endpoints([string]$captureFile) {
    if (-not (Test-Path -LiteralPath $captureFile)) { throw "Capture file not found." }
    if (((Resolve-Path -LiteralPath $captureFile).Path) -notlike (Join-Path $capturesRoot '*')) {
        throw "Capture must be under $capturesRoot."
    }
    $map = [ordered]@{}
    foreach ($line in [System.IO.File]::ReadLines($captureFile)) {
        if ([string]::IsNullOrWhiteSpace($line)) { continue }
        try { $o = $line | ConvertFrom-Json } catch { continue }
        $path = [regex]::Replace([string]$o.path, '/\d{3,}', '/{id}')
        $key = ('{0} {1}' -f $o.method, $path)
        if (-not $map.Contains($key)) {
            $map[$key] = @{ key = $key; method = [string]$o.method; path = $path
                            module = [string]$o.module; count = 0 }
        }
        $map[$key].count++
        if (-not $map[$key].module -and $o.module) { $map[$key].module = [string]$o.module }
    }
    return @($map.Values)
}

function Save-Labels($p) {
    if (((Resolve-Path -LiteralPath $p.captureFile).Path) -notlike (Join-Path $capturesRoot '*')) {
        throw "Capture must be under $capturesRoot."
    }
    $sidecar = [string]$p.captureFile + '.labels.json'
    ($p.labels | ConvertTo-Json -Depth 6) | Out-File -LiteralPath $sidecar -Encoding utf8
    return $sidecar
}

function Invoke-Run($p) {
    $mvn = 'C:\Program Files\Maven\apache-maven-3.10.0\bin\mvn.cmd'
    $psExe = (Get-Process -Id $PID).Path
    if ($p.action -eq 'record') {
        $args = @('-NoProfile','-File', (Join-Path $PSScriptRoot 'record.ps1'),
                  '-Project', $p.project, '-Role', $p.role, '-StartUrl', $p.startUrl)
        if ($p.zap) { $args += '-Zap' }
        Start-Process -FilePath $psExe -ArgumentList $args -WorkingDirectory $root
        return @{ ok = $true; output = "Recording started in a new window. Log in, walk the modules, then close the browser." }
    }
    if ($p.action -eq 'passive') {
        $out = & $psExe -NoProfile -File (Join-Path $PSScriptRoot 'passive-checks-har.ps1') `
                 -Project $p.project -Hosts $p.host -Har $p.harFile 2>&1 | Out-String
        $report = (Get-ChildItem (Join-Path $capturesRoot $p.project) -Filter '*passive-checks.html' -EA SilentlyContinue |
                   Sort-Object LastWriteTime -Desc | Select-Object -First 1).FullName
        return @{ ok = ($LASTEXITCODE -eq 0 -or $null -eq $LASTEXITCODE); output = $out; reportPath = $report }
    }
    if ($p.action -eq 'active') {
        $cfg = Save-VaptConfig $p
        $env:VAPT_ACTIVE_APPROVAL = $p.approvalReference
        if ($p.sessionValue) { $env:VAPT_SESSION_VALUE = $p.sessionValue }    # memory only
        if ($p.serverKey)    { $env:VAPT_SERVER_PUBLIC_KEY = $p.serverKey }
        try {
            $checks = ($p.checks -join ',')
            $aArgs = @('-NoProfile','-File', (Join-Path $PSScriptRoot 'active-checks.ps1'),
                       '-Config', $cfg, '-Capture', $p.captureFile, '-Approval', $p.approvalReference,
                       '-Hosts', $p.host, '-Checks', $checks)
            if ($p.otherIds) { $aArgs += @('-OtherIds', $p.otherIds) }
            if ($p.serverKey) { $aArgs += @('-ServerKey', $p.serverKey) }
            $out = & $psExe @aArgs 2>&1 | Out-String
        } finally {
            Remove-Item Env:\VAPT_SESSION_VALUE -EA SilentlyContinue
        }
        $report = (Get-ChildItem (Join-Path $capturesRoot $p.project) -Filter '*-active-*.html' -EA SilentlyContinue |
                   Sort-Object LastWriteTime -Desc | Select-Object -First 1).FullName
        return @{ ok = $true; output = $out; reportPath = $report }
    }
    throw "Unknown action: $($p.action)"
}

# ---------- server ----------
$token = New-Token
if ($Port -le 0) { $Port = Get-FreePort }
$prefix = "http://127.0.0.1:$Port/"
$listener = [System.Net.HttpListener]::new()
$listener.Prefixes.Add($prefix)
$listener.Start()
$url = "$prefix?t=$token"
Write-Host "VAPT wizard running at $url"
Start-Process $url
Write-Host "Leave this window open while you use the wizard. Press Ctrl+C here to stop."

try {
    while ($listener.IsListening) {
        $ctx = $listener.GetContext()
        try {
            $path = $ctx.Request.Url.AbsolutePath
            if ($ctx.Request.HttpMethod -eq 'GET' -and $path -eq '/') {
                $html = [System.IO.File]::ReadAllText($wizardHtml).Replace('window.__VAPT_TOKEN__', "'$token'")
                Send-Html $ctx $html
                continue
            }
            # All /api/* require the token header.
            if ($ctx.Request.Headers['X-Vapt-Token'] -ne $token) { Send-Json $ctx @{ error = 'forbidden' } 403; continue }
            $body = Read-Body $ctx
            switch ($path) {
                '/api/captures'    { Send-Json $ctx @{ files = @(Get-CaptureList $body.project) } }
                '/api/endpoints'   { Send-Json $ctx @{ endpoints = @(Get-Endpoints $body.captureFile) } }
                '/api/save-labels' { Send-Json $ctx @{ path = (Save-Labels $body) } }
                '/api/run'         { Send-Json $ctx (Invoke-Run $body) }
                '/api/quit'        { Send-Json $ctx @{ ok = $true }; $listener.Stop() }
                default            { Send-Json $ctx @{ error = 'not found' } 404 }
            }
        } catch {
            Send-Json $ctx @{ ok = $false; error = $_.Exception.Message; output = $_.Exception.Message } 200
        }
    }
} finally {
    $listener.Stop(); $listener.Close()
    Write-Host "Wizard stopped."
}
