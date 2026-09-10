<#
    NyayaVault — one-command demo startup.

    Brings up the seven infrastructure containers, waits for them to report healthy,
    then builds and runs the backend. The demo console is served by the backend itself
    at http://localhost:8080 — there is no separate frontend process to start.

    Usage:
        .\start-demo.ps1              # start infra, build, run
        .\start-demo.ps1 -SkipBuild   # skip the Maven build, run the existing jar
        .\start-demo.ps1 -InfraOnly   # bring up containers only
#>
[CmdletBinding()]
param(
    [switch]$SkipBuild,
    [switch]$InfraOnly,
    [int]$TimeoutSeconds = 300
)

$ErrorActionPreference = 'Stop'
$root = $PSScriptRoot

function Info($m) { Write-Host "==> $m" -ForegroundColor Cyan }
function Ok($m)   { Write-Host "    $m" -ForegroundColor Green }
function Warn($m) { Write-Host "    $m" -ForegroundColor Yellow }
function Die($m)  { Write-Host "!!! $m" -ForegroundColor Red; exit 1 }

# ── Locate the docker CLI (it is not always on PATH right after install) ──
$docker = (Get-Command docker -ErrorAction SilentlyContinue).Source
if (-not $docker) {
    $candidate = Join-Path $env:ProgramFiles 'Docker\Docker\resources\bin\docker.exe'
    if (Test-Path $candidate) { $docker = $candidate }
    else { Die 'docker CLI not found. Install Docker Desktop first.' }
}

# Image pulls shell out to the credential helper (docker-credential-desktop.exe) by bare
# name, so Docker's bin directory has to be on PATH or every pull fails with
# "error getting credentials". A freshly installed Docker Desktop is not on PATH in
# already-open shells, so put it there for this process.
$dockerBin = Split-Path $docker -Parent
if ($env:Path -notlike "*$dockerBin*") { $env:Path = "$dockerBin;$env:Path" }

# ── Locate JAVA_HOME if not set ──
if (-not $env:JAVA_HOME -or -not (Test-Path (Join-Path $env:JAVA_HOME 'bin\java.exe'))) {
    $jdkCandidates = @(
        (Join-Path $env:ProgramFiles 'Java\jdk-26.0.1'),
        (Join-Path $env:ProgramFiles 'Java\latest'),
        (Join-Path $env:ProgramFiles 'Java\jdk-21*')
    )
    foreach ($cand in $jdkCandidates) {
        $resolved = Resolve-Path $cand -ErrorAction SilentlyContinue | Select-Object -First 1
        if ($resolved -and (Test-Path (Join-Path $resolved.Path 'bin\java.exe'))) {
            $env:JAVA_HOME = $resolved.Path
            break
        }
    }
}
if (-not $env:JAVA_HOME -or -not (Test-Path (Join-Path $env:JAVA_HOME 'bin\java.exe'))) {
    Die 'JAVA_HOME is not set and no JDK was found in C:\Program Files\Java. Please install JDK 21+.'
}

# ── Make sure the engine is actually up ──
Info 'Checking the Docker engine'
$deadline = (Get-Date).AddSeconds(120)
while ($true) {
    # While Docker Desktop is still starting, "docker info" writes to stderr. Under
    # $ErrorActionPreference = 'Stop' that becomes a terminating NativeCommandError and
    # kills the script — precisely the case this loop exists to wait out. Neither "2>&1"
    # nor "2>$null" suppresses it; the preference has to be relaxed around the call.
    $prevEap = $ErrorActionPreference
    $ErrorActionPreference = 'Continue'
    & $docker info *> $null
    $dockerExit = $LASTEXITCODE
    $ErrorActionPreference = $prevEap
    if ($dockerExit -eq 0) { Ok 'engine is running'; break }
    if ((Get-Date) -gt $deadline) {
        Die 'Docker engine is not responding. Start Docker Desktop, wait for the whale icon to go steady, then re-run.'
    }
    Warn 'engine not ready yet, waiting...'
    Start-Sleep -Seconds 5
}

# ── Start infrastructure ──
Info 'Starting infrastructure (postgres, keycloak, minio, redis, rabbitmq, opensearch)'
Write-Host '    First run pulls several GB of images - this can take a while.' -ForegroundColor DarkGray
Push-Location $root
try {
    & $docker compose up -d
    if ($LASTEXITCODE -ne 0) { Die 'docker compose up failed - see the output above.' }
} finally { Pop-Location }

# ── Wait for health ──
# minio-init is a one-shot bucket-creation container, so it is expected to exit.
$services = @('crimenet-postgres', 'crimenet-keycloak', 'crimenet-minio',
              'crimenet-redis', 'crimenet-rabbitmq', 'crimenet-opensearch')

Info "Waiting for containers to report healthy (timeout ${TimeoutSeconds}s)"
$deadline = (Get-Date).AddSeconds($TimeoutSeconds)
$pending = [System.Collections.ArrayList]::new($services)

while ($pending.Count -gt 0) {
    foreach ($svc in @($pending)) {
        $state = (& $docker inspect --format '{{if .State.Health}}{{.State.Health.Status}}{{else}}{{.State.Status}}{{end}}' $svc 2>$null)
        if ($LASTEXITCODE -eq 0 -and ($state -eq 'healthy' -or $state -eq 'running')) {
            Ok "$svc -> $state"
            $pending.Remove($svc)
        }
    }
    if ($pending.Count -eq 0) { break }
    if ((Get-Date) -gt $deadline) {
        Warn "Still not healthy: $($pending -join ', ')"
        Warn "Inspect with:  docker compose logs $($pending[0] -replace '^crimenet-','')"
        Die  'Infrastructure did not come up in time.'
    }
    Start-Sleep -Seconds 5
}
Ok 'all infrastructure healthy'

if ($InfraOnly) {
    Info 'Infrastructure is up (-InfraOnly given, not starting the backend).'
    exit 0
}

# ── Stop any CrimeNet instance still running ──
$running = @(Get-CimInstance Win32_Process -Filter "Name='java.exe'" -ErrorAction SilentlyContinue |
             Where-Object { $_.CommandLine -like '*crimenet-backend*.jar*' -or $_.CommandLine -like '*nyayavault-backend*.jar*' })
if ($running.Count -gt 0) {
    Info 'Stopping the previous CrimeNet instance'
    foreach ($p in $running) {
        try { Stop-Process -Id $p.ProcessId -Force -ErrorAction Stop; Ok "stopped PID $($p.ProcessId)" }
        catch { Warn "could not stop PID $($p.ProcessId): $($_.Exception.Message)" }
    }
    Start-Sleep -Seconds 2   # let Windows release the file handle
}

# ── Build ──
$jar = Join-Path $root 'backend\target\crimenet-backend-0.1.0-SNAPSHOT.jar'
if (-not $SkipBuild) {
    Info 'Building the backend'
    Push-Location (Join-Path $root 'backend')
    try {
        & .\mvnw.cmd -B -q clean package -DskipTests
        if ($LASTEXITCODE -ne 0) { Die 'Maven build failed.' }
    } finally { Pop-Location }
    Ok 'build succeeded'
}
if (-not (Test-Path $jar)) { Die "Jar not found at $jar - run without -SkipBuild." }

# ── Run ──
Info 'Starting CrimeNet'
Write-Host ''
Write-Host '    Demo console : http://localhost:8080'          -ForegroundColor Green
Write-Host '    Swagger UI   : http://localhost:8080/swagger-ui.html' -ForegroundColor Green
Write-Host '    Keycloak     : http://localhost:8180  (admin/admin)'  -ForegroundColor DarkGray
Write-Host '    MinIO console: http://localhost:9001  (minioadmin/minioadmin123)' -ForegroundColor DarkGray
Write-Host '    RabbitMQ     : http://localhost:15672 (crimenet/crimenet_dev)' -ForegroundColor DarkGray
Write-Host ''
Write-Host '    Ctrl+C stops the backend; containers keep running.' -ForegroundColor DarkGray
Write-Host '    Stop everything with:  docker compose down' -ForegroundColor DarkGray
Write-Host ''

& "$env:JAVA_HOME\bin\java.exe" '-jar' $jar '--spring.profiles.active=dev'
