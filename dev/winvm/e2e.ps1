[CmdletBinding()]
param([string]$SourceDir, [string]$ArtifactDir, [string]$ImageManifest = 'C:\winvm\manifest.json')
$ErrorActionPreference = 'Stop'; Set-StrictMode -Version Latest
$env:CGO_ENABLED = '0'; $env:GOTOOLCHAIN = 'local'
$identity = [Security.Principal.WindowsIdentity]::GetCurrent()
if (-not $identity.IsSystem) { throw 'The live-driver gate must run as SYSTEM' }
if (-not [Environment]::Is64BitProcess) { throw 'The live-driver gate needs a 64-bit process' }
New-Item -ItemType Directory -Force -Path $ArtifactDir | Out-Null
. (Join-Path $SourceDir 'dev\winvm\driver.ps1')
. (Join-Path $SourceDir 'dev\winvm\test-output.ps1')
$manifest = Get-Content $ImageManifest -Raw | ConvertFrom-Json
if ($manifest.driverVersion -ne '1.3.0.0' -or $manifest.upstreamCommit -ne '0a0eb97f67d1dbcb3d08bda66d3b24f465d95475') { throw 'Driver identity does not match the controller ABI' }
$before = Get-DriverEvidence $ImageManifest; $before | ConvertTo-Json | Set-Content (Join-Path $ArtifactDir 'driver-before.json')
$service = $manifest.driverService; $started = $false
try {
    if ((Get-Service $service).Status -ne 'Stopped') { throw 'Driver service was not stopped at gate start' }
    Start-Service $service; $started = $true
    Set-Location $SourceDir
    $savedPreference = $ErrorActionPreference
    $ErrorActionPreference = 'Continue'
    & go test -json -count=1 -tags=winintegration -p=1 -timeout 10m ./integration 2>&1 |
        Tee-Object -FilePath (Join-Path $ArtifactDir 'e2e-events.jsonl') |
        Format-GoTestOutput
    $testExitCode = $LASTEXITCODE
    $ErrorActionPreference = $savedPreference
    if ($testExitCode -ne 0) { throw "live-driver tests failed with exit code $testExitCode" }
    $events = @(Get-Content (Join-Path $ArtifactDir 'e2e-events.jsonl') | Where-Object { $_ -match '^\s*\{' } | ConvertFrom-Json)
    if (-not ($events | Where-Object { $_.PSObject.Properties['Test'] -and $_.Test -eq 'TestDriverLifecycle' -and $_.Action -eq 'pass' })) { throw 'TestDriverLifecycle has no pass event' }
} finally {
    if ($started) {
        Stop-Service $service -Force -ErrorAction Continue
        (Get-Service $service).WaitForStatus('Stopped', [TimeSpan]::FromSeconds(30))
    }
    $after = Get-DriverEvidence $ImageManifest
    $after | ConvertTo-Json | Set-Content (Join-Path $ArtifactDir 'driver-after.json')
    if ($after.state -ne 'Stopped') { throw "Driver service final state is $($after.state)" }
}
