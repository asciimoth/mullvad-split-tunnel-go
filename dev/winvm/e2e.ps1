[CmdletBinding()]
param(
    [string]$SourceDir,
    [string]$ArtifactDir,
    [string]$ImageManifest = 'C:\winvm\manifest.json',
    [string]$GoExecutable = 'go',
    [switch]$Flow
)
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
$nativeArchitecture = switch ($env:PROCESSOR_ARCHITECTURE) { 'AMD64' { 'amd64' } 'ARM64' { 'arm64' } default { throw "Unsupported native architecture: $env:PROCESSOR_ARCHITECTURE" } }
if ($manifest.architecture.ToString().ToLowerInvariant() -ne $nativeArchitecture) { throw 'Driver package and native architecture do not match' }
$goVersion = (& $GoExecutable version | Out-String).Trim()
if ($goVersion -notmatch " windows/$nativeArchitecture$") { throw "Go process does not target native $nativeArchitecture" }
$before = Get-DriverEvidence $ImageManifest; $before | ConvertTo-Json | Set-Content (Join-Path $ArtifactDir 'driver-before.json')
$service = $manifest.driverService; $started = $false
try {
    if ((Get-Service $service).Status -ne 'Stopped') { throw 'Driver service was not stopped at gate start' }
    Start-Service $service; $started = $true
    Set-Location $SourceDir
    $tags = 'winintegration'
    $timeout = '10m'
    $runPattern = '.'
    if ($Flow) {
        $tags = 'winintegration,winflow'
        $timeout = '20m'
        $runPattern = '^TestPacketFlow'
        $env:FLOW_ARTIFACT_DIR = $ArtifactDir
    }
    $savedPreference = $ErrorActionPreference
    $ErrorActionPreference = 'Continue'
    & $GoExecutable test -json -count=1 "-tags=$tags" "-run=$runPattern" -p=1 -timeout $timeout ./integration 2>&1 |
        Tee-Object -FilePath (Join-Path $ArtifactDir 'e2e-events.jsonl') |
        Format-GoTestOutput
    $testExitCode = $LASTEXITCODE
    $ErrorActionPreference = $savedPreference
    if ($testExitCode -ne 0) { throw "live-driver tests failed with exit code $testExitCode" }
    $events = @(Get-Content (Join-Path $ArtifactDir 'e2e-events.jsonl') | Where-Object { $_ -match '^\s*\{' } | ConvertFrom-Json)
    if ($Flow) {
        $required = @('TestPacketFlowCharacterization')
    } else {
        $required = @(
            'TestDriverLifecycle',
            'TestEventCancellationStress',
            'TestEventCancellationWhileControllerCloses',
            'TestHardLinkAndAlternateLaunchPaths',
            'TestInjectedSetupFailureRecovery'
        )
    }
    foreach ($test in $required) {
        if (-not ($events | Where-Object { $_.PSObject.Properties['Test'] -and $_.Test -eq $test -and $_.Action -eq 'pass' })) { throw "$test has no pass event" }
    }
} finally {
    if ($started) {
        Stop-Service $service -Force -ErrorAction Continue
        (Get-Service $service).WaitForStatus('Stopped', [TimeSpan]::FromSeconds(30))
    }
    $after = Get-DriverEvidence $ImageManifest
    $after | ConvertTo-Json | Set-Content (Join-Path $ArtifactDir 'driver-after.json')
    if ($after.state -ne 'Stopped') { throw "Driver service final state is $($after.state)" }
}
