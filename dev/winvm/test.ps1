[CmdletBinding()]
param(
    [string]$ArtifactDir = (Join-Path $PWD '.artifacts-windows'),
    [string]$ImageManifest = $env:WINVM_IMAGE_MANIFEST,
    [string]$ExpectedGoVersion = $env:GO_EXPECTED_VERSION,
    [switch]$RequireStandardUser
)
$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest
$env:CGO_ENABLED = '0'; $env:GOTOOLCHAIN = 'local'
New-Item -ItemType Directory -Force -Path $ArtifactDir | Out-Null
$ArtifactDir = (Resolve-Path $ArtifactDir).Path
Start-Transcript -Path (Join-Path $ArtifactDir 'powershell.log') -Force | Out-Null
. (Join-Path $PSScriptRoot 'test-output.ps1')
function Invoke-Logged([string]$Name, [string]$Command, [string[]]$Arguments) {
    $savedPreference = $ErrorActionPreference
    $ErrorActionPreference = 'Continue'
    & $Command @Arguments 2>&1 | Tee-Object -FilePath (Join-Path $ArtifactDir "$Name.log")
    $exitCode = $LASTEXITCODE
    $ErrorActionPreference = $savedPreference
    if ($exitCode -ne 0) { throw "$Name failed with exit code $exitCode" }
}
try {
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = [Security.Principal.WindowsPrincipal]::new($identity)
    if ($RequireStandardUser -and ($identity.IsSystem -or $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator))) {
        throw 'The baseline must run as a standard user'
    }
    if ($ImageManifest) {
        $manifest = Get-Content -LiteralPath $ImageManifest -Raw | ConvertFrom-Json
        if (-not $ExpectedGoVersion) {
            if ($manifest.goVersion -notmatch '^go version go(?<Version>\S+) windows/amd64$') { throw 'Invalid image Go version' }
            $ExpectedGoVersion = $Matches.Version
        }
    }
    if ($ExpectedGoVersion) {
        $actual = (& go env GOVERSION | Out-String).Trim()
        if ($actual -ne "go$ExpectedGoVersion") { throw "Go version is $actual, not go$ExpectedGoVersion" }
    }
    Invoke-Logged 'go-version' 'go' @('version')
    Invoke-Logged 'go-env' 'go' @('env')
    Invoke-Logged 'go-mod-verify' 'go' @('mod', 'verify')
    Invoke-Logged 'go-mod-tidy' 'go' @('mod', 'tidy', '-diff')
    Invoke-Logged 'go-vet' 'go' @('vet', './...')
    $events = Join-Path $ArtifactDir 'test-events.jsonl'
    $savedPreference = $ErrorActionPreference
    $ErrorActionPreference = 'Continue'
    & go test -json -count=1 -timeout 2m ./... 2>&1 |
        Tee-Object -FilePath $events |
        Format-GoTestOutput
    $testExitCode = $LASTEXITCODE
    $ErrorActionPreference = $savedPreference
    if ($testExitCode -ne 0) { throw "tests failed with exit code $testExitCode" }
    $parsed = @(Get-Content $events | Where-Object { $_ -match '^\s*\{' } | ConvertFrom-Json)
    $required = 'TestResolveOwnExecutableAndSnapshot'
    if ($parsed | Where-Object { $_.PSObject.Properties['Test'] -and $_.Test -eq $required -and $_.Action -eq 'skip' }) { throw "$required was skipped" }
    if (-not ($parsed | Where-Object { $_.PSObject.Properties['Test'] -and $_.Test -eq $required -and $_.Action -eq 'pass' })) { throw "$required has no pass event" }
    $parsed | Where-Object Action -eq output | ForEach-Object Output | Set-Content (Join-Path $ArtifactDir 'tests.log')
    Invoke-Logged 'go-build' 'go' @('build', './...')
} finally { Stop-Transcript | Out-Null }
