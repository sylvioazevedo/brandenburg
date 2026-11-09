[CmdletBinding()]
param(
    [string]$Destination
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

if ($env:OS -ne 'Windows_NT') {
    throw 'This script builds a Windows sshd.exe. Run it from Windows PowerShell.'
}

$repoRoot = $PSScriptRoot
$releasesRoot = [System.IO.Path]::GetFullPath((Join-Path $repoRoot 'deploy\releases'))
if (-not $Destination) {
    $Destination = Join-Path $releasesRoot ("sshd-" + (Get-Date -Format 'yyyyMMdd-HHmmss'))
}

$destinationPath = [System.IO.Path]::GetFullPath(
    [System.IO.Path]::Combine($repoRoot, $Destination)
)
$releasePrefix = $releasesRoot.TrimEnd('\') + '\'
if (-not $destinationPath.StartsWith($releasePrefix, [StringComparison]::OrdinalIgnoreCase)) {
    throw "Destination must be a new versioned directory under $releasesRoot"
}
if (Test-Path -LiteralPath $destinationPath) {
    throw "Destination already exists; existing deployments are never overwritten: $destinationPath"
}

$uv = (Get-Command uv -ErrorAction Stop).Source
$buildId = [guid]::NewGuid().ToString('N')
$workRoot = Join-Path $repoRoot "build\deploy-$buildId"
$distRoot = Join-Path $workRoot 'dist'
$workPath = Join-Path $workRoot 'pyinstaller'
$stagePath = Join-Path $releasesRoot ".sshd-staging-$buildId"

function Invoke-CheckedCommand {
    param(
        [Parameter(Mandatory)][string]$Executable,
        [Parameter(Mandatory)][string[]]$Arguments
    )

    & $Executable @Arguments
    if ($LASTEXITCODE -ne 0) {
        throw "Command failed with exit code ${LASTEXITCODE}: $Executable $($Arguments -join ' ')"
    }
}

New-Item -ItemType Directory -Path $releasesRoot -Force | Out-Null
try {
    Invoke-CheckedCommand $uv @(
        'run', '--locked', 'python', '-m', 'unittest', 'discover', '-s', 'tests', '-v'
    )
    Invoke-CheckedCommand $uv @(
        'run', '--locked', 'python', '-m', 'PyInstaller', '--noconfirm',
        '--distpath', $distRoot, '--workpath', $workPath, 'app.spec'
    )

    $builtApp = Join-Path $distRoot 'app'
    $builtExecutable = Join-Path $builtApp 'app.exe'
    if (-not (Test-Path -LiteralPath $builtExecutable -PathType Leaf) -or
        -not (Test-Path -LiteralPath (Join-Path $builtApp '_internal') -PathType Container)) {
        throw 'PyInstaller did not produce the expected onedir app.exe and _internal directory.'
    }

    New-Item -ItemType Directory -Path $stagePath | Out-Null
    Copy-Item -Path (Join-Path $builtApp '*') -Destination $stagePath -Recurse
    $stagedExecutable = Join-Path $stagePath 'sshd.exe'
    Move-Item -LiteralPath (Join-Path $stagePath 'app.exe') -Destination $stagedExecutable

    Invoke-CheckedCommand $stagedExecutable @('--help')

    $previousTestExecutable = $env:BRANDENBURG_TEST_EXECUTABLE
    try {
        $env:BRANDENBURG_TEST_EXECUTABLE = $stagedExecutable
        Invoke-CheckedCommand $uv @(
            'run', '--locked', 'python', '-m', 'unittest', 'discover',
            '-s', 'tests', '-p', 'test_package.py', '-v'
        )
    }
    finally {
        if ($null -eq $previousTestExecutable) {
            Remove-Item Env:\BRANDENBURG_TEST_EXECUTABLE -ErrorAction SilentlyContinue
        }
        else {
            $env:BRANDENBURG_TEST_EXECUTABLE = $previousTestExecutable
        }
    }

    if (Test-Path -LiteralPath $destinationPath) {
        throw "Destination appeared during build; refusing to overwrite: $destinationPath"
    }
    [System.IO.Directory]::Move($stagePath, $destinationPath)
    Write-Host "Deployment ready: $destinationPath"
    Write-Host "Executable: $(Join-Path $destinationPath 'sshd.exe')"
    Write-Host 'Configuration and host keys are intentionally not copied. Keep them external and private.'
}
finally {
    if (Test-Path -LiteralPath $stagePath) {
        Remove-Item -LiteralPath $stagePath -Recurse -Force
    }
    if (Test-Path -LiteralPath $workRoot) {
        Remove-Item -LiteralPath $workRoot -Recurse -Force
    }
}
