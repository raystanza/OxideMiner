param(
    [string]$DistDir = $env:DIST_DIR,
    [string]$Target = $env:TARGET,
    [string]$RustupBin = $env:RUSTUP_BIN,
    [string]$CargoBin = $env:CARGO_BIN
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

function Resolve-Tool {
    param(
        [string]$Current,
        [string[]]$Candidates
    )

    if ($Current) {
        return $Current
    }

    foreach ($candidate in $Candidates) {
        $command = Get-Command -Name $candidate -ErrorAction SilentlyContinue | Select-Object -First 1
        if ($null -ne $command) {
            if ($command.Source) {
                return $command.Source
            }
            if ($command.Path) {
                return $command.Path
            }
            return $command.Name
        }
    }

    return $null
}

function Invoke-External {
    param(
        [string]$FilePath,
        [string[]]$Arguments
    )

    & $FilePath @Arguments
    if ($LASTEXITCODE -ne 0) {
        throw "Command failed ($LASTEXITCODE): $FilePath $($Arguments -join ' ')"
    }
}

$rootDir = [System.IO.Path]::GetFullPath((Join-Path $PSScriptRoot '../..'))
$Target = if ($Target) { $Target } else { 'x86_64-pc-windows-msvc' }

$RustupBin = Resolve-Tool -Current $RustupBin -Candidates @('rustup', 'rustup.exe')
if (-not $RustupBin) {
    throw 'rustup is required'
}

$CargoBin = Resolve-Tool -Current $CargoBin -Candidates @('cargo', 'cargo.exe')
if (-not $CargoBin) {
    throw 'cargo is required'
}

$installedTargets = & $RustupBin target list --installed
if ($LASTEXITCODE -ne 0) {
    throw "Command failed ($LASTEXITCODE): $RustupBin target list --installed"
}
if ($Target -notin @($installedTargets | ForEach-Object { $_.Trim() })) {
    throw "target '$Target' is not installed. Install it with: $RustupBin target add $Target"
}

if (-not $DistDir) {
    $DistRoot = [System.IO.Path]::GetFullPath((Join-Path $rootDir '..'))
    $DistDir = Join-Path $DistRoot 'oxide-randomx-dist/v8_05_amd_windows_capture'
}

$DistDir = [System.IO.Path]::GetFullPath($DistDir)
New-Item -ItemType Directory -Force -Path $DistDir | Out-Null

$builds = @(
    @{
        Label = 'baseline'
        Features = 'jit jit-fastregs bench-instrument'
        PerfOut = 'perf_harness_baseline.exe'
        SuperscalarOut = 'superscalar_hash_harness_baseline.exe'
    }
    @{
        Label = 'proto'
        Features = 'jit jit-fastregs bench-instrument superscalar-accel-proto'
        PerfOut = 'perf_harness_proto.exe'
        SuperscalarOut = 'superscalar_hash_harness_proto.exe'
    }
)

Push-Location $rootDir
try {
    foreach ($build in $builds) {
        Write-Host "Building v8_05 AMD capture examples ($($build.Label)) with features: $($build.Features)"
        Invoke-External -FilePath $CargoBin -Arguments @(
            'build'
            '--release'
            '--target'
            $Target
            '--example'
            'perf_harness'
            '--example'
            'superscalar_hash_harness'
            '--features'
            $build.Features
        )

        $perfSrc = Join-Path $rootDir "target/$Target/release/examples/perf_harness.exe"
        $superscalarSrc = Join-Path $rootDir "target/$Target/release/examples/superscalar_hash_harness.exe"
        if (-not (Test-Path -LiteralPath $perfSrc -PathType Leaf)) {
            throw "expected output missing: $perfSrc"
        }
        if (-not (Test-Path -LiteralPath $superscalarSrc -PathType Leaf)) {
            throw "expected output missing: $superscalarSrc"
        }

        Copy-Item -LiteralPath $perfSrc -Destination (Join-Path $DistDir $build.PerfOut) -Force
        Copy-Item -LiteralPath $superscalarSrc -Destination (Join-Path $DistDir $build.SuperscalarOut) -Force
    }
}
finally {
    Pop-Location
}

$runnerSrc = Join-Path $rootDir 'scripts/capture/run_v8_05_amd_windows_capture.ps1'
$runnerDst = Join-Path $DistDir 'run_v8_05_amd_windows_capture.ps1'
Copy-Item -LiteralPath $runnerSrc -Destination $runnerDst -Force

$instructionsPath = Join-Path $DistDir 'RUN_ON_REMOTE_WINDOWS_HOST.txt'
@'
Run instructions for remote AMD Windows 11 owner

1) Copy the entire folder to the target AMD Windows machine.
2) Open PowerShell in that folder.
3) Run:

   .\run_v8_05_amd_windows_capture.ps1

4) Wait for completion.
5) The script prints the output folder path and writes a `v8_05_share_instructions_*.txt` file.
6) Send the entire output folder as a zip.

Important:
- This bundle ships separate baseline/proto example executables because `superscalar-accel-proto` is a compile-time feature.
- Expected host classes are `AuthenticAMD/23/8` and `AuthenticAMD/23/113`; the runner records and stops on unexpected hosts.
- Required correctness validation (`cargo test`, oracle runs, feature-on oracle runs) must still be performed on the clean build host that produced this bundle.
'@ | Set-Content -Path $instructionsPath -Encoding ascii

$archivePath = Join-Path $DistDir 'oxide-randomx-v8_05-amd-capture.zip'
if (Get-Command -Name 'Compress-Archive' -ErrorAction SilentlyContinue) {
    if (Test-Path -LiteralPath $archivePath) {
        Remove-Item -LiteralPath $archivePath -Force
    }
    Compress-Archive -Path `
        (Join-Path $DistDir 'perf_harness_baseline.exe'),
        (Join-Path $DistDir 'perf_harness_proto.exe'),
        (Join-Path $DistDir 'superscalar_hash_harness_baseline.exe'),
        (Join-Path $DistDir 'superscalar_hash_harness_proto.exe'),
        $runnerDst,
        $instructionsPath `
        -DestinationPath $archivePath -Force
    Write-Host "Wrote: $archivePath"
}

Write-Host "Wrote: $(Join-Path $DistDir 'perf_harness_baseline.exe')"
Write-Host "Wrote: $(Join-Path $DistDir 'perf_harness_proto.exe')"
Write-Host "Wrote: $(Join-Path $DistDir 'superscalar_hash_harness_baseline.exe')"
Write-Host "Wrote: $(Join-Path $DistDir 'superscalar_hash_harness_proto.exe')"
Write-Host "Wrote: $runnerDst"
Write-Host "Wrote: $instructionsPath"
