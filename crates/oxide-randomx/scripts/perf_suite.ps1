<#
.SYNOPSIS
    Comprehensive performance benchmark suite for oxide-randomx (Windows/PowerShell)

.DESCRIPTION
    This script runs a complete series of performance benchmarks as outlined in docs/perf.md.
    It covers:
    - Light mode baseline (interpreter vs JIT)
    - JIT conservative vs fast-regs comparison
    - Fast mode (dataset) benchmarks
    - Cold vs warm JIT behavior
    - Large pages performance impact
    - Machine-readable output (CSV/JSON)
    - Validation runs

.PARAMETER Mode
    Benchmark mode: 'light', 'fast', or 'all' (default: all)

.PARAMETER Iters
    Number of measured iterations (default: 100)

.PARAMETER Warmup
    Number of warmup iterations (default: 10)

.PARAMETER Threads
    Thread count for dataset initialization (default: auto)

.PARAMETER LargePages
    Enable large pages for memory allocations

.PARAMETER OutputDir
    Directory for output files (default: ./perf_results). Results are stored in OutputDir\<machine-id>

.PARAMETER QuickTest
    Quick mode with minimal iterations for testing

.PARAMETER SkipValidation
    Skip validation runs

.PARAMETER SkipFast
    Skip fast mode benchmarks (saves time, avoids large allocations)

.EXAMPLE
    .\perf_suite.ps1
    # Run full benchmark suite with defaults

.EXAMPLE
    .\perf_suite.ps1 -Mode light -Iters 50 -QuickTest
    # Quick light-mode test

.EXAMPLE
    .\perf_suite.ps1 -LargePages -OutputDir ./my_results
    # Full suite with large pages, custom output directory
#>

[CmdletBinding()]
param(
    [ValidateSet("light", "fast", "all")]
    [string]$Mode = "all",
    [int]$Iters = 100,
    [int]$Warmup = 10,
    [int]$Threads = 0,
    [switch]$LargePages,
    [string]$OutputDir = "./perf_results",
    [switch]$QuickTest,
    [switch]$SkipValidation,
    [switch]$SkipFast
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

# We enforce native command success explicitly via exit codes below.
# Disable stderr-to-terminating-error promotion when supported (PowerShell 7+).
if (Get-Variable -Name PSNativeCommandUseErrorActionPreference -ErrorAction SilentlyContinue) {
    $PSNativeCommandUseErrorActionPreference = $false
}

# Quick test overrides
if ($QuickTest) {
    $Iters = 20
    $Warmup = 2
}

function Get-MachineId {
    $id = $null
    try {
        $id = (Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Cryptography" -Name "MachineGuid" -ErrorAction Stop).MachineGuid
    } catch {
    }

    if (-not $id) {
        try {
            $id = (Get-CimInstance -ClassName Win32_ComputerSystemProduct -ErrorAction Stop).UUID
        } catch {
        }
    }

    if (-not $id) {
        $id = $env:COMPUTERNAME
    }

    if (-not $id) {
        $id = "unknown-machine"
    }

    $id = ($id -replace "[^A-Za-z0-9._-]", "_")
    if ([string]::IsNullOrWhiteSpace($id)) {
        $id = "unknown-machine"
    }

    return $id
}

$machineId = Get-MachineId
if ((Split-Path -Leaf $OutputDir) -ne $machineId) {
    $OutputDir = Join-Path $OutputDir $machineId
}

# Ensure output directory exists
if (-not (Test-Path $OutputDir)) {
    New-Item -ItemType Directory -Path $OutputDir -Force | Out-Null
}

$timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
$summaryFile = Join-Path $OutputDir "perf_summary_$timestamp.txt"

function Write-Log {
    param([string]$Message, [string]$Color = "White")
    Write-Host $Message -ForegroundColor $Color
    Add-Content -Path $summaryFile -Value $Message
}

function Get-ThreadArgs {
    if ($Threads -gt 0) { return @("--threads", "$Threads") }
    return @()
}

function Get-ThreadArgText {
    if ($Threads -gt 0) { return "--threads $Threads" }
    return ""
}

$script:SuiteFailed = $false

function Set-SuiteFailure {
    param(
        [Parameter(Mandatory = $true)][string]$Step,
        [Parameter(Mandatory = $true)][string]$Reason,
        [string]$CommandOutput = ""
    )

    $script:SuiteFailed = $true
    Write-Log "        FAILED ($Step): $Reason" -Color Red

    if (-not [string]::IsNullOrWhiteSpace($CommandOutput)) {
        $lines = $CommandOutput -split "\r?\n"
        foreach ($line in $lines) {
            if (-not [string]::IsNullOrWhiteSpace($line)) {
                Write-Log "        $line" -Color Red
            }
        }
    }
}

function Invoke-NativeChecked {
    param(
        [Parameter(Mandatory = $true)][string]$Step,
        [Parameter(Mandatory = $true)][string]$CommandText,
        [Parameter(Mandatory = $true)][scriptblock]$Command,
        [switch]$CaptureOutput,
        [ref]$OutputRef
    )

    $captured = $null
    $oldErrorActionPreference = $ErrorActionPreference
    $ErrorActionPreference = "Continue"
    try {
        if ($CaptureOutput) {
            $captured = & $Command 2>&1
        } else {
            & $Command
        }
    } catch {
        $ErrorActionPreference = $oldErrorActionPreference
        Set-SuiteFailure -Step $Step -Reason "command threw exception: $($_.Exception.Message)"
        if ($CaptureOutput -and $OutputRef) {
            $OutputRef.Value = $captured
        }
        return $false
    }
    $ErrorActionPreference = $oldErrorActionPreference

    $exitCode = $LASTEXITCODE
    if ($CaptureOutput -and $OutputRef) {
        $OutputRef.Value = $captured
    }

    if ($exitCode -ne 0) {
        $outputText = ""
        if ($CaptureOutput -and $captured) {
            $outputText = ($captured | Out-String).Trim()
        }
        Set-SuiteFailure -Step $Step -Reason "command failed (exit code $exitCode): $CommandText" -CommandOutput $outputText
        return $false
    }

    return $true
}

function Test-OutputFileNonEmpty {
    param(
        [Parameter(Mandatory = $true)][string]$Step,
        [Parameter(Mandatory = $true)][string]$Path
    )

    if (-not (Test-Path -LiteralPath $Path)) {
        Set-SuiteFailure -Step $Step -Reason "missing output file: $Path"
        return $false
    }

    try {
        $item = Get-Item -LiteralPath $Path -ErrorAction Stop
    } catch {
        Set-SuiteFailure -Step $Step -Reason "unable to inspect output file '$Path': $($_.Exception.Message)"
        return $false
    }

    if ($item.Length -le 0) {
        Set-SuiteFailure -Step $Step -Reason "empty output file: $Path"
        return $false
    }

    return $true
}

# Set environment variables
if ($LargePages) {
    $env:OXIDE_RANDOMX_LARGE_PAGES = "1"
    Write-Log "Large pages: ENABLED" -Color Yellow
} else {
    Remove-Item Env:OXIDE_RANDOMX_LARGE_PAGES -ErrorAction SilentlyContinue
    Write-Log "Large pages: disabled" -Color Gray
}

Write-Log ""
Write-Log "========================================"
Write-Log " Oxide-RandomX Performance Suite"
Write-Log "========================================"
Write-Log ""
Write-Log "Configuration:"
Write-Log "  Mode        : $Mode"
Write-Log "  Iters       : $Iters"
Write-Log "  Warmup      : $Warmup"
Write-Log "  Threads     : $(if ($Threads -gt 0) { $Threads } else { '(auto)' })"
Write-Log "  Large Pages : $LargePages"
Write-Log "  Machine ID  : $machineId"
Write-Log "  Output Dir  : $OutputDir"
Write-Log "  Timestamp   : $timestamp"
Write-Log ""

$threadArgs = @(Get-ThreadArgs)
$threadArgText = Get-ThreadArgText
$results = @()

# ============================================================================
# SECTION 1: Validation (optional)
# ============================================================================
if (-not $SkipValidation) {
    Write-Log "----------------------------------------" -Color Cyan
    Write-Log "SECTION 1: Validation Runs" -Color Cyan
    Write-Log "----------------------------------------" -Color Cyan
    Write-Log ""

    Write-Log "  [1.1] Light mode validation (interpreter + JIT)..." -Color Gray
    $validationOutput = $null
    if (Invoke-NativeChecked -Step "1.1 Light validation both" `
            -CommandText "cargo run --release --example bench --features `"jit`" -- --mode light --jit both --validate" `
            -Command { cargo run --release --example bench --features "jit" -- --mode light --jit both --validate } `
            -CaptureOutput -OutputRef ([ref]$validationOutput)) {
        Write-Log "        PASSED" -Color Green
    } else {
        Write-Log "        FAILED" -Color Red
    }

    Write-Log "  [1.2] Light mode validation (JIT fast-regs)..." -Color Gray
    $validationOutput = $null
    if (Invoke-NativeChecked -Step "1.2 Light validation fast-regs" `
            -CommandText "cargo run --release --example bench --features `"jit jit-fastregs`" -- --mode light --jit on --jit-fast-regs on --validate" `
            -Command { cargo run --release --example bench --features "jit jit-fastregs" -- --mode light --jit on --jit-fast-regs on --validate } `
            -CaptureOutput -OutputRef ([ref]$validationOutput)) {
        Write-Log "        PASSED" -Color Green
    } else {
        Write-Log "        FAILED" -Color Red
    }

    Write-Log ""
}

# ============================================================================
# SECTION 2: Light Mode Benchmarks
# ============================================================================
if ($Mode -eq "light" -or $Mode -eq "all") {
    Write-Log "----------------------------------------" -Color Cyan
    Write-Log "SECTION 2: Light Mode Benchmarks" -Color Cyan
    Write-Log "----------------------------------------" -Color Cyan
    Write-Log ""

    # 2.1 Interpreter baseline
    Write-Log "  [2.1] Interpreter baseline..." -Color Gray
    $csvFile = Join-Path $OutputDir "light_interpreter_$timestamp.csv"
    if (Invoke-NativeChecked -Step "2.1 Interpreter baseline" `
            -CommandText "cargo run --release --example bench --features `"jit bench-instrument`" -- --mode light --jit off --iters $Iters --warmup $Warmup --report --format csv > $csvFile" `
            -Command { cargo run --release --example bench --features "jit bench-instrument" -- --mode light --jit off --iters $Iters --warmup $Warmup --report --format csv > $csvFile }) {
        [void](Test-OutputFileNonEmpty -Step "2.1 Interpreter baseline" -Path $csvFile)
    }
    Write-Log "        Output: $csvFile" -Color DarkGray

    # 2.2 JIT conservative
    Write-Log "  [2.2] JIT conservative..." -Color Gray
    $csvFile = Join-Path $OutputDir "light_jit_conservative_$timestamp.csv"
    if (Invoke-NativeChecked -Step "2.2 JIT conservative" `
            -CommandText "cargo run --release --example bench --features `"jit bench-instrument`" -- --mode light --jit on --jit-fast-regs off --iters $Iters --warmup $Warmup --report --format csv > $csvFile" `
            -Command { cargo run --release --example bench --features "jit bench-instrument" -- --mode light --jit on --jit-fast-regs off --iters $Iters --warmup $Warmup --report --format csv > $csvFile }) {
        [void](Test-OutputFileNonEmpty -Step "2.2 JIT conservative" -Path $csvFile)
    }
    Write-Log "        Output: $csvFile" -Color DarkGray

    # 2.3 JIT fast-regs
    Write-Log "  [2.3] JIT fast-regs..." -Color Gray
    $csvFile = Join-Path $OutputDir "light_jit_fastregs_$timestamp.csv"
    if (Invoke-NativeChecked -Step "2.3 JIT fast-regs" `
            -CommandText "cargo run --release --example bench --features `"jit jit-fastregs bench-instrument`" -- --mode light --jit on --jit-fast-regs on --iters $Iters --warmup $Warmup --report --format csv > $csvFile" `
            -Command { cargo run --release --example bench --features "jit jit-fastregs bench-instrument" -- --mode light --jit on --jit-fast-regs on --iters $Iters --warmup $Warmup --report --format csv > $csvFile }) {
        [void](Test-OutputFileNonEmpty -Step "2.3 JIT fast-regs" -Path $csvFile)
    }
    Write-Log "        Output: $csvFile" -Color DarkGray

    # 2.4 Cold JIT (warmup=0)
    Write-Log "  [2.4] Cold JIT (warmup=0)..." -Color Gray
    $csvFile = Join-Path $OutputDir "light_jit_cold_$timestamp.csv"
    if (Invoke-NativeChecked -Step "2.4 Cold JIT" `
            -CommandText "cargo run --release --example bench --features `"jit bench-instrument`" -- --mode light --jit on --iters $Iters --warmup 0 --report --format csv > $csvFile" `
            -Command { cargo run --release --example bench --features "jit bench-instrument" -- --mode light --jit on --iters $Iters --warmup 0 --report --format csv > $csvFile }) {
        [void](Test-OutputFileNonEmpty -Step "2.4 Cold JIT" -Path $csvFile)
    }
    Write-Log "        Output: $csvFile" -Color DarkGray

    # 2.5 Warm JIT (warmup=20)
    Write-Log "  [2.5] Warm JIT (warmup=20)..." -Color Gray
    $csvFile = Join-Path $OutputDir "light_jit_warm_$timestamp.csv"
    if (Invoke-NativeChecked -Step "2.5 Warm JIT" `
            -CommandText "cargo run --release --example bench --features `"jit bench-instrument`" -- --mode light --jit on --iters $Iters --warmup 20 --report --format csv > $csvFile" `
            -Command { cargo run --release --example bench --features "jit bench-instrument" -- --mode light --jit on --iters $Iters --warmup 20 --report --format csv > $csvFile }) {
        [void](Test-OutputFileNonEmpty -Step "2.5 Warm JIT" -Path $csvFile)
    }
    Write-Log "        Output: $csvFile" -Color DarkGray

    # 2.6 Combined interpreter + JIT (both)
    Write-Log "  [2.6] Combined (interpreter + JIT)..." -Color Gray
    $csvFile = Join-Path $OutputDir "light_both_$timestamp.csv"
    if (Invoke-NativeChecked -Step "2.6 Combined light both CSV" `
            -CommandText "cargo run --release --example bench --features `"jit bench-instrument`" -- --mode light --jit both --iters $Iters --warmup $Warmup --report --format csv > $csvFile" `
            -Command { cargo run --release --example bench --features "jit bench-instrument" -- --mode light --jit both --iters $Iters --warmup $Warmup --report --format csv > $csvFile }) {
        [void](Test-OutputFileNonEmpty -Step "2.6 Combined light both CSV" -Path $csvFile)
    }
    Write-Log "        Output: $csvFile" -Color DarkGray

    # 2.7 JSON output for programmatic analysis
    Write-Log "  [2.7] JSON output (combined)..." -Color Gray
    $jsonFile = Join-Path $OutputDir "light_both_$timestamp.json"
    if (Invoke-NativeChecked -Step "2.7 Combined light both JSON" `
            -CommandText "cargo run --release --example bench --features `"jit bench-instrument`" -- --mode light --jit both --iters $Iters --warmup $Warmup --report --format json > $jsonFile" `
            -Command { cargo run --release --example bench --features "jit bench-instrument" -- --mode light --jit both --iters $Iters --warmup $Warmup --report --format json > $jsonFile }) {
        [void](Test-OutputFileNonEmpty -Step "2.7 Combined light both JSON" -Path $jsonFile)
    }
    Write-Log "        Output: $jsonFile" -Color DarkGray

    Write-Log ""
}

# ============================================================================
# SECTION 3: Fast Mode Benchmarks (Dataset)
# ============================================================================
if (($Mode -eq "fast" -or $Mode -eq "all") -and (-not $SkipFast)) {
    Write-Log "----------------------------------------" -Color Cyan
    Write-Log "SECTION 3: Fast Mode Benchmarks (Dataset)" -Color Cyan
    Write-Log "----------------------------------------" -Color Cyan
    Write-Log ""
    Write-Log "  NOTE: Fast mode allocates ~2GB for dataset initialization" -Color Yellow
    Write-Log ""

    $env:OXIDE_RANDOMX_FAST_BENCH = "1"

    # 3.1 Interpreter baseline
    Write-Log "  [3.1] Interpreter baseline..." -Color Gray
    $csvFile = Join-Path $OutputDir "fast_interpreter_$timestamp.csv"
    if (Invoke-NativeChecked -Step "3.1 Fast interpreter baseline" `
            -CommandText "cargo run --release --example bench --features `"jit bench-instrument`" -- --mode fast --jit off --iters $Iters --warmup $Warmup $threadArgText --report --format csv > $csvFile" `
            -Command { cargo run --release --example bench --features "jit bench-instrument" -- --mode fast --jit off --iters $Iters --warmup $Warmup @threadArgs --report --format csv > $csvFile }) {
        [void](Test-OutputFileNonEmpty -Step "3.1 Fast interpreter baseline" -Path $csvFile)
    }
    Write-Log "        Output: $csvFile" -Color DarkGray

    # 3.2 JIT conservative
    Write-Log "  [3.2] JIT conservative..." -Color Gray
    $csvFile = Join-Path $OutputDir "fast_jit_conservative_$timestamp.csv"
    if (Invoke-NativeChecked -Step "3.2 Fast JIT conservative" `
            -CommandText "cargo run --release --example bench --features `"jit bench-instrument`" -- --mode fast --jit on --jit-fast-regs off --iters $Iters --warmup $Warmup $threadArgText --report --format csv > $csvFile" `
            -Command { cargo run --release --example bench --features "jit bench-instrument" -- --mode fast --jit on --jit-fast-regs off --iters $Iters --warmup $Warmup @threadArgs --report --format csv > $csvFile }) {
        [void](Test-OutputFileNonEmpty -Step "3.2 Fast JIT conservative" -Path $csvFile)
    }
    Write-Log "        Output: $csvFile" -Color DarkGray

    # 3.3 JIT fast-regs
    Write-Log "  [3.3] JIT fast-regs..." -Color Gray
    $csvFile = Join-Path $OutputDir "fast_jit_fastregs_$timestamp.csv"
    if (Invoke-NativeChecked -Step "3.3 Fast JIT fast-regs" `
            -CommandText "cargo run --release --example bench --features `"jit jit-fastregs bench-instrument`" -- --mode fast --jit on --jit-fast-regs on --iters $Iters --warmup $Warmup $threadArgText --report --format csv > $csvFile" `
            -Command { cargo run --release --example bench --features "jit jit-fastregs bench-instrument" -- --mode fast --jit on --jit-fast-regs on --iters $Iters --warmup $Warmup @threadArgs --report --format csv > $csvFile }) {
        [void](Test-OutputFileNonEmpty -Step "3.3 Fast JIT fast-regs" -Path $csvFile)
    }
    Write-Log "        Output: $csvFile" -Color DarkGray

    # 3.4 Combined interpreter + JIT (both)
    Write-Log "  [3.4] Combined (interpreter + JIT)..." -Color Gray
    $csvFile = Join-Path $OutputDir "fast_both_$timestamp.csv"
    if (Invoke-NativeChecked -Step "3.4 Fast combined both CSV" `
            -CommandText "cargo run --release --example bench --features `"jit bench-instrument`" -- --mode fast --jit both --iters $Iters --warmup $Warmup $threadArgText --report --format csv > $csvFile" `
            -Command { cargo run --release --example bench --features "jit bench-instrument" -- --mode fast --jit both --iters $Iters --warmup $Warmup @threadArgs --report --format csv > $csvFile }) {
        [void](Test-OutputFileNonEmpty -Step "3.4 Fast combined both CSV" -Path $csvFile)
    }
    Write-Log "        Output: $csvFile" -Color DarkGray

    # 3.5 JSON output
    Write-Log "  [3.5] JSON output (combined)..." -Color Gray
    $jsonFile = Join-Path $OutputDir "fast_both_$timestamp.json"
    if (Invoke-NativeChecked -Step "3.5 Fast combined both JSON" `
            -CommandText "cargo run --release --example bench --features `"jit bench-instrument`" -- --mode fast --jit both --iters $Iters --warmup $Warmup $threadArgText --report --format json > $jsonFile" `
            -Command { cargo run --release --example bench --features "jit bench-instrument" -- --mode fast --jit both --iters $Iters --warmup $Warmup @threadArgs --report --format json > $jsonFile }) {
        [void](Test-OutputFileNonEmpty -Step "3.5 Fast combined both JSON" -Path $jsonFile)
    }
    Write-Log "        Output: $jsonFile" -Color DarkGray

    Write-Log ""
}

# ============================================================================
# SECTION 4: Perf Harness (Structured Measurement)
# ============================================================================
Write-Log "----------------------------------------" -Color Cyan
Write-Log "SECTION 4: Perf Harness (Structured Measurement)" -Color Cyan
Write-Log "----------------------------------------" -Color Cyan
Write-Log ""

# 4.1 Light mode perf harness
Write-Log "  [4.1] Light mode perf harness (human)..." -Color Gray
$humanFile = Join-Path $OutputDir "perf_light_human_$timestamp.txt"
if (Invoke-NativeChecked -Step "4.1 Perf harness light human" `
        -CommandText "cargo run --release --example perf_harness --features `"jit bench-instrument`" -- --mode light --jit on --iters $Iters --warmup $Warmup --format human > $humanFile 2>&1" `
        -Command { cargo run --release --example perf_harness --features "jit bench-instrument" -- --mode light --jit on --iters $Iters --warmup $Warmup --format human > $humanFile 2>&1 }) {
    [void](Test-OutputFileNonEmpty -Step "4.1 Perf harness light human" -Path $humanFile)
}
Write-Log "        Output: $humanFile" -Color DarkGray

# 4.2 Light mode perf harness (CSV)
Write-Log "  [4.2] Light mode perf harness (CSV)..." -Color Gray
$csvFile = Join-Path $OutputDir "perf_light_$timestamp.csv"
if (Invoke-NativeChecked -Step "4.2 Perf harness light CSV" `
        -CommandText "cargo run --release --example perf_harness --features `"jit bench-instrument`" -- --mode light --jit on --iters $Iters --warmup $Warmup --format csv --out $csvFile" `
        -Command { cargo run --release --example perf_harness --features "jit bench-instrument" -- --mode light --jit on --iters $Iters --warmup $Warmup --format csv --out $csvFile 2>&1 | Out-Null }) {
    [void](Test-OutputFileNonEmpty -Step "4.2 Perf harness light CSV" -Path $csvFile)
}
Write-Log "        Output: $csvFile" -Color DarkGray

# 4.3 Light mode perf harness (JSON)
Write-Log "  [4.3] Light mode perf harness (JSON)..." -Color Gray
$jsonFile = Join-Path $OutputDir "perf_light_$timestamp.json"
if (Invoke-NativeChecked -Step "4.3 Perf harness light JSON" `
        -CommandText "cargo run --release --example perf_harness --features `"jit bench-instrument`" -- --mode light --jit on --iters $Iters --warmup $Warmup --format json --out $jsonFile" `
        -Command { cargo run --release --example perf_harness --features "jit bench-instrument" -- --mode light --jit on --iters $Iters --warmup $Warmup --format json --out $jsonFile 2>&1 | Out-Null }) {
    [void](Test-OutputFileNonEmpty -Step "4.3 Perf harness light JSON" -Path $jsonFile)
}
Write-Log "        Output: $jsonFile" -Color DarkGray

if (($Mode -eq "fast" -or $Mode -eq "all") -and (-not $SkipFast)) {
    $env:OXIDE_RANDOMX_FAST_BENCH = "1"

    # 4.4 Fast mode perf harness (CSV)
    Write-Log "  [4.4] Fast mode perf harness (CSV)..." -Color Gray
    $csvFile = Join-Path $OutputDir "perf_fast_$timestamp.csv"
    if (Invoke-NativeChecked -Step "4.4 Perf harness fast CSV" `
            -CommandText "cargo run --release --example perf_harness --features `"jit bench-instrument`" -- --mode fast --jit on --iters $Iters --warmup $Warmup $threadArgText --format csv --out $csvFile" `
            -Command { cargo run --release --example perf_harness --features "jit bench-instrument" -- --mode fast --jit on --iters $Iters --warmup $Warmup @threadArgs --format csv --out $csvFile 2>&1 | Out-Null }) {
        [void](Test-OutputFileNonEmpty -Step "4.4 Perf harness fast CSV" -Path $csvFile)
    }
    Write-Log "        Output: $csvFile" -Color DarkGray
}

Write-Log ""

# ============================================================================
# SECTION 5: Feature Comparison Summary
# ============================================================================
Write-Log "----------------------------------------" -Color Cyan
Write-Log "SECTION 5: Feature Comparison (Human Readable)" -Color Cyan
Write-Log "----------------------------------------" -Color Cyan
Write-Log ""

Write-Log "  Running comparison benchmarks..." -Color Gray
Write-Log ""

# Interpreter
Write-Log "  Interpreter:" -Color White
$output = $null
if (Invoke-NativeChecked -Step "5 Interpreter comparison" `
        -CommandText "cargo run --release --example bench --features `"jit bench-instrument`" -- --mode light --jit off --iters $Iters --warmup $Warmup" `
        -Command { cargo run --release --example bench --features "jit bench-instrument" -- --mode light --jit off --iters $Iters --warmup $Warmup } `
        -CaptureOutput -OutputRef ([ref]$output)) {
    $interpLine = $output | Select-String "ns/hash" | Select-Object -First 1
    if ($interpLine) {
        Write-Log "    $interpLine"
    } else {
        Set-SuiteFailure -Step "5 Interpreter comparison" -Reason "missing ns/hash line in command output"
        Write-Log "    <missing ns/hash output>" -Color Red
    }
} else {
    Write-Log "    <command failed>" -Color Red
}

# JIT Conservative
Write-Log "  JIT Conservative:" -Color White
$output = $null
if (Invoke-NativeChecked -Step "5 JIT conservative comparison" `
        -CommandText "cargo run --release --example bench --features `"jit bench-instrument`" -- --mode light --jit on --jit-fast-regs off --iters $Iters --warmup $Warmup" `
        -Command { cargo run --release --example bench --features "jit bench-instrument" -- --mode light --jit on --jit-fast-regs off --iters $Iters --warmup $Warmup } `
        -CaptureOutput -OutputRef ([ref]$output)) {
    $jitLine = $output | Select-String "ns/hash" | Select-Object -First 1
    if ($jitLine) {
        Write-Log "    $jitLine"
    } else {
        Set-SuiteFailure -Step "5 JIT conservative comparison" -Reason "missing ns/hash line in command output"
        Write-Log "    <missing ns/hash output>" -Color Red
    }
} else {
    Write-Log "    <command failed>" -Color Red
}

# JIT Fast-Regs
Write-Log "  JIT Fast-Regs:" -Color White
$output = $null
if (Invoke-NativeChecked -Step "5 JIT fast-regs comparison" `
        -CommandText "cargo run --release --example bench --features `"jit jit-fastregs bench-instrument`" -- --mode light --jit on --jit-fast-regs on --iters $Iters --warmup $Warmup" `
        -Command { cargo run --release --example bench --features "jit jit-fastregs bench-instrument" -- --mode light --jit on --jit-fast-regs on --iters $Iters --warmup $Warmup } `
        -CaptureOutput -OutputRef ([ref]$output)) {
    $fastRegsLine = $output | Select-String "ns/hash" | Select-Object -First 1
    if ($fastRegsLine) {
        Write-Log "    $fastRegsLine"
    } else {
        Set-SuiteFailure -Step "5 JIT fast-regs comparison" -Reason "missing ns/hash line in command output"
        Write-Log "    <missing ns/hash output>" -Color Red
    }
} else {
    Write-Log "    <command failed>" -Color Red
}

Write-Log ""

# ============================================================================
# SECTION 6: Perf Smoke Test
# ============================================================================
Write-Log "----------------------------------------" -Color Cyan
Write-Log "SECTION 6: Perf Smoke Test" -Color Cyan
Write-Log "----------------------------------------" -Color Cyan
Write-Log ""

$env:OXIDE_RANDOMX_PERF_SMOKE = "1"
Write-Log "  Running perf smoke test..." -Color Gray
$output = $null
if (Invoke-NativeChecked -Step "6 Perf smoke test" `
        -CommandText "cargo test --features bench-instrument --test perf_smoke" `
        -Command { cargo test --features bench-instrument --test perf_smoke } `
        -CaptureOutput -OutputRef ([ref]$output)) {
    Write-Log "  PASSED" -Color Green
} else {
    Write-Log "  FAILED" -Color Red
}

Write-Log ""

# ============================================================================
# Summary
# ============================================================================
if ($script:SuiteFailed) {
    Write-Log "========================================" -Color Red
    Write-Log " PERFORMANCE SUITE FAILED" -Color Red
    Write-Log "========================================" -Color Red
} else {
    Write-Log "========================================" -Color Green
    Write-Log " PERFORMANCE SUITE COMPLETE" -Color Green
    Write-Log "========================================" -Color Green
}
Write-Log ""
Write-Log "Results saved to: $OutputDir"
Write-Log "Summary file: $summaryFile"
Write-Log ""
Write-Log "Output files:"
Get-ChildItem $OutputDir -Filter "*$timestamp*" | ForEach-Object {
    Write-Log "  - $($_.Name)" -Color DarkGray
}
Write-Log ""

if ($script:SuiteFailed) {
    exit 1
}
exit 0
