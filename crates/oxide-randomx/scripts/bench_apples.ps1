<#
Comprehensive feature benchmark runner for oxide-randomx (Windows / PowerShell)

What it does:
- Builds and benchmarks multiple feature combinations to measure their impact:
  1. Baseline (interpreter only, no optional features)
  2. JIT enabled (conservative mode)
  3. JIT + fast-regs enabled
  4. SIMD block I/O enabled
  5. Threaded interpreter enabled
  6. Fast-decode enabled (default feature)
  7. Full feature set (all features combined)
- Each run uses `--jit both` where applicable for interpreter baseline comparison.
- Alternates execution order to reduce thermal / boost bias.
- Parses `ns/hash` from output and prints median/mean + speedup stats.

Prereqs:
- From the oxide-randomx repo root (or set -RepoRoot), you have:
  - examples/bench.rs
  - bench supports: --mode, --jit, --jit-fast-regs, --iters, --warmup, --threads, --report, --format human
- Fast mode requires OXIDE_RANDOMX_FAST_BENCH=1 (this script sets it).
- Large pages require OXIDE_RANDOMX_LARGE_PAGES=1 (optional, set via -LargePages switch).

Usage examples:
  # Basic usage with defaults (fast mode, 200 iters, 10 warmup, 5 repeats)
  .\bench_apples.ps1

  # Quick sanity check with minimal iterations (20 iters, 2 warmup, 2 repeats)
  .\bench_apples.ps1 -QuickTest

  # Custom iteration and repeat counts
  .\bench_apples.ps1 -Iters 200 -Warmup 10 -Repeats 5

  # Light mode benchmarking (smaller dataset, faster execution)
  .\bench_apples.ps1 -Mode light -Iters 500 -Repeats 3

  # Enable large pages for memory performance testing
  .\bench_apples.ps1 -LargePages

  # Specify thread count explicitly
  .\bench_apples.ps1 -Threads 8

  # Full configuration with all options
  .\bench_apples.ps1 -Mode fast -Iters 200 -Warmup 10 -Repeats 5 -Threads 8 -LargePages

  # Export results to CSV for analysis
  .\bench_apples.ps1 -SaveCsv

  # Run from a different directory
  .\bench_apples.ps1 -RepoRoot C:\path\to\oxide-randomx

  # Adjust pause between runs for thermal management
  .\bench_apples.ps1 -PauseMsBetweenRuns 1000 -Repeats 10

#>

[CmdletBinding()]
param(
  [string]$RepoRoot = (Get-Location).Path,
  [ValidateSet("light","fast")]
  [string]$Mode = "fast",
  [int]$Iters = 200,
  [int]$Warmup = 10,
  [int]$Repeats = 5,
  [int]$Threads = 0,                 # 0 = let bench choose default
  [int]$PauseMsBetweenRuns = 500,    # small settle time
  [switch]$SaveCsv,
  [switch]$LargePages,
  [switch]$QuickTest                 # Quick mode for testing: minimal iters
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

# Quick test mode overrides
if ($QuickTest) {
  $Iters = 20
  $Warmup = 2
  $Repeats = 2
}

# --- Feature Configurations ---
# Each config: Name, Features, JitMode (on/off/both), FastRegs (on/off)
$FeatureConfigs = @(
  @{ Name = "Baseline (Interpreter)";       Features = "bench-instrument";                                              JitMode = "off"; FastRegs = "off" }
  @{ Name = "JIT Conservative";             Features = "jit bench-instrument";                                          JitMode = "on";  FastRegs = "off" }
  @{ Name = "JIT + Fast-Regs";              Features = "jit bench-instrument jit-fastregs";                             JitMode = "on";  FastRegs = "on"  }
  @{ Name = "SIMD Block I/O";               Features = "bench-instrument simd-blockio";                                 JitMode = "off"; FastRegs = "off" }
  @{ Name = "Threaded Interpreter";         Features = "bench-instrument threaded-interp";                              JitMode = "off"; FastRegs = "off" }
  @{ Name = "Fast Decode";                  Features = "bench-instrument fast-decode";                                  JitMode = "off"; FastRegs = "off" }
  @{ Name = "SIMD + JIT Conservative";      Features = "jit bench-instrument simd-blockio";                             JitMode = "on";  FastRegs = "off" }
  @{ Name = "SIMD + JIT + Fast-Regs";       Features = "jit bench-instrument jit-fastregs simd-blockio";                JitMode = "on";  FastRegs = "on"  }
  @{ Name = "Full Features";                Features = "jit bench-instrument jit-fastregs simd-blockio fast-decode threaded-interp"; JitMode = "on";  FastRegs = "on"  }
)

function Get-Median {
  param([double[]]$Values)
  if (-not $Values -or $Values.Count -eq 0) { return [double]::NaN }
  $sorted = $Values | Sort-Object
  $n = $sorted.Count
  if ($n % 2 -eq 1) {
    return [double]$sorted[($n - 1) / 2]
  } else {
    $a = [double]$sorted[($n / 2) - 1]
    $b = [double]$sorted[$n / 2]
    return ($a + $b) / 2.0
  }
}

function Get-Mean {
  param([double[]]$Values)
  if (-not $Values -or $Values.Count -eq 0) { return [double]::NaN }
  return ($Values | Measure-Object -Average).Average
}

function Get-StdDev {
  param([double[]]$Values)
  if (-not $Values -or $Values.Count -lt 2) { return [double]::NaN }
  $mean = Get-Mean $Values
  $sumSqDiff = 0.0
  foreach ($v in $Values) {
    $sumSqDiff += ($v - $mean) * ($v - $mean)
  }
  return [Math]::Sqrt($sumSqDiff / ($Values.Count - 1))
}

function Convert-ProvenanceLine {
  param([string]$Line)
  $map = @{}
  $rx = [regex]'(?<key>[A-Za-z0-9_]+)=(?:"(?<qval>[^"]*)"|(?<val>[^\s]+))'
  foreach ($m in $rx.Matches($Line)) {
    $key = $m.Groups["key"].Value
    $val = if ($m.Groups["qval"].Success) { $m.Groups["qval"].Value } else { $m.Groups["val"].Value }
    if ($key) { $map[$key] = $val }
  }
  return $map
}

function Build-BenchExe {
  param([string]$Features)

  Write-Host "  Building bench (release) with features: $Features" -ForegroundColor Cyan
  $buildResult = & cargo build --release --example bench --features $Features 2>&1
  if ($LASTEXITCODE -ne 0) {
    Write-Host "  Build failed:" -ForegroundColor Red
    Write-Host $buildResult
    throw "cargo build failed (exit $LASTEXITCODE)"
  }

  $benchExe = Join-Path (Get-Location) "target\release\examples\bench.exe"
  if (-not (Test-Path $benchExe)) {
    throw "bench.exe not found at: $benchExe"
  }
  return $benchExe
}

function Invoke-BenchOnce {
  param(
    [string]$BenchExe,
    [string]$Mode,
    [int]$Iters,
    [int]$Warmup,
    [int]$Threads,
    [string]$JitMode,
    [string]$FastRegs
  )

  $benchArgs = @(
    "--mode", $Mode,
    "--jit", $JitMode,
    "--jit-fast-regs", $FastRegs,
    "--iters", $Iters,
    "--warmup", $Warmup,
    "--report",
    "--format", "human"
  )

  if ($Threads -gt 0) {
    $benchArgs += @("--threads", $Threads)
  }

  $output = & $BenchExe @benchArgs 2>&1
  if ($LASTEXITCODE -ne 0) {
    throw "bench.exe failed (exit $LASTEXITCODE). Output:`n$output"
  }

  # Parse result lines:
  # mode=Fast jit=false fast_regs=false hashes=1200 ns/hash=60198435
  # mode=Fast jit=true  fast_regs=false hashes=1200 ns/hash=58999280
  $rx = [regex]'mode=(?<mode>\w+)\s+jit=(?<jit>true|false)\s+fast_regs=(?<fastregs>true|false)\s+hashes=(?<hashes>\d+)\s+ns/hash=(?<nshash>\d+)'

  $interpNs = $null
  $jitNs = $null
  $activeNs = $null

  foreach ($line in $output) {
    $m = $rx.Match($line)
    if ($m.Success) {
      $jit = $m.Groups["jit"].Value
      $ns  = [double]$m.Groups["nshash"].Value
      if ($jit -eq "false") { $interpNs = $ns }
      if ($jit -eq "true")  { $jitNs = $ns }
    }
  }

  # Determine active result based on JitMode
  if ($JitMode -eq "off") {
    $activeNs = $interpNs
  } elseif ($JitMode -eq "on") {
    $activeNs = $jitNs
  } else {
    # "both" - use JIT as primary
    $activeNs = if ($null -ne $jitNs) { $jitNs } else { $interpNs }
  }

  if ($null -eq $activeNs) {
    throw "Failed to parse ns/hash from bench output. Raw output:`n$($output -join "`n")"
  }

  # Parse provenance
  $provLines = $output | Where-Object { $_ -like "provenance *" }
  $prov = @{}
  foreach ($line in $provLines) {
    $parsed = Convert-ProvenanceLine -Line $line
    if ($parsed.Count -gt 0) {
      $prov = $parsed
      break
    }
  }

  $gitShaShort = if ($prov["git_sha_short"]) { $prov["git_sha_short"] } else { "unknown" }
  $features = if ($prov["features"]) { $prov["features"] } else { "unknown" }
  $cpu = if ($prov["cpu"]) { $prov["cpu"] } else { "unknown" }
  $hashes = if ($prov["hashes"]) { $prov["hashes"] } else { "unknown" }
  $lpDataset = $output | Select-String "large_pages_dataset=(\w+)" | ForEach-Object { $_.Matches[0].Groups[1].Value }
  $lpScratchpad = $output | Select-String "large_pages_scratchpad=(\w+)" | ForEach-Object { $_.Matches[0].Groups[1].Value }

  [pscustomobject]@{
    mode              = $Mode
    iters             = $Iters
    warmup            = $Warmup
    threads           = $Threads
    jit_mode          = $JitMode
    fast_regs         = $FastRegs
    active_nsph       = [double]$activeNs
    interp_nsph       = if ($null -ne $interpNs) { [double]$interpNs } else { [double]::NaN }
    jit_nsph          = if ($null -ne $jitNs) { [double]$jitNs } else { [double]::NaN }
    git_sha_short     = $gitShaShort
    features          = $features
    cpu               = $cpu
    hashes            = $hashes
    large_pages_ds    = $lpDataset
    large_pages_sp    = $lpScratchpad
  }
}

# --- Main Execution ---
Push-Location $RepoRoot
try {
  if ($Mode -eq "fast") {
    $env:OXIDE_RANDOMX_FAST_BENCH = "1"
  }
  if ($LargePages) {
    $env:OXIDE_RANDOMX_LARGE_PAGES = "1"
    Write-Host "Large pages enabled" -ForegroundColor Yellow
  }

  Write-Host ""
  Write-Host "========================================" -ForegroundColor Green
  Write-Host " Oxide-RandomX Feature Benchmark Suite" -ForegroundColor Green
  Write-Host "========================================" -ForegroundColor Green
  Write-Host ""
  Write-Host "Configuration:"
  Write-Host "  Mode        : $Mode"
  Write-Host "  Iters       : $Iters"
  Write-Host "  Warmup      : $Warmup"
  Write-Host "  Repeats     : $Repeats"
  Write-Host "  Large Pages : $LargePages"
  if ($Threads -gt 0) { Write-Host "  Threads     : $Threads" } else { Write-Host "  Threads     : (auto)" }
  Write-Host ""

  # Store all results
  $allResults = @{}

  foreach ($config in $FeatureConfigs) {
    $configName = $config.Name
    $features = $config.Features
    $jitMode = $config.JitMode
    $fastRegs = $config.FastRegs

    Write-Host "----------------------------------------" -ForegroundColor Cyan
    Write-Host "Configuration: $configName" -ForegroundColor Cyan
    Write-Host "  Features: $features"
    Write-Host "  JIT: $jitMode, Fast-Regs: $fastRegs"
    Write-Host ""

    # Build for this configuration
    try {
      $benchExe = Build-BenchExe -Features $features
    } catch {
      Write-Host "  Skipping: Build failed - $_" -ForegroundColor Yellow
      continue
    }

    $configResults = New-Object System.Collections.Generic.List[object]

    for ($i = 1; $i -le $Repeats; $i++) {
      Write-Host "  Run $i/$Repeats" -NoNewline

      try {
        $result = Invoke-BenchOnce -BenchExe $benchExe -Mode $Mode -Iters $Iters -Warmup $Warmup -Threads $Threads -JitMode $jitMode -FastRegs $fastRegs
        $configResults.Add($result) | Out-Null
        Write-Host ("  {0:N0} ns/hash" -f $result.active_nsph) -ForegroundColor White
      } catch {
        Write-Host "  Failed: $_" -ForegroundColor Red
      }

      Start-Sleep -Milliseconds $PauseMsBetweenRuns
    }

    if ($configResults.Count -gt 0) {
      $allResults[$configName] = $configResults

      $nsValues = $configResults | ForEach-Object { [double]$_.active_nsph }
      $median = Get-Median $nsValues
      $mean = Get-Mean $nsValues
      $stddev = Get-StdDev $nsValues
      $hps = if ($median -gt 0) { 1e9 / $median } else { 0 }

      Write-Host ("  Summary: Median={0:N0} ns/hash, Mean={1:N0}, StdDev={2:N0}, HPS={3:N2}" -f $median, $mean, $stddev, $hps) -ForegroundColor Green
    }

    Write-Host ""
  }

  # --- Final Summary ---
  Write-Host ""
  Write-Host "========================================" -ForegroundColor Green
  Write-Host " FINAL SUMMARY" -ForegroundColor Green
  Write-Host "========================================" -ForegroundColor Green
  Write-Host ""

  # Calculate baseline for comparison
  $baselineMedian = [double]::NaN
  if ($allResults.ContainsKey("Baseline (Interpreter)")) {
    $baselineNs = $allResults["Baseline (Interpreter)"] | ForEach-Object { [double]$_.active_nsph }
    $baselineMedian = Get-Median $baselineNs
  }

  # Table header
  $fmt = "{0,-35} {1,15} {2,15} {3,12} {4,12}"
  Write-Host ($fmt -f "Configuration", "Median ns/hash", "Mean ns/hash", "HPS", "vs Baseline")
  Write-Host ("-" * 95)

  foreach ($configName in $FeatureConfigs | ForEach-Object { $_.Name }) {
    if (-not $allResults.ContainsKey($configName)) { continue }

    $nsValues = $allResults[$configName] | ForEach-Object { [double]$_.active_nsph }
    $median = Get-Median $nsValues
    $mean = Get-Mean $nsValues
    $hps = if ($median -gt 0) { 1e9 / $median } else { 0 }

    $speedup = ""
    if (-not [double]::IsNaN($baselineMedian) -and $median -gt 0) {
      $speedupX = $baselineMedian / $median
      $speedup = "{0:N2}x" -f $speedupX
    }

    Write-Host ($fmt -f $configName, ("{0:N0}" -f $median), ("{0:N0}" -f $mean), ("{0:N2}" -f $hps), $speedup)
  }

  Write-Host ""

  # Feature impact analysis
  Write-Host "Feature Impact Analysis:" -ForegroundColor Cyan

  # JIT impact
  if ($allResults.ContainsKey("Baseline (Interpreter)") -and $allResults.ContainsKey("JIT Conservative")) {
    $baseNs = Get-Median ($allResults["Baseline (Interpreter)"] | ForEach-Object { [double]$_.active_nsph })
    $jitNs = Get-Median ($allResults["JIT Conservative"] | ForEach-Object { [double]$_.active_nsph })
    $improvement = (($baseNs - $jitNs) / $baseNs) * 100
    Write-Host ("  JIT vs Interpreter: {0:N1}% improvement ({1:N2}x faster)" -f $improvement, ($baseNs / $jitNs))
  }

  # Fast-regs impact
  if ($allResults.ContainsKey("JIT Conservative") -and $allResults.ContainsKey("JIT + Fast-Regs")) {
    $conservNs = Get-Median ($allResults["JIT Conservative"] | ForEach-Object { [double]$_.active_nsph })
    $fastNs = Get-Median ($allResults["JIT + Fast-Regs"] | ForEach-Object { [double]$_.active_nsph })
    $improvement = (($conservNs - $fastNs) / $conservNs) * 100
    Write-Host ("  Fast-Regs vs Conservative JIT: {0:N1}% improvement ({1:N2}x faster)" -f $improvement, ($conservNs / $fastNs))
  }

  # SIMD impact
  if ($allResults.ContainsKey("Baseline (Interpreter)") -and $allResults.ContainsKey("SIMD Block I/O")) {
    $baseNs = Get-Median ($allResults["Baseline (Interpreter)"] | ForEach-Object { [double]$_.active_nsph })
    $simdNs = Get-Median ($allResults["SIMD Block I/O"] | ForEach-Object { [double]$_.active_nsph })
    $improvement = (($baseNs - $simdNs) / $baseNs) * 100
    Write-Host ("  SIMD Block I/O vs Baseline: {0:N1}% improvement ({1:N2}x faster)" -f $improvement, ($baseNs / $simdNs))
  }

  # Threaded interpreter impact
  if ($allResults.ContainsKey("Baseline (Interpreter)") -and $allResults.ContainsKey("Threaded Interpreter")) {
    $baseNs = Get-Median ($allResults["Baseline (Interpreter)"] | ForEach-Object { [double]$_.active_nsph })
    $threadedNs = Get-Median ($allResults["Threaded Interpreter"] | ForEach-Object { [double]$_.active_nsph })
    $improvement = (($baseNs - $threadedNs) / $baseNs) * 100
    Write-Host ("  Threaded Interpreter vs Baseline: {0:N1}% improvement ({1:N2}x faster)" -f $improvement, ($baseNs / $threadedNs))
  }

  # Full features impact
  if ($allResults.ContainsKey("Baseline (Interpreter)") -and $allResults.ContainsKey("Full Features")) {
    $baseNs = Get-Median ($allResults["Baseline (Interpreter)"] | ForEach-Object { [double]$_.active_nsph })
    $fullNs = Get-Median ($allResults["Full Features"] | ForEach-Object { [double]$_.active_nsph })
    $improvement = (($baseNs - $fullNs) / $baseNs) * 100
    Write-Host ("  Full Features vs Baseline: {0:N1}% improvement ({1:N2}x faster)" -f $improvement, ($baseNs / $fullNs))
  }

  Write-Host ""

  # Save CSV if requested
  if ($SaveCsv) {
    $csvPath = Join-Path (Get-Location) "bench_features_results.csv"
    $csvRows = @()
    foreach ($configName in $allResults.Keys) {
      foreach ($result in $allResults[$configName]) {
        $csvRows += [pscustomobject]@{
          configuration = $configName
          mode = $result.mode
          iters = $result.iters
          warmup = $result.warmup
          threads = $result.threads
          jit_mode = $result.jit_mode
          fast_regs = $result.fast_regs
          active_nsph = $result.active_nsph
          interp_nsph = $result.interp_nsph
          jit_nsph = $result.jit_nsph
          features = $result.features
          cpu = $result.cpu
          git_sha_short = $result.git_sha_short
          large_pages_dataset = $result.large_pages_ds
          large_pages_scratchpad = $result.large_pages_sp
        }
      }
    }
    $csvRows | Export-Csv -NoTypeInformation -Path $csvPath
    Write-Host "Results saved to: $csvPath" -ForegroundColor Green
  }

} finally {
  Pop-Location
}
