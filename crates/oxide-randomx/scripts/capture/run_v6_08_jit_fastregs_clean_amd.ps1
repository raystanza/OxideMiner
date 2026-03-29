<#
.SYNOPSIS
Runs the PROMPTv6_08 clean AMD guardrail rerun for the exact v6_07 jit-fastregs candidate.

.DESCRIPTION
Creates clean detached worktrees for the shared baseline and isolated candidate patch,
executes the required validation tests, captures ABBA perf_harness runs for the four
JIT scenarios, then writes combined CSVs, perf_compare outputs, provenance, and a
machine-readable summary into perf_results/AMD.
#>

[CmdletBinding()]
param(
    [string]$RootDir = (Resolve-Path (Join-Path $PSScriptRoot "../..")).Path,
    [string]$BaseSha = "a11022079897a7d2f76228e89be0109ff4f45e44",
    [string]$PatchSourceSha = "fcb47512f74f475e5e2c61c72ba3a86669fc4c69",
    [string]$HostTag = "amd",
    [int]$Threads = 0,
    [int]$LightIters = 100,
    [int]$LightWarmup = 10,
    [int]$FastIters = 100,
    [int]$FastWarmup = 10,
    [switch]$SkipTests,
    [switch]$KeepWorktrees,
    [string]$Timestamp = "",
    [string]$IntelReferencePatch = "",
    [string]$ResumeTmpOut = ""
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"
if (Get-Variable -Name PSNativeCommandUseErrorActionPreference -ErrorAction SilentlyContinue) {
    $PSNativeCommandUseErrorActionPreference = $false
}

$resumeMode = -not [string]::IsNullOrWhiteSpace($ResumeTmpOut)
if ($resumeMode -and [string]::IsNullOrWhiteSpace($Timestamp)) {
    if ($ResumeTmpOut -match 'oxide-randomx-v6_08-[^-]+-out-(\d{8}_\d{6})$') {
        $Timestamp = $matches[1]
    } else {
        throw "Timestamp was not provided and could not be derived from ResumeTmpOut: $ResumeTmpOut"
    }
}
if ([string]::IsNullOrWhiteSpace($Timestamp)) {
    $Timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
}

$RootDir = (Resolve-Path $RootDir).Path
if ($Threads -le 0) {
    $Threads = [Environment]::ProcessorCount
}

$repoParent = Split-Path -Parent $RootDir
$artifactDir = Join-Path $RootDir "perf_results/AMD"
$tmpOut = if ($resumeMode) {
    (Resolve-Path $ResumeTmpOut).Path
} else {
    Join-Path ([System.IO.Path]::GetTempPath()) "oxide-randomx-v6_08-$HostTag-out-$Timestamp"
}
$baseWt = Join-Path $repoParent "oxide-randomx-v6_08-$HostTag-baseline-$Timestamp"
$candWt = Join-Path $repoParent "oxide-randomx-v6_08-$HostTag-candidate-$Timestamp"

$patchFile = Join-Path $tmpOut "v6_08_p2_2_exact_candidate_${HostTag}_${Timestamp}.patch"
$manifestFile = Join-Path $tmpOut "v6_08_manifest_${HostTag}_${Timestamp}.txt"
$provenanceFile = Join-Path $tmpOut "v6_08_provenance_${HostTag}_${Timestamp}.txt"
$commandLogFile = Join-Path $tmpOut "v6_08_commands_${HostTag}_${Timestamp}.log"
$summaryFile = Join-Path $artifactDir "v6_08_jit_fastregs_clean_summary_${HostTag}_${Timestamp}.json"

if ([string]::IsNullOrWhiteSpace($IntelReferencePatch)) {
    $IntelReferencePatch = Join-Path $RootDir "perf_results/Intel/v6_07_p2_2_exact_candidate_intel_20260301_131819.patch"
}

if (-not (Test-Path -LiteralPath $artifactDir)) {
    New-Item -ItemType Directory -Path $artifactDir -Force | Out-Null
}
if ($resumeMode) {
    if (-not (Test-Path -LiteralPath $tmpOut)) {
        throw "ResumeTmpOut does not exist: $tmpOut"
    }
} else {
    if (Test-Path -LiteralPath $tmpOut) {
        Remove-Item -LiteralPath $tmpOut -Recurse -Force
    }
    New-Item -ItemType Directory -Path $tmpOut -Force | Out-Null
}

function Get-EnvSnapshot {
    param([Parameter(Mandatory = $true)][string]$Name)
    $path = "Env:$Name"
    if (Test-Path -LiteralPath $path) {
        return [pscustomobject]@{
            Name = $Name
            Present = $true
            Value = (Get-Item -LiteralPath $path).Value
        }
    }
    return [pscustomobject]@{
        Name = $Name
        Present = $false
        Value = $null
    }
}

function Restore-EnvSnapshot {
    param([Parameter(Mandatory = $true)]$Snapshot)
    $path = "Env:$($Snapshot.Name)"
    if ($Snapshot.Present) {
        Set-Item -LiteralPath $path -Value $Snapshot.Value
    } else {
        Remove-Item -LiteralPath $path -ErrorAction SilentlyContinue
    }
}

function Format-CommandForLog {
    param([Parameter(Mandatory = $true)][string[]]$Command)
    $quoted = foreach ($part in $Command) {
        if ($part -match '[\s"]') {
            '"' + ($part -replace '"', '\"') + '"'
        } else {
            $part
        }
    }
    return ($quoted -join " ")
}

function Get-RelativeRepoPath {
    param(
        [Parameter(Mandatory = $true)][string]$BasePath,
        [Parameter(Mandatory = $true)][string]$TargetPath
    )
    $baseFull = [System.IO.Path]::GetFullPath($BasePath)
    if (-not $baseFull.EndsWith([System.IO.Path]::DirectorySeparatorChar)) {
        $baseFull = $baseFull + [System.IO.Path]::DirectorySeparatorChar
    }
    $targetFull = [System.IO.Path]::GetFullPath($TargetPath)
    $baseUri = [System.Uri]::new($baseFull)
    $targetUri = [System.Uri]::new($targetFull)
    return [System.Uri]::UnescapeDataString(
        $baseUri.MakeRelativeUri($targetUri).ToString().Replace('/', '\')
    )
}

function Remove-WorktreeIfExists {
    param([Parameter(Mandatory = $true)][string]$Path)
    & git -C $RootDir worktree remove --force $Path *> $null
    Remove-Item -LiteralPath $Path -Recurse -Force -ErrorAction SilentlyContinue
}

function Test-GitDirty {
    param([Parameter(Mandatory = $true)][string]$RepoPath)
    $status = @(& git -C $RepoPath status --porcelain)
    return $status.Count -gt 0
}

function Invoke-NativeOrThrow {
    param(
        [Parameter(Mandatory = $true)][string[]]$Command,
        [Parameter(Mandatory = $true)][string]$FailureMessage
    )

    & $Command[0] @($Command | Select-Object -Skip 1) *> $null
    $exitCode = $LASTEXITCODE
    if ($null -eq $exitCode) {
        $exitCode = 0
    }
    if ($exitCode -ne 0) {
        throw "${FailureMessage} (exit code ${exitCode})"
    }
}

function Read-KeyValueFile {
    param([Parameter(Mandatory = $true)][string]$Path)

    $data = @{}
    foreach ($line in Get-Content -LiteralPath $Path) {
        if ($line -match '^(?<key>[^=]+)=(?<value>.*)$') {
            $data[$matches.key] = $matches.value
        }
    }
    return $data
}

function Invoke-LoggedCommand {
    param(
        [Parameter(Mandatory = $true)][string]$WorkingDirectory,
        [Parameter(Mandatory = $true)][string[]]$Command,
        [Parameter(Mandatory = $true)][string]$StdoutPath,
        [Parameter(Mandatory = $true)][string]$StderrPath,
        [hashtable]$EnvOverrides = @{},
        [int[]]$AllowedExitCodes = @(0),
        [string[]]$LogEnvNames = @()
    )

    $snapshots = @{}
    foreach ($name in $EnvOverrides.Keys) {
        $snapshots[$name] = Get-EnvSnapshot -Name $name
    }

    Add-Content -LiteralPath $commandLogFile -Value ""
    Add-Content -LiteralPath $commandLogFile -Value "# workdir: $WorkingDirectory"
    foreach ($name in $LogEnvNames) {
        if ($EnvOverrides.ContainsKey($name)) {
            $value = $EnvOverrides[$name]
            if ($null -eq $value) {
                Add-Content -LiteralPath $commandLogFile -Value "Remove-Item Env:$name -ErrorAction SilentlyContinue"
            } else {
                Add-Content -LiteralPath $commandLogFile -Value "`$env:$name='$value'"
            }
        }
    }
    Add-Content -LiteralPath $commandLogFile -Value (Format-CommandForLog -Command $Command)

    try {
        foreach ($name in $EnvOverrides.Keys) {
            $value = $EnvOverrides[$name]
            if ($null -eq $value) {
                Remove-Item -LiteralPath ("Env:" + $name) -ErrorAction SilentlyContinue
            } else {
                Set-Item -LiteralPath ("Env:" + $name) -Value $value
            }
        }

        Push-Location $WorkingDirectory
        try {
            & $Command[0] @($Command | Select-Object -Skip 1) 1> $StdoutPath 2> $StderrPath
            $exitCode = $LASTEXITCODE
            if ($null -eq $exitCode) {
                $exitCode = 0
            }
        } finally {
            Pop-Location
        }
    } finally {
        foreach ($snapshot in $snapshots.Values) {
            Restore-EnvSnapshot -Snapshot $snapshot
        }
    }

    if ($AllowedExitCodes -notcontains $exitCode) {
        throw "Command failed with exit code ${exitCode}: $(Format-CommandForLog -Command $Command)"
    }

    return $exitCode
}

function Invoke-MergedCommand {
    param(
        [Parameter(Mandatory = $true)][string]$WorkingDirectory,
        [Parameter(Mandatory = $true)][string[]]$Command,
        [Parameter(Mandatory = $true)][string]$OutputPath,
        [int[]]$AllowedExitCodes = @(0)
    )

    Add-Content -LiteralPath $commandLogFile -Value ""
    Add-Content -LiteralPath $commandLogFile -Value "# workdir: $WorkingDirectory"
    Add-Content -LiteralPath $commandLogFile -Value (Format-CommandForLog -Command $Command)

    Push-Location $WorkingDirectory
    try {
        & $Command[0] @($Command | Select-Object -Skip 1) *> $OutputPath
        $exitCode = $LASTEXITCODE
        if ($null -eq $exitCode) {
            $exitCode = 0
        }
    } finally {
        Pop-Location
    }

    if ($AllowedExitCodes -notcontains $exitCode) {
        throw "Command failed with exit code ${exitCode}: $(Format-CommandForLog -Command $Command)"
    }

    return $exitCode
}

function Write-CombinedCsv {
    param(
        [Parameter(Mandatory = $true)][string[]]$InputPaths,
        [Parameter(Mandatory = $true)][string]$OutputPath
    )

    if ($InputPaths.Count -lt 1) {
        throw "Write-CombinedCsv requires at least one input path."
    }

    $header = Get-Content -LiteralPath $InputPaths[0] -TotalCount 1
    $rows = New-Object System.Collections.Generic.List[string]
    foreach ($path in $InputPaths) {
        $currentHeader = Get-Content -LiteralPath $path -TotalCount 1
        if ($currentHeader -ne $header) {
            throw "Header mismatch while combining CSVs: $path"
        }
        foreach ($line in (Get-Content -LiteralPath $path | Select-Object -Skip 1)) {
            if (-not [string]::IsNullOrWhiteSpace($line)) {
                $rows.Add($line) | Out-Null
            }
        }
    }

    Set-Content -LiteralPath $OutputPath -Value $header -Encoding utf8NoBOM
    if ($rows.Count -gt 0) {
        Add-Content -LiteralPath $OutputPath -Value $rows -Encoding utf8NoBOM
    }
}

function Get-Mean {
    param([double[]]$Values)
    if (-not $Values -or $Values.Count -eq 0) {
        return $null
    }
    return ($Values | Measure-Object -Average).Average
}

function Get-MetricMean {
    param(
        [Parameter(Mandatory = $true)]$Rows,
        [Parameter(Mandatory = $true)][string]$Field
    )

    $values = New-Object System.Collections.Generic.List[double]
    foreach ($row in $Rows) {
        $raw = [string]$row.$Field
        $value = 0.0
        if (-not [double]::TryParse($raw, [ref]$value)) {
            return $null
        }
        $values.Add($value) | Out-Null
    }
    return Get-Mean -Values $values.ToArray()
}

function Get-PctDelta {
    param($Baseline, $Candidate)
    if ($null -eq $Baseline -or $null -eq $Candidate) {
        return $null
    }
    if ($Baseline -le 0) {
        return $null
    }
    return (($Candidate - $Baseline) / $Baseline) * 100.0
}

function Get-CaptureSummary {
    param(
        [Parameter(Mandatory = $true)][string[]]$Paths,
        [Parameter(Mandatory = $true)][string]$RepoPathForSummary
    )

    $rows = foreach ($path in $Paths) { Import-Csv -LiteralPath $path }
    return [ordered]@{
        paths = @($Paths | ForEach-Object { Get-RelativeRepoPath -BasePath $RepoPathForSummary -TargetPath $_ })
        ns_per_hash_mean = Get-MetricMean -Rows $rows -Field "ns_per_hash"
        execute_program_ns_jit_mean = Get-MetricMean -Rows $rows -Field "execute_program_ns_jit"
        finish_iteration_ns_mean = Get-MetricMean -Rows $rows -Field "finish_iteration_ns"
        prepare_iteration_ns_mean = Get-MetricMean -Rows $rows -Field "prepare_iteration_ns"
        jit_fastregs_spill_count_mean = Get-MetricMean -Rows $rows -Field "jit_fastregs_spill_count"
        jit_fastregs_reload_count_mean = Get-MetricMean -Rows $rows -Field "jit_fastregs_reload_count"
        jit_fastregs_sync_to_ctx_count_mean = Get-MetricMean -Rows $rows -Field "jit_fastregs_sync_to_ctx_count"
        jit_fastregs_sync_from_ctx_count_mean = Get-MetricMean -Rows $rows -Field "jit_fastregs_sync_from_ctx_count"
        jit_fastregs_call_boundary_count_mean = Get-MetricMean -Rows $rows -Field "jit_fastregs_call_boundary_count"
        jit_fastregs_call_boundary_float_nomem_mean = Get-MetricMean -Rows $rows -Field "jit_fastregs_call_boundary_float_nomem"
        jit_fastregs_call_boundary_float_mem_mean = Get-MetricMean -Rows $rows -Field "jit_fastregs_call_boundary_float_mem"
        jit_fastregs_call_boundary_prepare_finish_mean = Get-MetricMean -Rows $rows -Field "jit_fastregs_call_boundary_prepare_finish"
        jit_fastregs_preserve_spill_count_mean = Get-MetricMean -Rows $rows -Field "jit_fastregs_preserve_spill_count"
        jit_fastregs_preserve_reload_count_mean = Get-MetricMean -Rows $rows -Field "jit_fastregs_preserve_reload_count"
        run_ns_per_hash = @($rows | ForEach-Object { [double]$_.ns_per_hash })
    }
}

function Assert-CaptureRow {
    param(
        [Parameter(Mandatory = $true)][string]$CsvPath,
        [Parameter(Mandatory = $true)][string]$ExpectedSha,
        [Parameter(Mandatory = $true)][string]$ExpectedShortSha,
        [Parameter(Mandatory = $true)][string]$ExpectedDirty
    )

    $rows = @(Import-Csv -LiteralPath $CsvPath)
    if ($rows.Count -ne 1) {
        throw "Expected exactly one data row in $CsvPath"
    }
    $row = $rows[0]
    if ([string]$row.git_sha -ne $ExpectedSha) {
        throw "git_sha mismatch in ${CsvPath}: expected $ExpectedSha got $($row.git_sha)"
    }
    if ([string]$row.git_sha_short -ne $ExpectedShortSha) {
        throw "git_sha_short mismatch in ${CsvPath}: expected $ExpectedShortSha got $($row.git_sha_short)"
    }
    if ([string]$row.git_dirty -ne $ExpectedDirty) {
        throw "git_dirty mismatch in ${CsvPath}: expected $ExpectedDirty got $($row.git_dirty)"
    }
}

function Run-TestBundle {
    param(
        [Parameter(Mandatory = $true)][string]$State,
        [Parameter(Mandatory = $true)][string]$Worktree
    )

    $prefix = Join-Path $tmpOut "v6_08_${State}_${HostTag}_${Timestamp}"
    Invoke-LoggedCommand -WorkingDirectory $Worktree `
        -Command @("cargo", "test", "--test", "oracle") `
        -StdoutPath "${prefix}_oracle.stdout" `
        -StderrPath "${prefix}_oracle.stderr" | Out-Null

    Invoke-LoggedCommand -WorkingDirectory $Worktree `
        -Command @("cargo", "test", "--features", "jit jit-fastregs", "--test", "oracle") `
        -StdoutPath "${prefix}_oracle_jit_fastregs.stdout" `
        -StderrPath "${prefix}_oracle_jit_fastregs.stderr" | Out-Null

    Invoke-LoggedCommand -WorkingDirectory $Worktree `
        -Command @("cargo", "test", "--features", "jit bench-instrument", "--test", "jit_perf_smoke") `
        -StdoutPath "${prefix}_jit_perf_smoke.stdout" `
        -StderrPath "${prefix}_jit_perf_smoke.stderr" | Out-Null
}

function Run-Perf {
    param(
        [Parameter(Mandatory = $true)][string]$State,
        [Parameter(Mandatory = $true)][string]$Worktree,
        [Parameter(Mandatory = $true)][ValidateSet("light", "fast")][string]$Mode,
        [Parameter(Mandatory = $true)][ValidateSet("conservative", "fastregs")][string]$Variant,
        [Parameter(Mandatory = $true)][string]$Sequence,
        [Parameter(Mandatory = $true)][string]$ExpectedSha,
        [Parameter(Mandatory = $true)][string]$ExpectedShortSha
    )

    $features = if ($Variant -eq "fastregs") { "jit jit-fastregs bench-instrument" } else { "jit bench-instrument" }
    $jitFastRegs = if ($Variant -eq "fastregs") { "on" } else { "off" }
    $iters = if ($Mode -eq "fast") { $FastIters } else { $LightIters }
    $warmup = if ($Mode -eq "fast") { $FastWarmup } else { $LightWarmup }

    $csvPath = Join-Path $tmpOut "v6_08_${State}_${Mode}_jit_${Variant}_${Sequence}_${HostTag}_${Timestamp}.csv"
    $stdoutPath = [System.IO.Path]::ChangeExtension($csvPath, ".stdout")
    $stderrPath = [System.IO.Path]::ChangeExtension($csvPath, ".stderr")

    $envOverrides = @{
        OXIDE_RANDOMX_HUGE_1G = "0"
        OXIDE_RANDOMX_FAST_BENCH = $(if ($Mode -eq "fast") { "1" } else { $null })
        OXIDE_RANDOMX_FAST_BENCH_SMALL = $null
        OXIDE_RANDOMX_PREFETCH_DISTANCE = $null
        OXIDE_RANDOMX_PREFETCH_AUTO = $null
        OXIDE_RANDOMX_PREFETCH_SCRATCHPAD_DISTANCE = $null
        OXIDE_RANDOMX_SIMD_BLOCKIO_FORCE = $null
        OXIDE_RANDOMX_THREADED_INTERP = $null
        OXIDE_RANDOMX_THREADS = $null
        OXIDE_RANDOMX_LARGE_PAGES = $null
        OXIDE_RANDOMX_THREAD_NAMES = $null
        OXIDE_RANDOMX_AFFINITY = $null
    }

    $command = @(
        "cargo", "run", "--release", "--example", "perf_harness",
        "--features", $features, "--",
        "--mode", $Mode,
        "--jit", "on",
        "--jit-fast-regs", $jitFastRegs,
        "--iters", [string]$iters,
        "--warmup", [string]$warmup,
        "--threads", [string]$Threads,
        "--large-pages", "off",
        "--thread-names", "off",
        "--affinity", "off",
        "--format", "csv",
        "--out", $csvPath
    )

    Invoke-LoggedCommand -WorkingDirectory $Worktree `
        -Command $command `
        -StdoutPath $stdoutPath `
        -StderrPath $stderrPath `
        -EnvOverrides $envOverrides `
        -LogEnvNames @(
            "OXIDE_RANDOMX_HUGE_1G",
            "OXIDE_RANDOMX_FAST_BENCH",
            "OXIDE_RANDOMX_FAST_BENCH_SMALL",
            "OXIDE_RANDOMX_PREFETCH_DISTANCE",
            "OXIDE_RANDOMX_PREFETCH_AUTO",
            "OXIDE_RANDOMX_PREFETCH_SCRATCHPAD_DISTANCE",
            "OXIDE_RANDOMX_SIMD_BLOCKIO_FORCE",
            "OXIDE_RANDOMX_THREADED_INTERP",
            "OXIDE_RANDOMX_THREADS",
            "OXIDE_RANDOMX_LARGE_PAGES",
            "OXIDE_RANDOMX_THREAD_NAMES",
            "OXIDE_RANDOMX_AFFINITY"
        ) | Out-Null

    Assert-CaptureRow -CsvPath $csvPath -ExpectedSha $ExpectedSha -ExpectedShortSha $ExpectedShortSha -ExpectedDirty "false"
    return $csvPath
}

function Run-AbbaSet {
    param(
        [Parameter(Mandatory = $true)][string]$State,
        [Parameter(Mandatory = $true)][string]$Worktree,
        [Parameter(Mandatory = $true)][ValidateSet("light", "fast")][string]$Mode,
        [Parameter(Mandatory = $true)][string]$ExpectedSha,
        [Parameter(Mandatory = $true)][string]$ExpectedShortSha
    )

    Run-Perf -State $State -Worktree $Worktree -Mode $Mode -Variant conservative -Sequence a1 -ExpectedSha $ExpectedSha -ExpectedShortSha $ExpectedShortSha | Out-Null
    $fastregsB1 = Run-Perf -State $State -Worktree $Worktree -Mode $Mode -Variant fastregs -Sequence b1 -ExpectedSha $ExpectedSha -ExpectedShortSha $ExpectedShortSha
    $fastregsB2 = Run-Perf -State $State -Worktree $Worktree -Mode $Mode -Variant fastregs -Sequence b2 -ExpectedSha $ExpectedSha -ExpectedShortSha $ExpectedShortSha
    $conservativeA2 = Run-Perf -State $State -Worktree $Worktree -Mode $Mode -Variant conservative -Sequence a2 -ExpectedSha $ExpectedSha -ExpectedShortSha $ExpectedShortSha
    $conservativeA1 = Join-Path $tmpOut "v6_08_${State}_${Mode}_jit_conservative_a1_${HostTag}_${Timestamp}.csv"

    return [ordered]@{
        conservative = @($conservativeA1, $conservativeA2)
        fastregs = @($fastregsB1, $fastregsB2)
    }
}

$baselineHead = $null
$candidateHead = $null
$baselineShort = $null
$candidateShort = $null
$perfCompareExe = $null
$patchMatchesIntelArtifact = $null

try {
    $cpuInfo = Get-CimInstance -ClassName Win32_Processor | Select-Object -First 1
    $osInfo = Get-CimInstance -ClassName Win32_OperatingSystem
    $rustcLine = (& rustc --version).Trim()
    $rustcVerbose = (& rustc -Vv) -join [Environment]::NewLine
    $cargoVersion = (& cargo --version).Trim()

    if ($resumeMode) {
        $manifestData = Read-KeyValueFile -Path $manifestFile
        $BaseSha = $manifestData["base_sha"]
        $PatchSourceSha = $manifestData["patch_source_sha"]
        $baselineHead = $manifestData["baseline_head"]
        $candidateHead = $manifestData["candidate_head"]
        $baselineShort = $baselineHead.Substring(0, 7)
        $candidateShort = $candidateHead.Substring(0, 7)
        $Threads = [int]$manifestData["threads"]
        $LightIters = [int]$manifestData["light_iters"]
        $LightWarmup = [int]$manifestData["light_warmup"]
        $FastIters = [int]$manifestData["fast_iters"]
        $FastWarmup = [int]$manifestData["fast_warmup"]
        if ($manifestData.ContainsKey("patch_matches_intel_artifact")) {
            $patchMatchesIntelArtifact = [bool]::Parse($manifestData["patch_matches_intel_artifact"])
        }

        $baselineFast = [ordered]@{
            conservative = @(
                (Join-Path $tmpOut "v6_08_baseline_fast_jit_conservative_a1_${HostTag}_${Timestamp}.csv"),
                (Join-Path $tmpOut "v6_08_baseline_fast_jit_conservative_a2_${HostTag}_${Timestamp}.csv")
            )
            fastregs = @(
                (Join-Path $tmpOut "v6_08_baseline_fast_jit_fastregs_b1_${HostTag}_${Timestamp}.csv"),
                (Join-Path $tmpOut "v6_08_baseline_fast_jit_fastregs_b2_${HostTag}_${Timestamp}.csv")
            )
        }
        $candidateFast = [ordered]@{
            conservative = @(
                (Join-Path $tmpOut "v6_08_candidate_fast_jit_conservative_a1_${HostTag}_${Timestamp}.csv"),
                (Join-Path $tmpOut "v6_08_candidate_fast_jit_conservative_a2_${HostTag}_${Timestamp}.csv")
            )
            fastregs = @(
                (Join-Path $tmpOut "v6_08_candidate_fast_jit_fastregs_b1_${HostTag}_${Timestamp}.csv"),
                (Join-Path $tmpOut "v6_08_candidate_fast_jit_fastregs_b2_${HostTag}_${Timestamp}.csv")
            )
        }
        $candidateLight = [ordered]@{
            conservative = @(
                (Join-Path $tmpOut "v6_08_candidate_light_jit_conservative_a1_${HostTag}_${Timestamp}.csv"),
                (Join-Path $tmpOut "v6_08_candidate_light_jit_conservative_a2_${HostTag}_${Timestamp}.csv")
            )
            fastregs = @(
                (Join-Path $tmpOut "v6_08_candidate_light_jit_fastregs_b1_${HostTag}_${Timestamp}.csv"),
                (Join-Path $tmpOut "v6_08_candidate_light_jit_fastregs_b2_${HostTag}_${Timestamp}.csv")
            )
        }
        $baselineLight = [ordered]@{
            conservative = @(
                (Join-Path $tmpOut "v6_08_baseline_light_jit_conservative_a1_${HostTag}_${Timestamp}.csv"),
                (Join-Path $tmpOut "v6_08_baseline_light_jit_conservative_a2_${HostTag}_${Timestamp}.csv")
            )
            fastregs = @(
                (Join-Path $tmpOut "v6_08_baseline_light_jit_fastregs_b1_${HostTag}_${Timestamp}.csv"),
                (Join-Path $tmpOut "v6_08_baseline_light_jit_fastregs_b2_${HostTag}_${Timestamp}.csv")
            )
        }
    } else {
        Remove-WorktreeIfExists -Path $baseWt
        Remove-WorktreeIfExists -Path $candWt

        Invoke-NativeOrThrow -Command @("git", "-C", $RootDir, "worktree", "add", "--detach", $baseWt, $BaseSha) `
            -FailureMessage "Failed to create baseline worktree"
        Invoke-NativeOrThrow -Command @("git", "-C", $RootDir, "worktree", "add", "--detach", $candWt, $BaseSha) `
            -FailureMessage "Failed to create candidate worktree"

        $patchContent = & git -C $RootDir diff "$BaseSha..$PatchSourceSha" -- "src/vm/mod.rs" "src/vm/jit/x86_64.rs"
        if ($LASTEXITCODE -ne 0) {
            throw "Failed to generate candidate patch diff from $BaseSha..$PatchSourceSha"
        }
        $patchContent | Out-File -LiteralPath $patchFile -Encoding utf8NoBOM

        if (-not (Test-Path -LiteralPath $patchFile)) {
            throw "Failed to write patch file: $patchFile"
        }

        Invoke-NativeOrThrow -Command @("git", "-C", $candWt, "apply", $patchFile) `
            -FailureMessage "Failed to apply candidate patch"
        Invoke-NativeOrThrow -Command @("git", "-C", $candWt, "add", "src/vm/mod.rs", "src/vm/jit/x86_64.rs") `
            -FailureMessage "Failed to stage candidate patch files"
        Invoke-NativeOrThrow -Command @(
            "git", "-C", $candWt,
            "-c", "commit.gpgSign=false",
            "-c", "user.name=Codex",
            "-c", "user.email=codex@local",
            "commit", "-m", "v6_08 isolated P2.2 jit-fastregs candidate patch"
        ) -FailureMessage "Failed to commit isolated candidate patch"
        Invoke-NativeOrThrow -Command @(
            "git", "-C", $candWt, "diff", "--exit-code", $PatchSourceSha, "--", "src/vm/mod.rs", "src/vm/jit/x86_64.rs"
        ) -FailureMessage "Candidate patch does not match the recorded Intel source diff"

        $baselineHead = (& git -C $baseWt rev-parse HEAD).Trim()
        $candidateHead = (& git -C $candWt rev-parse HEAD).Trim()
        $baselineShort = (& git -C $baseWt rev-parse --short HEAD).Trim()
        $candidateShort = (& git -C $candWt rev-parse --short HEAD).Trim()

        if (Test-Path -LiteralPath $IntelReferencePatch) {
            $patchMatchesIntelArtifact = ([System.IO.File]::ReadAllText($patchFile) -eq [System.IO.File]::ReadAllText($IntelReferencePatch))
        }

        @(
            "# v6_08 AMD jit-fastregs guardrail rerun commands ($Timestamp)"
            "# baseline worktree: $baseWt ($baselineHead)"
            "# candidate worktree: $candWt ($candidateHead)"
            "# base_sha: $BaseSha"
            "# patch_source_sha: $PatchSourceSha"
            "# exact patch file: $patchFile"
        ) | Set-Content -LiteralPath $commandLogFile -Encoding utf8NoBOM

        @(
            "capture_timestamp=$Timestamp"
            "host_tag=$HostTag"
            "artifact_repo=$RootDir"
            "artifact_dir=$artifactDir"
            "tmp_out=$tmpOut"
            "command_log=$(Get-RelativeRepoPath -BasePath $RootDir -TargetPath $commandLogFile)"
            "base_sha=$BaseSha"
            "patch_source_sha=$PatchSourceSha"
            "baseline_head=$baselineHead"
            "candidate_head=$candidateHead"
            "baseline_worktree=$baseWt"
            "candidate_worktree=$candWt"
            "baseline_git_dirty=$(if (Test-GitDirty -RepoPath $baseWt) { "true" } else { "false" })"
            "candidate_git_dirty=$(if (Test-GitDirty -RepoPath $candWt) { "true" } else { "false" })"
            "threads=$Threads"
            "light_iters=$LightIters"
            "light_warmup=$LightWarmup"
            "fast_iters=$FastIters"
            "fast_warmup=$FastWarmup"
            "run_tests=$(if ($SkipTests) { "false" } else { "true" })"
            "keep_worktrees=$(if ($KeepWorktrees) { "true" } else { "false" })"
            "rustc=$rustcLine"
            "cargo=$cargoVersion"
            "cpu_name=$($cpuInfo.Name)"
            "cpu_family=$($cpuInfo.Family)"
            "cpu_description=$($cpuInfo.Description)"
            "cpu_manufacturer=$($cpuInfo.Manufacturer)"
            "processor_identifier=$($cpuInfo.ProcessorId)"
            "logical_cores=$($cpuInfo.NumberOfLogicalProcessors)"
            "physical_cores=$($cpuInfo.NumberOfCores)"
            "os_caption=$($osInfo.Caption)"
            "os_version=$($osInfo.Version)"
            "os_build_number=$($osInfo.BuildNumber)"
            "intel_reference_patch=$(Get-RelativeRepoPath -BasePath $RootDir -TargetPath $IntelReferencePatch)"
            "patch_matches_intel_artifact=$patchMatchesIntelArtifact"
        ) | Set-Content -LiteralPath $provenanceFile -Encoding utf8NoBOM

        @(
            "ts=$Timestamp"
            "host_tag=$HostTag"
            "base_sha=$BaseSha"
            "patch_source_sha=$PatchSourceSha"
            "baseline_head=$baselineHead"
            "candidate_head=$candidateHead"
            "threads=$Threads"
            "light_iters=$LightIters"
            "light_warmup=$LightWarmup"
            "fast_iters=$FastIters"
            "fast_warmup=$FastWarmup"
            "run_tests=$(if ($SkipTests) { 0 } else { 1 })"
            "keep_worktrees=$(if ($KeepWorktrees) { 1 } else { 0 })"
            "base_worktree=$baseWt"
            "candidate_worktree=$candWt"
            "tmp_out=$tmpOut"
            "final_out=$artifactDir"
            "intel_reference_patch=$IntelReferencePatch"
            "patch_matches_intel_artifact=$patchMatchesIntelArtifact"
        ) | Set-Content -LiteralPath $manifestFile -Encoding utf8NoBOM

        Add-Content -LiteralPath $provenanceFile -Value ""
        Add-Content -LiteralPath $provenanceFile -Value "rustc_verbose<<EOF"
        Add-Content -LiteralPath $provenanceFile -Value $rustcVerbose
        Add-Content -LiteralPath $provenanceFile -Value "EOF"

        if (-not $SkipTests) {
            Run-TestBundle -State baseline -Worktree $baseWt
            Run-TestBundle -State candidate -Worktree $candWt
        }

        $baselineFast = Run-AbbaSet -State baseline -Worktree $baseWt -Mode fast -ExpectedSha $baselineHead -ExpectedShortSha $baselineShort
        $candidateFast = Run-AbbaSet -State candidate -Worktree $candWt -Mode fast -ExpectedSha $candidateHead -ExpectedShortSha $candidateShort
        $candidateLight = Run-AbbaSet -State candidate -Worktree $candWt -Mode light -ExpectedSha $candidateHead -ExpectedShortSha $candidateShort
        $baselineLight = Run-AbbaSet -State baseline -Worktree $baseWt -Mode light -ExpectedSha $baselineHead -ExpectedShortSha $baselineShort
    }

    Copy-Item -LiteralPath $patchFile, $manifestFile, $provenanceFile, $commandLogFile -Destination $artifactDir -Force
    Get-ChildItem -LiteralPath $tmpOut -Filter "v6_08_*_${HostTag}_${Timestamp}.csv" | Copy-Item -Destination $artifactDir -Force
    Get-ChildItem -LiteralPath $tmpOut -Filter "v6_08_*_${HostTag}_${Timestamp}.stdout" -ErrorAction SilentlyContinue | Copy-Item -Destination $artifactDir -Force
    Get-ChildItem -LiteralPath $tmpOut -Filter "v6_08_*_${HostTag}_${Timestamp}.stderr" -ErrorAction SilentlyContinue | Copy-Item -Destination $artifactDir -Force

    $baselineFast = [ordered]@{
        conservative = @($baselineFast.conservative | ForEach-Object { Join-Path $artifactDir ([System.IO.Path]::GetFileName($_)) })
        fastregs = @($baselineFast.fastregs | ForEach-Object { Join-Path $artifactDir ([System.IO.Path]::GetFileName($_)) })
    }
    $candidateFast = [ordered]@{
        conservative = @($candidateFast.conservative | ForEach-Object { Join-Path $artifactDir ([System.IO.Path]::GetFileName($_)) })
        fastregs = @($candidateFast.fastregs | ForEach-Object { Join-Path $artifactDir ([System.IO.Path]::GetFileName($_)) })
    }
    $candidateLight = [ordered]@{
        conservative = @($candidateLight.conservative | ForEach-Object { Join-Path $artifactDir ([System.IO.Path]::GetFileName($_)) })
        fastregs = @($candidateLight.fastregs | ForEach-Object { Join-Path $artifactDir ([System.IO.Path]::GetFileName($_)) })
    }
    $baselineLight = [ordered]@{
        conservative = @($baselineLight.conservative | ForEach-Object { Join-Path $artifactDir ([System.IO.Path]::GetFileName($_)) })
        fastregs = @($baselineLight.fastregs | ForEach-Object { Join-Path $artifactDir ([System.IO.Path]::GetFileName($_)) })
    }

    $combined = [ordered]@{
        baseline = [ordered]@{
            fast = [ordered]@{
                conservative = Join-Path $artifactDir "v6_08_baseline_fast_jit_conservative_combined_${HostTag}_${Timestamp}.csv"
                fastregs = Join-Path $artifactDir "v6_08_baseline_fast_jit_fastregs_combined_${HostTag}_${Timestamp}.csv"
            }
            light = [ordered]@{
                conservative = Join-Path $artifactDir "v6_08_baseline_light_jit_conservative_combined_${HostTag}_${Timestamp}.csv"
                fastregs = Join-Path $artifactDir "v6_08_baseline_light_jit_fastregs_combined_${HostTag}_${Timestamp}.csv"
            }
        }
        candidate = [ordered]@{
            fast = [ordered]@{
                conservative = Join-Path $artifactDir "v6_08_candidate_fast_jit_conservative_combined_${HostTag}_${Timestamp}.csv"
                fastregs = Join-Path $artifactDir "v6_08_candidate_fast_jit_fastregs_combined_${HostTag}_${Timestamp}.csv"
            }
            light = [ordered]@{
                conservative = Join-Path $artifactDir "v6_08_candidate_light_jit_conservative_combined_${HostTag}_${Timestamp}.csv"
                fastregs = Join-Path $artifactDir "v6_08_candidate_light_jit_fastregs_combined_${HostTag}_${Timestamp}.csv"
            }
        }
    }

    Write-CombinedCsv -InputPaths $baselineFast.conservative -OutputPath $combined.baseline.fast.conservative
    Write-CombinedCsv -InputPaths $baselineFast.fastregs -OutputPath $combined.baseline.fast.fastregs
    Write-CombinedCsv -InputPaths $baselineLight.conservative -OutputPath $combined.baseline.light.conservative
    Write-CombinedCsv -InputPaths $baselineLight.fastregs -OutputPath $combined.baseline.light.fastregs
    Write-CombinedCsv -InputPaths $candidateFast.conservative -OutputPath $combined.candidate.fast.conservative
    Write-CombinedCsv -InputPaths $candidateFast.fastregs -OutputPath $combined.candidate.fast.fastregs
    Write-CombinedCsv -InputPaths $candidateLight.conservative -OutputPath $combined.candidate.light.conservative
    Write-CombinedCsv -InputPaths $candidateLight.fastregs -OutputPath $combined.candidate.light.fastregs

    Invoke-LoggedCommand -WorkingDirectory $RootDir `
        -Command @("cargo", "build", "--release", "--bin", "perf_compare") `
        -StdoutPath (Join-Path $tmpOut "v6_08_perf_compare_build_${HostTag}_${Timestamp}.stdout") `
        -StderrPath (Join-Path $tmpOut "v6_08_perf_compare_build_${HostTag}_${Timestamp}.stderr") | Out-Null

    $perfCompareExe = Join-Path $RootDir "target/release/perf_compare.exe"
    if (-not (Test-Path -LiteralPath $perfCompareExe)) {
        throw "perf_compare.exe not found at $perfCompareExe"
    }

    $compareSpecs = @(
        @{
            Baseline = $combined.baseline.fast.conservative
            Candidate = $combined.baseline.fast.fastregs
            Output = Join-Path $artifactDir "v6_08_perf_compare_baseline_fast_fastregs_vs_conservative_${HostTag}_${Timestamp}.txt"
        },
        @{
            Baseline = $combined.candidate.fast.conservative
            Candidate = $combined.candidate.fast.fastregs
            Output = Join-Path $artifactDir "v6_08_perf_compare_candidate_fast_fastregs_vs_conservative_${HostTag}_${Timestamp}.txt"
        },
        @{
            Baseline = $combined.baseline.light.conservative
            Candidate = $combined.baseline.light.fastregs
            Output = Join-Path $artifactDir "v6_08_perf_compare_baseline_light_fastregs_vs_conservative_${HostTag}_${Timestamp}.txt"
        },
        @{
            Baseline = $combined.candidate.light.conservative
            Candidate = $combined.candidate.light.fastregs
            Output = Join-Path $artifactDir "v6_08_perf_compare_candidate_light_fastregs_vs_conservative_${HostTag}_${Timestamp}.txt"
        },
        @{
            Baseline = $combined.baseline.fast.conservative
            Candidate = $combined.candidate.fast.conservative
            Output = Join-Path $artifactDir "v6_08_perf_compare_fast_conservative_candidate_vs_baseline_${HostTag}_${Timestamp}.txt"
        },
        @{
            Baseline = $combined.baseline.fast.fastregs
            Candidate = $combined.candidate.fast.fastregs
            Output = Join-Path $artifactDir "v6_08_perf_compare_fast_fastregs_candidate_vs_baseline_${HostTag}_${Timestamp}.txt"
        },
        @{
            Baseline = $combined.baseline.light.conservative
            Candidate = $combined.candidate.light.conservative
            Output = Join-Path $artifactDir "v6_08_perf_compare_light_conservative_candidate_vs_baseline_${HostTag}_${Timestamp}.txt"
        },
        @{
            Baseline = $combined.baseline.light.fastregs
            Candidate = $combined.candidate.light.fastregs
            Output = Join-Path $artifactDir "v6_08_perf_compare_light_fastregs_candidate_vs_baseline_${HostTag}_${Timestamp}.txt"
        }
    )

    foreach ($spec in $compareSpecs) {
        Invoke-MergedCommand -WorkingDirectory $RootDir `
            -Command @(
                $perfCompareExe,
                "--baseline", (Get-RelativeRepoPath -BasePath $RootDir -TargetPath $spec.Baseline),
                "--candidate", (Get-RelativeRepoPath -BasePath $RootDir -TargetPath $spec.Candidate),
                "--threshold-pct", "2.0"
            ) `
            -OutputPath $spec.Output `
            -AllowedExitCodes @(0, 1) | Out-Null
    }

    $summary = [ordered]@{
        ts = $Timestamp
        host = $cpuInfo.Name
        baseline_sha = $BaseSha
        patch_source_sha = $PatchSourceSha
        candidate_sha = $candidateHead
        light_iters = $LightIters
        light_warmup = $LightWarmup
        fast_iters = $FastIters
        fast_warmup = $FastWarmup
        threads = $Threads
        states = [ordered]@{
            baseline = [ordered]@{
                fast = [ordered]@{
                    conservative = Get-CaptureSummary -Paths $baselineFast.conservative -RepoPathForSummary $RootDir
                    fastregs = Get-CaptureSummary -Paths $baselineFast.fastregs -RepoPathForSummary $RootDir
                }
                light = [ordered]@{
                    conservative = Get-CaptureSummary -Paths $baselineLight.conservative -RepoPathForSummary $RootDir
                    fastregs = Get-CaptureSummary -Paths $baselineLight.fastregs -RepoPathForSummary $RootDir
                }
            }
            candidate = [ordered]@{
                fast = [ordered]@{
                    conservative = Get-CaptureSummary -Paths $candidateFast.conservative -RepoPathForSummary $RootDir
                    fastregs = Get-CaptureSummary -Paths $candidateFast.fastregs -RepoPathForSummary $RootDir
                }
                light = [ordered]@{
                    conservative = Get-CaptureSummary -Paths $candidateLight.conservative -RepoPathForSummary $RootDir
                    fastregs = Get-CaptureSummary -Paths $candidateLight.fastregs -RepoPathForSummary $RootDir
                }
            }
        }
    }

    foreach ($state in @("baseline", "candidate")) {
        foreach ($mode in @("fast", "light")) {
            $conservativeMean = $summary.states.$state.$mode.conservative.ns_per_hash_mean
            $fastregsMean = $summary.states.$state.$mode.fastregs.ns_per_hash_mean
            $summary.states.$state.$mode.uplift_pct_vs_conservative = Get-PctDelta -Baseline $conservativeMean -Candidate $fastregsMean
        }
    }

    $summary.before_after = [ordered]@{
        fast = [ordered]@{
            conservative = [ordered]@{
                ns_per_hash_pct = Get-PctDelta -Baseline $summary.states.baseline.fast.conservative.ns_per_hash_mean -Candidate $summary.states.candidate.fast.conservative.ns_per_hash_mean
                execute_program_ns_jit_pct = Get-PctDelta -Baseline $summary.states.baseline.fast.conservative.execute_program_ns_jit_mean -Candidate $summary.states.candidate.fast.conservative.execute_program_ns_jit_mean
                finish_iteration_ns_pct = Get-PctDelta -Baseline $summary.states.baseline.fast.conservative.finish_iteration_ns_mean -Candidate $summary.states.candidate.fast.conservative.finish_iteration_ns_mean
            }
            fastregs = [ordered]@{
                ns_per_hash_pct = Get-PctDelta -Baseline $summary.states.baseline.fast.fastregs.ns_per_hash_mean -Candidate $summary.states.candidate.fast.fastregs.ns_per_hash_mean
                execute_program_ns_jit_pct = Get-PctDelta -Baseline $summary.states.baseline.fast.fastregs.execute_program_ns_jit_mean -Candidate $summary.states.candidate.fast.fastregs.execute_program_ns_jit_mean
                finish_iteration_ns_pct = Get-PctDelta -Baseline $summary.states.baseline.fast.fastregs.finish_iteration_ns_mean -Candidate $summary.states.candidate.fast.fastregs.finish_iteration_ns_mean
            }
        }
        light = [ordered]@{
            conservative = [ordered]@{
                ns_per_hash_pct = Get-PctDelta -Baseline $summary.states.baseline.light.conservative.ns_per_hash_mean -Candidate $summary.states.candidate.light.conservative.ns_per_hash_mean
                execute_program_ns_jit_pct = Get-PctDelta -Baseline $summary.states.baseline.light.conservative.execute_program_ns_jit_mean -Candidate $summary.states.candidate.light.conservative.execute_program_ns_jit_mean
                finish_iteration_ns_pct = Get-PctDelta -Baseline $summary.states.baseline.light.conservative.finish_iteration_ns_mean -Candidate $summary.states.candidate.light.conservative.finish_iteration_ns_mean
            }
            fastregs = [ordered]@{
                ns_per_hash_pct = Get-PctDelta -Baseline $summary.states.baseline.light.fastregs.ns_per_hash_mean -Candidate $summary.states.candidate.light.fastregs.ns_per_hash_mean
                execute_program_ns_jit_pct = Get-PctDelta -Baseline $summary.states.baseline.light.fastregs.execute_program_ns_jit_mean -Candidate $summary.states.candidate.light.fastregs.execute_program_ns_jit_mean
                finish_iteration_ns_pct = Get-PctDelta -Baseline $summary.states.baseline.light.fastregs.finish_iteration_ns_mean -Candidate $summary.states.candidate.light.fastregs.finish_iteration_ns_mean
            }
        }
    }

    $summary.delta_uplift_pp = [ordered]@{
        fast = $summary.states.candidate.fast.uplift_pct_vs_conservative - $summary.states.baseline.fast.uplift_pct_vs_conservative
        light = $summary.states.candidate.light.uplift_pct_vs_conservative - $summary.states.baseline.light.uplift_pct_vs_conservative
    }

    $summary | ConvertTo-Json -Depth 8 | Set-Content -LiteralPath $summaryFile -Encoding utf8NoBOM

    Write-Host "wrote artifacts to $artifactDir"
}
finally {
    if (-not $KeepWorktrees) {
        Remove-WorktreeIfExists -Path $baseWt
        Remove-WorktreeIfExists -Path $candWt
    }
}
