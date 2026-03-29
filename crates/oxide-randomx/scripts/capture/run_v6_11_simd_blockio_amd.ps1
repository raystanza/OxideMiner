<#
.SYNOPSIS
Runs the PROMPTv6_11 clean AMD simd-blockio family-evidence capture.

.DESCRIPTION
Creates a clean detached worktree at the requested HEAD, validates the required
test bundle, captures repeated bench subset runs plus perf_harness ABBA runs for
scalar baseline vs simd-blockio, then writes host-tagged v6_11 artifacts into
perf_results/AMD.
#>

[CmdletBinding()]
param(
    [string]$RootDir = (Resolve-Path (Join-Path $PSScriptRoot "../..")).Path,
    [string]$HeadSha = "",
    [string]$HostTag = "",
    [int]$Threads = 0,
    [int]$BenchIters = 30,
    [int]$BenchWarmup = 5,
    [int]$BenchRepeats = 3,
    [int]$PerfIters = 30,
    [int]$PerfWarmup = 5,
    [ValidateSet("on", "off")][string]$LargePages = "on",
    [int]$PauseMs = 500,
    [switch]$SkipTests,
    [switch]$KeepWorktree,
    [string]$Timestamp = ""
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"
if (Get-Variable -Name PSNativeCommandUseErrorActionPreference -ErrorAction SilentlyContinue) {
    $PSNativeCommandUseErrorActionPreference = $false
}

if ([string]::IsNullOrWhiteSpace($Timestamp)) {
    $Timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
}

$RootDir = (Resolve-Path $RootDir).Path
if ([string]::IsNullOrWhiteSpace($HeadSha)) {
    $HeadSha = (& git -C $RootDir rev-parse HEAD).Trim()
}

$cpuInfo = Get-CimInstance -ClassName Win32_Processor | Select-Object -First 1
$osInfo = Get-CimInstance -ClassName Win32_OperatingSystem
$vendor = [string]$cpuInfo.Manufacturer
$cpuDescription = [string]$cpuInfo.Description
$cpuModelString = [string]$cpuInfo.Name

if ($vendor -ne "AuthenticAMD") {
    throw "This runner is AMD-only, but the current host vendor is '$vendor'."
}
if ($cpuDescription -notmatch 'Family\s+(?<family>\d+)\s+Model\s+(?<model>\d+)(?:\s+Stepping\s+(?<stepping>\d+))?') {
    throw "Could not parse CPU family/model from Win32_Processor.Description: $cpuDescription"
}

$cpuFamily = [int]$matches.family
$cpuModel = [int]$matches.model
$cpuStepping = if ($matches.stepping) { [int]$matches.stepping } else { $null }

if ([string]::IsNullOrWhiteSpace($HostTag)) {
    $HostTag = "amd_fam${cpuFamily}_mod${cpuModel}"
}

if ($Threads -le 0) {
    $Threads = [int]$cpuInfo.NumberOfLogicalProcessors
}

$artifactDir = Join-Path $RootDir "perf_results/AMD"
$repoParent = Split-Path -Parent $RootDir
$worktree = Join-Path $repoParent "oxide-randomx-v6_11-$HostTag-$Timestamp"
$tmpOut = Join-Path ([System.IO.Path]::GetTempPath()) "oxide-randomx-v6_11-$HostTag-out-$Timestamp"

$manifestFile = Join-Path $tmpOut "v6_11_manifest_${HostTag}_${Timestamp}.txt"
$provenanceFile = Join-Path $tmpOut "v6_11_host_provenance_${HostTag}_${Timestamp}.txt"
$commandLogFile = Join-Path $tmpOut "v6_11_commands_${HostTag}_${Timestamp}.log"
$benchIndexFile = Join-Path $tmpOut "v6_11_bench_index_${HostTag}_${Timestamp}.csv"
$perfIndexFile = Join-Path $tmpOut "v6_11_perf_index_${HostTag}_${Timestamp}.csv"
$summaryFile = Join-Path $tmpOut "v6_11_simd_blockio_summary_${HostTag}_${Timestamp}.json"

if (-not (Test-Path -LiteralPath $artifactDir)) {
    New-Item -ItemType Directory -Path $artifactDir -Force | Out-Null
}
if (Test-Path -LiteralPath $tmpOut) {
    Remove-Item -LiteralPath $tmpOut -Recurse -Force
}
New-Item -ItemType Directory -Path $tmpOut -Force | Out-Null

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

function Get-FinalArtifactAbsolutePath {
    param([Parameter(Mandatory = $true)][string]$Path)
    return Join-Path $artifactDir (Split-Path -Leaf $Path)
}

function Get-FinalArtifactRelativePath {
    param([Parameter(Mandatory = $true)][string]$Path)
    return Get-RelativeRepoPath -BasePath $RootDir -TargetPath (Get-FinalArtifactAbsolutePath -Path $Path)
}

function Remove-WorktreeIfExists {
    param([Parameter(Mandatory = $true)][string]$Path)
    & git -C $RootDir worktree remove --force $Path *> $null
    Remove-Item -LiteralPath $Path -Recurse -Force -ErrorAction SilentlyContinue
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

function Invoke-CapturedCommand {
    param(
        [Parameter(Mandatory = $true)][string]$WorkingDirectory,
        [Parameter(Mandatory = $true)][string[]]$Command,
        [hashtable]$EnvOverrides = @{},
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
            $output = & $Command[0] @($Command | Select-Object -Skip 1) 2>&1
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

    if ($exitCode -ne 0) {
        $joined = ($output | ForEach-Object { $_.ToString() }) -join [Environment]::NewLine
        throw "Command failed with exit code ${exitCode}: $(Format-CommandForLog -Command $Command)`n$joined"
    }

    return @($output | ForEach-Object { $_.ToString() })
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
    Set-Content -LiteralPath $OutputPath -Value $header -Encoding utf8NoBOM
    foreach ($path in $InputPaths) {
        $currentHeader = Get-Content -LiteralPath $path -TotalCount 1
        if ($currentHeader -ne $header) {
            throw "Header mismatch while combining CSVs: $path"
        }
        $rows = @(Get-Content -LiteralPath $path | Select-Object -Skip 1)
        if ($rows.Count -gt 0) {
            Add-Content -LiteralPath $OutputPath -Value $rows -Encoding utf8NoBOM
        }
    }
}

function Convert-KeyValueLine {
    param([Parameter(Mandatory = $true)][string]$Line)

    $map = @{}
    $rx = [regex]'(?<key>[A-Za-z0-9_\/]+)=(?:"(?<qval>[^"]*)"|(?<val>[^\s]+))'
    foreach ($m in $rx.Matches($Line)) {
        $key = $m.Groups["key"].Value
        $value = if ($m.Groups["qval"].Success) { $m.Groups["qval"].Value } else { $m.Groups["val"].Value }
        if ($key) {
            $map[$key] = $value
        }
    }
    return $map
}

function Get-Mean {
    param([double[]]$Values)
    if (-not $Values -or $Values.Count -eq 0) {
        return $null
    }
    return ($Values | Measure-Object -Average).Average
}

function Get-Median {
    param([double[]]$Values)
    if (-not $Values -or $Values.Count -eq 0) {
        return $null
    }
    $sorted = $Values | Sort-Object
    $count = $sorted.Count
    if ($count % 2 -eq 1) {
        return [double]$sorted[($count - 1) / 2]
    }
    return ([double]$sorted[($count / 2) - 1] + [double]$sorted[$count / 2]) / 2.0
}

function Get-StdDev {
    param([double[]]$Values)
    if (-not $Values -or $Values.Count -lt 2) {
        return 0.0
    }
    $mean = Get-Mean -Values $Values
    $sumSqDiff = 0.0
    foreach ($value in $Values) {
        $sumSqDiff += ($value - $mean) * ($value - $mean)
    }
    return [Math]::Sqrt($sumSqDiff / ($Values.Count - 1))
}

function Get-PctDelta {
    param($Baseline, $Candidate)
    if ($null -eq $Baseline -or $null -eq $Candidate) {
        return $null
    }
    if ([double]$Baseline -le 0.0) {
        return $null
    }
    return (([double]$Candidate - [double]$Baseline) / [double]$Baseline) * 100.0
}

function Get-RowDouble {
    param(
        [Parameter(Mandatory = $true)]$Row,
        [Parameter(Mandatory = $true)][string]$Field
    )
    $value = 0.0
    if ([double]::TryParse([string]$Row.$Field, [ref]$value)) {
        return $value
    }
    return $null
}

function Get-RowBool {
    param(
        [Parameter(Mandatory = $true)]$Row,
        [Parameter(Mandatory = $true)][string]$Field
    )

    $raw = [string]$Row.$Field
    if ([string]::IsNullOrWhiteSpace($raw) -or $raw -eq "n/a") {
        return $null
    }

    $value = $false
    if ([bool]::TryParse($raw, [ref]$value)) {
        return $value
    }
    return $null
}

function Get-MetricMean {
    param(
        [Parameter(Mandatory = $true)]$Rows,
        [Parameter(Mandatory = $true)][string]$Field
    )

    $values = New-Object System.Collections.Generic.List[double]
    foreach ($row in $Rows) {
        $value = Get-RowDouble -Row $row -Field $Field
        if ($null -eq $value) {
            return $null
        }
        $values.Add($value) | Out-Null
    }
    return Get-Mean -Values $values.ToArray()
}

function Assert-CaptureRow {
    param(
        [Parameter(Mandatory = $true)][string]$CsvPath,
        [Parameter(Mandatory = $true)][string]$ExpectedSha,
        [Parameter(Mandatory = $true)][string]$ExpectedShortSha
    )

    $rows = @(Import-Csv -LiteralPath $CsvPath)
    if ($rows.Count -ne 1) {
        throw "Expected exactly one row in $CsvPath"
    }
    $row = $rows[0]
    if ([string]$row.git_sha -ne $ExpectedSha) {
        throw "git_sha mismatch in ${CsvPath}: expected $ExpectedSha got $($row.git_sha)"
    }
    if ([string]$row.git_sha_short -ne $ExpectedShortSha) {
        throw "git_sha_short mismatch in ${CsvPath}: expected $ExpectedShortSha got $($row.git_sha_short)"
    }
    if ([string]$row.git_dirty -ne "false") {
        throw "git_dirty mismatch in ${CsvPath}: expected false got $($row.git_dirty)"
    }
}

function Build-ExampleSet {
    param(
        [Parameter(Mandatory = $true)][string]$Label,
        [Parameter(Mandatory = $true)][string]$Features
    )

    $stdoutPath = Join-Path $tmpOut "v6_11_build_${Label}_${HostTag}_${Timestamp}.stdout"
    $stderrPath = Join-Path $tmpOut "v6_11_build_${Label}_${HostTag}_${Timestamp}.stderr"
    Invoke-LoggedCommand -WorkingDirectory $worktree `
        -Command @("cargo", "build", "--release", "--example", "bench", "--example", "perf_harness", "--features", $Features) `
        -StdoutPath $stdoutPath `
        -StderrPath $stderrPath | Out-Null

    $benchExe = Join-Path $tmpOut "bench_${Label}_${HostTag}_${Timestamp}.exe"
    $perfExe = Join-Path $tmpOut "perf_harness_${Label}_${HostTag}_${Timestamp}.exe"

    Copy-Item -LiteralPath (Join-Path $worktree "target\release\examples\bench.exe") -Destination $benchExe -Force
    Copy-Item -LiteralPath (Join-Path $worktree "target\release\examples\perf_harness.exe") -Destination $perfExe -Force

    return [ordered]@{
        bench = $benchExe
        perf = $perfExe
    }
}

function Build-PerfCompare {
    $stdoutPath = Join-Path $tmpOut "v6_11_build_perf_compare_${HostTag}_${Timestamp}.stdout"
    $stderrPath = Join-Path $tmpOut "v6_11_build_perf_compare_${HostTag}_${Timestamp}.stderr"
    Invoke-LoggedCommand -WorkingDirectory $worktree `
        -Command @("cargo", "build", "--release", "--bin", "perf_compare") `
        -StdoutPath $stdoutPath `
        -StderrPath $stderrPath | Out-Null

    $perfCompareExe = Join-Path $tmpOut "perf_compare_${HostTag}_${Timestamp}.exe"
    Copy-Item -LiteralPath (Join-Path $worktree "target\release\perf_compare.exe") -Destination $perfCompareExe -Force
    return $perfCompareExe
}

function Run-TestBundle {
    $prefix = Join-Path $tmpOut "v6_11_tests_${HostTag}_${Timestamp}"

    Invoke-LoggedCommand -WorkingDirectory $worktree `
        -Command @("cargo", "test", "--test", "oracle") `
        -StdoutPath "${prefix}_oracle.stdout" `
        -StderrPath "${prefix}_oracle.stderr" | Out-Null

    Invoke-LoggedCommand -WorkingDirectory $worktree `
        -Command @("cargo", "test", "--features", "jit jit-fastregs", "--test", "oracle") `
        -StdoutPath "${prefix}_oracle_jit_fastregs.stdout" `
        -StderrPath "${prefix}_oracle_jit_fastregs.stderr" | Out-Null

    Invoke-LoggedCommand -WorkingDirectory $worktree `
        -Command @("cargo", "test", "--features", "simd-blockio", "--test", "oracle") `
        -StdoutPath "${prefix}_oracle_simd_blockio.stdout" `
        -StderrPath "${prefix}_oracle_simd_blockio.stderr" | Out-Null

    Invoke-LoggedCommand -WorkingDirectory $worktree `
        -Command @("cargo", "test", "--features", "simd-blockio", "simd_prepare_finish_matches_scalar") `
        -StdoutPath "${prefix}_simd_prepare_finish.stdout" `
        -StderrPath "${prefix}_simd_prepare_finish.stderr" | Out-Null

    Invoke-LoggedCommand -WorkingDirectory $worktree `
        -Command @("cargo", "test", "--features", "simd-blockio", "simd_blockio_blocked_cpu_classifier_targets_xeon_model_45") `
        -StdoutPath "${prefix}_simd_classifier.stdout" `
        -StderrPath "${prefix}_simd_classifier.stderr" | Out-Null
}

function Invoke-BenchRun {
    param(
        [Parameter(Mandatory = $true)][string]$Mode,
        [Parameter(Mandatory = $true)][string]$ConfigLabel,
        [Parameter(Mandatory = $true)][string]$BenchExe,
        [Parameter(Mandatory = $true)][int]$RepeatIndex,
        [Parameter(Mandatory = $true)][int]$RunOrder
    )

    $envOverrides = @{
        OXIDE_RANDOMX_HUGE_1G = "0"
        OXIDE_RANDOMX_FAST_BENCH = $(if ($Mode -eq "fast") { "1" } else { $null })
        OXIDE_RANDOMX_LARGE_PAGES = $(if ($LargePages -eq "on") { "1" } else { $null })
        OXIDE_RANDOMX_SIMD_BLOCKIO_FORCE = $null
        OXIDE_RANDOMX_PREFETCH_DISTANCE = $null
        OXIDE_RANDOMX_PREFETCH_AUTO = $null
        OXIDE_RANDOMX_PREFETCH_SCRATCHPAD_DISTANCE = $null
        OXIDE_RANDOMX_THREADED_INTERP = $null
        OXIDE_RANDOMX_THREADS = $null
        OXIDE_RANDOMX_THREAD_NAMES = $null
        OXIDE_RANDOMX_AFFINITY = $null
    }

    $output = Invoke-CapturedCommand -WorkingDirectory $tmpOut `
        -Command @(
            $BenchExe,
            "--mode", $Mode,
            "--jit", "off",
            "--jit-fast-regs", "off",
            "--iters", [string]$BenchIters,
            "--warmup", [string]$BenchWarmup,
            "--threads", [string]$Threads,
            "--report",
            "--format", "human"
        ) `
        -EnvOverrides $envOverrides `
        -LogEnvNames @(
            "OXIDE_RANDOMX_HUGE_1G",
            "OXIDE_RANDOMX_FAST_BENCH",
            "OXIDE_RANDOMX_LARGE_PAGES",
            "OXIDE_RANDOMX_SIMD_BLOCKIO_FORCE",
            "OXIDE_RANDOMX_PREFETCH_DISTANCE",
            "OXIDE_RANDOMX_PREFETCH_AUTO",
            "OXIDE_RANDOMX_PREFETCH_SCRATCHPAD_DISTANCE",
            "OXIDE_RANDOMX_THREADED_INTERP",
            "OXIDE_RANDOMX_THREADS",
            "OXIDE_RANDOMX_THREAD_NAMES",
            "OXIDE_RANDOMX_AFFINITY"
        )

    $modeLine = $output | Where-Object { $_ -match '^mode=' } | Select-Object -First 1
    $provenanceLine = $output | Where-Object { $_ -match '^provenance ' } | Select-Object -First 1
    $largePagesLine = $output | Where-Object { $_ -match '^large_pages_requested=' } | Select-Object -First 1

    if ([string]::IsNullOrWhiteSpace($modeLine) -or [string]::IsNullOrWhiteSpace($provenanceLine) -or [string]::IsNullOrWhiteSpace($largePagesLine)) {
        $joined = $output -join [Environment]::NewLine
        throw "Failed to parse bench output for $ConfigLabel`n$joined"
    }

    $provenanceMap = Convert-KeyValueLine -Line $provenanceLine
    $largePagesMap = Convert-KeyValueLine -Line $largePagesLine
    $nsMatch = [regex]::Match($modeLine, 'ns/hash=(?<ns>\d+)')
    if (-not $nsMatch.Success) {
        throw "Failed to parse ns/hash from bench output line: $modeLine"
    }

    $row = [pscustomobject]@{
        config_label = $ConfigLabel
        mode = $Mode
        repeat_index = $RepeatIndex
        run_order = $RunOrder
        ns_per_hash = [int64]$nsMatch.Groups["ns"].Value
        features = [string]$provenanceMap["features"]
        cpu = [string]$provenanceMap["cpu"]
        git_sha = [string]$provenanceMap["git_sha"]
        git_sha_short = [string]$provenanceMap["git_sha_short"]
        git_dirty = [string]$provenanceMap["git_dirty"]
        large_pages_requested = [string]$largePagesMap["large_pages_requested"]
        large_pages_1gb_requested = [string]$largePagesMap["large_pages_1gb_requested"]
        large_pages_dataset = [string]$largePagesMap["large_pages_dataset"]
        large_pages_1gb_dataset = [string]$largePagesMap["large_pages_1gb_dataset"]
        large_pages_scratchpad = [string]$largePagesMap["large_pages_scratchpad"]
        large_pages_1gb_scratchpad = [string]$largePagesMap["large_pages_1gb_scratchpad"]
    }

    return [pscustomobject]@{
        Row = $row
        OutputText = ($output -join [Environment]::NewLine)
    }
}

function Run-BenchPair {
    param(
        [Parameter(Mandatory = $true)][string]$Mode,
        [Parameter(Mandatory = $true)][string]$BaselineBenchExe,
        [Parameter(Mandatory = $true)][string]$SimdBenchExe
    )

    $pairLabel = "baseline_vs_simd"
    $rows = New-Object System.Collections.Generic.List[object]
    $rawLogPath = Join-Path $tmpOut "v6_11_bench_${Mode}_${pairLabel}_${HostTag}_${Timestamp}.raw.log"
    $csvPath = Join-Path $tmpOut "v6_11_bench_${Mode}_${pairLabel}_${HostTag}_${Timestamp}.csv"

    Set-Content -LiteralPath $rawLogPath -Value "" -Encoding utf8NoBOM

    for ($repeat = 1; $repeat -le $BenchRepeats; $repeat++) {
        if ($repeat % 2 -eq 1) {
            $first = Invoke-BenchRun -Mode $Mode -ConfigLabel "baseline_scalar" -BenchExe $BaselineBenchExe -RepeatIndex $repeat -RunOrder 1
            $rows.Add($first.Row) | Out-Null
            Add-Content -LiteralPath $rawLogPath -Value "---- mode=$Mode config=baseline_scalar repeat=$repeat order=1 ----`n$($first.OutputText)`n" -Encoding utf8NoBOM

            Start-Sleep -Milliseconds $PauseMs

            $second = Invoke-BenchRun -Mode $Mode -ConfigLabel "simd_enabled" -BenchExe $SimdBenchExe -RepeatIndex $repeat -RunOrder 2
            $rows.Add($second.Row) | Out-Null
            Add-Content -LiteralPath $rawLogPath -Value "---- mode=$Mode config=simd_enabled repeat=$repeat order=2 ----`n$($second.OutputText)`n" -Encoding utf8NoBOM
        } else {
            $first = Invoke-BenchRun -Mode $Mode -ConfigLabel "simd_enabled" -BenchExe $SimdBenchExe -RepeatIndex $repeat -RunOrder 1
            $rows.Add($first.Row) | Out-Null
            Add-Content -LiteralPath $rawLogPath -Value "---- mode=$Mode config=simd_enabled repeat=$repeat order=1 ----`n$($first.OutputText)`n" -Encoding utf8NoBOM

            Start-Sleep -Milliseconds $PauseMs

            $second = Invoke-BenchRun -Mode $Mode -ConfigLabel "baseline_scalar" -BenchExe $BaselineBenchExe -RepeatIndex $repeat -RunOrder 2
            $rows.Add($second.Row) | Out-Null
            Add-Content -LiteralPath $rawLogPath -Value "---- mode=$Mode config=baseline_scalar repeat=$repeat order=2 ----`n$($second.OutputText)`n" -Encoding utf8NoBOM
        }

        if ($repeat -lt $BenchRepeats) {
            Start-Sleep -Milliseconds $PauseMs
        }
    }

    $rows | Export-Csv -LiteralPath $csvPath -NoTypeInformation -Encoding utf8NoBOM
    return [ordered]@{
        mode = $Mode
        pair_label = $pairLabel
        csv = $csvPath
        raw_log = $rawLogPath
    }
}

function Run-PerfOnce {
    param(
        [Parameter(Mandatory = $true)][string]$Mode,
        [Parameter(Mandatory = $true)][string]$ConfigLabel,
        [Parameter(Mandatory = $true)][string]$PerfExe,
        [Parameter(Mandatory = $true)][string]$Sequence,
        [Parameter(Mandatory = $true)][string]$ExpectedSha,
        [Parameter(Mandatory = $true)][string]$ExpectedShortSha
    )

    $csvPath = Join-Path $tmpOut "v6_11_perf_${Mode}_baseline_vs_simd_${ConfigLabel}_${Sequence}_${HostTag}_${Timestamp}.csv"
    $stdoutPath = [System.IO.Path]::ChangeExtension($csvPath, ".stdout")
    $stderrPath = [System.IO.Path]::ChangeExtension($csvPath, ".stderr")

    $envOverrides = @{
        OXIDE_RANDOMX_HUGE_1G = "0"
        OXIDE_RANDOMX_FAST_BENCH = $(if ($Mode -eq "fast") { "1" } else { $null })
        OXIDE_RANDOMX_FAST_BENCH_SMALL = $null
        OXIDE_RANDOMX_LARGE_PAGES = $null
        OXIDE_RANDOMX_SIMD_BLOCKIO_FORCE = $null
        OXIDE_RANDOMX_PREFETCH_DISTANCE = $null
        OXIDE_RANDOMX_PREFETCH_AUTO = $null
        OXIDE_RANDOMX_PREFETCH_SCRATCHPAD_DISTANCE = $null
        OXIDE_RANDOMX_THREADED_INTERP = $null
        OXIDE_RANDOMX_THREADS = $null
        OXIDE_RANDOMX_THREAD_NAMES = $null
        OXIDE_RANDOMX_AFFINITY = $null
    }

    Invoke-LoggedCommand -WorkingDirectory $tmpOut `
        -Command @(
            $PerfExe,
            "--mode", $Mode,
            "--jit", "off",
            "--jit-fast-regs", "off",
            "--iters", [string]$PerfIters,
            "--warmup", [string]$PerfWarmup,
            "--threads", [string]$Threads,
            "--large-pages", $LargePages,
            "--thread-names", "off",
            "--affinity", "off",
            "--format", "csv",
            "--out", $csvPath
        ) `
        -StdoutPath $stdoutPath `
        -StderrPath $stderrPath `
        -EnvOverrides $envOverrides `
        -LogEnvNames @(
            "OXIDE_RANDOMX_HUGE_1G",
            "OXIDE_RANDOMX_FAST_BENCH",
            "OXIDE_RANDOMX_FAST_BENCH_SMALL",
            "OXIDE_RANDOMX_LARGE_PAGES",
            "OXIDE_RANDOMX_SIMD_BLOCKIO_FORCE",
            "OXIDE_RANDOMX_PREFETCH_DISTANCE",
            "OXIDE_RANDOMX_PREFETCH_AUTO",
            "OXIDE_RANDOMX_PREFETCH_SCRATCHPAD_DISTANCE",
            "OXIDE_RANDOMX_THREADED_INTERP",
            "OXIDE_RANDOMX_THREADS",
            "OXIDE_RANDOMX_THREAD_NAMES",
            "OXIDE_RANDOMX_AFFINITY"
        ) | Out-Null

    Assert-CaptureRow -CsvPath $csvPath -ExpectedSha $ExpectedSha -ExpectedShortSha $ExpectedShortSha

    return [ordered]@{
        config_label = $ConfigLabel
        seq = $Sequence
        csv = $csvPath
        stdout = $stdoutPath
        stderr = $stderrPath
    }
}

function Run-PerfCompare {
    param(
        [Parameter(Mandatory = $true)][string]$PerfCompareExe,
        [Parameter(Mandatory = $true)][string]$Mode,
        [Parameter(Mandatory = $true)][string]$BaselineCsv,
        [Parameter(Mandatory = $true)][string]$CandidateCsv
    )

    $stdoutPath = Join-Path $tmpOut "v6_11_perf_compare_${Mode}_baseline_vs_simd_${HostTag}_${Timestamp}.txt"
    $stderrPath = Join-Path $tmpOut "v6_11_perf_compare_${Mode}_baseline_vs_simd_${HostTag}_${Timestamp}.stderr"

    $exitCode = Invoke-LoggedCommand -WorkingDirectory $tmpOut `
        -Command @(
            $PerfCompareExe,
            "--baseline", $BaselineCsv,
            "--candidate", $CandidateCsv,
            "--threshold-pct", "1.0"
        ) `
        -StdoutPath $stdoutPath `
        -StderrPath $stderrPath `
        -AllowedExitCodes @(0, 1)

    Add-Content -LiteralPath $stdoutPath -Value "exit_code=$exitCode" -Encoding utf8NoBOM

    return [ordered]@{
        stdout = $stdoutPath
        stderr = $stderrPath
        exit_code = $exitCode
    }
}

function Run-PerfPair {
    param(
        [Parameter(Mandatory = $true)][string]$Mode,
        [Parameter(Mandatory = $true)][string]$BaselinePerfExe,
        [Parameter(Mandatory = $true)][string]$SimdPerfExe,
        [Parameter(Mandatory = $true)][string]$PerfCompareExe,
        [Parameter(Mandatory = $true)][string]$ExpectedSha,
        [Parameter(Mandatory = $true)][string]$ExpectedShortSha
    )

    $a1 = Run-PerfOnce -Mode $Mode -ConfigLabel "baseline_scalar" -PerfExe $BaselinePerfExe -Sequence "a1" -ExpectedSha $ExpectedSha -ExpectedShortSha $ExpectedShortSha
    $b1 = Run-PerfOnce -Mode $Mode -ConfigLabel "simd_enabled" -PerfExe $SimdPerfExe -Sequence "b1" -ExpectedSha $ExpectedSha -ExpectedShortSha $ExpectedShortSha
    $b2 = Run-PerfOnce -Mode $Mode -ConfigLabel "simd_enabled" -PerfExe $SimdPerfExe -Sequence "b2" -ExpectedSha $ExpectedSha -ExpectedShortSha $ExpectedShortSha
    $a2 = Run-PerfOnce -Mode $Mode -ConfigLabel "baseline_scalar" -PerfExe $BaselinePerfExe -Sequence "a2" -ExpectedSha $ExpectedSha -ExpectedShortSha $ExpectedShortSha

    $baselineCombined = Join-Path $tmpOut "v6_11_perf_${Mode}_baseline_vs_simd_baseline_scalar_combined_${HostTag}_${Timestamp}.csv"
    $simdCombined = Join-Path $tmpOut "v6_11_perf_${Mode}_baseline_vs_simd_simd_enabled_combined_${HostTag}_${Timestamp}.csv"
    $pairMatrix = Join-Path $tmpOut "v6_11_perf_${Mode}_baseline_vs_simd_pair_matrix_${HostTag}_${Timestamp}.csv"

    Write-CombinedCsv -InputPaths @($a1.csv, $a2.csv) -OutputPath $baselineCombined
    Write-CombinedCsv -InputPaths @($b1.csv, $b2.csv) -OutputPath $simdCombined
    Write-CombinedCsv -InputPaths @($a1.csv, $b1.csv, $b2.csv, $a2.csv) -OutputPath $pairMatrix

    $compare = Run-PerfCompare -PerfCompareExe $PerfCompareExe -Mode $Mode -BaselineCsv $baselineCombined -CandidateCsv $simdCombined

    return [ordered]@{
        mode = $Mode
        pair_label = "baseline_vs_simd"
        baseline_rows = @($a1, $a2)
        simd_rows = @($b1, $b2)
        baseline_combined = $baselineCombined
        simd_combined = $simdCombined
        pair_matrix = $pairMatrix
        compare = $compare
    }
}

function Get-BenchSummary {
    param([Parameter(Mandatory = $true)][string]$CsvPath)

    $rows = @(Import-Csv -LiteralPath $CsvPath)
    $baselineRows = @($rows | Where-Object { $_.config_label -eq "baseline_scalar" })
    $simdRows = @($rows | Where-Object { $_.config_label -eq "simd_enabled" })

    $baselineValues = @($baselineRows | ForEach-Object { [double]$_.ns_per_hash })
    $simdValues = @($simdRows | ForEach-Object { [double]$_.ns_per_hash })

    $pairDeltas = New-Object System.Collections.Generic.List[double]
    foreach ($repeatGroup in ($rows | Group-Object repeat_index)) {
        $baselineRow = $repeatGroup.Group | Where-Object { $_.config_label -eq "baseline_scalar" } | Select-Object -First 1
        $simdRow = $repeatGroup.Group | Where-Object { $_.config_label -eq "simd_enabled" } | Select-Object -First 1
        if ($null -ne $baselineRow -and $null -ne $simdRow) {
            $pairDeltas.Add((Get-PctDelta -Baseline ([double]$baselineRow.ns_per_hash) -Candidate ([double]$simdRow.ns_per_hash))) | Out-Null
        }
    }

    $baselineMean = Get-Mean -Values $baselineValues
    $simdMean = Get-Mean -Values $simdValues
    $baselineStdDev = Get-StdDev -Values $baselineValues
    $simdStdDev = Get-StdDev -Values $simdValues

    $firstBaseline = $baselineRows | Select-Object -First 1
    $firstSimd = $simdRows | Select-Object -First 1

    return [ordered]@{
        baseline = [ordered]@{
            runs = $baselineValues
            mean_ns_per_hash = $baselineMean
            median_ns_per_hash = Get-Median -Values $baselineValues
            stddev_ns_per_hash = $baselineStdDev
            cv_pct = if ($baselineMean) { ($baselineStdDev / $baselineMean) * 100.0 } else { $null }
        }
        simd = [ordered]@{
            runs = $simdValues
            mean_ns_per_hash = $simdMean
            median_ns_per_hash = Get-Median -Values $simdValues
            stddev_ns_per_hash = $simdStdDev
            cv_pct = if ($simdMean) { ($simdStdDev / $simdMean) * 100.0 } else { $null }
        }
        delta_pct_simd_vs_baseline_mean = Get-PctDelta -Baseline $baselineMean -Candidate $simdMean
        delta_pct_simd_vs_baseline_median = Get-PctDelta -Baseline (Get-Median -Values $baselineValues) -Candidate (Get-Median -Values $simdValues)
        pair_deltas_pct = $pairDeltas.ToArray()
        large_pages_truth = [ordered]@{
            baseline = [ordered]@{
                requested = [string]$firstBaseline.large_pages_requested
                dataset = [string]$firstBaseline.large_pages_dataset
                scratchpad = [string]$firstBaseline.large_pages_scratchpad
            }
            simd = [ordered]@{
                requested = [string]$firstSimd.large_pages_requested
                dataset = [string]$firstSimd.large_pages_dataset
                scratchpad = [string]$firstSimd.large_pages_scratchpad
            }
        }
    }
}

function Get-PerfSummary {
    param([Parameter(Mandatory = $true)]$PerfCapture)

    $baselineRows = foreach ($item in $PerfCapture.baseline_rows) { Import-Csv -LiteralPath $item.csv }
    $simdRows = foreach ($item in $PerfCapture.simd_rows) { Import-Csv -LiteralPath $item.csv }

    $baselineA1 = (Import-Csv -LiteralPath $PerfCapture.baseline_rows[0].csv)[0]
    $baselineA2 = (Import-Csv -LiteralPath $PerfCapture.baseline_rows[1].csv)[0]
    $simdB1 = (Import-Csv -LiteralPath $PerfCapture.simd_rows[0].csv)[0]
    $simdB2 = (Import-Csv -LiteralPath $PerfCapture.simd_rows[1].csv)[0]

    $baselineNsMean = Get-MetricMean -Rows $baselineRows -Field "ns_per_hash"
    $simdNsMean = Get-MetricMean -Rows $simdRows -Field "ns_per_hash"
    $baselinePrepareMean = Get-MetricMean -Rows $baselineRows -Field "prepare_iteration_ns"
    $simdPrepareMean = Get-MetricMean -Rows $simdRows -Field "prepare_iteration_ns"
    $baselineExecuteMean = Get-MetricMean -Rows $baselineRows -Field "execute_program_ns_interpreter"
    $simdExecuteMean = Get-MetricMean -Rows $simdRows -Field "execute_program_ns_interpreter"
    $baselineFinishMean = Get-MetricMean -Rows $baselineRows -Field "finish_iteration_ns"
    $simdFinishMean = Get-MetricMean -Rows $simdRows -Field "finish_iteration_ns"

    $counterKeys = @(
        "program_execs",
        "scratchpad_read_bytes",
        "scratchpad_write_bytes",
        "dataset_item_loads",
        "mem_read_l1",
        "mem_read_l2",
        "mem_read_l3",
        "mem_write_l1",
        "mem_write_l2",
        "mem_write_l3",
        "instr_int",
        "instr_float",
        "instr_mem",
        "instr_ctrl",
        "instr_store"
    )

    $counterSpans = [ordered]@{}
    foreach ($key in $counterKeys) {
        $values = New-Object System.Collections.Generic.List[double]
        foreach ($row in @($baselineA1, $simdB1, $simdB2, $baselineA2)) {
            $value = Get-RowDouble -Row $row -Field $key
            if ($null -ne $value) {
                $values.Add($value) | Out-Null
            }
        }
        if ($values.Count -gt 0) {
            $range = $values | Measure-Object -Maximum -Minimum
            $counterSpans[$key] = $range.Maximum - $range.Minimum
        }
    }

    $allSpansZero = $true
    foreach ($value in $counterSpans.Values) {
        if ([double]$value -ne 0.0) {
            $allSpansZero = $false
            break
        }
    }

    return [ordered]@{
        baseline = [ordered]@{
            paths = @($PerfCapture.baseline_rows | ForEach-Object { Get-FinalArtifactRelativePath -Path $_.csv })
            mean_ns_per_hash = $baselineNsMean
            mean_prepare_iteration_ns = $baselinePrepareMean
            mean_execute_program_ns_interpreter = $baselineExecuteMean
            mean_finish_iteration_ns = $baselineFinishMean
        }
        simd = [ordered]@{
            paths = @($PerfCapture.simd_rows | ForEach-Object { Get-FinalArtifactRelativePath -Path $_.csv })
            mean_ns_per_hash = $simdNsMean
            mean_prepare_iteration_ns = $simdPrepareMean
            mean_execute_program_ns_interpreter = $simdExecuteMean
            mean_finish_iteration_ns = $simdFinishMean
        }
        delta_pct_simd_vs_baseline = [ordered]@{
            ns_per_hash = Get-PctDelta -Baseline $baselineNsMean -Candidate $simdNsMean
            prepare_iteration_ns = Get-PctDelta -Baseline $baselinePrepareMean -Candidate $simdPrepareMean
            execute_program_ns_interpreter = Get-PctDelta -Baseline $baselineExecuteMean -Candidate $simdExecuteMean
            finish_iteration_ns = Get-PctDelta -Baseline $baselineFinishMean -Candidate $simdFinishMean
        }
        pair_deltas_pct = @(
            (Get-PctDelta -Baseline (Get-RowDouble -Row $baselineA1 -Field "ns_per_hash") -Candidate (Get-RowDouble -Row $simdB1 -Field "ns_per_hash")),
            (Get-PctDelta -Baseline (Get-RowDouble -Row $baselineA2 -Field "ns_per_hash") -Candidate (Get-RowDouble -Row $simdB2 -Field "ns_per_hash"))
        )
        drift_pct = [ordered]@{
            baseline_a2_vs_a1 = Get-PctDelta -Baseline (Get-RowDouble -Row $baselineA1 -Field "ns_per_hash") -Candidate (Get-RowDouble -Row $baselineA2 -Field "ns_per_hash")
            simd_b2_vs_b1 = Get-PctDelta -Baseline (Get-RowDouble -Row $simdB1 -Field "ns_per_hash") -Candidate (Get-RowDouble -Row $simdB2 -Field "ns_per_hash")
        }
        counters = [ordered]@{
            spans = $counterSpans
            all_spans_zero = $allSpansZero
        }
        large_pages_truth = [ordered]@{
            baseline = [ordered]@{
                requested = Get-RowBool -Row $baselineA1 -Field "large_pages_requested"
                dataset = Get-RowBool -Row $baselineA1 -Field "large_pages_dataset"
                scratchpad = Get-RowBool -Row $baselineA1 -Field "large_pages_scratchpad"
            }
            simd = [ordered]@{
                requested = Get-RowBool -Row $simdB1 -Field "large_pages_requested"
                dataset = Get-RowBool -Row $simdB1 -Field "large_pages_dataset"
                scratchpad = Get-RowBool -Row $simdB1 -Field "large_pages_scratchpad"
            }
        }
        artifacts = [ordered]@{
            baseline_combined = Get-FinalArtifactRelativePath -Path $PerfCapture.baseline_combined
            simd_combined = Get-FinalArtifactRelativePath -Path $PerfCapture.simd_combined
            pair_matrix = Get-FinalArtifactRelativePath -Path $PerfCapture.pair_matrix
            perf_compare = Get-FinalArtifactRelativePath -Path $PerfCapture.compare.stdout
        }
    }
}

function Write-SummaryJson {
    param(
        [Parameter(Mandatory = $true)]$BenchLightMeta,
        [Parameter(Mandatory = $true)]$BenchFastMeta,
        [Parameter(Mandatory = $true)]$PerfLightCapture,
        [Parameter(Mandatory = $true)]$PerfFastCapture,
        [Parameter(Mandatory = $true)][string]$ExpectedShortSha
    )

    $summary = [ordered]@{
        prompt = "PROMPTv6_11"
        timestamp = $Timestamp
        head_sha = $HeadSha
        head_sha_short = $ExpectedShortSha
        host = [ordered]@{
            vendor = $vendor
            family = $cpuFamily
            model = $cpuModel
            stepping = $cpuStepping
            cpu_model_string = $cpuModelString
            description = $cpuDescription
            host_tag = $HostTag
            duplicate_family_relative_to_prior_amd_capture = ($cpuFamily -eq 23 -and $cpuModel -eq 8)
            new_amd_family_evidence = -not ($cpuFamily -eq 23 -and $cpuModel -eq 8)
        }
        methodology = [ordered]@{
            threads = $Threads
            bench = [ordered]@{
                iters = $BenchIters
                warmup = $BenchWarmup
                repeats = $BenchRepeats
                pair_label = "baseline_vs_simd"
                alternating_order = $true
                large_pages = $LargePages
            }
            perf = [ordered]@{
                iters = $PerfIters
                warmup = $PerfWarmup
                pair_label = "baseline_vs_simd"
                abba = @("baseline_scalar_a1", "simd_enabled_b1", "simd_enabled_b2", "baseline_scalar_a2")
                large_pages = $LargePages
            }
        }
        bench = [ordered]@{
            light = Get-BenchSummary -CsvPath $BenchLightMeta.csv
            fast = Get-BenchSummary -CsvPath $BenchFastMeta.csv
        }
        perf = [ordered]@{
            light = Get-PerfSummary -PerfCapture $PerfLightCapture
            fast = Get-PerfSummary -PerfCapture $PerfFastCapture
        }
        artifacts = [ordered]@{
            manifest = Get-FinalArtifactRelativePath -Path $manifestFile
            provenance = Get-FinalArtifactRelativePath -Path $provenanceFile
            command_log = Get-FinalArtifactRelativePath -Path $commandLogFile
            bench_index = Get-FinalArtifactRelativePath -Path $benchIndexFile
            perf_index = Get-FinalArtifactRelativePath -Path $perfIndexFile
            bench_light = Get-FinalArtifactRelativePath -Path $BenchLightMeta.csv
            bench_fast = Get-FinalArtifactRelativePath -Path $BenchFastMeta.csv
        }
    }

    $summary | ConvertTo-Json -Depth 8 | Set-Content -LiteralPath $summaryFile -Encoding utf8NoBOM
}

$cleanupWorktree = $true
try {
    Remove-WorktreeIfExists -Path $worktree
    Invoke-NativeOrThrow -Command @("git", "-C", $RootDir, "worktree", "add", "--detach", $worktree, $HeadSha) `
        -FailureMessage "Failed to create detached worktree"

    $headShaResolved = (& git -C $worktree rev-parse HEAD).Trim()
    $headShaShort = (& git -C $worktree rev-parse --short HEAD).Trim()
    if ($headShaResolved -ne $HeadSha) {
        throw "Resolved worktree HEAD mismatch: expected $HeadSha got $headShaResolved"
    }

    @(
        "capture_timestamp=$Timestamp"
        "host_tag=$HostTag"
        "head_sha=$HeadSha"
        "vendor=$vendor"
        "family=$cpuFamily"
        "model=$cpuModel"
        "stepping=$cpuStepping"
        "cpu_model_string=$cpuModelString"
        "threads=$Threads"
        "bench_iters=$BenchIters"
        "bench_warmup=$BenchWarmup"
        "bench_repeats=$BenchRepeats"
        "perf_iters=$PerfIters"
        "perf_warmup=$PerfWarmup"
        "large_pages=$LargePages"
        "pause_ms=$PauseMs"
        "worktree=$worktree"
        "tmp_out=$tmpOut"
        "artifact_dir=$artifactDir"
    ) | Set-Content -LiteralPath $manifestFile -Encoding utf8NoBOM

    @(
        "# v6_11 AMD simd-blockio family capture commands ($Timestamp)"
        "# worktree: $worktree ($HeadSha)"
        "# host_tag: $HostTag"
        "# vendor=$vendor family=$cpuFamily model=$cpuModel"
    ) | Set-Content -LiteralPath $commandLogFile -Encoding utf8NoBOM

    @(
        "timestamp=$(Get-Date -Format o)"
        ""
        "os_caption=$($osInfo.Caption)"
        "os_version=$($osInfo.Version)"
        "os_build=$($osInfo.BuildNumber)"
        ""
        "cpu_name=$cpuModelString"
        "cpu_vendor=$vendor"
        "cpu_description=$cpuDescription"
        "logical_processors=$($cpuInfo.NumberOfLogicalProcessors)"
        "physical_cores=$($cpuInfo.NumberOfCores)"
        ""
        "rustc_version=$((& rustc --version).Trim())"
        ""
        (& rustc -Vv)
        ""
        "cargo_version=$((& cargo --version).Trim())"
        ""
        "git_head=$HeadSha"
        "git_status="
        (& git -C $worktree status --short)
    ) | Set-Content -LiteralPath $provenanceFile -Encoding utf8NoBOM

    if (-not $SkipTests) {
        Run-TestBundle
    }

    $baselineBins = Build-ExampleSet -Label "baseline" -Features "bench-instrument"
    $simdBins = Build-ExampleSet -Label "simd" -Features "bench-instrument simd-blockio"
    $perfCompareExe = Build-PerfCompare

    $benchLightMeta = Run-BenchPair -Mode "light" -BaselineBenchExe $baselineBins.bench -SimdBenchExe $simdBins.bench
    $benchFastMeta = Run-BenchPair -Mode "fast" -BaselineBenchExe $baselineBins.bench -SimdBenchExe $simdBins.bench

    @(
        [pscustomobject]@{
            mode = $benchLightMeta.mode
            pair_label = $benchLightMeta.pair_label
            csv = Get-FinalArtifactAbsolutePath -Path $benchLightMeta.csv
            raw_log = Get-FinalArtifactAbsolutePath -Path $benchLightMeta.raw_log
        }
        [pscustomobject]@{
            mode = $benchFastMeta.mode
            pair_label = $benchFastMeta.pair_label
            csv = Get-FinalArtifactAbsolutePath -Path $benchFastMeta.csv
            raw_log = Get-FinalArtifactAbsolutePath -Path $benchFastMeta.raw_log
        }
    ) | Export-Csv -LiteralPath $benchIndexFile -NoTypeInformation -Encoding utf8NoBOM

    $perfLightCapture = Run-PerfPair -Mode "light" -BaselinePerfExe $baselineBins.perf -SimdPerfExe $simdBins.perf -PerfCompareExe $perfCompareExe -ExpectedSha $HeadSha -ExpectedShortSha $headShaShort
    $perfFastCapture = Run-PerfPair -Mode "fast" -BaselinePerfExe $baselineBins.perf -SimdPerfExe $simdBins.perf -PerfCompareExe $perfCompareExe -ExpectedSha $HeadSha -ExpectedShortSha $headShaShort

    $perfIndexRows = New-Object System.Collections.Generic.List[object]
    foreach ($capture in @($perfLightCapture, $perfFastCapture)) {
        foreach ($row in @($capture.baseline_rows + $capture.simd_rows)) {
            $perfIndexRows.Add([pscustomobject]@{
                    mode = $capture.mode
                    pair_label = $capture.pair_label
                    config_label = $row.config_label
                    seq = $row.seq
                    csv = Get-FinalArtifactAbsolutePath -Path $row.csv
                    stdout = Get-FinalArtifactAbsolutePath -Path $row.stdout
                    stderr = Get-FinalArtifactAbsolutePath -Path $row.stderr
                }) | Out-Null
        }
    }
    $perfIndexRows | Export-Csv -LiteralPath $perfIndexFile -NoTypeInformation -Encoding utf8NoBOM

    Write-SummaryJson -BenchLightMeta $benchLightMeta -BenchFastMeta $benchFastMeta -PerfLightCapture $perfLightCapture -PerfFastCapture $perfFastCapture -ExpectedShortSha $headShaShort

    Copy-Item -Path (Join-Path $tmpOut "v6_11*") -Destination $artifactDir -Recurse -Force
} finally {
    if ($cleanupWorktree -and -not $KeepWorktree) {
        Remove-WorktreeIfExists -Path $worktree
    }
}
