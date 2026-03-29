param(
    [string]$OutDir
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

function Get-DisplayWindowsName {
    param(
        [string]$ProductName,
        [string]$BuildNumber
    )

    $name = if ($ProductName) { $ProductName } else { 'Windows' }
    $build = 0
    [void][int]::TryParse($BuildNumber, [ref]$build)
    if ($build -ge 22000 -and $name -like 'Windows 10*') {
        return $name -replace '^Windows 10', 'Microsoft Windows 11'
    }
    if ($name -notlike 'Microsoft *') {
        return "Microsoft $name"
    }
    return $name
}

function Set-ProcessEnv {
    param([hashtable]$Values)

    $original = @{}
    foreach ($entry in $Values.GetEnumerator()) {
        $original[$entry.Key] = [Environment]::GetEnvironmentVariable($entry.Key, 'Process')
        [Environment]::SetEnvironmentVariable($entry.Key, $entry.Value, 'Process')
    }
    return $original
}

function Restore-ProcessEnv {
    param([hashtable]$Original)

    foreach ($entry in $Original.GetEnumerator()) {
        [Environment]::SetEnvironmentVariable($entry.Key, $entry.Value, 'Process')
    }
}

function Add-CommandLog {
    param(
        [string]$Path,
        [string[]]$Lines
    )

    foreach ($line in $Lines) {
        Add-Content -Path $Path -Encoding ascii -Value $line
    }
}

function Invoke-Capture {
    param(
        [string]$CommandLog,
        [string]$Display,
        [string]$ExePath,
        [string[]]$Arguments,
        [string]$StdoutPath,
        [string]$StderrPath,
        [hashtable]$EnvVars
    )

    Add-CommandLog -Path $CommandLog -Lines @('', "PS> $Display")
    $saved = Set-ProcessEnv -Values $EnvVars
    try {
        & $ExePath @Arguments 1> $StdoutPath 2> $StderrPath
        if ($LASTEXITCODE -ne 0) {
            throw "command failed ($LASTEXITCODE): $Display"
        }
    }
    finally {
        Restore-ProcessEnv -Original $saved
    }
}

function Read-Json {
    param(
        [string]$Dir,
        [string]$Name
    )

    Get-Content (Join-Path $Dir $Name) | ConvertFrom-Json
}

function Pct-Faster {
    param(
        [double]$Baseline,
        [double]$Candidate
    )

    if ($Baseline -eq 0) {
        return 0.0
    }
    return (($Baseline - $Candidate) / $Baseline) * 100.0
}

$required = @{
    perf_baseline = Join-Path $PSScriptRoot 'perf_harness_baseline.exe'
    perf_proto = Join-Path $PSScriptRoot 'perf_harness_proto.exe'
    superscalar_baseline = Join-Path $PSScriptRoot 'superscalar_hash_harness_baseline.exe'
    superscalar_proto = Join-Path $PSScriptRoot 'superscalar_hash_harness_proto.exe'
}

foreach ($path in $required.Values) {
    if (-not (Test-Path -LiteralPath $path -PathType Leaf)) {
        throw "Missing packaged binary: $path. Rebuild the bundle with scripts/build/package_v8_05_amd_capture.ps1."
    }
}

$timestamp = Get-Date -Format 'yyyyMMdd_HHmmss'
$dateStamp = Get-Date -Format 'yyyy-MM-dd'
$cpu = Get-CimInstance Win32_Processor | Select-Object -First 1
$computerInfo = Get-ComputerInfo
$processorIdentifier = $env:PROCESSOR_IDENTIFIER
if ($processorIdentifier -notmatch 'Family\s+(?<family>\d+)\s+Model\s+(?<model>\d+)\s+Stepping\s+(?<stepping>\d+)') {
    throw "Unable to parse PROCESSOR_IDENTIFIER: $processorIdentifier"
}

$family = [int]$Matches.family
$model = [int]$Matches.model
$stepping = [int]$Matches.stepping
$hostTag = "amd_fam${family}_mod${model}"
$expectedHostTags = @('amd_fam23_mod8', 'amd_fam23_mod113')
$displayWindowsName = Get-DisplayWindowsName -ProductName $computerInfo.WindowsProductName -BuildNumber $computerInfo.OsBuildNumber
$windowsVer = [string]((cmd /c ver | Out-String).Trim())

$outBase = if ($OutDir) {
    $OutDir
}
else {
    Join-Path $PSScriptRoot "v8_05_capture_${hostTag}_${timestamp}"
}

New-Item -ItemType Directory -Force -Path $outBase | Out-Null

$commandsName = "v8_05_commands_${hostTag}_${timestamp}.log"
$provenanceName = "v8_05_host_provenance_${hostTag}_${timestamp}.txt"
$manifestName = "v8_05_manifest_${hostTag}_${timestamp}.txt"
$perfIndexName = "v8_05_perf_index_${hostTag}_${timestamp}.csv"
$summaryName = "v8_05_summary_${hostTag}_${timestamp}.json"
$shareName = "v8_05_share_instructions_${hostTag}_${timestamp}.txt"
$unexpectedName = "v8_05_unexpected_host_${hostTag}_${timestamp}.txt"

$commandsPath = Join-Path $outBase $commandsName
$provenancePath = Join-Path $outBase $provenanceName
$manifestPath = Join-Path $outBase $manifestName
$perfIndexPath = Join-Path $outBase $perfIndexName
$summaryPath = Join-Path $outBase $summaryName
$sharePath = Join-Path $outBase $shareName

@(
    "timestamp=$timestamp"
    "host_tag=$hostTag"
    "runner_root=$PSScriptRoot"
) | Set-Content -Path $commandsPath -Encoding ascii

@(
    "timestamp=$timestamp"
    "host_tag=$hostTag"
    "vendor=$($cpu.Manufacturer)"
    "family=$family"
    "model=$model"
    "stepping=$stepping"
    "cpu_model_string=$($cpu.Name)"
    "processor_identifier=$processorIdentifier"
    "os_name=$displayWindowsName"
    "windows_product_name=$($computerInfo.WindowsProductName)"
    "windows_version=$($computerInfo.WindowsVersion)"
    "os_build_number=$($computerInfo.OsBuildNumber)"
    "logical_threads=$($cpu.NumberOfLogicalProcessors)"
    "windows_ver=$windowsVer"
) | Set-Content -Path $provenancePath -Encoding ascii

if ($cpu.Manufacturer -ne 'AuthenticAMD' -or $hostTag -notin $expectedHostTags) {
    @(
        "prompt=PROMPTv8_05"
        "status=unexpected_host"
        "host_tag=$hostTag"
        "processor_identifier=$processorIdentifier"
        "cpu_model_string=$($cpu.Name)"
        "os_name=$displayWindowsName"
        "timestamp=$timestamp"
    ) | Set-Content -Path (Join-Path $outBase $unexpectedName) -Encoding ascii

    @(
        'prompt=PROMPTv8_05'
        "timestamp=$timestamp"
        "host_tag=$hostTag"
        'artifacts:'
        "- $commandsName"
        "- $provenanceName"
        "- $unexpectedName"
    ) | Set-Content -Path $manifestPath -Encoding ascii

    Write-Output "Unexpected host for PROMPTv8_05. Output folder: $outBase"
    exit 1
}

$superscalarCommon = @('--config', 'default', '--iters', '2000', '--warmup', '200', '--items', '256')

Invoke-Capture -CommandLog $commandsPath `
    -Display 'superscalar_hash_harness_baseline.exe --format json --impl active --config default --iters 2000 --warmup 200 --items 256' `
    -ExePath $required.superscalar_baseline `
    -Arguments @('--format', 'json', '--impl', 'active') + $superscalarCommon `
    -StdoutPath (Join-Path $outBase "v8_05_superscalar_hash_baseline_active_${hostTag}_${timestamp}.json") `
    -StderrPath (Join-Path $outBase "v8_05_superscalar_hash_baseline_active_${hostTag}_${timestamp}.json.stderr") `
    -EnvVars @{}
Invoke-Capture -CommandLog $commandsPath `
    -Display 'superscalar_hash_harness_baseline.exe --format csv --impl active --config default --iters 2000 --warmup 200 --items 256' `
    -ExePath $required.superscalar_baseline `
    -Arguments @('--format', 'csv', '--impl', 'active') + $superscalarCommon `
    -StdoutPath (Join-Path $outBase "v8_05_superscalar_hash_baseline_active_${hostTag}_${timestamp}.csv") `
    -StderrPath (Join-Path $outBase "v8_05_superscalar_hash_baseline_active_${hostTag}_${timestamp}.csv.stderr") `
    -EnvVars @{}
Invoke-Capture -CommandLog $commandsPath `
    -Display 'superscalar_hash_harness_proto.exe --format json --impl active --config default --iters 2000 --warmup 200 --items 256' `
    -ExePath $required.superscalar_proto `
    -Arguments @('--format', 'json', '--impl', 'active') + $superscalarCommon `
    -StdoutPath (Join-Path $outBase "v8_05_superscalar_hash_proto_active_${hostTag}_${timestamp}.json") `
    -StderrPath (Join-Path $outBase "v8_05_superscalar_hash_proto_active_${hostTag}_${timestamp}.json.stderr") `
    -EnvVars @{}
Invoke-Capture -CommandLog $commandsPath `
    -Display 'superscalar_hash_harness_proto.exe --format csv --impl active --config default --iters 2000 --warmup 200 --items 256' `
    -ExePath $required.superscalar_proto `
    -Arguments @('--format', 'csv', '--impl', 'active') + $superscalarCommon `
    -StdoutPath (Join-Path $outBase "v8_05_superscalar_hash_proto_active_${hostTag}_${timestamp}.csv") `
    -StderrPath (Join-Path $outBase "v8_05_superscalar_hash_proto_active_${hostTag}_${timestamp}.csv.stderr") `
    -EnvVars @{}
Invoke-Capture -CommandLog $commandsPath `
    -Display 'superscalar_hash_harness_proto.exe --format json --impl scalar --config default --iters 2000 --warmup 200 --items 256' `
    -ExePath $required.superscalar_proto `
    -Arguments @('--format', 'json', '--impl', 'scalar') + $superscalarCommon `
    -StdoutPath (Join-Path $outBase "v8_05_superscalar_hash_proto_scalar_${hostTag}_${timestamp}.json") `
    -StderrPath (Join-Path $outBase "v8_05_superscalar_hash_proto_scalar_${hostTag}_${timestamp}.json.stderr") `
    -EnvVars @{}
Invoke-Capture -CommandLog $commandsPath `
    -Display 'superscalar_hash_harness_proto.exe --format csv --impl scalar --config default --iters 2000 --warmup 200 --items 256' `
    -ExePath $required.superscalar_proto `
    -Arguments @('--format', 'csv', '--impl', 'scalar') + $superscalarCommon `
    -StdoutPath (Join-Path $outBase "v8_05_superscalar_hash_proto_scalar_${hostTag}_${timestamp}.csv") `
    -StderrPath (Join-Path $outBase "v8_05_superscalar_hash_proto_scalar_${hostTag}_${timestamp}.csv.stderr") `
    -EnvVars @{}

$perfRows = @(
    @{
        Label = 'light_interp'
        Variant = 'baseline'
        Exe = $required.perf_baseline
        Mode = 'light'
        Jit = 'off'
        JitFastRegs = 'off'
        Features = 'jit,jit-fastregs,bench-instrument'
        Env = @{ OXIDE_RANDOMX_HUGE_1G = '0'; OXIDE_RANDOMX_FAST_BENCH = $null; OXIDE_RANDOMX_FAST_BENCH_SMALL = $null }
    }
    @{
        Label = 'light_interp'
        Variant = 'proto'
        Exe = $required.perf_proto
        Mode = 'light'
        Jit = 'off'
        JitFastRegs = 'off'
        Features = 'jit,jit-fastregs,bench-instrument,superscalar-accel-proto'
        Env = @{ OXIDE_RANDOMX_HUGE_1G = '0'; OXIDE_RANDOMX_FAST_BENCH = $null; OXIDE_RANDOMX_FAST_BENCH_SMALL = $null }
    }
    @{
        Label = 'light_jit_conservative'
        Variant = 'baseline'
        Exe = $required.perf_baseline
        Mode = 'light'
        Jit = 'on'
        JitFastRegs = 'off'
        Features = 'jit,jit-fastregs,bench-instrument'
        Env = @{ OXIDE_RANDOMX_HUGE_1G = '0'; OXIDE_RANDOMX_FAST_BENCH = $null; OXIDE_RANDOMX_FAST_BENCH_SMALL = $null }
    }
    @{
        Label = 'light_jit_conservative'
        Variant = 'proto'
        Exe = $required.perf_proto
        Mode = 'light'
        Jit = 'on'
        JitFastRegs = 'off'
        Features = 'jit,jit-fastregs,bench-instrument,superscalar-accel-proto'
        Env = @{ OXIDE_RANDOMX_HUGE_1G = '0'; OXIDE_RANDOMX_FAST_BENCH = $null; OXIDE_RANDOMX_FAST_BENCH_SMALL = $null }
    }
    @{
        Label = 'light_jit_fastregs'
        Variant = 'baseline'
        Exe = $required.perf_baseline
        Mode = 'light'
        Jit = 'on'
        JitFastRegs = 'on'
        Features = 'jit,jit-fastregs,bench-instrument'
        Env = @{ OXIDE_RANDOMX_HUGE_1G = '0'; OXIDE_RANDOMX_FAST_BENCH = $null; OXIDE_RANDOMX_FAST_BENCH_SMALL = $null }
    }
    @{
        Label = 'light_jit_fastregs'
        Variant = 'proto'
        Exe = $required.perf_proto
        Mode = 'light'
        Jit = 'on'
        JitFastRegs = 'on'
        Features = 'jit,jit-fastregs,bench-instrument,superscalar-accel-proto'
        Env = @{ OXIDE_RANDOMX_HUGE_1G = '0'; OXIDE_RANDOMX_FAST_BENCH = $null; OXIDE_RANDOMX_FAST_BENCH_SMALL = $null }
    }
    @{
        Label = 'fast_jit_conservative'
        Variant = 'baseline'
        Exe = $required.perf_baseline
        Mode = 'fast'
        Jit = 'on'
        JitFastRegs = 'off'
        Features = 'jit,jit-fastregs,bench-instrument'
        Env = @{ OXIDE_RANDOMX_HUGE_1G = '0'; OXIDE_RANDOMX_FAST_BENCH = '1'; OXIDE_RANDOMX_FAST_BENCH_SMALL = $null }
    }
    @{
        Label = 'fast_jit_conservative'
        Variant = 'proto'
        Exe = $required.perf_proto
        Mode = 'fast'
        Jit = 'on'
        JitFastRegs = 'off'
        Features = 'jit,jit-fastregs,bench-instrument,superscalar-accel-proto'
        Env = @{ OXIDE_RANDOMX_HUGE_1G = '0'; OXIDE_RANDOMX_FAST_BENCH = '1'; OXIDE_RANDOMX_FAST_BENCH_SMALL = $null }
    }
    @{
        Label = 'fast_jit_fastregs'
        Variant = 'baseline'
        Exe = $required.perf_baseline
        Mode = 'fast'
        Jit = 'on'
        JitFastRegs = 'on'
        Features = 'jit,jit-fastregs,bench-instrument'
        Env = @{ OXIDE_RANDOMX_HUGE_1G = '0'; OXIDE_RANDOMX_FAST_BENCH = '1'; OXIDE_RANDOMX_FAST_BENCH_SMALL = $null }
    }
    @{
        Label = 'fast_jit_fastregs'
        Variant = 'proto'
        Exe = $required.perf_proto
        Mode = 'fast'
        Jit = 'on'
        JitFastRegs = 'on'
        Features = 'jit,jit-fastregs,bench-instrument,superscalar-accel-proto'
        Env = @{ OXIDE_RANDOMX_HUGE_1G = '0'; OXIDE_RANDOMX_FAST_BENCH = '1'; OXIDE_RANDOMX_FAST_BENCH_SMALL = $null }
    }
)

foreach ($row in $perfRows) {
    foreach ($format in @('json', 'csv')) {
        $outName = "v8_05_perf_harness_{0}_{1}_{2}_{3}.{4}" -f $row.Label, $row.Variant, $hostTag, $timestamp, $format
        $stderrName = "$outName.stderr"
        $display = "{0} --mode {1} --jit {2} --jit-fast-regs {3} --iters 50 --warmup 5 --threads 12 --large-pages off --thread-names off --affinity off --format {4} --out {5}" -f (Split-Path $row.Exe -Leaf), $row.Mode, $row.Jit, $row.JitFastRegs, $format, $outName
        Invoke-Capture -CommandLog $commandsPath `
            -Display $display `
            -ExePath $row.Exe `
            -Arguments @('--mode', $row.Mode, '--jit', $row.Jit, '--jit-fast-regs', $row.JitFastRegs, '--iters', '50', '--warmup', '5', '--threads', '12', '--large-pages', 'off', '--thread-names', 'off', '--affinity', 'off', '--format', $format, '--out', (Join-Path $outBase $outName)) `
            -StdoutPath (Join-Path $outBase "$outName.stdout") `
            -StderrPath (Join-Path $outBase $stderrName) `
            -EnvVars $row.Env
    }
}

$supBase = Read-Json -Dir $outBase -Name "v8_05_superscalar_hash_baseline_active_${hostTag}_${timestamp}.json"
$supProto = Read-Json -Dir $outBase -Name "v8_05_superscalar_hash_proto_active_${hostTag}_${timestamp}.json"
$supScalar = Read-Json -Dir $outBase -Name "v8_05_superscalar_hash_proto_scalar_${hostTag}_${timestamp}.json"

$pairDefs = @(
    @{ Label = 'light_interp'; Mode = 'Light'; Config = 'Interpreter' }
    @{ Label = 'light_jit_conservative'; Mode = 'Light'; Config = 'JIT conservative' }
    @{ Label = 'light_jit_fastregs'; Mode = 'Light'; Config = 'JIT fast-regs' }
    @{ Label = 'fast_jit_conservative'; Mode = 'Fast'; Config = 'JIT conservative' }
    @{ Label = 'fast_jit_fastregs'; Mode = 'Fast'; Config = 'JIT fast-regs' }
)

$perfIndexRows = @()
$pairDeltas = @()
foreach ($pair in $pairDefs) {
    $baselineName = "v8_05_perf_harness_{0}_baseline_{1}_{2}.json" -f $pair.Label, $hostTag, $timestamp
    $protoName = "v8_05_perf_harness_{0}_proto_{1}_{2}.json" -f $pair.Label, $hostTag, $timestamp
    $baseline = Read-Json -Dir $outBase -Name $baselineName
    $proto = Read-Json -Dir $outBase -Name $protoName
    $baselineDataset = if ($null -eq $baseline.stages.dataset_init_ns) { $null } else { [int64]$baseline.stages.dataset_init_ns }
    $protoDataset = if ($null -eq $proto.stages.dataset_init_ns) { $null } else { [int64]$proto.stages.dataset_init_ns }
    $pairDeltas += [pscustomobject]@{
        label = $pair.Label
        mode = $pair.Mode
        config = $pair.Config
        baseline_ns_per_hash = [int64]$baseline.results.ns_per_hash
        proto_ns_per_hash = [int64]$proto.results.ns_per_hash
        speedup_pct = [math]::Round((Pct-Faster ([double]$baseline.results.ns_per_hash) ([double]$proto.results.ns_per_hash)), 3)
        baseline_dataset_init_ns = $baselineDataset
        proto_dataset_init_ns = $protoDataset
        dataset_init_speedup_pct = if ($null -eq $baselineDataset -or $null -eq $protoDataset) { $null } else { [math]::Round((Pct-Faster ([double]$baselineDataset) ([double]$protoDataset)), 3) }
    }

    foreach ($variant in @('baseline', 'proto')) {
        $jsonName = "v8_05_perf_harness_{0}_{1}_{2}_{3}.json" -f $pair.Label, $variant, $hostTag, $timestamp
        $csvName = "v8_05_perf_harness_{0}_{1}_{2}_{3}.csv" -f $pair.Label, $variant, $hostTag, $timestamp
        $json = if ($variant -eq 'baseline') { $baseline } else { $proto }
        $perfIndexRows += [pscustomobject]@{
            label = $pair.Label
            mode = $pair.Mode
            config = $pair.Config
            variant = $variant
            runtime_jit_flags = if ($json.params.jit_requested) { if ($json.params.jit_fast_regs) { '--jit on --jit-fast-regs on' } else { '--jit on --jit-fast-regs off' } } else { '--jit off --jit-fast-regs off' }
            csv_artifact = $csvName
            json_artifact = $jsonName
            git_sha = $json.provenance.git_sha
            git_sha_short = $json.provenance.git_sha_short
            git_dirty = [string]$json.provenance.git_dirty
            features = $json.provenance.features
            cpu = $json.provenance.cpu
            cores = [int]$json.provenance.cores
            rustc = $json.provenance.rustc
            ns_per_hash = [int64]$json.results.ns_per_hash
            hashes_per_sec = [math]::Round([double]$json.results.hashes_per_sec, 6)
            dataset_init_ns = if ($null -eq $json.stages.dataset_init_ns) { 'n/a' } else { [int64]$json.stages.dataset_init_ns }
            jit_active = [bool]$json.results.jit_active
            jit_fast_regs = [bool]$json.params.jit_fast_regs
            large_pages_requested = [bool]$json.params.large_pages_requested
            large_pages_1gb_requested = [bool]$json.params.large_pages_1gb_requested
            thread_names = [bool]$json.params.thread_names
            affinity = if ($null -eq $json.params.affinity) { 'off' } else { [string]$json.params.affinity }
            prefetch_distance = [int]$json.params.prefetch_distance
            prefetch_auto_tune = [bool]$json.params.prefetch_auto_tune
        }
    }
}

$perfIndexRows | Export-Csv -Path $perfIndexPath -NoTypeInformation -Encoding ascii

$summary = [ordered]@{
    prompt = 'PROMPTv8_05'
    timestamp = $timestamp
    date = $dateStamp
    host_tag = $hostTag
    provenance = [ordered]@{
        cpu_model_string = $cpu.Name.Trim()
        processor_identifier = $processorIdentifier
        vendor = $cpu.Manufacturer
        family = $family
        model = $model
        stepping = $stepping
        os_name = $displayWindowsName
        windows_product_name = $computerInfo.WindowsProductName
        windows_version = $computerInfo.WindowsVersion
        os_build_number = $computerInfo.OsBuildNumber
        windows_ver = $windowsVer
        packaged_runner_root = $PSScriptRoot
        perf_git_dirty_all_false = (($perfIndexRows | Where-Object { $_.git_dirty -ne 'false' }).Count -eq 0)
    }
    runtime = [ordered]@{
        superscalar_iters = 2000
        superscalar_warmup = 200
        superscalar_items = 256
        perf_iters = 50
        perf_warmup = 5
        threads = 12
        large_pages_requested = $false
        large_pages_1gb_requested = $false
        thread_names = $false
        affinity = 'off'
        fast_mode_env = 'OXIDE_RANDOMX_FAST_BENCH=1'
        huge_1g_env = 'OXIDE_RANDOMX_HUGE_1G=0'
    }
    isolated = [ordered]@{
        baseline_active = $supBase
        proto_active = $supProto
        proto_scalar = $supScalar
        checksum_parity = [ordered]@{
            compute_checksum = (($supBase.compute_checksum -eq $supProto.compute_checksum) -and ($supBase.compute_checksum -eq $supScalar.compute_checksum))
            execute_checksum = (($supBase.execute_checksum -eq $supProto.execute_checksum) -and ($supBase.execute_checksum -eq $supScalar.execute_checksum))
            execute_select_checksum = (($supBase.execute_select_checksum -eq $supProto.execute_select_checksum) -and ($supBase.execute_select_checksum -eq $supScalar.execute_select_checksum))
        }
        deltas = [ordered]@{
            proto_active_vs_baseline_compute_speedup_pct = [math]::Round((Pct-Faster ([double]$supBase.compute_ns_per_call) ([double]$supProto.compute_ns_per_call)), 3)
            proto_active_vs_baseline_execute_speedup_pct = [math]::Round((Pct-Faster ([double]$supBase.execute_ns_per_call) ([double]$supProto.execute_ns_per_call)), 3)
            proto_active_vs_scalar_compute_speedup_pct = [math]::Round((Pct-Faster ([double]$supScalar.compute_ns_per_call) ([double]$supProto.compute_ns_per_call)), 3)
            proto_active_vs_scalar_execute_speedup_pct = [math]::Round((Pct-Faster ([double]$supScalar.execute_ns_per_call) ([double]$supProto.execute_ns_per_call)), 3)
        }
    }
    perf_rows = $perfIndexRows
    pair_deltas = $pairDeltas
}

$summary | ConvertTo-Json -Depth 8 | Set-Content -Path $summaryPath -Encoding ascii

$shareLines = @(
    'Share the entire output folder from this run.',
    ''
    'Recommended files to call out:'
    "- $commandsName"
    "- $provenanceName"
    "- $perfIndexName"
    "- $summaryName"
)
$shareLines += Get-ChildItem $outBase -Filter 'v8_05_superscalar_hash_*' | Sort-Object Name | ForEach-Object { "- $($_.Name)" }
$shareLines += Get-ChildItem $outBase -Filter 'v8_05_perf_harness_*' | Sort-Object Name | ForEach-Object { "- $($_.Name)" }
$shareLines | Set-Content -Path $sharePath -Encoding ascii

$manifest = @(
    'prompt=PROMPTv8_05'
    "timestamp=$timestamp"
    "host_tag=$hostTag"
    "out_dir=$outBase"
    'artifacts:'
)
$manifest += Get-ChildItem $outBase | Sort-Object Name | ForEach-Object { "- $($_.Name)" }
$manifest | Set-Content -Path $manifestPath -Encoding ascii

Write-Output "Output folder: $outBase"
Write-Output "Share instructions: $sharePath"
