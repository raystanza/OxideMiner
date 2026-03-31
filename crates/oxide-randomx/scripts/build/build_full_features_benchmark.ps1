param(
    [ValidateSet('windows', 'linux')]
    [string]$TargetHost = $env:TARGET_HOST,
    [string]$Target = $env:TARGET,
    [string]$Features = $env:FEATURES,
    [string]$DistDir = $env:DIST_DIR,
    [ValidateRange(1, 100)]
    [int]$RunCount = $(if ($env:RUN_COUNT) { [int]$env:RUN_COUNT } else { 1 }),
    [string]$RemoteBundleRoot = $env:REMOTE_BUNDLE_ROOT,
    [string]$RemoteRunPrefix = $(if ($env:REMOTE_RUN_PREFIX) { $env:REMOTE_RUN_PREFIX } else { 'ff_capture' }),
    [string]$RemoteHostContextFile = $(if ($env:REMOTE_HOST_CONTEXT_FILE) { $env:REMOTE_HOST_CONTEXT_FILE } else { 'HOST_CONTEXT_NOTES.txt' }),
    [string]$WindowsGnuLinker = $(if ($env:WINDOWS_GNU_LINKER) { $env:WINDOWS_GNU_LINKER } elseif ($env:CARGO_TARGET_X86_64_PC_WINDOWS_GNU_LINKER) { $env:CARGO_TARGET_X86_64_PC_WINDOWS_GNU_LINKER } else { 'x86_64-w64-mingw32-gcc' }),
    [string]$LinuxGnuLinker = $(if ($env:LINUX_GNU_LINKER) { $env:LINUX_GNU_LINKER } elseif ($env:CARGO_TARGET_X86_64_UNKNOWN_LINUX_GNU_LINKER) { $env:CARGO_TARGET_X86_64_UNKNOWN_LINUX_GNU_LINKER } else { '' }),
    [string]$RustupBin = $env:RUSTUP_BIN,
    [string]$CargoBin = $env:CARGO_BIN
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

function Test-HostIsWindows {
    return [System.Runtime.InteropServices.RuntimeInformation]::IsOSPlatform([System.Runtime.InteropServices.OSPlatform]::Windows)
}

function Get-DefaultTarget {
    if (Test-HostIsWindows) {
        return 'x86_64-pc-windows-msvc'
    }

    return 'x86_64-unknown-linux-gnu'
}

function Get-WindowsTarget {
    if (Test-HostIsWindows) {
        return 'x86_64-pc-windows-msvc'
    }

    if (($CargoBin -and $CargoBin.EndsWith('.exe', [System.StringComparison]::OrdinalIgnoreCase)) -or
        ($RustupBin -and $RustupBin.EndsWith('.exe', [System.StringComparison]::OrdinalIgnoreCase))) {
        return 'x86_64-pc-windows-msvc'
    }

    if ((Get-Command -Name 'cargo.exe' -ErrorAction SilentlyContinue | Select-Object -First 1) -or
        (Get-Command -Name 'rustup.exe' -ErrorAction SilentlyContinue | Select-Object -First 1)) {
        return 'x86_64-pc-windows-msvc'
    }

    return 'x86_64-pc-windows-gnu'
}

function Resolve-TargetForHost {
    param(
        [ValidateSet('windows', 'linux')]
        [string]$SelectedHost
    )

    switch ($SelectedHost) {
        'windows' {
            return Get-WindowsTarget
        }
        'linux' {
            return 'x86_64-unknown-linux-gnu'
        }
    }
}

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

function Test-CommandAvailable {
    param([string]$Name)

    return $null -ne (Get-Command -Name $Name -ErrorAction SilentlyContinue | Select-Object -First 1)
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

function Get-DefaultRemoteBundleRoot {
    param([string]$Platform)

    switch ($Platform) {
        'windows' { return 'C:\oxide-randomx-captures\full_features_benchmark_windows' }
        'linux' { return '/tmp/oxide-randomx-captures/full_features_benchmark_linux' }
        default { throw "unsupported platform '$Platform'" }
    }
}

$RootDir = [System.IO.Path]::GetFullPath((Join-Path $PSScriptRoot '../..'))
if ($Target -and $TargetHost) {
    throw "Specify either -Target/TARGET or -TargetHost/TARGET_HOST, not both."
}

$Target = if ($Target) {
    $Target
}
elseif ($TargetHost) {
    Resolve-TargetForHost -SelectedHost $TargetHost
}
else {
    Get-DefaultTarget
}

$Features = if ($Features) { $Features } else { 'jit jit-fastregs bench-instrument threaded-interp simd-blockio simd-xor-paths superscalar-accel-proto' }
$BinName = 'full_features_benchmark'

switch -Wildcard ($Target) {
    '*windows*' {
        $PlatformTag = 'windows'
        $OutName = 'oxide-randomx-full-features-benchmark.exe'
        $InstructionsName = 'RUN_ON_REMOTE_WINDOWS_HOST.txt'
        $ArchiveName = 'oxide-randomx-full-features-benchmark.zip'
    }
    '*linux*' {
        $PlatformTag = 'linux'
        $OutName = 'oxide-randomx-full-features-benchmark'
        $InstructionsName = 'RUN_ON_REMOTE_UBUNTU_LINUX_HOST.txt'
        $ArchiveName = 'oxide-randomx-full-features-benchmark-linux.tar.gz'
    }
    default {
        throw "unsupported TARGET '$Target' (expected a Windows or Linux target)"
    }
}

if (-not $DistDir) {
    $DistRoot = [System.IO.Path]::GetFullPath((Join-Path $RootDir '..'))
    $DistDir = Join-Path $DistRoot "oxide-randomx-dist/full_features_benchmark_${PlatformTag}"
}
if ([string]::IsNullOrWhiteSpace($RemoteRunPrefix)) {
    throw '-RemoteRunPrefix / REMOTE_RUN_PREFIX must not be empty.'
}
if ([string]::IsNullOrWhiteSpace($RemoteHostContextFile)) {
    throw '-RemoteHostContextFile / REMOTE_HOST_CONTEXT_FILE must not be empty.'
}
$RemoteBundleRoot = if ($RemoteBundleRoot) {
    $RemoteBundleRoot
}
else {
    Get-DefaultRemoteBundleRoot -Platform $PlatformTag
}

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

$installedTargetSet = @($installedTargets | ForEach-Object { $_.Trim() } | Where-Object { $_ })
if ($Target -notin $installedTargetSet) {
    throw "target '$Target' is not installed. Install it with: $RustupBin target add $Target"
}

if ($Target -like '*-windows-gnu') {
    if (-not (Test-CommandAvailable -Name $WindowsGnuLinker)) {
        throw @"
required Windows GNU linker '$WindowsGnuLinker' was not found.
target '$Target' requires a MinGW cross-linker.
Debian/Ubuntu install hint: sudo apt-get install -y mingw-w64
or set CARGO_TARGET_X86_64_PC_WINDOWS_GNU_LINKER to a valid linker path.
"@
    }
}

if ((Test-HostIsWindows) -and $Target -eq 'x86_64-unknown-linux-gnu') {
    if (-not $LinuxGnuLinker) {
        throw "Windows -> Linux cross-build requires -LinuxGnuLinker or CARGO_TARGET_X86_64_UNKNOWN_LINUX_GNU_LINKER."
    }
    if (-not (Test-CommandAvailable -Name $LinuxGnuLinker)) {
        throw "required Linux GNU linker '$LinuxGnuLinker' was not found. Set CARGO_TARGET_X86_64_UNKNOWN_LINUX_GNU_LINKER to a valid linker path/command."
    }
}

Write-Host "Building $BinName for $Target with features: $Features"
$prevWindowsLinker = $env:CARGO_TARGET_X86_64_PC_WINDOWS_GNU_LINKER
$prevLinuxLinker = $env:CARGO_TARGET_X86_64_UNKNOWN_LINUX_GNU_LINKER
Push-Location $RootDir
try {
    if ($Target -like '*-windows-gnu') {
        $env:CARGO_TARGET_X86_64_PC_WINDOWS_GNU_LINKER = $WindowsGnuLinker
    }
    if ((Test-HostIsWindows) -and $Target -eq 'x86_64-unknown-linux-gnu') {
        $env:CARGO_TARGET_X86_64_UNKNOWN_LINUX_GNU_LINKER = $LinuxGnuLinker
    }
    Invoke-External -FilePath $CargoBin -Arguments @(
        'build'
        '--release'
        '--target'
        $Target
        '--bin'
        $BinName
        '--features'
        $Features
    )
}
finally {
    if ($null -ne $prevWindowsLinker) {
        $env:CARGO_TARGET_X86_64_PC_WINDOWS_GNU_LINKER = $prevWindowsLinker
    }
    else {
        Remove-Item Env:CARGO_TARGET_X86_64_PC_WINDOWS_GNU_LINKER -ErrorAction SilentlyContinue
    }
    if ($null -ne $prevLinuxLinker) {
        $env:CARGO_TARGET_X86_64_UNKNOWN_LINUX_GNU_LINKER = $prevLinuxLinker
    }
    else {
        Remove-Item Env:CARGO_TARGET_X86_64_UNKNOWN_LINUX_GNU_LINKER -ErrorAction SilentlyContinue
    }
    Pop-Location
}

$SrcBin = Join-Path $RootDir "target/$Target/release/$BinName"
if ($PlatformTag -eq 'windows') {
    $SrcBin = "$SrcBin.exe"
}

if (-not (Test-Path -LiteralPath $SrcBin -PathType Leaf)) {
    throw "expected output missing: $SrcBin"
}

$DistDir = [System.IO.Path]::GetFullPath($DistDir)
$OutPath = Join-Path $DistDir $OutName
$InstructionsPath = Join-Path $DistDir $InstructionsName
$ArchivePath = Join-Path $DistDir $ArchiveName

New-Item -ItemType Directory -Force -Path $DistDir | Out-Null
Copy-Item -LiteralPath $SrcBin -Destination $OutPath -Force

if ($PlatformTag -eq 'linux' -and (Test-CommandAvailable -Name 'chmod')) {
    Invoke-External -FilePath 'chmod' -Arguments @('+x', $OutPath)
}

if ($RunCount -eq 1) {
    $RunNames = @($RemoteRunPrefix)
}
else {
    $RunNames = @(1..$RunCount | ForEach-Object { '{0}_r{1:d2}' -f $RemoteRunPrefix, $_ })
}

if ($PlatformTag -eq 'windows') {
    $WindowsRunBlock = if ($RunCount -eq 1) {
        @'
   .\oxide-randomx-full-features-benchmark.exe `
     --out-dir (Join-Path $bundleRoot "{0}")
'@ -f $RunNames[0]
    }
    else {
        $RunList = ($RunNames | ForEach-Object { '     "{0}"' -f $_ }) -join "`r`n"
        @'
   $runDirs = @(
{0}
   )

   foreach ($runDir in $runDirs) {{
     .\oxide-randomx-full-features-benchmark.exe `
       --out-dir (Join-Path $bundleRoot $runDir)
   }}
'@ -f $RunList
    }
    $InstructionsText = @'
Run instructions for remote Windows host

1) Copy `oxide-randomx-full-features-benchmark.exe` to the target Windows machine.
2) Open PowerShell in that folder.
3) Pick a bundle root outside any git checkout so the raw `ff_*` directories stay intact:

   $bundleRoot = "{0}"

4) Optional binary validation:

   .\oxide-randomx-full-features-benchmark.exe --validate-only

5) Run the capture with unchanged canonical settings:

{1}

6) Record host context before returning the raw bundle:

   @'
   privilege_state=
   large_page_privilege=
   memory_pressure_notes=
   reboot_or_fresh_session=
   run_order_notes=
   '@ | Set-Content -Encoding ascii -Path (Join-Path $bundleRoot "{2}")

7) Return the entire `$bundleRoot` directory, including every emitted `ff_*` directory and `{2}`.
8) Back in the repo, preserve the raw returned bundle first, then place the intact `ff_*` directories under your local `perf_results/` tree and classify them with `docs/full-features-benchmark-workflow.md`.

Keep these settings unchanged unless you are deliberately doing exploratory work:
- `--perf-iters 50`
- `--perf-warmup 5`
- `--threads <detected logical-thread-count>`
- the packaged binary's default feature plan and page-profile set

Optional run args:
- `--out-dir C:\path\to\capture`
- `--validate-only`

This package was configured with:
- `run_count={3}`
- `bundle_root={0}`
- `run_prefix={4}`
- `host_context_file={2}`

This binary is built with:
- `jit`
- `jit-fastregs`
- `bench-instrument`
- `threaded-interp`
- `simd-blockio`
- `simd-xor-paths`
- `superscalar-accel-proto`
'@ -f $RemoteBundleRoot, $WindowsRunBlock, $RemoteHostContextFile, $RunCount, $RemoteRunPrefix
}
else {
    $LinuxRunBlock = if ($RunCount -eq 1) {
        @'
   ./oxide-randomx-full-features-benchmark \
     --out-dir "${bundle_root}/{0}"
'@ -f $RunNames[0]
    }
    else {
        $RunList = ($RunNames | ForEach-Object { '     "{0}"' -f $_ }) -join "`n"
        @'
   run_dirs=(
{0}
   )

   for run_dir in "${{run_dirs[@]}}"; do
     ./oxide-randomx-full-features-benchmark \
       --out-dir "${{bundle_root}}/${{run_dir}}"
   done
'@ -f $RunList
    }
    $InstructionsText = @'
Run instructions for remote Ubuntu/Debian Linux host

1) Copy `oxide-randomx-full-features-benchmark` to the target Linux machine.
2) Open a shell in that folder.
3) Pick a bundle root outside any git checkout so the raw `ff_*` directories stay intact:

   bundle_root="{0}"

4) Optional binary validation:

   ./oxide-randomx-full-features-benchmark --validate-only

5) Run the capture with unchanged canonical settings:

{1}

6) Record host context before returning the raw bundle:

   cat > "${{bundle_root}}/{2}" <<'EOF'
   privilege_state=
   large_page_privilege=
   memory_pressure_notes=
   reboot_or_fresh_session=
   run_order_notes=
   EOF

7) Return the entire `${{bundle_root}}` directory, including every emitted `ff_*` directory and `{2}`.
8) Back in the repo, preserve the raw returned bundle first, then place the intact `ff_*` directories under your local `perf_results/` tree and classify them with `docs/full-features-benchmark-workflow.md`.

Keep these settings unchanged unless you are deliberately doing exploratory work:
- `--perf-iters 50`
- `--perf-warmup 5`
- `--threads <detected logical-thread-count>`
- the packaged binary's default feature plan and page-profile set

Optional run args:
- `--out-dir /path/to/capture`
- `--validate-only`

This package was configured with:
- `run_count={3}`
- `bundle_root={0}`
- `run_prefix={4}`
- `host_context_file={2}`

This binary is built with:
- `jit`
- `jit-fastregs`
- `bench-instrument`
- `threaded-interp`
- `simd-blockio`
- `simd-xor-paths`
- `superscalar-accel-proto`
'@ -f $RemoteBundleRoot, $LinuxRunBlock, $RemoteHostContextFile, $RunCount, $RemoteRunPrefix
}

Set-Content -Path $InstructionsPath -Value $InstructionsText -Encoding ascii

if ($PlatformTag -eq 'windows') {
    if (Test-CommandAvailable -Name 'Compress-Archive') {
        if (Test-Path -LiteralPath $ArchivePath) {
            Remove-Item -LiteralPath $ArchivePath -Force
        }
        Compress-Archive -Path $OutPath, $InstructionsPath -DestinationPath $ArchivePath -Force
        Write-Host "Wrote: $ArchivePath"
    }
}
else {
    if (Test-CommandAvailable -Name 'tar') {
        if (Test-Path -LiteralPath $ArchivePath) {
            Remove-Item -LiteralPath $ArchivePath -Force
        }
        Invoke-External -FilePath 'tar' -Arguments @('-czf', $ArchivePath, '-C', $DistDir, $OutName, $InstructionsName)
        Write-Host "Wrote: $ArchivePath"
    }
}

Write-Host "Wrote: $OutPath"
Write-Host "Wrote: $InstructionsPath"
