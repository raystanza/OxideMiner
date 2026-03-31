param(
    [ValidateSet('windows', 'linux')]
    [string]$TargetHost = $env:TARGET_HOST,
    [string]$Target = $env:TARGET,
    [string]$ReleaseId = $(if ($env:RELEASE_ID) { $env:RELEASE_ID } elseif ($env:OXIDE_RANDOMX_CAPTURE_RELEASE_ID) { $env:OXIDE_RANDOMX_CAPTURE_RELEASE_ID } else { 'local-dev' }),
    [string]$Features = $env:FEATURES,
    [string]$DistDir = $env:DIST_DIR,
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
    if (Test-HostIsWindows) { return 'x86_64-pc-windows-msvc' }
    return 'x86_64-unknown-linux-gnu'
}

function Get-WindowsTarget {
    if (Test-HostIsWindows) { return 'x86_64-pc-windows-msvc' }
    if ((Get-Command -Name 'cargo.exe' -ErrorAction SilentlyContinue | Select-Object -First 1) -or
        (Get-Command -Name 'rustup.exe' -ErrorAction SilentlyContinue | Select-Object -First 1)) {
        return 'x86_64-pc-windows-msvc'
    }
    return 'x86_64-pc-windows-gnu'
}

function Resolve-TargetForHost {
    param([ValidateSet('windows', 'linux')][string]$SelectedHost)
    switch ($SelectedHost) {
        'windows' { return Get-WindowsTarget }
        'linux' { return 'x86_64-unknown-linux-gnu' }
    }
}

function Resolve-Tool {
    param([string]$Current, [string[]]$Candidates)
    if ($Current) { return $Current }
    foreach ($candidate in $Candidates) {
        $tool = Get-Command -Name $candidate -ErrorAction SilentlyContinue | Select-Object -First 1
        if ($null -ne $tool) {
            if ($tool.Source) { return $tool.Source }
            if ($tool.Path) { return $tool.Path }
            return $tool.Name
        }
    }
    return $null
}

function Invoke-External {
    param([string]$FilePath, [string[]]$Arguments)
    & $FilePath @Arguments
    if ($LASTEXITCODE -ne 0) {
        throw "Command failed ($LASTEXITCODE): $FilePath $($Arguments -join ' ')"
    }
}

$RootDir = [System.IO.Path]::GetFullPath((Join-Path $PSScriptRoot '../..'))
if ($Target -and $TargetHost) {
    throw "Specify either -Target or -TargetHost, not both."
}

$Target = if ($Target) { $Target } elseif ($TargetHost) { Resolve-TargetForHost -SelectedHost $TargetHost } else { Get-DefaultTarget }
$Features = if ($Features) { $Features } else { 'jit jit-fastregs bench-instrument threaded-interp simd-blockio simd-xor-paths superscalar-accel-proto' }
$BinName = 'oxide-randomx-public-capture'

switch -Wildcard ($Target) {
    '*windows*' {
        $PlatformTag = 'windows-x86_64'
        $OutName = 'oxide-randomx-public-capture.exe'
        $InstructionsName = 'RUN_PUBLIC_CAPTURE_ON_WINDOWS_HOST.txt'
        $ArchiveName = 'oxide-randomx-public-capture-windows-x86_64.zip'
    }
    '*linux*' {
        $PlatformTag = 'linux-x86_64'
        $OutName = 'oxide-randomx-public-capture'
        $InstructionsName = 'RUN_PUBLIC_CAPTURE_ON_LINUX_HOST.txt'
        $ArchiveName = 'oxide-randomx-public-capture-linux-x86_64.tar.gz'
    }
    default { throw "unsupported TARGET '$Target'" }
}

if (-not $DistDir) {
    $DistDir = [System.IO.Path]::GetFullPath((Join-Path $RootDir "../oxide-randomx-dist/public_capture_${PlatformTag}"))
}

$RustupBin = Resolve-Tool -Current $RustupBin -Candidates @('rustup', 'rustup.exe')
$CargoBin = Resolve-Tool -Current $CargoBin -Candidates @('cargo', 'cargo.exe')
if (-not $RustupBin -or -not $CargoBin) {
    throw 'cargo and rustup are required'
}

$installedTargets = & $RustupBin target list --installed
if ($Target -notin @($installedTargets | ForEach-Object { $_.Trim() } | Where-Object { $_ })) {
    throw "target '$Target' is not installed"
}

Write-Host "Building $BinName for $Target with release ID: $ReleaseId"
$prevReleaseId = $env:OXIDE_RANDOMX_CAPTURE_RELEASE_ID
Push-Location $RootDir
try {
    $env:OXIDE_RANDOMX_CAPTURE_RELEASE_ID = $ReleaseId
    if ($Target -like '*-windows-gnu') {
        $env:CARGO_TARGET_X86_64_PC_WINDOWS_GNU_LINKER = $WindowsGnuLinker
    }
    if ((Test-HostIsWindows) -and $Target -eq 'x86_64-unknown-linux-gnu' -and $LinuxGnuLinker) {
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
    if ($null -ne $prevReleaseId) { $env:OXIDE_RANDOMX_CAPTURE_RELEASE_ID = $prevReleaseId } else { Remove-Item Env:OXIDE_RANDOMX_CAPTURE_RELEASE_ID -ErrorAction SilentlyContinue }
    Pop-Location
}

$SrcBin = Join-Path $RootDir "target/$Target/release/$BinName"
if ($Target -like '*windows*') { $SrcBin = "$SrcBin.exe" }

New-Item -ItemType Directory -Force -Path $DistDir | Out-Null
$OutPath = Join-Path $DistDir $OutName
$InstructionsPath = Join-Path $DistDir $InstructionsName
$ArchivePath = Join-Path $DistDir $ArchiveName
$ChecksumPath = Join-Path $DistDir 'SHA256SUMS.txt'
Copy-Item -LiteralPath $SrcBin -Destination $OutPath -Force

if ($Target -like '*windows*') {
    $InstructionsText = @'
Public capture run instructions for Windows x86_64

1) Copy `oxide-randomx-public-capture.exe` to the target Windows host.
2) Open PowerShell in that folder.
3) Run:

   .\oxide-randomx-public-capture.exe --accept-data-contract

4) For a deeper rerun, use:

   .\oxide-randomx-public-capture.exe --profile full --accept-data-contract

5) Send back the generated file named like:

   oxide-randomx-public-results-<bundle_id>.zip

Notes:
- No installer is required.
- No automatic upload happens.
- Manual code signing, if used, happens outside this repo.
'@
}
else {
    $InstructionsText = @'
Public capture run instructions for Linux x86_64

1) Copy `oxide-randomx-public-capture` to the target Linux host.
2) Open a shell in that folder.
3) Run:

   ./oxide-randomx-public-capture --accept-data-contract

4) For a deeper rerun, use:

   ./oxide-randomx-public-capture --profile full --accept-data-contract

5) Send back the generated file named like:

   oxide-randomx-public-results-<bundle_id>.zip

Notes:
- No installer is required.
- No automatic upload happens.
- Manual signing, if used, happens outside this repo.
'@
}

Set-Content -Path $InstructionsPath -Value $InstructionsText -Encoding ascii
$hash1 = (Get-FileHash -LiteralPath $OutPath -Algorithm SHA256).Hash.ToLowerInvariant()
$hash2 = (Get-FileHash -LiteralPath $InstructionsPath -Algorithm SHA256).Hash.ToLowerInvariant()
Set-Content -Path $ChecksumPath -Value @(
    "$hash1  $OutName"
    "$hash2  $InstructionsName"
) -Encoding ascii

if ($Target -like '*windows*') {
    if (Get-Command -Name 'Compress-Archive' -ErrorAction SilentlyContinue) {
        if (Test-Path -LiteralPath $ArchivePath) { Remove-Item -LiteralPath $ArchivePath -Force }
        Compress-Archive -Path $OutPath, $InstructionsPath, $ChecksumPath -DestinationPath $ArchivePath -Force
    }
}
elseif (Get-Command -Name 'tar' -ErrorAction SilentlyContinue) {
    if (Test-Path -LiteralPath $ArchivePath) { Remove-Item -LiteralPath $ArchivePath -Force }
    Invoke-External -FilePath 'tar' -Arguments @('-czf', $ArchivePath, '-C', $DistDir, $OutName, $InstructionsName, 'SHA256SUMS.txt')
}

Write-Host "Manual signing step (not automated here): sign $OutPath before public release if required."
Write-Host "Wrote: $OutPath"
Write-Host "Wrote: $InstructionsPath"
Write-Host "Wrote: $ChecksumPath"
if (Test-Path -LiteralPath $ArchivePath) {
    Write-Host "Wrote: $ArchivePath"
}
