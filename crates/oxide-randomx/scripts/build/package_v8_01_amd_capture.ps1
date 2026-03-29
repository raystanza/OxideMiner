param(
    [ValidateSet('windows', 'linux')]
    [string]$TargetHost = $env:TARGET_HOST,
    [string]$Target = $env:TARGET,
    [string]$Features = $env:FEATURES,
    [string]$DistDir = $env:DIST_DIR,
    [string]$WindowsGnuLinker = $(if ($env:WINDOWS_GNU_LINKER) { $env:WINDOWS_GNU_LINKER } elseif ($env:CARGO_TARGET_X86_64_PC_WINDOWS_GNU_LINKER) { $env:CARGO_TARGET_X86_64_PC_WINDOWS_GNU_LINKER } else { 'x86_64-w64-mingw32-gcc' }),
    [string]$RustupBin = $env:RUSTUP_BIN,
    [string]$CargoBin = $env:CARGO_BIN
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

function Get-DefaultTarget {
    if ([System.Runtime.InteropServices.RuntimeInformation]::IsOSPlatform([System.Runtime.InteropServices.OSPlatform]::Windows)) {
        return 'x86_64-pc-windows-msvc'
    }

    return 'x86_64-unknown-linux-gnu'
}

function Get-WindowsTarget {
    if ([System.Runtime.InteropServices.RuntimeInformation]::IsOSPlatform([System.Runtime.InteropServices.OSPlatform]::Windows)) {
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

$Features = if ($Features) { $Features } else { 'jit jit-fastregs bench-instrument' }
$BinName = 'v8_01_amd_capture'

switch -Wildcard ($Target) {
    '*windows*' {
        $PlatformTag = 'windows'
        $OutName = 'oxide-randomx-v8_01-amd-capture.exe'
        $InstructionsName = 'RUN_ON_REMOTE_WINDOWS_HOST.txt'
        $ArchiveName = 'oxide-randomx-v8_01-amd-capture.zip'
    }
    '*linux*' {
        $PlatformTag = 'linux'
        $OutName = 'oxide-randomx-v8_01-amd-capture'
        $InstructionsName = 'RUN_ON_REMOTE_UBUNTU_LINUX_HOST.txt'
        $ArchiveName = 'oxide-randomx-v8_01-amd-capture-linux.tar.gz'
    }
    default {
        throw "unsupported TARGET '$Target' (expected a Windows or Linux target)"
    }
}

if (-not $DistDir) {
    $DistRoot = [System.IO.Path]::GetFullPath((Join-Path $RootDir '..'))
    $DistDir = Join-Path $DistRoot "oxide-randomx-dist/v8_01_amd_${PlatformTag}_capture"
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

Write-Host "Building $BinName for $Target with features: $Features"
Push-Location $RootDir
try {
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

if ($PlatformTag -eq 'windows') {
    $InstructionsText = @'
Run instructions for remote AMD Windows 11 owner

1) Copy `oxide-randomx-v8_01-amd-capture.exe` to the target AMD Windows machine.
2) Open PowerShell in that folder.
3) Run:

   .\oxide-randomx-v8_01-amd-capture.exe

4) Wait for completion.
5) The tool prints the artifact folder path and writes `v8_01_share_instructions_*.txt`.
6) Send the entire output folder as a zip to: raystanza@raystanza.uk

Optional run args:
- `--perf-iters 50 --perf-warmup 5`
- `--threads 12`
- `--large-pages off`
- `--validate-only`

Important:
- This single binary captures perf rows only.
- Required validation (`cargo test`, oracle runs, bench-instrument runs) must still be performed on the clean build host that produced the binary.
'@
}
else {
    $InstructionsText = @'
Run instructions for remote Ubuntu/Debian AMD Linux host owner

1) Copy `oxide-randomx-v8_01-amd-capture` to the target AMD Linux machine.
2) Open a shell in that folder.
3) Run:

   ./oxide-randomx-v8_01-amd-capture

4) Wait for completion.
5) The tool prints the artifact folder path and writes `v8_01_share_instructions_*.txt`.
6) Send the entire output folder as a tarball/zip to: raystanza@raystanza.uk

Optional run args:
- `--perf-iters 50 --perf-warmup 5`
- `--threads 12`
- `--large-pages off`
- `--validate-only`

Important:
- This single binary captures perf rows only.
- Required validation (`cargo test`, oracle runs, bench-instrument runs) must still be performed on the clean build host that produced the binary.
'@
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
