param(
    [Parameter(ValueFromRemainingArguments = $true)]
    [string[]]$ForwardArgs
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

$binary = Join-Path $PSScriptRoot 'oxide-randomx-v8_01-amd-capture.exe'
if (-not (Test-Path $binary)) {
    throw "Missing packaged binary: $binary. Use scripts/build/package_v8_01_amd_capture.sh --target-host windows or scripts/build/package_v8_01_amd_capture.ps1 -TargetHost windows to build the single-binary bundle first."
}

Write-Warning 'run_v8_01_amd_windows_capture.ps1 is now a compatibility forwarder to oxide-randomx-v8_01-amd-capture.exe.'
& $binary @ForwardArgs
exit $LASTEXITCODE
