<#
.SYNOPSIS
    Grants the "Lock pages in memory" privilege to the current user on Windows Home editions.

.DESCRIPTION
    This script enables large pages support by granting the SeLockMemoryPrivilege to the
    current user. This is required for applications to allocate large pages (2MB) instead
    of standard 4KB pages, which can improve performance for memory-intensive workloads.

    On Windows Pro/Enterprise, this can be done via secpol.msc or gpedit.msc.
    On Windows Home, this script uses secedit to modify the local security policy.

.NOTES
    - Must be run as Administrator
    - Requires logout/restart to take effect
    - Only needs to be run once per user account

.EXAMPLE
    .\Enable-LargePages.ps1
#>

[CmdletBinding()]
param()

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

# Check for Administrator privileges
$isAdmin = ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $isAdmin) {
    Write-Host "ERROR: This script must be run as Administrator." -ForegroundColor Red
    Write-Host ""
    Write-Host "Please right-click PowerShell and select 'Run as Administrator', then run this script again." -ForegroundColor Yellow
    exit 1
}

$tempCfg = "$env:TEMP\secpol_largepages.cfg"
$tempDb = "$env:TEMP\secedit_largepages.sdb"

try {
    Write-Host "Enabling Large Pages for user: $env:USERNAME" -ForegroundColor Cyan
    Write-Host ""

    # Get current user's SID
    Write-Host "  [1/4] Resolving user SID..." -ForegroundColor Gray
    $ntAccount = New-Object System.Security.Principal.NTAccount($env:USERNAME)
    $sid = $ntAccount.Translate([System.Security.Principal.SecurityIdentifier]).Value
    Write-Host "        SID: $sid" -ForegroundColor DarkGray

    # Export current security policy
    Write-Host "  [2/4] Exporting current security policy..." -ForegroundColor Gray
    $exportResult = secedit /export /cfg $tempCfg 2>&1
    if ($LASTEXITCODE -ne 0) {
        throw "Failed to export security policy: $exportResult"
    }

    # Read and modify the policy
    Write-Host "  [3/4] Adding SeLockMemoryPrivilege..." -ForegroundColor Gray
    $cfg = Get-Content $tempCfg -Raw

    # Check if privilege line exists
    if ($cfg -match 'SeLockMemoryPrivilege\s*=\s*(.*)') {
        $currentValue = $Matches[1].Trim()

        # Check if user already has the privilege
        if ($currentValue -match [regex]::Escape("*$sid")) {
            Write-Host ""
            Write-Host "User '$env:USERNAME' already has the Lock Pages in Memory privilege." -ForegroundColor Green
            Write-Host "No changes needed." -ForegroundColor Green
            exit 0
        }

        # Add user to existing privilege (prepend with comma if there are existing entries)
        if ($currentValue -and $currentValue -ne "") {
            $cfg = $cfg -replace '(SeLockMemoryPrivilege\s*=\s*)', "`$1*$sid,"
        } else {
            $cfg = $cfg -replace '(SeLockMemoryPrivilege\s*=\s*)', "`$1*$sid"
        }
    } else {
        # Privilege line doesn't exist, add it to [Privilege Rights] section
        if ($cfg -match '\[Privilege Rights\]') {
            $cfg = $cfg -replace '(\[Privilege Rights\])', "`$1`r`nSeLockMemoryPrivilege = *$sid"
        } else {
            # No [Privilege Rights] section, append it
            $cfg += "`r`n[Privilege Rights]`r`nSeLockMemoryPrivilege = *$sid`r`n"
        }
    }

    # Write modified policy
    $cfg | Set-Content $tempCfg -Encoding Unicode

    # Apply the modified policy
    Write-Host "  [4/4] Applying modified security policy..." -ForegroundColor Gray
    $configResult = secedit /configure /db $tempDb /cfg $tempCfg 2>&1
    if ($LASTEXITCODE -ne 0) {
        throw "Failed to apply security policy: $configResult"
    }

    Write-Host ""
    Write-Host "SUCCESS: Lock Pages in Memory privilege granted to '$env:USERNAME'" -ForegroundColor Green
    Write-Host ""
    Write-Host "IMPORTANT: You must log out and log back in (or restart) for changes to take effect." -ForegroundColor Yellow
    Write-Host ""

} catch {
    Write-Host ""
    Write-Host "ERROR: $($_.Exception.Message)" -ForegroundColor Red
    exit 1

} finally {
    # Cleanup temporary files
    if (Test-Path $tempCfg) { Remove-Item $tempCfg -Force -ErrorAction SilentlyContinue }
    if (Test-Path $tempDb) { Remove-Item $tempDb -Force -ErrorAction SilentlyContinue }
}
