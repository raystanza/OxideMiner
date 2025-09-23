#
# OxideMiner/scripts/windows/Enable-LargePages.ps1
#
# Grants "Lock pages in memory" (SeLockMemoryPrivilege) to a user so apps can use large pages.
# RUN THIS FROM AN ELEVATED (ADMIN) POWERSHELL.
# Usage:
#   .\Enable-LargePages.ps1                      # target current user
#   .\Enable-LargePages.ps1 -User 'MACHINE\miner' # explicit local user
#   .\Enable-LargePages.ps1 -User 'DOMAIN\user'   # domain user
# Optional:
#   -SkipGpUpdate   # do not call gpupdate /force
#   -Verbose        # print detailed steps

[CmdletBinding()]
param(
    [string]$User = "$env:USERDOMAIN\$env:USERNAME",
    [switch]$SkipGpUpdate
)

function Assert-Administrator {
    $id  = [Security.Principal.WindowsIdentity]::GetCurrent()
    $pri = New-Object Security.Principal.WindowsPrincipal($id)
    if (-not $pri.IsInRole([Security.Principal.WindowsBuiltinRole]::Administrator)) {
        Write-Error "This script must be run as Administrator. Right-click your console > Run as administrator."
        return $false
    }
    return $true
}

function Resolve-UserSid([string]$AccountName) {
    try {
        $nt  = New-Object System.Security.Principal.NTAccount($AccountName)
        $sid = $nt.Translate([System.Security.Principal.SecurityIdentifier]).Value
        return $sid
    } catch {
        throw "Could not resolve account '$AccountName' to a SID. Try 'MACHINE\user' or 'DOMAIN\user'."
    }
}

function Get-SeceditPath {
    $p = Join-Path $env:SystemRoot 'System32\secedit.exe'
    if (-not (Test-Path $p)) { throw "secedit.exe not found at $p" }
    return $p
}

function Export-LocalPolicy([string]$OutInfPath) {
    $secedit = Get-SeceditPath
    Write-Verbose "Exporting USER_RIGHTS to: $OutInfPath"
    & $secedit /export /cfg "$OutInfPath" /areas USER_RIGHTS | Out-Null
    if ($LASTEXITCODE -eq 740) { throw "Elevation required (exit 740). Run this script as Administrator." }
    if ($LASTEXITCODE -ne 0 -or -not (Test-Path $OutInfPath)) {
        throw "secedit export failed with exit code $LASTEXITCODE"
    }
}

function Set-LocalPolicy([string]$DbPath, [string]$CfgPath) {
    $secedit = Get-SeceditPath
    Write-Verbose "Applying USER_RIGHTS from: $CfgPath"
    & $secedit /configure /db "$DbPath" /cfg "$CfgPath" /areas USER_RIGHTS | Out-Null
    if ($LASTEXITCODE -ne 0) {
        throw "secedit configure failed with exit code $LASTEXITCODE"
    }
}

function Merge-SeLockMemoryPrivilege([string[]]$InfLines, [string]$Sid) {
    # Returns updated lines with *SID added to SeLockMemoryPrivilege (de-duplicated)
    $out    = New-Object System.Collections.Generic.List[string]
    $inPR   = $false
    $found  = $false
    $sawPR  = $false
    $star   = "*$Sid"

    for ($i = 0; $i -lt $InfLines.Count; $i++) {
        $line = $InfLines[$i]

        if ($line -match '^\s*\[Privilege Rights\]\s*$') {
            $inPR = $true
            $sawPR = $true
            $out.Add($line)
            continue
        }

        if ($inPR -and $line -match '^\s*\[') {
            if (-not $found) {
                $out.Add("SeLockMemoryPrivilege = $star")
                $found = $true
            }
            $inPR = $false
            $out.Add($line)
            continue
        }

        if ($inPR -and $line -match '^\s*SeLockMemoryPrivilege\s*=\s*(.*)$') {
            $vals = $matches[1].Split(',') | ForEach-Object { $_.Trim() } | Where-Object { $_ }
            if ($vals -notcontains $star) { $vals += $star }
            $vals = $vals | Select-Object -Unique
            $out.Add("SeLockMemoryPrivilege = " + ($vals -join ', '))
            $found = $true
            continue
        }

        $out.Add($line)
    }

    if (-not $sawPR) {
        $out.Add('')
        $out.Add('[Privilege Rights]')
        $out.Add("SeLockMemoryPrivilege = $star")
        $found = $true
    } elseif ($inPR -and -not $found) {
        $out.Add("SeLockMemoryPrivilege = $star")
        $found = $true
    }

    return ,$out
}

function Grant-SeLockMemoryPrivilege([string]$TargetUser) {
    Write-Host "Target user: $TargetUser" -ForegroundColor Yellow
    $sid = Resolve-UserSid $TargetUser
    Write-Host "Resolved SID: $sid" -ForegroundColor Yellow

    $temp    = Join-Path $env:TEMP ("lp_" + [Guid]::NewGuid().ToString('N'))
    New-Item -ItemType Directory -Force -Path $temp | Out-Null
    $export  = Join-Path $temp 'secpol_export.inf'
    $import  = Join-Path $temp 'secpol_import.inf'
    $db      = Join-Path $temp 'secpol.sdb'

    # 1) Export
    Write-Host "1) Exporting current local security policy (USER_RIGHTS)..." -ForegroundColor Cyan
    Export-LocalPolicy -OutInfPath $export

    # 2) Merge
    Write-Host "2) Updating SeLockMemoryPrivilege with *$sid ..." -ForegroundColor Cyan
    $lines = Get-Content -LiteralPath $export -Encoding Unicode
    $updated = Merge-SeLockMemoryPrivilege -InfLines $lines -Sid $sid
    [System.IO.File]::WriteAllText($import, ($updated -join "`r`n"), [System.Text.Encoding]::Unicode)

    # 3) Apply
    Write-Host "3) Applying updated privilege rights..." -ForegroundColor Cyan
    Set-LocalPolicy -DbPath $db -CfgPath $import

    if (-not $SkipGpUpdate) {
        Write-Host "4) Forcing policy refresh (gpupdate /target:computer /force)..." -ForegroundColor Cyan
        & (Join-Path $env:SystemRoot 'System32\gpupdate.exe') /target:computer /force | Out-Null
        # ignore gpupdate exit code; local user rights typically apply without it, but this helps under some configs
    } else {
        Write-Verbose "Skipping gpupdate per -SkipGpUpdate."
    }

    # 5) Verify by re-export
    Write-Host "5) Verifying assignment by re-exporting policy..." -ForegroundColor Cyan
    $verify = Join-Path $temp 'verify.inf'
    Export-LocalPolicy -OutInfPath $verify
    $verifyLines = Get-Content -LiteralPath $verify -Encoding Unicode

    $inPR = $false
    $present = $false
    foreach ($line in $verifyLines) {
        if ($line -match '^\s*\[Privilege Rights\]\s*$') { $inPR = $true; continue }
        if ($inPR -and $line -match '^\s*\[') { break }
        if ($inPR -and $line -match '^\s*SeLockMemoryPrivilege\s*=\s*(.*)$') {
            $vals = $matches[1].Split(',') | ForEach-Object { $_.Trim() } | Where-Object { $_ }
            if ($vals -contains "*$sid") { $present = $true; break }
        }
    }

    if ($present) {
        Write-Host ""
        Write-Host "SUCCESS: 'Lock pages in memory' (SeLockMemoryPrivilege) is assigned to $TargetUser." -ForegroundColor Green
        Write-Host "IMPORTANT: Sign out and back in (or restart the service account) so the new privilege is in your logon token."
        Write-Host "Note: 'whoami /priv' may show SeLockMemoryPrivilege as 'Disabled' until an app enables it at runtime." -ForegroundColor DarkYellow
    } else {
        Write-Host ""
        Write-Host "WARNING: Could not confirm the SID under SeLockMemoryPrivilege after applying." -ForegroundColor Yellow
        Write-Host "Check for domain GPO overrides (run: gpresult /r) or re-run this script." -ForegroundColor Yellow
    }

    Write-Host ""
    Write-Host "Diagnostics:" -ForegroundColor DarkCyan
    Write-Host "  whoami /priv | findstr /I SeLockMemoryPrivilege"
    Write-Host "  gpresult /r"
    Write-Host "  (If domain-joined, domain GPO can override local Privilege Rights.)"
}

# ----- Main -----
if (-not (Assert-Administrator)) { return }
try {
    Write-Host "Granting Large Pages privilege (SeLockMemoryPrivilege) for: $User" -ForegroundColor White
    Grant-SeLockMemoryPrivilege -TargetUser $User
} catch {
    Write-Host "FAILED: $($_.Exception.Message)" -ForegroundColor Red
    # Do not close the window; just return.
}
