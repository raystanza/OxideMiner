# Enable-LargePages.ps1
# Grants "Lock pages in memory" (SeLockMemoryPrivilege) to a user so apps can use large pages.
# Usage (Run as Admin):
#   .\Enable-LargePages.ps1                   # targets current user
#   .\Enable-LargePages.ps1 -User 'MYPC\miner' # explicit user
# Notes: Sign out/in after success so new privilege is in your token.

[CmdletBinding()]
param(
    [string]$User = "$env:USERDOMAIN\$env:USERNAME"
)

function Assert-Administrator {
    $isAdmin = ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).
        IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
    if (-not $isAdmin) {
        Write-Host "ERROR: This script must be run as Administrator." -ForegroundColor Red
        exit 1
    }
}

function Get-Sid([string]$accountName) {
    try {
        $nt = New-Object System.Security.Principal.NTAccount($accountName)
        return ($nt.Translate([System.Security.Principal.SecurityIdentifier]).Value)
    } catch {
        Write-Host "ERROR: Could not resolve user '$accountName' to a SID." -ForegroundColor Red
        throw
    }
}

function Update-SeLockMemoryPrivilege([string]$sid) {
    $temp = [IO.Path]::GetTempPath()
    $export = Join-Path $temp ("secpol-export-{0}.inf" -f ([guid]::NewGuid()))
    $import = Join-Path $temp ("secpol-import-{0}.inf" -f ([guid]::NewGuid()))
    $dbPath = Join-Path $temp ("secpol-{0}.sdb" -f ([guid]::NewGuid()))

    Write-Host "1) Exporting current local security policy..." -ForegroundColor Cyan
    $p = Start-Process secedit "/export /cfg `"$export`"" -PassThru -Wait -WindowStyle Hidden
    if ($p.ExitCode -ne 0) { throw "secedit export failed with code $($p.ExitCode)" }

    Write-Host "2) Preparing updated INF with SeLockMemoryPrivilege for SID: $sid" -ForegroundColor Cyan
    $content = Get-Content -Raw -LiteralPath $export
    if ($content -notmatch '\[Privilege Rights\]') {
        $content = $content.TrimEnd() + "`r`n`r`n[Privilege Rights]`r`n"
    }

    $lines = $content -split "`r?`n"
    $outLines = New-Object System.Collections.Generic.List[string]
    $inPrivilegeSection = $false
    $handled = $false

    foreach ($line in $lines) {
        if ($line -match '^\s*\[Privilege Rights\]\s*$') { $inPrivilegeSection = $true }
        if ($inPrivilegeSection -and $line -match '^\s*SeLockMemoryPrivilege\s*=\s*(.*)$') {
            $existing = $matches[1].Split(',') | ForEach-Object { $_.Trim() } | Where-Object { $_ -ne '' }
            $sidEntry = "*$sid"
            if ($existing -notcontains $sidEntry) { $existing += $sidEntry }
            $new = "SeLockMemoryPrivilege = " + ($existing -join ',')
            $outLines.Add($new)
            $handled = $true
        } else {
            $outLines.Add($line)
        }
    }

    if (-not $handled) {
        # Append inside [Privilege Rights]
        $idx = $outLines.FindIndex({ $_ -match '^\s*\[Privilege Rights\]\s*$' })
        if ($idx -ge 0) {
            $outLines.Insert($idx + 1, "SeLockMemoryPrivilege = *$sid")
        } else {
            # Fallback: append at end with section
            $outLines.Add("[Privilege Rights]")
            $outLines.Add("SeLockMemoryPrivilege = *$sid")
        }
    }

    $final = ($outLines -join "`r`n")
    [System.IO.File]::WriteAllText($import, $final, [System.Text.Encoding]::Unicode)

    Write-Host "3) Applying updated privilege rights (this changes local security policy)..." -ForegroundColor Cyan
    $p = Start-Process secedit "/configure /db `"$dbPath`" /cfg `"$import`" /areas USER_RIGHTS" -PassThru -Wait -WindowStyle Hidden
    if ($p.ExitCode -ne 0) { throw "secedit configure failed with code $($p.ExitCode)" }

    Write-Host "4) Forcing policy refresh..." -ForegroundColor Cyan
    Start-Process gpupdate "/target:computer /force" -Wait -WindowStyle Hidden | Out-Null

    Write-Host ""
    Write-Host "SUCCESS: 'Lock pages in memory' granted to $User." -ForegroundColor Green
    Write-Host "IMPORTANT: Sign out and back in (or restart the service account) so the new privilege appears in your token."
    Write-Host "You can check with:  whoami /priv | findstr /I SeLockMemoryPrivilege"
}

try {
    Assert-Administrator
    Write-Host "Enabling Large Pages (SeLockMemoryPrivilege) for user: $User" -ForegroundColor Yellow
    Write-Host "This lets apps that request large pages allocate them. It does NOT force large pages globally." -ForegroundColor DarkYellow
    $sid = Get-Sid -accountName $User
    Update-SeLockMemoryPrivilege -sid $sid
} catch {
    Write-Host "FAILED: $($_.Exception.Message)" -ForegroundColor Red
    exit 1
}
