#
# OxideMiner/scripts/windows/Disable-LargePages.ps1
#
# Rollback script to remove SeLockMemoryPrivilege from a user.
# It will:
#  - Modify local security policy to remove SeLockMemoryPrivilege from the target user.
# After success, SIGN OUT/IN (or restart the service account).

[CmdletBinding()]
param(
  [string]$User = "$env:USERDOMAIN\$env:USERNAME"
)

function Test-IsAdmin {
  $id=[Security.Principal.WindowsIdentity]::GetCurrent()
  $pri=New-Object Security.Principal.WindowsPrincipal($id)
  $pri.IsInRole([Security.Principal.WindowsBuiltinRole]::Administrator)
}
function Get-64BitHostPath {
  $c=Get-Command pwsh -ErrorAction SilentlyContinue
  $p=$null
  if($c){ $p=$c.Source; if($p -match 'Program Files \(x86\)'){ $p=$p -replace 'Program Files \(x86\)','Program Files'} }
  if(-not $p){ $p=Join-Path $env:ProgramFiles 'PowerShell\7\pwsh.exe' }
  if(-not (Test-Path $p)){ $p=Join-Path $env:SystemRoot 'System32\WindowsPowerShell\v1.0\powershell.exe' }
  $p
}
if(-not (Test-IsAdmin)){
  $me = $PSCommandPath; if(-not $me){ $me=$MyInvocation.MyCommand.Path }
  $hostPath = Get-64BitHostPath
  Start-Process -FilePath $hostPath -Verb RunAs -ArgumentList @('-NoProfile','-ExecutionPolicy','Bypass','-NoExit','-File',"$me","-User",$User) -Wait
  return
}

function Get-Sid($acct){
  (New-Object System.Security.Principal.NTAccount($acct)).
    Translate([System.Security.Principal.SecurityIdentifier]).Value
}

$sid = Get-Sid $User
$star="*$sid"

$temp = Join-Path $env:TEMP ("lp_" + [guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory -Path $temp -Force | Out-Null
$exp = Join-Path $temp 'secpol_export.inf'
$imp = Join-Path $temp 'secpol_import.inf'
$db  = Join-Path $temp 'secpol.sdb'
$sec = Join-Path $env:SystemRoot 'System32\secedit.exe'

& $sec /export /cfg "$exp" /areas USER_RIGHTS | Out-Null
if($LASTEXITCODE -ne 0){ Write-Host "Export failed: $LASTEXITCODE" -ForegroundColor Red; return 1 }

$lines = Get-Content -LiteralPath $exp -Encoding Unicode
$out   = New-Object System.Collections.Generic.List[string]
$inPR=$false
foreach($line in $lines){
  if($line -match '^\s*\[Privilege Rights\]\s*$'){ $inPR=$true; $out.Add($line); continue }
  if($inPR -and $line -match '^\s*\['){ $inPR=$false; $out.Add($line); continue }
  if($inPR -and $line -match '^\s*SeLockMemoryPrivilege\s*=\s*(.*)$'){
    $vals = $matches[1].Split(',') | ForEach-Object { $_.Trim() } | Where-Object { $_ }
    $vals = $vals | Where-Object { $_ -ne $star }
    if($vals.Count -gt 0){
      $out.Add("SeLockMemoryPrivilege = " + ($vals -join ', '))
    } else {
      # drop the line entirely if empty
    }
    continue
  }
  $out.Add($line)
}

[IO.File]::WriteAllText($imp, ($out -join "`r`n"), [Text.Encoding]::Unicode)
& $sec /configure /db "$db" /cfg "$imp" /areas USER_RIGHTS | Out-Null
if($LASTEXITCODE -ne 0){ Write-Host "Apply failed: $LASTEXITCODE" -ForegroundColor Red; return 1 }

Write-Host "Removed SeLockMemoryPrivilege for $User. Sign out/in to take effect." -ForegroundColor Yellow
