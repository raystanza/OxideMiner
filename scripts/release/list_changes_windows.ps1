#!/usr/bin/env pwsh
<#
.SYNOPSIS
  Generate a Markdown changelog for the current Git repo.

.DESCRIPTION
  Default: full history → changelog_full.md at repo root.
  -LatestOnly: only commits that make up the most recent tag since the previous tag
               → changelog_<prev>_to_<latest>.md
#>

param(
    [switch] $LatestOnly
)

# ----- Preconditions -----
if (-not (Get-Command git -ErrorAction SilentlyContinue)) {
    Write-Error "git is not installed or not on PATH."
    exit 1
}

try {
    $repoRoot = git rev-parse --show-toplevel 2>$null
    if (-not $repoRoot) { throw "Not a Git repo" }
} catch {
    Write-Error "This script must be run inside a Git repository."
    exit 1
}

$repoRoot = $repoRoot.Trim()
Set-Location $repoRoot

$branchName = (git rev-parse --abbrev-ref HEAD 2>$null).Trim()

function Get-GitTagsAscending {
    git tag --sort=creatordate 2>$null | Where-Object { $_ -and $_.Trim() -ne "" }
}

$tagsAsc = @(Get-GitTagsAscending)

if ($LatestOnly -and $tagsAsc.Count -eq 0) {
    Write-Warning "No tags found; falling back to full history."
    $LatestOnly = $false
}

# Accumulator for Markdown lines
$lines = New-Object System.Collections.Generic.List[string]

function Add-Line {
    param([string] $Text)
    [void]$lines.Add($Text)
}

Add-Line "# OxideMiner Change History"
Add-Line ""
Add-Line ('- Branch: `{0}`' -f $branchName)
Add-Line ("- Generated: {0}" -f (Get-Date -Format 'yyyy-MM-dd HH:mm:ss'))
Add-Line ""

function Get-SectionCommits {
    param([string] $Range)
    $log = git log --no-merges --pretty=format:'%H%x01%an%x01%ad%x01%s' --date=short $Range 2>$null
    if (-not $log) { return @() }

    return $log -split "`n" | ForEach-Object {
        if (-not $_) { return }
        $parts = $_ -split ([char]0x1)
        if ($parts.Count -lt 4) { return }

        [pscustomobject]@{
            Sha     = $parts[0]
            Author  = $parts[1]
            Date    = $parts[2]
            Subject = $parts[3]
        }
    }
}

function Group-Commits {
    param([array] $Commits)

    $categories = [ordered]@{
        "Features"       = New-Object System.Collections.Generic.List[object]
        "Fixes"          = New-Object System.Collections.Generic.List[object]
        "Docs"           = New-Object System.Collections.Generic.List[object]
        "Refactors"      = New-Object System.Collections.Generic.List[object]
        "Chores / Build" = New-Object System.Collections.Generic.List[object]
        "Other"          = New-Object System.Collections.Generic.List[object]
    }

    foreach ($c in $Commits) {
        $subject = $c.Subject
        $lower   = $subject.ToLowerInvariant()

        if     ($lower.StartsWith("feat:")     -or $lower.StartsWith("feat(")     -or $lower.StartsWith("feature:")) {
            $categories["Features"].Add($c)
        }
        elseif ($lower.StartsWith("fix:")      -or $lower.StartsWith("fix(")      -or
                $lower.StartsWith("bug:")      -or $lower.StartsWith("bugfix:")) {
            $categories["Fixes"].Add($c)
        }
        elseif ($lower.StartsWith("doc:")      -or $lower.StartsWith("docs:")     -or
                $lower.StartsWith("readme:")   -or $lower.StartsWith("readme(")) {
            $categories["Docs"].Add($c)
        }
        elseif ($lower.StartsWith("refactor:") -or $lower.StartsWith("refactor(")) {
            $categories["Refactors"].Add($c)
        }
        elseif ($lower.StartsWith("chore:")    -or $lower.StartsWith("chore(")    -or
                $lower.StartsWith("build:")) {
            $categories["Chores / Build"].Add($c)
        }
        else {
            $categories["Other"].Add($c)
        }
    }

    return $categories
}

function Write-SectionMd {
    param(
        [string] $Title,
        [string] $Range
    )

    $commits = @(Get-SectionCommits -Range $Range)
    if ($commits.Count -eq 0) { return }

    Add-Line ""
    Add-Line ("## {0}" -f $Title)
    Add-Line ""

    $categories = Group-Commits -Commits $commits

    foreach ($key in $categories.Keys) {
        $list = $categories[$key]
        if ($list.Count -eq 0) { continue }

        Add-Line ("### {0}" -f $key)
        Add-Line ""

        foreach ($c in $list) {
            $short = if ($c.Sha.Length -ge 7) { $c.Sha.Substring(0,7) } else { $c.Sha }
            Add-Line ("- [{0}] {1} ({2}, {3})" -f $short, $c.Subject, $c.Author, $c.Date)
        }

        Add-Line ""
    }
}

function SanitizeTag {
    param([string] $Tag)
    $t = $Tag -replace '[\\/ ]', '_'
    return $t
}

$outFileName = $null

if ($tagsAsc.Count -eq 0) {
    # No tags at all → single section with full history
    $outFileName = "dev\changelog_full.md"
    Write-SectionMd -Title "All changes (no Git tags yet)" -Range "HEAD"
}
else {
    if ($LatestOnly) {
        $lastIndex = $tagsAsc.Count - 1
        $latestTag = $tagsAsc[$lastIndex].Trim()
        if ($tagsAsc.Count -ge 2) {
            $prevTag = $tagsAsc[$lastIndex - 1].Trim()
        } else {
            $prevTag = $null
        }

        $safeLatest = SanitizeTag $latestTag
        if ($prevTag) {
            $safePrev    = SanitizeTag $prevTag
            $outFileName = "dev\changelog_{0}_to_{1}.md" -f $safePrev, $safeLatest
            Write-SectionMd -Title ("Changes for {0} (since {1})" -f $latestTag, $prevTag) `
                            -Range ("{0}..{1}" -f $prevTag, $latestTag)
        }
        else {
            $outFileName = "dev\changelog_{0}.md" -f $safeLatest
            Write-SectionMd -Title ("Changes for {0}" -f $latestTag) -Range $latestTag
        }
    }
    else {
        $outFileName = "dev\changelog_full.md"

        $sections  = New-Object System.Collections.Generic.List[object]
        $lastIndex = $tagsAsc.Count - 1
        $latestTag = $tagsAsc[$lastIndex].Trim()

        $sections.Add([pscustomobject]@{
            Title = "Unreleased (since $latestTag)"
            Range = "$latestTag..HEAD"
        })

        for ($i = 0; $i -lt $tagsAsc.Count; $i++) {
            $cur  = $tagsAsc[$i].Trim()
            $date = git log -1 --format='%ad' --date=short $cur 2>$null

            if ($i -eq 0) {
                $range = $cur
            }
            else {
                $prev  = $tagsAsc[$i-1].Trim()
                $range = "$prev..$cur"
            }

            $sections.Add([pscustomobject]@{
                Title = "$cur ($date)"
                Range = $range
            })
        }

        for ($i = $sections.Count - 1; $i -ge 0; $i--) {
            $s = $sections[$i]
            Write-SectionMd -Title $s.Title -Range $s.Range
        }
    }
}

if (-not $outFileName) {
    $outFileName = "changelog_full.md"
}

$outPath = Join-Path $repoRoot $outFileName
$lines | Set-Content -Encoding UTF8 $outPath

Write-Host ("Generated {0}" -f $outPath)
exit 0