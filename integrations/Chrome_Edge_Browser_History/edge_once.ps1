<# Microsoft Edge → NDJSON incremental exporter for Wazuh (Windows)
   - One-time execution
   - Daily log rotation (logs & debug)
   - AllUsers support
   - Safe logging
   - Pre-creates NDJSON files
#>

[CmdletBinding()]
param(
    [int]$IntervalSeconds = 20,
    [switch]$BootstrapEmitExisting, # export existing history on first run
    [switch]$AllUsers,              # scan all users
    [string]$DebugLog = "C:\WazuhLogs\Exporting-Edge-Browser-History-to-Wazuh-Windows\edge_export_debug.log"
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

# ===================== CONFIG =====================
$SQLite   = "C:\sqlite\sqlite3.exe"
$OutDir   = "C:\WazuhLogs\Exporting-Edge-Browser-History-to-Wazuh-Windows"
$TmpDir   = Join-Path $env:TEMP "edge_hist_export"
$StateDir = "C:\Users\Public\state\edge"
$MaxRows  = 200000
$ProfileRegex = '^(Default|Profile \d+)$'
# ================== END CONFIG ====================

# ---------- Prep (dirs, daily log rotation) ----------
[void][IO.Directory]::CreateDirectory($OutDir)
[void][IO.Directory]::CreateDirectory($TmpDir)
[void][IO.Directory]::CreateDirectory($StateDir)

$Today = (Get-Date).ToString('yyyy-MM-dd')
$UrlsLog = Join-Path $OutDir "edge_urls_$Today.ndjson"
$VLLog   = Join-Path $OutDir "edge_visited_links_$Today.ndjson"
$VSLog   = Join-Path $OutDir "edge_visit_source_$Today.ndjson"

foreach ($f in @($UrlsLog, $VLLog, $VSLog, $DebugLog)) {
    $dir = Split-Path $f -Parent
    if ($dir) { [void][IO.Directory]::CreateDirectory($dir) }
    if (-not (Test-Path -LiteralPath $f)) { New-Item -ItemType File -Path $f -Force | Out-Null }
}

# ---------- Debug helper ----------
function Write-DebugLog { 
    param([string]$msg)
    $stamp = (Get-Date).ToString("s")
    Add-Content -Path $DebugLog -Value "[$stamp] $msg"
}

$Utf8NoBom = New-Object System.Text.UTF8Encoding($false)
function Write-NDJson { 
    param([hashtable]$Obj, [string]$Path)
    $line = ($Obj | ConvertTo-Json -Compress)
    $sw = New-Object System.IO.StreamWriter($Path, $true, $Utf8NoBom)
    try { $sw.WriteLine($line) } finally { $sw.Close() }
}

# ---------- SQLite resolver ----------
function Resolve-Sqlite { 
    param([string]$PathPref)
    if ($PathPref -and (Test-Path -LiteralPath $PathPref)) { return $PathPref }
    $cmd = Get-Command sqlite3.exe -ErrorAction SilentlyContinue
    if ($cmd) { return $cmd.Source }
    throw "sqlite3.exe not found. Set `$SQLite or add it to PATH."
}
$SQLite = Resolve-Sqlite $SQLite
Write-DebugLog ("Using sqlite3 at: {0}" -f $SQLite)

# ---------- Safe helpers ----------
function SafeStr([object]$v, [string]$fallback = "<unknown>") {
    if ($null -eq $v) { return $fallback }
    $s = "$v"
    if ([string]::IsNullOrWhiteSpace($s)) { return $fallback }
    return $s
}
function SafeName([string]$s) { $s = SafeStr $s "<unknown>"; return ($s -replace '[\\/:*?"<>|]', '_') }
function Table-Exists($db, $table) {
    $q = "SELECT name FROM sqlite_master WHERE type='table' AND name='$table';"
    $res = & $SQLite -noheader $db $q 2>$null
    return [bool]$res
}
function Invoke-SqliteJson { 
    param([string]$db, [string]$sql)
    $json = & $SQLite -json $db $sql 2>$null
    if ([string]::IsNullOrWhiteSpace($json)) { return @() }
    try { 
        $res = $json | ConvertFrom-Json -ErrorAction Stop
        if ($null -eq $res) { @() }
        elseif ($res -is [System.Array]) { $res }
        else { @($res) }
    } catch { @() }
}
function Convert-EdgeTimeToIso8601([long]$us) {
    if (-not $us) { return $null }
    $epoch = [DateTime]::new(1601,1,1,0,0,0,[DateTimeKind]::Utc)
    try { $epoch.AddTicks($us * 10).ToString("o") } catch { $null }
}
function Load-State([string]$file) {
    if (Test-Path -LiteralPath $file) {
        try { return (Get-Content -LiteralPath $file -Raw | ConvertFrom-Json) } catch {}
    }
    [ordered]@{
        urls_last_visit_time_us = 0
        visit_last_time_us = 0
        visited_links_last_row262 = 0
        bootstrapped = $false
    }
}
function Save-State($state, [string]$file) {
    ($state | ConvertTo-Json -Compress) | Set-Content -Path $file -Encoding UTF8
}
function Bootstrap-State-IfNeeded([string]$db, [hashtable]$state) {
    if ($state.bootstrapped -or -not (Test-Path -LiteralPath $db)) { return $state }
    $urlsMax = 0; $visitMax = 0; $vlMax = 0
    if (Table-Exists $db 'urls') {
        $r = & $SQLite -noheader $db "SELECT COALESCE(MAX(last_visit_time),0) FROM urls;" 2>$null
        [void][long]::TryParse("$r", [ref]$urlsMax)
    }
    if (Table-Exists $db 'visit_source' -and (Table-Exists $db 'visits')) {
        $r = & $SQLite -noheader $db "SELECT COALESCE(MAX(v.visit_time),0) FROM visit_source vs JOIN visits v ON v.id=vs.id;" 2>$null
        [void][long]::TryParse("$r", [ref]$visitMax)
    }
    if (Table-Exists $db 'visited_links') {
        $r = & $SQLite -noheader $db "SELECT COALESCE(MAX(rowid),0) FROM visited_links;" 2>$null
        [void][long]::TryParse("$r", [ref]$vlMax)
    }
    $state.urls_last_visit_time_us = $urlsMax
    $state.visit_last_time_us = $visitMax
    $state.visited_links_last_row262 = $vlMax
    $state.bootstrapped = $true
    return $state
}

# ---------- TARGET DISCOVERY (MICROSOFT EDGE) ----------
function Get-Targets {
    $targets = @()
    if ($AllUsers) {
        Write-DebugLog "Scanning all users under C:\Users (SYSTEM mode)."
        $userDirs = Get-ChildItem -Directory 'C:\Users' -ErrorAction SilentlyContinue |
                    Where-Object { $_.Name -notin @('Public','Default','Default User','All Users') -and -not $_.Name.StartsWith('WDAGUtilityAccount') }
        foreach ($ud in $userDirs) {
            $root = Join-Path $ud.FullName 'AppData\Local\Microsoft\Edge\User Data'
            if (-not (Test-Path -LiteralPath $root)) { continue }
            $profiles = Get-ChildItem -Directory $root -ErrorAction SilentlyContinue | Where-Object { $_.Name -match $ProfileRegex }
            foreach ($p in $profiles) {
                $hist = Join-Path $p.FullName 'History'
                if (-not (Test-Path -LiteralPath $hist)) { continue }
                $targets += [pscustomobject]@{
                    WinUser = SafeStr $ud.Name 'unknown'
                    ProfileName = SafeStr $p.Name 'Default'
                    ProfileDir = $p.FullName
                    HistoryPath = $hist
                }
            }
        }
    } else {
        $currentRoot = Join-Path $env:LOCALAPPDATA 'Microsoft\Edge\User Data'
        Write-DebugLog ("Scanning current user root: {0}" -f $currentRoot)
        if (Test-Path -LiteralPath $currentRoot) {
            $profiles = Get-ChildItem -Directory $currentRoot -ErrorAction SilentlyContinue | Where-Object { $_.Name -match $ProfileRegex }
            foreach ($p in $profiles) {
                $hist = Join-Path $p.FullName 'History'
                if (-not (Test-Path -LiteralPath $hist)) { continue }
                $targets += [pscustomobject]@{
                    WinUser = SafeStr $env:USERNAME 'unknown'
                    ProfileName = SafeStr $p.Name 'Default'
                    ProfileDir = $p.FullName
                    HistoryPath = $hist
                }
            }
        }
    }
    foreach ($t in $targets) {
        if ([string]::IsNullOrWhiteSpace($t.WinUser)) { $t.WinUser = 'unknown' }
        if ([string]::IsNullOrWhiteSpace($t.ProfileName)) { $t.ProfileName = 'Default' }
    }
    return $targets
}

# ---------- HARVEST ONE PROFILE ----------
function Harvest-Target { 
    param($t)
    $win = SafeName $t.WinUser
    $prof = SafeName $t.ProfileName
    $DbCopy = Join-Path $TmpDir ("History_{0}_{1}.sqlite" -f $win, $prof)
  
    try { Copy-Item -LiteralPath $t.HistoryPath -Destination $DbCopy -Force } 
    catch { Write-DebugLog ("Copy failed for {0}\{1}: {2}" -f $win, $prof, $_.Exception.Message); return }

    $StateFile = Join-Path $StateDir ("{0}_{1}.json" -f $win, $prof)
    $State = Load-State $StateFile

    if (-not $BootstrapEmitExisting.IsPresent -and -not $State.bootstrapped) {
        $State = Bootstrap-State-IfNeeded $DbCopy $State
        Save-State $State $StateFile
        Remove-Item $DbCopy -Force -ErrorAction SilentlyContinue
        Write-DebugLog ("Bootstrapped {0}/{1} (no backfill)." -f $win, $prof)
        return
    }

    # === URLs ===
    if (Table-Exists $DbCopy 'urls') {
        $where = if ($State.urls_last_visit_time_us -gt 0) { "WHERE last_visit_time > $($State.urls_last_visit_time_us)" } else { "" }
        $sql = "SELECT id, url, title, visit_count, typed_count, last_visit_time FROM urls $where ORDER BY last_visit_time ASC LIMIT $MaxRows;"
        $rows = @(Invoke-SqliteJson $DbCopy $sql)
        Write-DebugLog ("urls rows for {0}\{1}: {2}" -f $win, $prof, $rows.Count)
        if ($rows.Count -gt 0) {
            $max = $State.urls_last_visit_time_us
            foreach ($r in $rows) {
                Write-NDJson ([ordered]@{
                    browser = "Edge"
                    event_type = "edge_urls"
                    host = $env:COMPUTERNAME
                    user = $win
                    profile = $prof
                    id = $r.id
                    url = $r.url
                    title = $r.title
                    visit_count = $r.visit_count
                    typed_count = $r.typed_count
                    last_visit_iso = Convert-EdgeTimeToIso8601 ([long]$r.last_visit_time)
                }) $UrlsLog
                if ([long]$r.last_visit_time -gt $max) { $max = [long]$r.last_visit_time }
            }
            if ($max -gt $State.urls_last_visit_time_us) { $State.urls_last_visit_time_us = $max }
        }
    }

    # === VISITED LINKS ===
    if (Table-Exists $DbCopy 'visited_links') {
        $where = if ($State.visited_links_last_row262 -gt 0) { "WHERE rowid > $($State.visited_links_last_row262)" } else { "" }
        $sql = "SELECT rowid AS _rowid_, * FROM visited_links $where ORDER BY rowid ASC LIMIT $MaxRows;"
        $rows = @(Invoke-SqliteJson $DbCopy $sql)
        Write-DebugLog ("visited_links rows for {0}\{1}: {2}" -f $win, $prof, $rows.Count)
        if ($rows.Count -gt 0) {
            $max = $State.visited_links_last_row262
            foreach ($r in $rows) {
                Write-NDJson ([ordered]@{
                    browser = "Edge"
                    event_type = "edge_visited_links"
                    host = $env:COMPUTERNAME
                    user = $win
                    profile = $prof
                    data = $r
                }) $VLLog
                if ($r.PSObject.Properties.Name -contains "_rowid_") {
                    $rid = [long]$r._rowid_; if ($rid -gt $max) { $max = $rid }
                }
            }
            if ($max -gt $State.visited_links_last_row262) { $State.visited_links_last_row262 = $max }
        }
    }

    # === VISIT SOURCE ===
    if (Table-Exists $DbCopy 'visit_source' -and Table-Exists $DbCopy 'visits' -and Table-Exists $DbCopy 'urls') {
        $where = if ($State.visit_last_time_us -gt 0) { "WHERE v.visit_time > $($State.visit_last_time_us)" } else { "" }
        $sql = @"
SELECT
  vs.id AS visit_id,
  vs.source AS source,
  v.visit_time AS visit_time,
  u.id AS url_id,
  u.url AS url,
  u.title AS title
FROM visit_source vs
JOIN visits v ON v.id = vs.id
JOIN urls u ON u.id = v.url
$where
ORDER BY v.visit_time ASC
LIMIT $MaxRows;
"@
        $rows = @(Invoke-SqliteJson $DbCopy $sql)
        Write-DebugLog ("visit_source rows for {0}\{1}: {2}" -f $win, $prof, $rows.Count)
        if ($rows.Count -gt 0) {
            $max = $State.visit_last_time_us
            foreach ($r in $rows) {
                Write-NDJson ([ordered]@{
                    browser = "Edge"
                    event_type = "edge_visit_source"
                    host = $env:COMPUTERNAME
                    user = $win
                    profile = $prof
                    visit_id = $r.visit_id
                    source = $r.source
                    url_id = $r.url_id
                    url = $r.url
                    title = $r.title
                    visit_time_iso = Convert-EdgeTimeToIso8601 ([long]$r.visit_time)
                }) $VSLog
                if ([long]$r.visit_time -gt $max) { $max = [long]$r.visit_time }
            }
            if ($max -gt $State.visit_last_time_us) { $State.visit_last_time_us = $max }
        }
    }

    Save-State $State $StateFile
    Remove-Item $DbCopy -Force -ErrorAction SilentlyContinue
}

# ---------- MAIN HARVEST ----------
function Harvest-Once {
    $targets = Get-Targets
    Write-DebugLog ("Discovered targets: {0}" -f @($targets).Count)
    if (@($targets).Count -eq 0) {
        Write-DebugLog "No Edge profiles found. If running as SYSTEM, use -AllUsers."
        return
    }
    foreach ($t in $targets) { Harvest-Target $t }
}

# ---------- EXECUTION ----------
Write-DebugLog ("Started one-time Edge harvest. AllUsers={0}; BootstrapEmitExisting={1}" -f $AllUsers, $BootstrapEmitExisting.IsPresent)
try { Harvest-Once } catch { Write-DebugLog ("Run failed: {0}" -f $_.Exception.Message) }
Write-DebugLog "Completed one-time execution."
