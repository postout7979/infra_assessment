# =============================================================================
# [Script 5] VMSA CVE Lookup - CSV + searchable HTML report
# -----------------------------------------------------------------------------
# Environment: Internet-connected PC
# Function:
# 1. Takes a CVE list CSV as input (the "VMSA_CVE_List_<timestamp>.csv" file
#    produced by VMSA_FullList_Downloader.ps1, or any CSV with a "CVE"
#    column - AdvisoryIDs/AdvisoryCount columns are carried through if
#    present, but are not required).
# 2. Looks up each CVE ID online against the NVD CVE API
#    (https://services.nvd.nist.gov/rest/json/cves/2.0) to get its English
#    description, CVSS v3 base score + severity (falls back to CVSS v2 if a
#    CVE has no v3 score), published date, and a few reference links.
# 3. CACHED: results are kept in CVE_Lookup_Cache.json (fixed name, no
#    timestamp) next to this script. On every run, CVE IDs already present
#    in that cache are reused instead of being looked up again - only CVE
#    IDs not yet in the cache are fetched from NVD. Pass -ForceRefreshAll to
#    ignore the cache and re-fetch every CVE in the input list.
# 4. Writes CVE_Lookup_Results_<timestamp>.csv (one row per CVE) and
#    CVE_Lookup_<timestamp>.html - a single search box where typing a CVE ID
#    (full or partial) instantly filters the list to matching CVEs and shows
#    their description/CVSS/severity/references/related VMSA advisories.
#    Both files are written into their own CVE_Lookup_<timestamp>/ output
#    folder (created next to this script) - only CVE_Lookup_Cache.json stays
#    directly next to the script itself, since it's the fixed-name cache
#    every run (regardless of that run's output folder) reads and updates.
#
# Usage:
#   .\VMSA_CVE_Lookup.ps1 -CveListCsv .\VMSA_CVE_List_20260828-1529.csv
#   .\VMSA_CVE_Lookup.ps1 -CveListCsv .\VMSA_CVE_List_20260828-1529.csv -NvdApiKey "xxxxxxxx-...."
#   .\VMSA_CVE_Lookup.ps1 -CveListCsv .\VMSA_CVE_List_20260828-1529.csv -ForceRefreshAll
# =============================================================================

param(
    [Parameter(Mandatory = $true)]
    [string]$CveListCsv,          # path to a CSV with a "CVE" column (AdvisoryIDs/AdvisoryCount optional)
    [string]$NvdApiKey = "",      # optional NVD API key - raises the allowed request rate
    [int]$DelayMs = 0,            # 0 = auto (6200ms without a key, 650ms with one)
    [switch]$ForceRefreshAll      # ignore CVE_Lookup_Cache.json and re-fetch every CVE
)

$ErrorActionPreference = "Stop"
$CurrentDir = $PSScriptRoot
if ([string]::IsNullOrWhiteSpace($CurrentDir)) { $CurrentDir = Get-Location }

if (-not (Test-Path -LiteralPath $CveListCsv)) {
    Write-Error "Input CSV not found: $CveListCsv"
    exit
}

if ($DelayMs -le 0) {
    $DelayMs = if ([string]::IsNullOrWhiteSpace($NvdApiKey)) { 6200 } else { 650 }
}

$Timestamp     = Get-Date -Format "yyyyMMdd-HHmm"
# Cache JSON stays right next to the script (fixed name, no timestamp, no
# subfolder) so every run - regardless of output folder - finds and reuses
# it. The CSV/HTML results for THIS run go into their own timestamped output
# folder instead of being dropped loose next to the script.
$CachePath     = Join-Path $CurrentDir "CVE_Lookup_Cache.json"
$OutputDir     = Join-Path $CurrentDir "CVE_Lookup_$Timestamp"
New-Item -ItemType Directory -Path $OutputDir -Force | Out-Null
$OutCsvPath    = Join-Path $OutputDir "CVE_Lookup_Results_$Timestamp.csv"
$OutHtmlPath   = Join-Path $OutputDir "CVE_Lookup_$Timestamp.html"
$NvdApiUrl     = "https://services.nvd.nist.gov/rest/json/cves/2.0"

# These two ServicePointManager settings work around a common Windows
# PowerShell 5.1 / .NET Framework issue where a long run of sequential HTTPS
# calls eventually throws "The underlying connection was closed: An
# unexpected error occurred on a send" - once it starts, every remaining
# request on that (bad) pooled connection fails the same way. Raising the
# connection limit and disabling Expect100Continue avoids the bad pooled
# connection in the first place; Get-NvdCveInfo below also retries each
# call a few times as a second line of defense.
[System.Net.ServicePointManager]::SecurityProtocol = [System.Net.SecurityProtocolType]::Tls12
[System.Net.ServicePointManager]::Expect100Continue = $false
[System.Net.ServicePointManager]::DefaultConnectionLimit = 20

# =============================================================================
# 0. Load the input CVE list
# =============================================================================
Write-Host "[0] Reading CVE list from $CveListCsv ..." -ForegroundColor Cyan
$InputRows = Import-Csv -LiteralPath $CveListCsv
if (-not $InputRows -or $InputRows.Count -eq 0) {
    Write-Error "No rows found in $CveListCsv"
    exit
}
if (-not ($InputRows[0].PSObject.Properties.Name -contains "CVE")) {
    Write-Error "$CveListCsv has no 'CVE' column. Expected a CSV like VMSA_CVE_List_<timestamp>.csv."
    exit
}

$InputByCve = @{}
foreach ($row in $InputRows) {
    $cveId = ($row.CVE | Out-String).Trim()
    if ([string]::IsNullOrWhiteSpace($cveId)) { continue }
    $InputByCve[$cveId] = $row
}
$CveIds = @($InputByCve.Keys | Sort-Object)
Write-Host "    -> $($CveIds.Count) unique CVE ID(s) in the input file." -ForegroundColor Gray

# =============================================================================
# 1. Load the lookup cache (if any) so re-runs only fetch new CVE IDs
# =============================================================================
$Cache = @{}
if ((Test-Path -LiteralPath $CachePath) -and (-not $ForceRefreshAll)) {
    try {
        $CacheData = Get-Content -LiteralPath $CachePath -Raw -Encoding UTF8 | ConvertFrom-Json
        foreach ($prop in $CacheData.PSObject.Properties) { $Cache[$prop.Name] = $prop.Value }
        Write-Host "[1] Loaded $($Cache.Count) cached CVE lookup(s) from $CachePath" -ForegroundColor Gray
    } catch {
        Write-Warning "Could not read existing $CachePath - starting with an empty cache. ($($_.Exception.Message))"
        $Cache = @{}
    }
} elseif ($ForceRefreshAll) {
    Write-Host "[1] -ForceRefreshAll set - ignoring the cache and re-fetching every CVE." -ForegroundColor Yellow
} else {
    Write-Host "[1] No existing cache found - every CVE will be looked up." -ForegroundColor Gray
}

$NewCveIds = @($CveIds | Where-Object { -not $Cache.ContainsKey($_) })
Write-Host "    -> $($CveIds.Count - $NewCveIds.Count) already cached / $($NewCveIds.Count) need to be looked up." -ForegroundColor Cyan

# =============================================================================
# 2. Look up each new CVE ID against the NVD API
# =============================================================================
# Calls Invoke-RestMethod with a few retries + backoff, so a single dropped
# connection doesn't fail the lookup outright - the caller still gets the
# real exception if every attempt fails.
function Invoke-NvdRequest {
    param([string]$Uri, [hashtable]$Headers, [int]$MaxRetries = 3)
    for ($attempt = 1; $attempt -le $MaxRetries; $attempt++) {
        try {
            return Invoke-RestMethod -Uri $Uri -Headers $Headers -TimeoutSec 20 -ErrorAction Stop
        } catch {
            if ($attempt -ge $MaxRetries) { throw }
            $backoffMs = 2000 * $attempt
            Start-Sleep -Milliseconds $backoffMs
        }
    }
}

function Get-NvdCveInfo {
    param([string]$CveId, [string]$ApiKey)

    # Success = $false means "not written to the cache" - a transient error
    # (like a dropped connection) should be retried on the NEXT run rather
    # than being remembered forever as a permanent failure. A confirmed
    # "not found in NVD" answer IS stable, so that case sets Success = $true.
    $Result = [PSCustomObject][ordered]@{
        CVE         = $CveId
        Description = "Lookup failed - see NVD directly."
        CVSSv3      = "N/A"
        Severity    = "N/A"
        Published   = "N/A"
        References  = ""
        Success     = $false
    }

    $Headers = @{}
    if (-not [string]::IsNullOrWhiteSpace($ApiKey)) { $Headers["apiKey"] = $ApiKey }

    try {
        $Uri = "$NvdApiUrl`?cveId=$CveId"
        $Response = Invoke-NvdRequest -Uri $Uri -Headers $Headers
        $Vuln = $Response.vulnerabilities | Select-Object -First 1
        if (-not $Vuln) {
            $Result.Description = "CVE not found in NVD."
            $Result.Success = $true
            return $Result
        }
        $Cve = $Vuln.cve

        $EnDesc = $Cve.descriptions | Where-Object { $_.lang -eq "en" } | Select-Object -First 1
        if ($EnDesc) { $Result.Description = $EnDesc.value }

        $Metrics = $Cve.metrics
        $CvssData = $null
        $Severity = $null
        if ($Metrics.cvssMetricV31) {
            $m = $Metrics.cvssMetricV31 | Select-Object -First 1
            $CvssData = $m.cvssData.baseScore
            $Severity = $m.cvssData.baseSeverity
        } elseif ($Metrics.cvssMetricV30) {
            $m = $Metrics.cvssMetricV30 | Select-Object -First 1
            $CvssData = $m.cvssData.baseScore
            $Severity = $m.cvssData.baseSeverity
        } elseif ($Metrics.cvssMetricV2) {
            $m = $Metrics.cvssMetricV2 | Select-Object -First 1
            $CvssData = $m.cvssData.baseScore
            $Severity = $m.baseSeverity
        }
        if ($null -ne $CvssData) { $Result.CVSSv3 = "$CvssData" }
        if ($Severity) { $Result.Severity = $Severity }

        if ($Cve.published) {
            try { $Result.Published = ([DateTime]$Cve.published).ToString("yyyy-MM-dd") } catch { $Result.Published = $Cve.published }
        }

        $RefUrls = @($Cve.references | Select-Object -First 3 -ExpandProperty url)
        $Result.References = ($RefUrls -join "; ")
        $Result.Success = $true
    } catch {
        $StatusCode = $null
        if ($_.Exception.Response) { $StatusCode = [int]$_.Exception.Response.StatusCode }
        if ($StatusCode -eq 404) {
            $Result.Description = "CVE not found in NVD."
            $Result.Success = $true
        } else {
            Write-Warning "    ! Lookup failed for $CveId : $($_.Exception.Message)"
        }
    }
    return $Result
}

Write-Host "[2] Looking up $($NewCveIds.Count) new CVE(s) against NVD (delay: ${DelayMs}ms between calls)..." -ForegroundColor Cyan
$Counter = 0
$Total = $NewCveIds.Count
$FailedCveIds = New-Object System.Collections.Generic.List[string]
foreach ($cveId in $NewCveIds) {
    $Counter++
    Write-Progress -Activity "Looking up CVEs on NVD" -Status "[$Counter/$Total] $cveId" -PercentComplete $(if ($Total -gt 0) { [math]::Round(($Counter / $Total) * 100) } else { 100 })
    $info = Get-NvdCveInfo -CveId $cveId -ApiKey $NvdApiKey
    if ($info.Success) {
        $Cache[$cveId] = $info
    } else {
        $FailedCveIds.Add($cveId)
    }
    Start-Sleep -Milliseconds $DelayMs
}
Write-Progress -Activity "Looking up CVEs on NVD" -Completed
Write-Host "[2] Done. $($NewCveIds.Count - $FailedCveIds.Count) CVE(s) looked up; $($CveIds.Count - $NewCveIds.Count) reused from cache." -ForegroundColor Green
if ($FailedCveIds.Count -gt 0) {
    Write-Host "    -> $($FailedCveIds.Count) CVE(s) could not be reached this run (not cached, so they'll be retried automatically next run): $($FailedCveIds -join ', ')" -ForegroundColor Yellow
}

# =============================================================================
# 3. Save the cache (fixed filename - this IS the incremental cache)
# =============================================================================
$Cache | ConvertTo-Json -Depth 5 | Set-Content -LiteralPath $CachePath -Encoding UTF8
Write-Host "    -> Cache: $CachePath ($($Cache.Count) CVE(s) total)" -ForegroundColor Gray

# =============================================================================
# 4. Write the results CSV (carries AdvisoryIDs/AdvisoryCount through from
#    the input file when present)
# =============================================================================
Write-Host "[4] Writing results CSV..." -ForegroundColor Cyan

$i = 0
# A CVE that failed this run (and every previous run) has no cache entry at
# all - fall back to placeholder text for it rather than erroring out, and
# it will be retried automatically the next time this script runs.
$OutRows = $CveIds | ForEach-Object {
    $i++
    $cveId = $_
    $info  = $Cache[$cveId]
    if (-not $info) {
        $info = [PSCustomObject]@{ Description = "Lookup failed - see NVD directly (will retry next run)."; CVSSv3 = "N/A"; Severity = "N/A"; Published = "N/A"; References = "" }
    }
    $inRow = $InputByCve[$cveId]
    [PSCustomObject][ordered]@{
        No            = $i
        CVE           = $cveId
        Description   = $info.Description
        CVSSv3        = $info.CVSSv3
        Severity      = $info.Severity
        Published     = $info.Published
        References    = $info.References
        AdvisoryIDs   = if ($inRow.PSObject.Properties.Name -contains "AdvisoryIDs") { $inRow.AdvisoryIDs } else { "" }
        AdvisoryCount = if ($inRow.PSObject.Properties.Name -contains "AdvisoryCount") { $inRow.AdvisoryCount } else { "" }
    }
}
$OutRows | Export-Csv -LiteralPath $OutCsvPath -NoTypeInformation -Encoding UTF8
Write-Host "    -> CSV: $OutCsvPath ($($OutRows.Count) rows)" -ForegroundColor Gray

# =============================================================================
# 5. Write the searchable HTML report (English UI) - type a CVE ID into the
#    search box and matching results filter instantly.
# =============================================================================
Write-Host "[5] Writing HTML report..." -ForegroundColor Cyan

$HtmlJsonPieces = @($OutRows | ForEach-Object { $_ | ConvertTo-Json -Depth 4 -Compress })
$HtmlJson = "[" + ($HtmlJsonPieces -join ",") + "]"
$HtmlJson = $HtmlJson -replace "(?i)</script", "<\/script"

$GeneratedAtLabel = Get-Date -Format "yyyy-MM-dd HH:mm"

$HtmlTemplate = @"
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<title>VMSA CVE Lookup</title>
<style>
  :root {
    --navy:#1e3a8a; --navy-dark:#1e2a5e; --border:#e2e8f0; --muted:#64748b;
    --crit-bg:#fee2e2; --crit-fg:#dc2626; --high-bg:#ffedd5; --high-fg:#ea580c;
    --med-bg:#fef3c7; --med-fg:#d97706; --low-bg:#dcfce7; --low-fg:#16a34a;
  }
  * { box-sizing:border-box; }
  body { margin:0; font-family:Segoe UI,Arial,sans-serif; background:#f1f5f9; color:#1e293b; }
  header { background:linear-gradient(135deg,var(--navy),var(--navy-dark)); color:#fff; padding:28px 32px; }
  header h1 { margin:0 0 6px 0; font-size:22px; }
  header p { margin:0; font-size:13px; opacity:.85; }
  .wrap { max-width:1100px; margin:0 auto; padding:24px 20px 60px; }
  .card { background:#fff; border:1px solid var(--border); border-radius:10px; padding:20px 22px; margin-bottom:20px; box-shadow:0 1px 3px rgba(0,0,0,.04); }
  .search-box { width:100%; padding:12px 14px; font-size:16px; border:1px solid var(--border); border-radius:8px; }
  .search-box:focus { outline:2px solid var(--navy); border-color:var(--navy); }
  #searchSummary { font-size:13px; color:var(--muted); margin-top:10px; }
  .badge { display:inline-block; padding:3px 10px; border-radius:20px; font-size:11px; font-weight:700; letter-spacing:.03em; }
  .badge-critical { background:var(--crit-bg); color:var(--crit-fg); }
  .badge-high { background:var(--high-bg); color:var(--high-fg); }
  .badge-medium { background:var(--med-bg); color:var(--med-fg); }
  .badge-low { background:var(--low-bg); color:var(--low-fg); }
  .badge-default { background:#e2e8f0; color:#475569; }
  .cve-card { border:1px solid var(--border); border-radius:8px; padding:16px 18px; margin-bottom:14px; }
  .cve-head { display:flex; align-items:center; gap:10px; flex-wrap:wrap; }
  .cve-id { font-weight:700; color:var(--navy); font-size:15px; }
  .cve-meta { font-size:12px; color:var(--muted); margin:6px 0 10px 0; }
  .cve-desc { font-size:13px; line-height:1.5; margin:0 0 10px 0; }
  .cve-refs { font-size:12px; word-break:break-all; }
  .cve-refs a { color:var(--navy); }
  .cve-advisories { font-size:12px; color:var(--muted); margin-top:8px; }
  .muted { color:var(--muted); font-size:13px; }
</style>
</head>
<body>
<header>
  <h1>VMSA CVE Lookup</h1>
  <p>Generated $GeneratedAtLabel &nbsp;|&nbsp; Source: NVD (National Vulnerability Database) &nbsp;|&nbsp; Total CVEs: <span id="totalCount">0</span></p>
</header>
<div class="wrap">

  <div class="card">
    <input type="text" id="searchBox" class="search-box" placeholder="Type a CVE ID (full or partial), e.g. CVE-2026-0001 or 2026-0001 - separate multiple with commas, e.g. CVE-2026-0001,CVE-2026-0002" autofocus>
    <div id="searchSummary"></div>
  </div>

  <div id="resultList"></div>

</div>

<script>
const RECORDS = $HtmlJson;

function esc(s) {
  return String(s == null ? "" : s).replace(/[&<>"']/g, function (c) {
    return { "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c];
  });
}

function sevBadgeClass(s) {
  const v = (s || "").toLowerCase();
  if (v.indexOf("crit") !== -1) return "badge-critical";
  if (v.indexOf("high") !== -1) return "badge-high";
  if (v.indexOf("med") !== -1) return "badge-medium";
  if (v.indexOf("low") !== -1) return "badge-low";
  return "badge-default";
}

function buildReferences(refs) {
  if (!refs) return "";
  return refs.split(";").map(function (r) { return r.trim(); }).filter(Boolean).map(function (url) {
    return '<div><a href="' + esc(url) + '" target="_blank" rel="noopener">' + esc(url) + "</a></div>";
  }).join("");
}

function renderList(items) {
  const container = document.getElementById("resultList");
  if (items.length === 0) {
    container.innerHTML = '<p class="muted">No matching CVE found.</p>';
    return;
  }
  container.innerHTML = items.map(function (r) {
    return '<div class="cve-card">' +
      '<div class="cve-head"><span class="cve-id">' + esc(r.CVE) + '</span>' +
      '<span class="badge ' + sevBadgeClass(r.Severity) + '">' + esc((r.Severity || "N/A").toUpperCase()) + "</span></div>" +
      '<div class="cve-meta">CVSSv3: ' + esc(r.CVSSv3) + " &nbsp;|&nbsp; Published: " + esc(r.Published) + "</div>" +
      '<p class="cve-desc">' + esc(r.Description) + "</p>" +
      '<div class="cve-refs">' + buildReferences(r.References) + "</div>" +
      (r.AdvisoryIDs ? '<div class="cve-advisories">Related VMSA advisories: ' + esc(r.AdvisoryIDs) + "</div>" : "") +
      "</div>";
  }).join("");
}

function runSearch() {
  const raw = document.getElementById("searchBox").value.trim();
  const summary = document.getElementById("searchSummary");
  // Comma-separated input, e.g. "CVE-2026-0001, CVE-2026-0002", looks up
  // every listed CVE ID (full or partial) at once - a record matches if it
  // matches ANY of the comma-separated terms.
  const terms = raw.split(",").map(function (t) { return t.trim().toLowerCase(); }).filter(Boolean);
  let matched;
  if (terms.length === 0) {
    matched = RECORDS;
    summary.textContent = "Showing all " + matched.length + " CVE(s). Type above to search.";
  } else {
    matched = RECORDS.filter(function (r) {
      const cveLower = r.CVE.toLowerCase();
      return terms.some(function (t) { return cveLower.indexOf(t) !== -1; });
    });
    if (terms.length === 1) {
      summary.textContent = matched.length + " CVE(s) match \"" + terms[0] + "\".";
    } else {
      summary.textContent = matched.length + " CVE(s) match " + terms.length + " search term(s): " + terms.join(", ") + ".";
    }
  }
  renderList(matched);
}

function init() {
  document.getElementById("totalCount").textContent = RECORDS.length;
  document.getElementById("searchBox").addEventListener("input", runSearch);
  runSearch();
}

document.addEventListener("DOMContentLoaded", init);
</script>
</body>
</html>
"@

Set-Content -LiteralPath $OutHtmlPath -Value $HtmlTemplate -Encoding UTF8
Write-Host "    -> HTML: $OutHtmlPath ($($OutRows.Count) CVEs embedded)" -ForegroundColor Gray

Write-Host "`n[DONE] Total CVEs: $($CveIds.Count) | New lookups this run: $($NewCveIds.Count - $FailedCveIds.Count) | Reused from cache: $($CveIds.Count - $NewCveIds.Count) | Failed (will retry next run): $($FailedCveIds.Count)" -ForegroundColor Green