# =============================================================================
# [Script 2] VMSA Auditor for Air-Gapped Environment (Strict Matrix + N/A Fix)
# -----------------------------------------------------------------------------
# Environment: Internal Network (No Internet required for this script)
# Function:
# 1. Loads 'VMSA_Offline_Data.json'.
# 2. Lets the user choose how to get vCenter/ESXi versions:
#      Mode 1) Connect to vCenter and read versions automatically
#      Mode 2) Enter versions manually, without logging in anywhere
#    Credentials (Mode 1) are requested fresh every run and never stored.
# 3. Strict Matching Logic:
#    - Standard: Col 1 (Product) -> Col 2 (Version).
#      [New] If Col 2 is "N/A", check Col 3 for Version.
#    - VCF Case: Col 1 (VCF) -> Col 2 (Component) -> Col 3 (Version).
# 4. Generates CSV and a report-style HTML dashboard (English).
# =============================================================================

# --- Configuration ---
$CurrentDir = $PSScriptRoot
if ([string]::IsNullOrWhiteSpace($CurrentDir)) { $CurrentDir = Get-Location }

$JsonFile = Join-Path $CurrentDir "VMSA_Offline_Data.json"
$Timestamp = Get-Date -Format "yyyyMMdd-HHmm"
$CsvPath  = Join-Path $CurrentDir "Audit_Report_$Timestamp.csv"
$HtmlPath = Join-Path $CurrentDir "Audit_Report_$Timestamp.html"

# --- 1. Load Offline Data ---
if (-not (Test-Path $JsonFile)) {
    Write-Error "Data file not found: $JsonFile"
    exit
}
try {
    $JsonData = Get-Content -Path $JsonFile -Raw -Encoding UTF8 | ConvertFrom-Json
    $VmsaList = $JsonData.Advisories
    Write-Host "[1] Offline Data Loaded ($($VmsaList.Count) items)" -ForegroundColor Cyan
} catch {
    Write-Error "Failed to parse JSON file."
    exit
}

# --- 2. Choose Analysis Mode ---
Write-Host "[2] Select Analysis Mode" -ForegroundColor Cyan
Write-Host "    1) Connect to vCenter and read versions automatically (login required)"
Write-Host "    2) Enter vCenter / ESXi versions manually (no login, fully offline)"
$ModeChoice = Read-Host "Select mode (1 or 2)"

$vcServer     = $null
$VcVerFull    = $null
$VcMajorDigit = $null
$HostList     = @()
$Connected    = $false   # tracks whether we actually logged into vCenter

if ($ModeChoice -eq "2") {

    # ---- Mode 2: Manual Entry (no login) ----
    Write-Host "`n[Manual Mode] No vCenter login is required." -ForegroundColor Yellow
    Write-Host "    Example  ->  vCenter version: 8.0.3        ESXi host: fu-01.epa.com (8.0.3)" -ForegroundColor Gray
    Write-Host ""

    $vcServer = Read-Host "Enter a label for this environment (e.g. site or vCenter name)"
    if ([string]::IsNullOrWhiteSpace($vcServer)) { $vcServer = "Manual Entry" }

    $VcVerFull = Read-Host "Enter vCenter version (e.g. 8.0.3)"
    $VcMajorDigit = if ($VcVerFull -match "^(\d+)") { $matches[1] } else { "Unknown" }

    Write-Host "`nEnter ESXi host info one by one. Leave the host name blank and press Enter to finish." -ForegroundColor Gray
    $HostIndex = 0
    while ($true) {
        $HostIndex++
        $hName = Read-Host "  ESXi Host #$HostIndex Name (blank to finish)"
        if ([string]::IsNullOrWhiteSpace($hName)) { break }
        $hVer = Read-Host "  ESXi Host #$HostIndex Version (e.g. 8.0.3)"
        $hMajor = if ($hVer -match "^(\d+)") { $matches[1] } else { "Unknown" }

        $HostList += [PSCustomObject]@{
            Name            = $hName
            MajorDigit      = $hMajor
            FullVer         = $hVer
            Build           = "N/A"
            ConnectionState = "Manual Entry"
        }
    }

    if ($HostList.Count -eq 0) {
        Write-Warning "No ESXi hosts entered. Continuing with vCenter version only."
    }

} else {

    # ---- Mode 1: Connect to vCenter ----
    # NOTE: Credentials are never written to disk. They are requested fresh on
    # every run and only kept in memory for the duration of the session.
    Write-Host "`n[Authentication]" -ForegroundColor Cyan

    $vcServer = Read-Host "Enter vCenter Server IP or FQDN"
    Write-Host "    (Enter credentials in popup)" -ForegroundColor Gray
    $vcCred = Get-Credential -Message "Enter vCenter credentials for $vcServer"

    try {
        Set-PowerCLIConfiguration -InvalidCertificateAction Ignore -Confirm:$false -Scope Session
        Connect-VIServer -Server $vcServer -Credential $vcCred -ErrorAction Stop
        Write-Host "    -> Connected to $vcServer" -ForegroundColor Green
        $Connected = $true
    } catch {
        Write-Error "Connection Failed: $($_.Exception.Message)"
        exit
    }

    # vCenter version
    $VcInstance = $global:DefaultVIServer
    $VcVerFull  = $VcInstance.Version # e.g. "8.0.2.00000"
    $VcMajorDigit = if ($VcVerFull -match "^(\d+)") { $matches[1] } else { "Unknown" }

    # ESXi Hosts (List all)
    $EsxiHosts = Get-VMHost
    foreach ($h in $EsxiHosts) {
        $ver = $h.Version # "7.0.3"
        $majDigit = if ($ver -match "^(\d+)") { $matches[1] } else { "Unknown" }

        $HostList += [PSCustomObject]@{
            Name            = $h.Name
            MajorDigit      = $majDigit
            FullVer         = $ver
            Build           = $h.Build
            ConnectionState = $h.ConnectionState
        }
    }
}

# --- 3. Scan & Match Assets (Strict Matrix Check) ---
Write-Host "`n[3] Analyzing environment (Strict Matrix Matching with N/A Handling)..." -ForegroundColor Cyan

$Report = @()

# 3-2. Matching Logic
$RowIdCounter = 0

foreach ($vmsa in $VmsaList) {

    # Flags to determine if this VMSA should be reported
    $ShouldReport = $false
    $MatchedProductTypes = @()
    $RelevantAssets = @()

    # Split FixedInfo (Response Matrix) into rows
    $MatrixRows = $vmsa.FixedInfo -split "<br>"

    # --- Matrix Analysis ---
    foreach ($row in $MatrixRows) {
        $parts = $row -split "\|"

        # Variables to hold the target component and version for this row
        $targetComponent = $null
        $targetVersionStr = $null

        # Logic: Distinguish between Standard vs VCF vs Standard with N/A
        if ($parts.Count -ge 2) {
            $col1 = $parts[0].Trim() # Product (e.g., vCenter Server, VMware Cloud Foundation)

            # Case A: VCF (Needs 3 columns: Product | Component | Version)
            if ($col1 -match "Cloud\s*Foundation" -and $parts.Count -ge 3) {
                $targetComponent = $parts[1].Trim() # Col 2 is the actual component
                $targetVersionStr = $parts[2].Trim() # Col 3 is the version
            }
            # Case B: Standard (vCenter/ESX)
            elseif ($col1 -match "vCenter|ESX") {
                $targetComponent = $col1
                $col2 = $parts[1].Trim()

                # [New Logic] Check if Col2 is N/A. If so, check Col3.
                if ($col2 -match "^N\/A" -and $parts.Count -ge 3) {
                     $targetVersionStr = $parts[2].Trim() # Fallback to Col 3
                } else {
                     $targetVersionStr = $col2 # Default to Col 2
                }
            }
        }

        # If valid component and version found, proceed with matching
        if ($targetComponent -and $targetVersionStr) {

            # Extract Major Digit from the Target Version String
            $MatrixMajor = if ($targetVersionStr -match "^(\d+)") { $matches[1] } else { $null }

            if ($MatrixMajor) {
                # Check vCenter Match
                if ($targetComponent -match "vCenter") {
                    if ($MatrixMajor -eq $VcMajorDigit) {
                        $ShouldReport = $true
                        if ($MatchedProductTypes -notcontains "vCenter") {
                            $MatchedProductTypes += "vCenter"
                            $RelevantAssets += "vCenter ($VcVerFull)"
                        }
                    }
                }

                # Check ESX or ESXi Match
                if ($targetComponent -match "ESX") {
                    foreach ($hostItem in $HostList) {
                        if ($MatrixMajor -eq $hostItem.MajorDigit) {
                            $ShouldReport = $true
                            if ($MatchedProductTypes -notcontains "ESX") {
                                $MatchedProductTypes += "ESX"
                            }
                            $assetEntry = "$($hostItem.Name) ($($hostItem.FullVer))"
                            if ($RelevantAssets -notcontains $assetEntry) {
                                $RelevantAssets += $assetEntry
                            }
                        }
                    }
                }
            }
        }
    }

    # --- Add to Report if Match Found ---
    if ($ShouldReport) {
        $RowIdCounter++

        # Format the "My Version" info (unique assets)
        $AssetStr = ($RelevantAssets | Select-Object -Unique) -join ", "

        $Report += [PSCustomObject]@{
            RowID           = "row_$RowIdCounter"
            Type            = ($MatchedProductTypes | Select-Object -Unique) -join ", "
            MatchedAssets   = $AssetStr
            AdvisoryID      = $vmsa.AdvisoryID
            Title           = $vmsa.Title
            Severity        = $vmsa.Severity
            FixedIn         = $vmsa.FixedInfo
            Link            = $vmsa.Link
            Published       = $vmsa.Published
        }
    }
}

# --- Helper: Severity -> sort rank / CSS class / label ---
function Get-SeverityRank {
    param([string]$Severity)
    switch -Regex ($Severity) {
        "Critical"  { return 0 }
        "High"      { return 1 }
        "Important" { return 1 }
        "Medium"    { return 2 }
        "Moderate"  { return 2 }
        "Low"       { return 3 }
        default     { return 4 }
    }
}
function Get-SeverityClass {
    param([string]$Severity)
    switch -Regex ($Severity) {
        "Critical"  { return "sev-crit" }
        "High"      { return "sev-high" }
        "Important" { return "sev-high" }
        "Medium"    { return "sev-med" }
        "Moderate"  { return "sev-med" }
        "Low"       { return "sev-low" }
        default     { return "sev-none" }
    }
}

# Sort the report so the most severe advisories are shown first
$Report = $Report | Sort-Object { Get-SeverityRank $_.Severity }, { $_.AdvisoryID } -Descending:$false

# --- 4. Output Results ---
if ($Report.Count -gt 0) {
    # CSV
    $Report | Export-Csv -Path $CsvPath -NoTypeInformation -Encoding UTF8

    # --- 4-1. Summary Stats for the dashboard cards ---
    $CritCount = ($Report | Where-Object { (Get-SeverityRank $_.Severity) -eq 0 }).Count
    $HighCount = ($Report | Where-Object { (Get-SeverityRank $_.Severity) -eq 1 }).Count
    $MedCount  = ($Report | Where-Object { (Get-SeverityRank $_.Severity) -eq 2 }).Count
    $LowCount  = ($Report | Where-Object { (Get-SeverityRank $_.Severity) -ge 3 }).Count
    $TotalCount = $Report.Count

    $VcCritical = ($Report | Where-Object { $_.Type -match "vCenter" -and (Get-SeverityRank $_.Severity) -eq 0 }).Count
    $EsxCritical = ($Report | Where-Object { $_.Type -match "ESX" -and (Get-SeverityRank $_.Severity) -eq 0 }).Count

    # --- 4-2. Environment (Inventory) rows ---
    $VcConnLabel = if ($Connected) { "Connected" } else { "Manual Entry" }
    $VcConnClass = if ($Connected) { "status-ok" } else { "status-manual" }

    $InventoryRows = ""
    $InventoryRows += "<tr><td><span class='tag tag-vc'>vCenter</span></td><td>$vcServer</td><td>$VcVerFull</td><td><span class='$VcConnClass'>$VcConnLabel</span></td></tr>"
    foreach ($h in ($HostList | Sort-Object Name)) {
        $connClass = switch ($h.ConnectionState) {
            "Connected"    { "status-ok" }
            "Manual Entry" { "status-manual" }
            default        { "status-warn" }
        }
        $InventoryRows += "<tr><td><span class='tag tag-esx'>ESXi</span></td><td>$($h.Name)</td><td>$($h.FullVer) (Build $($h.Build))</td><td><span class='$connClass'>$($h.ConnectionState)</span></td></tr>"
    }

    # --- 4-3. Advisory Table Rows ---
    # Title line for the Response Matrix block, matching the column layout
    # used on the Broadcom advisory pages.
    $MatrixHeader = "VMware Product | Version | Running On | CVE | CVSSv3 | Severity | Fixed Version | Workarounds | Additional Documentation"

    $HtmlRows = ""
    foreach ($row in $Report) {
        $sevClass = Get-SeverityClass $row.Severity
        $sevLabel = $row.Severity.ToUpper()

        $HtmlRows += "<tr class='adv-row' data-severity='$sevClass'>"
        $HtmlRows += "<td class='sev-cell $sevClass'></td>"
        $HtmlRows += "<td><span class='badge $sevClass'>$sevLabel</span></td>"
        $HtmlRows += "<td><b>$($row.Type)</b></td>"
        $HtmlRows += "<td><a href='$($row.Link)' target='_blank'>$($row.AdvisoryID)</a></td>"
        $HtmlRows += "<td class='title-cell'>$($row.Title)</td>"
        $HtmlRows += "<td class='pub-cell'>$($row.Published)</td>"
        $HtmlRows += "<td><button class='btn-toggle' onclick=`"toggleDetails('$($row.RowID)', this)`">Details <span class='chev'>&#9660;</span></button></td>"
        $HtmlRows += "</tr>"

        $HtmlRows += "<tr id='$($row.RowID)' class='details-row' data-severity='$sevClass'>"
        $HtmlRows += "<td colspan='7'>"
        $HtmlRows += "<div class='details-box'>"

        # Details Content
        $HtmlRows += "<div class='detail-grid'>"
        $HtmlRows += "<div><strong>Advisory URL</strong><br><a href='$($row.Link)' target='_blank' class='link-text'>$($row.Link)</a></div>"
        $HtmlRows += "<div><strong>Matched Local Assets</strong><br><span class='asset-text'>$($row.MatchedAssets)</span></div>"
        $HtmlRows += "</div>"
        $HtmlRows += "<strong>Response Matrix (Fixed Versions)</strong>"
        $HtmlRows += "<div class='matrix-header'>$MatrixHeader</div>"
        $HtmlRows += "<span class='info-text'>$($row.FixedIn)</span>"
        $HtmlRows += "</div></td></tr>"
    }

    $GeneratedAtDisplay = Get-Date -Format "yyyy-MM-dd HH:mm"
    $ModeLabel = if ($Connected) { "Live vCenter Connection" } else { "Manual Entry (Offline)" }

$HtmlContent = @"
<!DOCTYPE html>
<html lang='en'>
<head>
<meta charset='UTF-8'>
<title>vSphere Security Audit Report - $vcServer</title>
<style>
    :root {
        --crit: #dc2626; --crit-bg: #fee2e2;
        --high: #ea580c; --high-bg: #ffedd5;
        --med:  #d97706; --med-bg:  #fef3c7;
        --low:  #16a34a; --low-bg:  #dcfce7;
        --none: #64748b; --none-bg: #e2e8f0;
        --accent: #2563eb;
    }
    * { box-sizing: border-box; }
    body { font-family: 'Segoe UI', Tahoma, Arial, sans-serif; margin: 0; background: #f1f5f9; color: #1e293b; }

    .page { max-width: 1200px; margin: 0 auto; padding: 24px; }

    /* ---------- Header ---------- */
    .report-header { background: linear-gradient(135deg, #1e3a8a, #2563eb); color: white; border-radius: 10px; padding: 28px 32px; margin-bottom: 20px; box-shadow: 0 4px 10px rgba(0,0,0,0.15); }
    .report-header h1 { margin: 0 0 6px 0; font-size: 1.6em; }
    .report-header .sub { opacity: 0.9; font-size: 0.95em; }
    .meta-row { display: flex; flex-wrap: wrap; gap: 22px; margin-top: 16px; font-size: 0.88em; }
    .meta-row div span.label { display: block; opacity: 0.75; font-size: 0.8em; text-transform: uppercase; letter-spacing: 0.04em; }
    .meta-row div span.value { font-weight: 600; font-size: 1.05em; }

    /* ---------- Summary Cards ---------- */
    .cards { display: grid; grid-template-columns: repeat(auto-fit, minmax(150px, 1fr)); gap: 14px; margin-bottom: 22px; }
    .card { background: white; border-radius: 10px; padding: 16px 18px; box-shadow: 0 2px 6px rgba(0,0,0,0.06); border-top: 4px solid var(--none); cursor: pointer; transition: transform .12s ease; }
    .card:hover { transform: translateY(-2px); }
    .card.active { outline: 2px solid #1e293b33; }
    .card .num { font-size: 1.9em; font-weight: 700; line-height: 1; }
    .card .lbl { color: #64748b; font-size: 0.82em; margin-top: 6px; text-transform: uppercase; letter-spacing: 0.03em; }
    .card.crit { border-top-color: var(--crit); } .card.crit .num { color: var(--crit); }
    .card.high { border-top-color: var(--high); } .card.high .num { color: var(--high); }
    .card.med  { border-top-color: var(--med);  } .card.med  .num { color: var(--med); }
    .card.low  { border-top-color: var(--low);  } .card.low  .num { color: var(--low); }
    .card.total{ border-top-color: var(--accent); } .card.total .num { color: var(--accent); }

    /* ---------- Sections ---------- */
    .section { background: white; border-radius: 10px; box-shadow: 0 2px 6px rgba(0,0,0,0.06); margin-bottom: 20px; overflow: hidden; }
    .section h2 { margin: 0; padding: 16px 20px; font-size: 1.05em; border-bottom: 1px solid #e2e8f0; color: #1e293b; }

    table { width: 100%; border-collapse: collapse; }
    th { background: #f8fafc; padding: 10px 14px; text-align: left; font-size: 0.78em; text-transform: uppercase; letter-spacing: 0.03em; color: #64748b; border-bottom: 2px solid #e2e8f0; }
    td { padding: 10px 14px; border-bottom: 1px solid #f1f5f9; font-size: 0.88em; vertical-align: middle; }
    tr.adv-row:hover { background: #f8fafc; }

    .sev-cell { width: 5px; padding: 0; }
    .sev-cell.sev-crit { background: var(--crit); }
    .sev-cell.sev-high { background: var(--high); }
    .sev-cell.sev-med  { background: var(--med); }
    .sev-cell.sev-low  { background: var(--low); }
    .sev-cell.sev-none { background: var(--none); }

    .badge { padding: 3px 10px; border-radius: 20px; font-weight: 700; font-size: 0.72em; display: inline-block; letter-spacing: 0.03em; }
    .badge.sev-crit { background: var(--crit-bg); color: var(--crit); }
    .badge.sev-high { background: var(--high-bg); color: var(--high); }
    .badge.sev-med  { background: var(--med-bg);  color: var(--med); }
    .badge.sev-low  { background: var(--low-bg);  color: var(--low); }
    .badge.sev-none { background: var(--none-bg); color: var(--none); }

    .tag { padding: 2px 8px; border-radius: 4px; font-size: 0.75em; font-weight: 700; }
    .tag-vc  { background: #dbeafe; color: #1d4ed8; }
    .tag-esx { background: #ede9fe; color: #6d28d9; }
    .status-ok     { color: var(--low); font-weight: 600; }
    .status-warn   { color: var(--med); font-weight: 600; }
    .status-manual { color: var(--none); font-weight: 600; }

    .title-cell { max-width: 420px; }
    .pub-cell { white-space: nowrap; color: #64748b; font-size: 0.85em; }

    .btn-toggle { background-color: #eff6ff; color: var(--accent); border: 1px solid #bfdbfe; padding: 5px 10px; border-radius: 6px; cursor: pointer; font-size: 0.82em; white-space: nowrap; }
    .btn-toggle:hover { background-color: #dbeafe; }
    .btn-toggle .chev { display: inline-block; transition: transform .15s ease; font-size: 0.8em; }
    .btn-toggle.open .chev { transform: rotate(180deg); }

    .details-row { display: none; background-color: #f8fafc; }
    .details-box { padding: 16px 18px; border-left: 4px solid var(--accent); margin: 8px; background: white; border-radius: 6px; }
    .detail-grid { display: grid; grid-template-columns: 1fr 1fr; gap: 16px; margin-bottom: 12px; }
    .matrix-header { background: #eef2ff; color: #3730a3; font-family: Consolas, 'Courier New', monospace; font-size: 0.8em; font-weight: 700; padding: 6px 10px; border-radius: 4px 4px 0 0; margin-top: 6px; white-space: pre-wrap; border: 1px solid #e0e7ff; border-bottom: none; }
    .info-text { font-family: Consolas, 'Courier New', monospace; color: #334155; font-size: 0.85em; white-space: pre-wrap; display: block; padding: 6px 10px; border: 1px solid #e2e8f0; border-radius: 0 0 4px 4px; background: #f8fafc; }
    .asset-text { font-family: 'Segoe UI', sans-serif; color: #b91c1c; font-weight: 600; font-size: 0.92em; }
    .link-text { color: var(--accent); font-size: 0.88em; word-break: break-all; }

    a { color: var(--accent); text-decoration: none; font-weight: 600; } a:hover { text-decoration: underline; }

    /* ---------- Toolbar ---------- */
    .toolbar { display: flex; flex-wrap: wrap; gap: 10px; align-items: center; padding: 14px 20px; border-bottom: 1px solid #e2e8f0; }
    .toolbar input[type=text] { flex: 1; min-width: 200px; padding: 8px 12px; border: 1px solid #cbd5e1; border-radius: 6px; font-size: 0.9em; }
    .toolbar button.util-btn { background: #f1f5f9; border: 1px solid #cbd5e1; padding: 7px 12px; border-radius: 6px; cursor: pointer; font-size: 0.82em; color: #334155; }
    .toolbar button.util-btn:hover { background: #e2e8f0; }

    .footer { text-align: center; color: #94a3b8; font-size: 0.8em; padding: 16px 0 30px; }

    @media print {
        body { background: white; }
        .toolbar, .card { display: none !important; }
        .details-row { display: table-row !important; }
    }
</style>
<script>
    function toggleDetails(rowId, btn) {
        var row = document.getElementById(rowId);
        var isOpen = row.style.display === 'table-row';
        row.style.display = isOpen ? 'none' : 'table-row';
        if (btn) { btn.classList.toggle('open', !isOpen); }
    }
    function setAllDetails(show) {
        document.querySelectorAll('.details-row').forEach(function(r){ r.style.display = show ? 'table-row' : 'none'; });
        document.querySelectorAll('.btn-toggle').forEach(function(b){ b.classList.toggle('open', show); });
    }
    function filterSeverity(sev, cardEl) {
        document.querySelectorAll('.card').forEach(function(c){ c.classList.remove('active'); });
        if (cardEl) { cardEl.classList.add('active'); }
        document.querySelectorAll('tr.adv-row').forEach(function(r){
            var match = (sev === 'all') || (r.getAttribute('data-severity') === sev);
            r.style.display = match ? '' : 'none';
            var detailsRow = r.nextElementSibling;
            if (detailsRow && detailsRow.classList.contains('details-row')) {
                if (!match) { detailsRow.style.display = 'none'; }
            }
        });
        applySearch();
    }
    function applySearch() {
        var q = document.getElementById('searchBox').value.toLowerCase();
        document.querySelectorAll('tr.adv-row').forEach(function(r){
            if (r.style.display === 'none' && q === '') { return; }
            var text = r.innerText.toLowerCase();
            var visible = text.indexOf(q) !== -1;
            var alreadyHidden = r.style.display === 'none';
            if (q === '') {
                // leave severity filter state alone
            } else {
                r.style.display = visible ? '' : 'none';
            }
        });
    }
</script>
</head>
<body>
<div class="page">

    <div class="report-header">
        <h1>vSphere Security Audit Report</h1>
        <div class="sub">Offline VMSA advisory matching against live vCenter / ESXi inventory</div>
        <div class="meta-row">
            <div><span class="label">Target vCenter</span><span class="value">$vcServer</span></div>
            <div><span class="label">Analysis Mode</span><span class="value">$ModeLabel</span></div>
            <div><span class="label">Report Generated</span><span class="value">$GeneratedAtDisplay</span></div>
            <div><span class="label">Advisory Data Source Date</span><span class="value">$($JsonData.Metadata.GeneratedAt)</span></div>
            <div><span class="label">Advisories Checked</span><span class="value">$($JsonData.Metadata.TotalCount)</span></div>
        </div>
    </div>

    <div class="cards">
        <div class="card total" onclick="filterSeverity('all', this)"><div class="num">$TotalCount</div><div class="lbl">Total Matches</div></div>
        <div class="card crit" onclick="filterSeverity('sev-crit', this)"><div class="num">$CritCount</div><div class="lbl">Critical</div></div>
        <div class="card high" onclick="filterSeverity('sev-high', this)"><div class="num">$HighCount</div><div class="lbl">High</div></div>
        <div class="card med"  onclick="filterSeverity('sev-med', this)"><div class="num">$MedCount</div><div class="lbl">Medium</div></div>
        <div class="card low"  onclick="filterSeverity('sev-low', this)"><div class="num">$LowCount</div><div class="lbl">Low</div></div>
    </div>

    <div class="section">
        <h2>Environment Inventory</h2>
        <table>
            <thead><tr><th>Component</th><th>Name</th><th>Version</th><th>Status</th></tr></thead>
            <tbody>
                $InventoryRows
            </tbody>
        </table>
    </div>

    <div class="section">
        <h2>Matched Advisories ($TotalCount)</h2>
        <div class="toolbar">
            <input type="text" id="searchBox" placeholder="Search by ID, title, or asset..." onkeyup="applySearch()">
            <button class="util-btn" onclick="setAllDetails(true)">Expand All</button>
            <button class="util-btn" onclick="setAllDetails(false)">Collapse All</button>
            <button class="util-btn" onclick="filterSeverity('all', document.querySelector('.card.total'))">Clear Filter</button>
        </div>
        <table>
            <thead><tr>
                <th></th><th>Severity</th><th>Product</th><th>Advisory ID</th><th>Title</th><th>Published</th><th>Action</th>
            </tr></thead>
            <tbody>
                $HtmlRows
            </tbody>
        </table>
    </div>

    <div class="footer">Generated by vmsa_audit.ps1 &middot; $GeneratedAtDisplay &middot; $ModeLabel &middot; Credentials (if used) are requested interactively and are never saved to disk.</div>

</div>
</body>
</html>
"@

    $HtmlContent | Out-File -FilePath $HtmlPath -Encoding UTF8

    Write-Host "`n[DONE] Report Generated." -ForegroundColor Green
    Write-Host " - CSV: $CsvPath"
    Write-Host " - HTML: $HtmlPath"
    Invoke-Item $HtmlPath
} else {
    Write-Host "`n[DONE] No advisories matched your specific versions based on the Response Matrix." -ForegroundColor Green
}

if ($Connected) {
    Disconnect-VIServer -Confirm:$false
}
