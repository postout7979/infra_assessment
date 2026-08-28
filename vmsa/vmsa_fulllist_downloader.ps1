# =============================================================================
# [Script 4] VMSA Full List Downloader - CSV + JSON Report (Incremental)
# -----------------------------------------------------------------------------
# Environment: Internet-connected PC
# Function:
# 1. Calls Broadcom's Security Advisory List API (POST) and pages through
#    EVERY page (pageSize=20) for the "VC" (VMware Cloud) segment, collecting
#    the full advisory list (currently ~340 items across ~17 pages) - this is
#    the same listing shown at:
#      https://support.broadcom.com/web/ecx/security-advisory
#    That page itself is a JavaScript app that calls this API client-side, so
#    a plain page fetch never shows the list - this script calls the API
#    directly instead, exactly like the site's own front-end does.
# 2. Re-opens EACH *new* advisory's individual detail page (VMSA-####-####)
#    to pull its CVSS score, full Response Matrix, AND every CVE's
#    description - all straight from that same page. No NVD / external CVE
#    database call is made anymore, so there is no query rate limit.
# 3. INCREMENTAL: on the first run, VMSA_FullList_Data.json (no date in the
#    name) is created from scratch. On every later run, that file is read
#    first, its known AdvisoryIDs are noted, and ONLY advisories whose ID is
#    not already in the file get their detail page crawled - already-known
#    advisories are carried forward unchanged instead of being re-fetched.
#    Pass -ForceRefreshAll to ignore the cache and re-crawl everything.
# 3b. PAGE RANGE: -StartPage / -EndPage (both 1-based, EndPage=0 means "no
#    limit - go to the last page") let you fetch only part of the listing,
#    e.g. -StartPage 1 -EndPage 2 to pull just the newest 40 items instead of
#    paging through all ~17 pages every time.
#      Examples:
#        .\VMSA_FullList_Downloader.ps1                          # all pages
#        .\VMSA_FullList_Downloader.ps1 -StartPage 1 -EndPage 2  # newest 2 pages only
#        .\VMSA_FullList_Downloader.ps1 -StartPage 5 -EndPage 5  # just page 5
#        .\VMSA_FullList_Downloader.ps1 -PageSize 50 -EndPage 3  # 50/page, first 3 pages
# 4. Writes TWO CSV files (timestamped, one snapshot per run) and updates the
#    single JSON file (Metadata + Advisories, each with CveDescriptions):
#      - VMSA_All_Advisories_<timestamp>.csv -> every advisory (all ~340)
#      - VMSA_CVE_List_<timestamp>.csv       -> one row per unique CVE - just
#                                                the ID and which advisory(ies)
#                                                it belongs to, NO description
#                                                (use the companion
#                                                VMSA_CVE_Lookup.ps1 script to
#                                                fetch descriptions/CVSS for
#                                                these IDs from an online CVE
#                                                database)
#      - VMSA_FullList_Data.json             -> cumulative full dataset, same
#                                                shape as VMSA_Offline_Data.json
# 5. Also writes an HTML report (VMSA_Report_<timestamp>.html, English UI)
#    with a Product dropdown and a dependent Version checkbox list (every
#    exact version found for that product, same 8 fixed categories as the
#    CSV split below, plus an "ALL" checkbox to show every version at once);
#    multiple versions can be checked together, and the matching advisories
#    are shown with each Response Matrix rendered as a real table.
# 6. Also splits the advisories into a FIXED set of category CSVs based on
#    the "VMware Product" (and, where present, "Component") columns of each
#    advisory's own Response Matrix, written into a
#    VMSA_By_Category_<timestamp>/ subfolder - one file each:
#      ESX / vCenter / VMware Cloud Foundation / VMware vSphere Foundation /
#      Operations / Automation / NSX / Tools
#    -> column 1 of each file is that category's affected version(s) for the
#       advisory in that row (an advisory can appear in more than one
#       category's file if its matrix covers more than one of them). A
#       "Product | Component | Version | ..." row (e.g. a VMware Cloud
#       Foundation bundle listing "vCenter Server" as the affected
#       component) is matched against BOTH the Product and Component text,
#       using the Version from the correct column either way.
# 7. Response Matrix extraction has a text-mining last resort: if an
#    advisory's page has no real table, no <pre> ASCII table, and no
#    data-label div table either, the page's plain visible text is scanned
#    for "<product name> ... <version>" mentions so at least Product +
#    Version can still be recovered instead of leaving the matrix empty.
# =============================================================================

param(
    [string]$Segment = "VC",     # VMware Cloud segment - same as the site's default VC filter
    [int]$PageSize = 20,
    [int]$StartPage = 1,         # 1-based - first list page to fetch (e.g. 1 = newest 20 items)
    [int]$EndPage = 0,           # 1-based, inclusive - last list page to fetch. 0 = no limit (fetch through the last page)
    [int]$DelayMsBetweenListPages = 400,
    [int]$DelayMsBetweenDetailPages = 300,
    [switch]$ForceRefreshAll     # ignore the JSON cache and re-crawl every advisory
)

if ($StartPage -lt 1) { $StartPage = 1 }
if ($EndPage -ne 0 -and $EndPage -lt $StartPage) {
    Write-Error "-EndPage ($EndPage) cannot be smaller than -StartPage ($StartPage)."
    exit
}

$ErrorActionPreference = "Stop"
$CurrentDir = $PSScriptRoot
if ([string]::IsNullOrWhiteSpace($CurrentDir)) { $CurrentDir = Get-Location }

$Timestamp      = Get-Date -Format "yyyyMMdd-HHmm"
$CsvAllPath     = Join-Path $CurrentDir "VMSA_All_Advisories_$Timestamp.csv"
$CsvCveListPath = Join-Path $CurrentDir "VMSA_CVE_List_$Timestamp.csv"
$JsonPath       = Join-Path $CurrentDir "VMSA_FullList_Data.json"   # fixed name - no timestamp, used as the incremental cache

[System.Net.ServicePointManager]::SecurityProtocol = [System.Net.SecurityProtocolType]::Tls12
$ApiUrl = "https://support.broadcom.com/web/ecx/security-advisory/-/securityadvisory/getSecurityAdvisoryList"
$CveIdRegex = "CVE-\d{4}-\d{4,7}"

# =============================================================================
# 0. Load previously saved data (if any) so we only fetch what's new
# =============================================================================
$ExistingById = @{}
if ((Test-Path $JsonPath) -and (-not $ForceRefreshAll)) {
    try {
        $ExistingData = Get-Content -Path $JsonPath -Raw -Encoding UTF8 | ConvertFrom-Json
        foreach ($rec in $ExistingData.Advisories) { $ExistingById[$rec.AdvisoryID] = $rec }
        Write-Host "[0] Loaded existing data: $($ExistingById.Count) advisories already known from $JsonPath" -ForegroundColor Gray
    } catch {
        Write-Warning "Could not read existing $JsonPath - treating this as a first run. ($($_.Exception.Message))"
        $ExistingById = @{}
    }
} elseif ($ForceRefreshAll) {
    Write-Host "[0] -ForceRefreshAll set - ignoring any existing $JsonPath and re-crawling everything." -ForegroundColor Yellow
} else {
    Write-Host "[0] No existing $JsonPath found - this is the first run, every advisory will be crawled." -ForegroundColor Gray
}

# =============================================================================
# 1. Page through the FULL advisory list via the POST API (all pages)
# =============================================================================
$pageRangeLabel = if ($EndPage -eq 0) { "page $StartPage through the last page" } else { "pages $StartPage-$EndPage" }
Write-Host "[1] Collecting the advisory list for segment '$Segment' ($pageRangeLabel, pageSize=$PageSize) ..." -ForegroundColor Cyan

$AllItems = New-Object System.Collections.Generic.List[Object]
$PageNumber = $StartPage - 1   # API's pageNumber is 0-based; -StartPage is the 1-based page a person would type
$TotalCount = $null
$MaxPagesSafety = 100   # hard stop so a bug/API change can't loop forever
$PagesFetched = 0

do {
    $Payload = @{
        pageNumber = $PageNumber
        pageSize   = $PageSize
        searchVal  = ""
        segment    = $Segment
        sortInfo   = @{ column = "published"; order = "DESC" }
    }

    try {
        $Response = Invoke-RestMethod -Uri $ApiUrl -Method Post -Body ($Payload | ConvertTo-Json) -ContentType "application/json" -TimeoutSec 20
    } catch {
        Write-Warning "  ! Page $($PageNumber + 1) failed: $($_.Exception.Message). Stopping pagination here."
        break
    }

    $PageItems = @($Response.data.list)
    if ($null -eq $TotalCount -and $Response.data.total) { $TotalCount = [int]$Response.data.total }

    if ($PageItems.Count -gt 0) { $AllItems.AddRange([object[]]$PageItems) }
    $PagesFetched++

    $totalLabel = if ($TotalCount) { " / $TotalCount" } else { "" }
    Write-Host "    -> Page $($PageNumber + 1): $($PageItems.Count) items (running total: $($AllItems.Count)$totalLabel)" -ForegroundColor Gray

    $PageNumber++
    Start-Sleep -Milliseconds $DelayMsBetweenListPages

} while ($PageItems.Count -gt 0 -and (-not $TotalCount -or ($PageNumber * $PageSize) -lt $TotalCount) -and ($EndPage -eq 0 -or $PageNumber -lt $EndPage) -and $PagesFetched -lt $MaxPagesSafety)

Write-Host "[1] Done. Collected $($AllItems.Count) advisories from $PagesFetched page(s) ($pageRangeLabel)." -ForegroundColor Green

if ($AllItems.Count -eq 0) {
    Write-Error "No advisories were collected - the API may have changed or the connection failed. Aborting."
    exit
}

# Split into "already known" (reuse as-is) vs "new" (needs a detail crawl)
$NewItems = @($AllItems | Where-Object { -not $ExistingById.ContainsKey($_.documentId) })
$KnownCount = $AllItems.Count - $NewItems.Count
Write-Host "    -> $KnownCount already known (will be reused, not re-crawled) / $($NewItems.Count) new (will be crawled)" -ForegroundColor Cyan

# =============================================================================
# 2. Re-open each NEW advisory's own detail page for CVSS + Response Matrix
#    + CVE descriptions - everything read from that one page, no NVD calls.
# =============================================================================

# Strips tags and decodes EVERY HTML entity (not just the literal "&nbsp;"
# text) - a numeric entity like "&#160;" was slipping through untouched
# before and showing up as literal "&#160;" in product names, splitting
# what should be one product ("VMware Cloud Foundation" vs "VMware Cloud
# Foundation&#160;") into two different-looking strings.
function Get-CleanCellText {
    param([string]$Html)
    if ($null -eq $Html) { return "" }
    $stripped = $Html -replace "<.*?>", ""
    return ([System.Net.WebUtility]::HtmlDecode($stripped)).Trim()
}
function Get-CveDescriptionFromPage {
    param($AllRowsHtml, [string]$HtmlContent, [string]$CveId)

    $Description = $null

    # Strategy A: find a table row that mentions this CVE ID, and use the
    # longest OTHER cell in that row as its description (skips cells that
    # are just the CVE id itself, a bare score, or a bare severity word).
    foreach ($row in $AllRowsHtml) {
        $rowContent = $row.Groups[1].Value
        if ($rowContent -notmatch [Regex]::Escape($CveId)) { continue }

        $Cells = [Regex]::Matches($rowContent, "<t[dh].*?>(.*?)<\/t[dh]>", [System.Text.RegularExpressions.RegexOptions]::IgnoreCase)
        $CellTexts = @()
        foreach ($cell in $Cells) {
            $txt = (Get-CleanCellText -Html ($cell.Groups[1].Value))
            if (-not [string]::IsNullOrWhiteSpace($txt)) { $CellTexts += $txt }
        }
        if ($CellTexts.Count -eq 0) { continue }

        $Candidates = $CellTexts | Where-Object {
            $_ -notmatch "^CVE-\d{4}-\d+" -and
            $_ -notmatch "^\d+(\.\d+)?(\s*[-,]\s*\d+(\.\d+)?)*$" -and
            $_ -notmatch "^(Critical|Important|Moderate|Low|High|Medium|N\/A)$" -and
            $_.Length -ge 15
        }
        if ($Candidates.Count -gt 0) {
            $Description = ($Candidates | Sort-Object Length -Descending | Select-Object -First 1)
            break
        }
    }

    # Strategy B: fallback - grab the text that immediately follows the CVE
    # ID mention anywhere on the page (covers pages using paragraphs instead
    # of a table for the per-CVE write-up).
    if (-not $Description) {
        $pattern = [Regex]::Escape($CveId) + "\s*[\)\:\-]?\s*([^<]{20,400})"
        if ($HtmlContent -match $pattern) {
            $candidate = (Get-CleanCellText -Html $matches[1])
            if ($candidate.Length -ge 15) { $Description = $candidate }
        }
    }

    if (-not $Description) {
        $Description = "No inline description found on the advisory page - see the advisory link for full details."
    }

    return $Description
}

# Some older advisories (roughly VMSA-2018-era and earlier) don't render the
# Response Matrix as a real HTML <table> at all - they instead reproduce the
# original plain-text security bulletin verbatim inside a <pre> block, using
# a fixed-width, space-aligned ASCII table (often with a "=====" underline
# row under each column header). Get-AdvisoryDetail's normal <tr>/<td> scan
# finds nothing on those pages. This function parses that ASCII layout
# instead: it finds the header line, locates the character offset of each
# known column name on that line, and slices every following data line at
# those same offsets - a standard technique for monospaced/columnar text.
function Get-LegacyMatrixFromPreText {
    param([string]$PreText)

    if ([string]::IsNullOrWhiteSpace($PreText)) { return @() }
    $Lines = $PreText -split "`r?`n"

    $HeaderIdx = -1
    for ($i = 0; $i -lt $Lines.Count; $i++) {
        if ($Lines[$i] -match "(?i)VMware\s*Product") { $HeaderIdx = $i; break }
    }
    if ($HeaderIdx -eq -1) { return @() }

    $KnownHeaders = @(
        @{ Name = "Product";    Pattern = "VMware\s*Product" },
        @{ Name = "Version";    Pattern = "Product\s*Version" },
        @{ Name = "RunningOn";  Pattern = "Running\s*on" },
        @{ Name = "Severity";   Pattern = "Severity" },
        @{ Name = "Fixed";      Pattern = "Replace\s*with\s*/?\s*Apply\s*Patch" },
        @{ Name = "Mitigation"; Pattern = "Mitigation\s*/?\s*Workaround" }
    )

    $HeaderLine = $Lines[$HeaderIdx]
    $Cols = @()
    foreach ($h in $KnownHeaders) {
        $hm = [Regex]::Match($HeaderLine, $h.Pattern, [System.Text.RegularExpressions.RegexOptions]::IgnoreCase)
        if ($hm.Success) { $Cols += [PSCustomObject]@{ Name = $h.Name; Start = $hm.Index } }
    }
    if ($Cols.Count -lt 2) { return @() }
    $Cols = @($Cols | Sort-Object Start)

    $Rows = New-Object System.Collections.Generic.List[Object]
    for ($i = $HeaderIdx + 1; $i -lt $Lines.Count; $i++) {
        $line = $Lines[$i]
        if ([string]::IsNullOrWhiteSpace($line)) { continue }
        if ($line -match "^[\s=\-\*]+$") { continue }                              # "=====" underline rows
        if ($line -match "(?i)^\s*(Bulletins?,|Note\s*:|\*\s*Customers)") { break } # trailing footnote ends the table

        $Record = [ordered]@{ Product = $null; Version = $null; RunningOn = $null; Severity = $null; Fixed = $null; Mitigation = $null }
        for ($c = 0; $c -lt $Cols.Count; $c++) {
            $colStart = $Cols[$c].Start
            $colEnd   = if ($c + 1 -lt $Cols.Count) { $Cols[$c + 1].Start } else { $line.Length }
            $colEnd   = [Math]::Min($colEnd, $line.Length)
            if ($colStart -ge $line.Length -or $colEnd -le $colStart) { continue }
            $Record[$Cols[$c].Name] = $line.Substring($colStart, $colEnd - $colStart).Trim()
        }
        if ($Record.Product) { $Rows.Add([PSCustomObject]$Record) }
    }
    return $Rows
}

# Fallback for older pages that use a div-based "responsive table" instead of
# a real <table> - each cell carries a data-label="Field Name" attribute
# (used by CSS to show the field name on narrow screens) right next to its
# actual value text, so the field/value pairs can be read straight off the
# attribute + following text without needing <tr>/<td> at all.
function Get-LegacyMatrixFromDataLabels {
    param([string]$HtmlContent)

    $CellMatches = [Regex]::Matches($HtmlContent, 'data-label\s*=\s*"([^"]*)"[^>]*>\s*([^<]*)', [System.Text.RegularExpressions.RegexOptions]::IgnoreCase)
    if ($CellMatches.Count -eq 0) { return @() }

    $LabelMap = @{
        "vmware product" = "Product"; "product version" = "Version"; "running on" = "RunningOn"
        "severity" = "Severity"
        "replace with/ apply patch" = "Fixed"; "replace with/apply patch" = "Fixed"; "replace with / apply patch" = "Fixed"
        "mitigation/ workaround" = "Mitigation"; "mitigation/workaround" = "Mitigation"; "mitigation / workaround" = "Mitigation"
    }

    $Rows = New-Object System.Collections.Generic.List[Object]
    $Current = $null
    foreach ($m in $CellMatches) {
        $label = ([System.Net.WebUtility]::HtmlDecode($m.Groups[1].Value) -replace "=+", "").Trim().ToLower()
        $value = ([System.Net.WebUtility]::HtmlDecode($m.Groups[2].Value)).Trim()
        if (-not $LabelMap.ContainsKey($label)) { continue }
        $field = $LabelMap[$label]
        if ($field -eq "Product") {
            if ($Current -and $Current.Product) { $Rows.Add([PSCustomObject]$Current) }
            $Current = [ordered]@{ Product = $null; Version = $null; RunningOn = $null; Severity = $null; Fixed = $null; Mitigation = $null }
        }
        if ($Current) { $Current[$field] = $value }
    }
    if ($Current -and $Current.Product) { $Rows.Add([PSCustomObject]$Current) }
    return $Rows
}

# Last-resort fallback when a page has no real <table>, no <pre> ASCII
# table, and no data-label div table either: scan the page's plain visible
# text for "<known product name> ... <version-looking token>" mentions, so
# at least Product + Version can be recovered instead of leaving the matrix
# completely empty.
function Get-LegacyMatrixFromFreeText {
    param([string]$HtmlContent)

    $Plain = [System.Net.WebUtility]::HtmlDecode(($HtmlContent -replace "<[^>]+>", " "))
    $Plain = $Plain -replace "\s+", " "

    $KnownProducts = @(
        "VMware Cloud Foundation",
        "VMware vSphere Foundation",
        "vCenter Server",
        "ESXi",
        "NSX-T Data Center",
        "NSX",
        "Aria Operations",
        "Aria Automation",
        "VMware Tools"
    )

    $Rows = New-Object System.Collections.Generic.List[Object]
    $Seen = @{}
    foreach ($productName in $KnownProducts) {
        $pattern = [Regex]::Escape($productName) + "\D{0,20}?(\d+(?:\.\d+){0,3}(?:\s*[Uu]\d+)?)"
        $ms = [Regex]::Matches($Plain, $pattern, [System.Text.RegularExpressions.RegexOptions]::IgnoreCase)
        foreach ($m in $ms) {
            $ver = $m.Groups[1].Value.Trim()
            if ([string]::IsNullOrWhiteSpace($ver)) { continue }
            $key = "$productName|$ver"
            if ($Seen.ContainsKey($key)) { continue }
            $Seen[$key] = $true
            $Rows.Add([PSCustomObject]@{ Product = $productName; Version = $ver })
        }
    }
    return $Rows
}

function Get-AdvisoryDetail {
    param($Item)

    $Result = [PSCustomObject][ordered]@{
        AdvisoryID      = $Item.documentId
        Title           = $Item.title
        Severity        = $Item.severity
        CVSS            = "N/A"
        FixedInfo       = "Check Link for details"
        CveDescriptions = @()
        Link            = $Item.notificationUrl
        Published       = $Item.published
    }

    $HtmlContent = ""
    $PreBlocks = @()
    try {
        $WebReq = Invoke-WebRequest -Uri $Item.notificationUrl -UseBasicParsing -TimeoutSec 10 -ErrorAction Stop
        $RawContent = $WebReq.Content
        # Grab any <pre> blocks BEFORE newlines are collapsed below, so an
        # old-style ASCII response-matrix table keeps its original line breaks.
        $PreBlocks = [Regex]::Matches($RawContent, "<pre[^>]*>(.*?)</pre>", [System.Text.RegularExpressions.RegexOptions]::IgnoreCase -bor [System.Text.RegularExpressions.RegexOptions]::Singleline) |
            ForEach-Object { [System.Net.WebUtility]::HtmlDecode(($_.Groups[1].Value -replace "<[^>]+>", "")) }
        $HtmlContent = $RawContent -replace "`r", " " -replace "`n", " "
    } catch {
        Write-Warning "    ! Failed to open detail page for $($Item.documentId): $($_.Exception.Message)"
        return $Result
    }

    $AllRowsHtml = [Regex]::Matches($HtmlContent, "<tr.*?>(.*?)<\/tr>", [System.Text.RegularExpressions.RegexOptions]::IgnoreCase)

    # --- CVSS ---
    $CvssText = "N/A"
    foreach ($row in $AllRowsHtml) {
        $rowHtml = $row.Groups[1].Value
        $Cells = [Regex]::Matches($rowHtml, "<t[dh].*?>(.*?)<\/t[dh]>", [System.Text.RegularExpressions.RegexOptions]::IgnoreCase)
        if ($Cells.Count -ge 2) {
            $col1 = (Get-CleanCellText -Html ($Cells[0].Groups[1].Value))
            if ($col1 -match "(?i)CVSS.*?Range" -or $col1 -match "(?i)Base\s*Score") {
                $CvssText = (Get-CleanCellText -Html ($Cells[1].Groups[1].Value))
                break
            }
        }
    }
    if ($CvssText -eq "N/A") {
        if ($HtmlContent -match "(?i)CVSS\s*(?:v3)?\s*Base\s*Score\s*[:\s-]*\s*([^<]*)") {
            $CvssText = $matches[1].Trim()
        } elseif ($HtmlContent -match "(?i)CVSSv3\s*Range\s*[:\s-]*\s*([^<]*)") {
            $CvssText = $matches[1].Trim()
        }
        if ($CvssText -eq "N/A" -and $Item.severity) { $CvssText = $Item.severity }
    }
    $Result.CVSS = $CvssText

    # --- Response Matrix ---
    $FixedInfoText = @()
    foreach ($row in $AllRowsHtml) {
        $rowContent = $row.Groups[1].Value
        if ($rowContent -match "(ESXi|\bESX\b|vCenter\s*Server|Cloud\s*Foundation|NSX|Aria|Avi|Workstation|Fusion|Tools)") {
            $Cells = [Regex]::Matches($rowContent, "<td.*?>(.*?)<\/td>", [System.Text.RegularExpressions.RegexOptions]::IgnoreCase)
            $RowValues = @()
            foreach ($cell in $Cells) {
                $txt = (Get-CleanCellText -Html ($cell.Groups[1].Value))
                if (-not [string]::IsNullOrWhiteSpace($txt)) { $RowValues += $txt }
            }
            if ($RowValues.Count -gt 0 -and $RowValues[0].Trim() -notmatch "^(?i)Synopsis:?$") {
                $FixedInfoText += ($RowValues -join " | ")
            }
        }
    }
    if ($FixedInfoText.Count -eq 0) {
        if ($HtmlContent -match "(?i)Fixed Version.*?(:|<\/strong>|<\/b>)(.*?)(<br>|<\/p>|<\/td>)") {
            $rawText = (Get-CleanCellText -Html ($matches[2]))
            if (-not [string]::IsNullOrWhiteSpace($rawText)) { $FixedInfoText += $rawText }
        }
    }

    # --- Older bulletins: no real <table> at all - try the ASCII <pre> table,
    #     then the div/data-label responsive-table layout, as last resorts so
    #     we can still surface at least Product + Version (+ whatever else is
    #     available) instead of leaving the matrix empty.
    if ($FixedInfoText.Count -eq 0 -and $PreBlocks.Count -gt 0) {
        foreach ($pre in $PreBlocks) {
            $LegacyRows = Get-LegacyMatrixFromPreText -PreText $pre
            foreach ($lr in $LegacyRows) {
                $product    = if ($lr.Product)    { $lr.Product }    else { "N/A" }
                $version    = if ($lr.Version)    { $lr.Version }    else { "N/A" }
                $runningOn  = if ($lr.RunningOn)  { $lr.RunningOn }  else { "N/A" }
                $severity   = if ($lr.Severity)   { $lr.Severity }   else { "N/A" }
                $fixed      = if ($lr.Fixed)      { $lr.Fixed }      else { "N/A" }
                $mitigation = if ($lr.Mitigation) { $lr.Mitigation } else { "N/A" }
                $FixedInfoText += "$product | $version | $runningOn | N/A | N/A | $severity | $fixed | $mitigation | "
            }
            if ($FixedInfoText.Count -gt 0) { break }
        }
    }
    if ($FixedInfoText.Count -eq 0) {
        $LegacyRows = Get-LegacyMatrixFromDataLabels -HtmlContent $HtmlContent
        foreach ($lr in $LegacyRows) {
            $product    = if ($lr.Product)    { $lr.Product }    else { "N/A" }
            $version    = if ($lr.Version)    { $lr.Version }    else { "N/A" }
            $runningOn  = if ($lr.RunningOn)  { $lr.RunningOn }  else { "N/A" }
            $severity   = if ($lr.Severity)   { $lr.Severity }   else { "N/A" }
            $fixed      = if ($lr.Fixed)      { $lr.Fixed }      else { "N/A" }
            $mitigation = if ($lr.Mitigation) { $lr.Mitigation } else { "N/A" }
            $FixedInfoText += "$product | $version | $runningOn | N/A | N/A | $severity | $fixed | $mitigation | "
        }
    }
    if ($FixedInfoText.Count -eq 0) {
        $LegacyRows = Get-LegacyMatrixFromFreeText -HtmlContent $HtmlContent
        foreach ($lr in $LegacyRows) {
            $FixedInfoText += "$($lr.Product) | $($lr.Version) | N/A | N/A | N/A | N/A | N/A | N/A | "
        }
    }

    $FixedStr = if ($FixedInfoText.Count -gt 0) { $FixedInfoText -join "<br>" } else { "Check Link for details" }
    if ($FixedStr.Length -gt 3000) { $FixedStr = $FixedStr.Substring(0, 2997) + "..." }
    $Result.FixedInfo = $FixedStr

    # --- CVE Descriptions (straight from this same page - no NVD call) ---
    $TitleCveIds  = [Regex]::Matches($Result.Title, $CveIdRegex) | ForEach-Object { $_.Value }
    $MatrixCveIds = [Regex]::Matches($HtmlContent, $CveIdRegex) | ForEach-Object { $_.Value }
    $CveIds = ($TitleCveIds + $MatrixCveIds) | Select-Object -Unique

    $CveDescriptions = @()
    foreach ($cveId in $CveIds) {
        $desc = Get-CveDescriptionFromPage -AllRowsHtml $AllRowsHtml -HtmlContent $HtmlContent -CveId $cveId
        $CveDescriptions += [PSCustomObject][ordered]@{ CVE = $cveId; Description = $desc }
    }
    $Result.CveDescriptions = $CveDescriptions

    return $Result
}

Write-Host "[2] Crawling detail pages for $($NewItems.Count) new advisories (CVSS + Response Matrix + CVE descriptions)..." -ForegroundColor Cyan

$NewRecords = New-Object System.Collections.Generic.List[Object]
$Counter = 0
$Total = $NewItems.Count

foreach ($item in $NewItems) {
    $Counter++
    $PctComplete = 100
    if ($Total -gt 0) { $PctComplete = [math]::Round(($Counter / $Total) * 100) }
    Write-Progress -Activity "Crawling VMSA detail pages" -Status "[$Counter/$Total] $($item.documentId)" -PercentComplete $PctComplete
    $detail = Get-AdvisoryDetail -Item $item
    $NewRecords.Add($detail)
    Start-Sleep -Milliseconds $DelayMsBetweenDetailPages
}
Write-Progress -Activity "Crawling VMSA detail pages" -Completed

Write-Host "[2] Done. $($NewRecords.Count) new advisories crawled; $KnownCount reused from the existing JSON." -ForegroundColor Green

# =============================================================================
# 3. Combine: current live list order, using the freshly crawled record for
#    new items and the previously saved record for everything already known.
# =============================================================================
$NewById = @{}
foreach ($r in $NewRecords) { $NewById[$r.AdvisoryID] = $r }

$AllRecords = foreach ($item in $AllItems) {
    if ($NewById.ContainsKey($item.documentId)) {
        $NewById[$item.documentId]
    } else {
        $ExistingById[$item.documentId]
    }
}

# =============================================================================
# 4. Write the CSV files (each run gets its own timestamped snapshot)
# =============================================================================
Write-Host "[4] Writing CSV files..." -ForegroundColor Cyan

function ConvertTo-CsvRow {
    param($Record, [int]$Index)
    [PSCustomObject][ordered]@{
        No         = $Index
        AdvisoryID = $Record.AdvisoryID
        Title      = $Record.Title
        Severity   = $Record.Severity
        CVSS       = $Record.CVSS
        Published  = $Record.Published
        CVEs       = ($Record.CveDescriptions | ForEach-Object { $_.CVE }) -join "; "
        Link       = $Record.Link
        FixedInfo  = $Record.FixedInfo
    }
}

$i = 0
$AllCsvRows = $AllRecords | ForEach-Object { $i++; ConvertTo-CsvRow -Record $_ -Index $i }
$AllCsvRows | Export-Csv -LiteralPath $CsvAllPath -NoTypeInformation -Encoding UTF8

# CVE-level CSV: just the CVE list (no description - see the companion
# VMSA_CVE_Lookup.ps1 script to fetch descriptions/CVSS for these IDs online).
$CveIndex = @{}
foreach ($rec in $AllRecords) {
    foreach ($cd in $rec.CveDescriptions) {
        if (-not $CveIndex.ContainsKey($cd.CVE)) {
            $CveIndex[$cd.CVE] = New-Object System.Collections.Generic.List[string]
        }
        if (-not $CveIndex[$cd.CVE].Contains($rec.AdvisoryID)) {
            $CveIndex[$cd.CVE].Add($rec.AdvisoryID)
        }
    }
}

$i = 0
$CveCsvRows = $CveIndex.GetEnumerator() | Sort-Object Name | ForEach-Object {
    $i++
    [PSCustomObject][ordered]@{
        No            = $i
        CVE           = $_.Name
        AdvisoryIDs   = ($_.Value -join "; ")
        AdvisoryCount = $_.Value.Count
    }
}
$CveCsvRows | Export-Csv -LiteralPath $CsvCveListPath -NoTypeInformation -Encoding UTF8

Write-Host "    -> All Advisories CSV : $($AllCsvRows.Count) rows -> $CsvAllPath" -ForegroundColor Gray
Write-Host "    -> CVE List CSV       : $($CveCsvRows.Count) rows -> $CsvCveListPath" -ForegroundColor Gray

# =============================================================================
# 5. Write/update the JSON file (fixed filename - this IS the incremental cache)
# =============================================================================
Write-Host "[5] Writing JSON file..." -ForegroundColor Cyan

$ExportData = @{
    Metadata = @{
        GeneratedAt   = Get-Date -Format "yyyy-MM-dd HH:mm"
        LastUpdatedAt = Get-Date -Format "yyyy-MM-dd HH:mm"
        Source        = "Broadcom Support Portal (full '$Segment' segment list) - CVE descriptions read from each advisory's own page"
        TotalCount    = $AllRecords.Count
    }
    Advisories = $AllRecords
}

$ExportData | ConvertTo-Json -Depth 6 | Set-Content -Path $JsonPath -Encoding UTF8
Write-Host "    -> JSON: $JsonPath (no date in the filename - re-run this script anytime to append only new advisories)" -ForegroundColor Gray

# =============================================================================
# 6. Write the HTML report (English UI) - a Product dropdown, a dependent
#    Version checkbox list (every exact version found for whichever product
#    is selected, multi-select, plus an "ALL" checkbox), and a bottom list of
#    matching advisories, each with a real Response Matrix table (header row
#    included). Product options are the same 8 fixed
#    categories used for the CSV split in Step 8, so the two stay consistent.
# =============================================================================
Write-Host "[6] Writing HTML report..." -ForegroundColor Cyan

$HtmlPath = Join-Path $CurrentDir "VMSA_Report_$Timestamp.html"

$HtmlRecords = $AllRecords | ForEach-Object {
    [PSCustomObject][ordered]@{
        AdvisoryID = $_.AdvisoryID
        Title      = $_.Title
        Severity   = $_.Severity
        CVSS       = $_.CVSS
        Published  = $_.Published
        Link       = $_.Link
        FixedInfo  = $_.FixedInfo
    }
}

# Force a JSON array even when there is exactly 0 or 1 record (ConvertTo-Json
# can otherwise collapse a single object to a bare "{...}" instead of "[{...}]").
$HtmlJsonPieces = @($HtmlRecords | ForEach-Object { $_ | ConvertTo-Json -Depth 5 -Compress })
$HtmlJson = "[" + ($HtmlJsonPieces -join ",") + "]"
$HtmlJson = $HtmlJson -replace "(?i)</script", "<\/script"

$GeneratedAtLabel = Get-Date -Format "yyyy-MM-dd HH:mm"

$HtmlTemplate = @"
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<title>VMSA Advisory Report</title>
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
  .wrap { max-width:1200px; margin:0 auto; padding:24px 20px 60px; }
  .card { background:#fff; border:1px solid var(--border); border-radius:10px; padding:20px 22px; margin-bottom:20px; box-shadow:0 1px 3px rgba(0,0,0,.04); }
  .card h2 { margin:0 0 14px 0; font-size:16px; color:var(--navy); }
  .select-row { display:flex; gap:24px; flex-wrap:wrap; }
  .select-col { flex:1; min-width:260px; }
  .select-col label { display:block; font-size:13px; color:var(--navy); margin:0 0 6px 0; font-weight:600; }
  .select-col select { width:100%; padding:9px 10px; font-size:14px; border:1px solid var(--border); border-radius:6px; background:#fff; color:#1e293b; }
  .select-col select:disabled { background:#f1f5f9; color:var(--muted); }
  .version-checkbox-box { width:100%; max-height:180px; overflow-y:auto; border:1px solid var(--border); border-radius:6px; background:#fff; padding:8px 10px; box-sizing:border-box; }
  .version-check-item { display:block; font-size:13px; color:#1e293b; padding:3px 0; cursor:pointer; font-weight:400; }
  .version-check-item input { margin-right:8px; }
  .version-check-all { font-weight:600; color:var(--navy); border-bottom:1px solid var(--border); margin-bottom:4px; padding-bottom:6px; }
  .version-checkbox-box p.muted { margin:2px 0; }
  .sev-summary-row { display:flex; gap:12px; flex-wrap:wrap; }
  .sev-tile { flex:1; min-width:130px; border-radius:8px; padding:14px 16px; text-align:center; background:#f1f5f9; color:#475569; }
  .sev-tile .sev-count { font-size:26px; font-weight:700; line-height:1.1; }
  .sev-tile .sev-label { font-size:12px; margin-top:4px; font-weight:600; letter-spacing:.03em; text-transform:uppercase; }
  .sev-tile.sev-critical { background:var(--crit-bg); color:var(--crit-fg); }
  .sev-tile.sev-high { background:var(--high-bg); color:var(--high-fg); }
  .sev-tile.sev-medium { background:var(--med-bg); color:var(--med-fg); }
  .sev-tile.sev-low { background:var(--low-bg); color:var(--low-fg); }
  .sev-tile.sev-default { background:#e2e8f0; color:#475569; }
  .toolbar { margin-top:16px; display:flex; gap:10px; align-items:center; }
  button.reset { border:1px solid var(--border); background:#fff; border-radius:6px; padding:7px 14px; font-size:13px; cursor:pointer; color:#334155; }
  button.reset:hover { background:#f1f5f9; }
  #filterSummary { font-size:13px; color:var(--muted); }
  .badge { display:inline-block; padding:3px 10px; border-radius:20px; font-size:11px; font-weight:700; letter-spacing:.03em; }
  .badge-critical { background:var(--crit-bg); color:var(--crit-fg); }
  .badge-high { background:var(--high-bg); color:var(--high-fg); }
  .badge-medium { background:var(--med-bg); color:var(--med-fg); }
  .badge-low { background:var(--low-bg); color:var(--low-fg); }
  .badge-default { background:#e2e8f0; color:#475569; }
  .advisory-card { border:1px solid var(--border); border-radius:8px; margin-bottom:12px; overflow:hidden; }
  .advisory-card summary { cursor:pointer; padding:12px 16px; display:flex; align-items:center; gap:10px; flex-wrap:wrap; list-style:none; background:#f8fafc; }
  .advisory-card summary::-webkit-details-marker { display:none; }
  .advisory-card summary::before { content:"\25B8"; color:var(--muted); font-size:12px; margin-right:2px; transition:transform .15s ease; }
  .advisory-card[open] summary::before { transform:rotate(90deg); }
  .advisory-card summary:hover { background:#eef2f7; }
  .advisory-id { font-weight:700; color:var(--navy); font-size:13px; }
  .advisory-title-text { font-size:13px; color:#1e293b; flex:1; min-width:160px; }
  .advisory-date { font-size:12px; color:var(--muted); }
  .advisory-body { padding:14px 16px 16px; border-top:1px solid var(--border); }
  .advisory-title { font-weight:700; color:var(--navy); text-decoration:none; font-size:14px; }
  .advisory-title:hover { text-decoration:underline; }
  .advisory-meta { font-size:12px; color:var(--muted); margin:0 0 12px 0; }
  .advisory-meta a { color:var(--navy); }
  table.matrix-table { width:100%; border-collapse:collapse; font-size:12px; }
  table.matrix-table th { background:#f1f5f9; color:#334155; text-align:left; padding:7px 8px; border:1px solid var(--border); white-space:nowrap; }
  table.matrix-table td { padding:7px 8px; border:1px solid var(--border); vertical-align:top; }
  td.sev-critical { background:var(--crit-bg); color:var(--crit-fg); font-weight:700; }
  td.sev-high { background:var(--high-bg); color:var(--high-fg); font-weight:700; }
  td.sev-medium { background:var(--med-bg); color:var(--med-fg); font-weight:700; }
  td.sev-low { background:var(--low-bg); color:var(--low-fg); font-weight:700; }
  .muted { color:var(--muted); font-size:13px; }
  .matrix-wrap { overflow-x:auto; }
</style>
</head>
<body>
<header>
  <h1>VMSA Advisory Report</h1>
  <p>Generated $GeneratedAtLabel &nbsp;|&nbsp; Source: Broadcom Support Portal (advisory pages) &nbsp;|&nbsp; Total advisories: <span id="totalCount">0</span></p>
</header>
<div class="wrap">

  <div class="card">
    <h2 id="severitySummaryTitle">Severity Summary - All Advisories</h2>
    <div class="sev-summary-row" id="severitySummaryRow"></div>
  </div>

  <div class="card">
    <h2>Select Product and Version</h2>
    <div class="select-row">
      <div class="select-col">
        <label for="productSelect">Product</label>
        <select id="productSelect">
          <option value="">-- Select Product --</option>
        </select>
      </div>
      <div class="select-col">
        <label for="versionCheckboxes">Version (multi-select, or ALL)</label>
        <div id="versionCheckboxes" class="version-checkbox-box">
          <p class="muted">-- Select Product First --</p>
        </div>
      </div>
    </div>
    <div class="toolbar">
      <button class="reset" id="resetBtn">Reset</button>
      <span id="filterSummary"></span>
    </div>
  </div>

  <div class="card">
    <h2>Matching Advisories</h2>
    <div class="toolbar" id="expandToolbar" style="display:none; margin-top:0; margin-bottom:14px;">
      <button class="reset" id="expandAllBtn">Expand All</button>
      <button class="reset" id="collapseAllBtn">Collapse All</button>
    </div>
    <div id="filteredList"></div>
  </div>

</div>

<script>
const RECORDS = $HtmlJson;
const MATRIX_HEADERS = ["VMware Product","Version","Running On","CVE","CVSSv3","Severity","Fixed Version","Workarounds","Additional Documentation"];
const CVE_TEST_RE = /CVE-\d{4}-\d{4,7}/i;
const SEV_TEST_RE = /^(critical|important|high|moderate|medium|low)$/i;
const CVSS_TEST_RE = /^\d+(\.\d+)?(\s*[-,]\s*\d+(\.\d+)?)*$/;

// Same 8 fixed categories as the CSV split in Step 8 of the .ps1 script,
// so the product list here always matches the CSV files it produces.
const CATEGORY_DEFS = [
  { name: "ESX", re: /\bESXi?\b/i },
  { name: "vCenter", re: /vcenter/i },
  { name: "VMware Cloud Foundation", re: /cloud\s*foundation/i },
  { name: "VMware vSphere Foundation", re: /vsphere\s*foundation/i },
  { name: "Operations", re: /operations/i },
  { name: "Automation", re: /automation/i },
  { name: "NSX", re: /nsx/i },
  { name: "Tools", re: /tools/i }
];

function esc(s) {
  return String(s == null ? "" : s).replace(/[&<>"']/g, function (c) {
    return { "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c];
  });
}

function splitMatrixRows(fixedInfo) {
  if (!fixedInfo || fixedInfo === "Check Link for details") return [];
  return fixedInfo.split(/<br\s*\/?>/i).map(function (r) { return r.trim(); }).filter(Boolean);
}

function splitCols(row) {
  return row.split("|").map(function (c) { return c.trim(); });
}

function mapRow(cols) {
  const out = ["", "", "", "", "", "", "", "", ""];
  if (cols.length === 0) return out;
  const pv = extractProductVersion(cols);
  out[0] = pv.component ? (pv.product + " (" + pv.component + ")") : pv.product;
  out[1] = pv.version || "";
  const dataStart = pv.dataStartIdx;

  let cveIdx = -1, sevIdx = -1;
  for (let i = dataStart; i < cols.length; i++) {
    if (cveIdx === -1 && CVE_TEST_RE.test(cols[i])) cveIdx = i;
  }
  for (let i = dataStart; i < cols.length; i++) {
    if (SEV_TEST_RE.test(cols[i])) { sevIdx = i; break; }
  }
  if (cveIdx > dataStart) out[2] = cols.slice(dataStart, cveIdx).join(" / ");
  if (cveIdx !== -1) out[3] = cols[cveIdx];

  if (sevIdx !== -1) {
    out[5] = cols[sevIdx];
    if (sevIdx - 1 >= 0 && CVSS_TEST_RE.test(cols[sevIdx - 1])) out[4] = cols[sevIdx - 1];
    const rest = cols.slice(sevIdx + 1);
    out[6] = rest[0] || ""; out[7] = rest[1] || ""; out[8] = rest[2] || "";
  } else {
    const startIdx = cveIdx !== -1 ? cveIdx + 1 : dataStart;
    const rest = cols.slice(startIdx);
    out[6] = rest[0] || ""; out[7] = rest[1] || ""; out[8] = rest[2] || "";
  }
  return out;
}

function sevClassFromText(t) {
  const s = (t || "").toLowerCase();
  if (s.indexOf("critical") !== -1) return "sev-critical";
  if (s.indexOf("important") !== -1 || s.indexOf("high") !== -1) return "sev-high";
  if (s.indexOf("moderate") !== -1 || s.indexOf("medium") !== -1) return "sev-medium";
  if (s.indexOf("low") !== -1) return "sev-low";
  return "";
}

function sevRank(s) {
  const c = sevClassFromText(s);
  if (c === "sev-critical") return 4;
  if (c === "sev-high") return 3;
  if (c === "sev-medium") return 2;
  if (c === "sev-low") return 1;
  return 0;
}

// Fixed tile order/labels for the severity summary bar - matches VMware's
// own severity terms (sev-high covers both "Important" and "High" text,
// sev-medium covers both "Moderate" and "Medium"; sev-default is anything
// that doesn't match a known severity word at all).
const SEVERITY_TILES = [
  { cls: "sev-critical", label: "Critical" },
  { cls: "sev-high", label: "Important" },
  { cls: "sev-medium", label: "Moderate" },
  { cls: "sev-low", label: "Low" },
  { cls: "sev-default", label: "Other" }
];

// Renders the severity count tiles for whatever record list is passed in -
// called with ALL records when nothing is selected, and with just the
// currently matched/filtered records once a Product (and Version) is picked,
// so the counts always reflect what's actually showing below.
function renderSeveritySummary(records, titleSuffix) {
  const counts = { "sev-critical": 0, "sev-high": 0, "sev-medium": 0, "sev-low": 0, "sev-default": 0 };
  records.forEach(function (r) {
    const cls = sevClassFromText(r.Severity) || "sev-default";
    counts[cls] = (counts[cls] || 0) + 1;
  });
  document.getElementById("severitySummaryTitle").textContent =
    "Severity Summary - " + titleSuffix + " (" + records.length + " total)";
  const row = document.getElementById("severitySummaryRow");
  row.innerHTML = SEVERITY_TILES.map(function (t) {
    return '<div class="sev-tile ' + t.cls + '"><div class="sev-count">' + (counts[t.cls] || 0) +
      '</div><div class="sev-label">' + esc(t.label) + "</div></div>";
  }).join("");
}

function sevBadgeClass(s) {
  const c = sevClassFromText(s);
  return "badge-" + (c ? c.replace("sev-", "") : "default");
}

function getCategoryByName(name) {
  return CATEGORY_DEFS.find(function (c) { return c.name === name; });
}

// Most Response Matrix rows are "Product | Version | ..." (2 leading
// columns), but VMware Cloud Foundation / vSphere Foundation bundle rows are
// sometimes "Product | Component | Version | ..." (3 leading columns) where
// the 2nd column names the actually-affected sub-product (e.g. "vCenter
// Server", "ESXi") rather than a version number. Without this check, that
// component name was landing straight in the "version" slot. Detected the
// same way as the PowerShell-side Get-ProductVersionPairsFromFixedInfo: if
// there are >= 3 columns, column 2 does NOT look like a version and column 3
// DOES, treat column 2 as Component and column 3 as the real Version.
function extractProductVersion(cols) {
  const product = cols[0] || "";
  const col1 = cols.length > 1 ? cols[1] : "";
  const col2 = cols.length > 2 ? cols[2] : "";
  const looksLikeVersion = function (v) { return /^\d/.test(v || ""); };
  const isEmptyish = function (v) { return !v || /^(n\/a|-)$/i.test(v); };

  let component = null, version = "", dataStartIdx = 2;
  if (cols.length >= 3 && !isEmptyish(col1) && !looksLikeVersion(col1) && looksLikeVersion(col2)) {
    component = col1;
    version = col2;
    dataStartIdx = 3;
  } else {
    version = col1;
    dataStartIdx = 2;
  }

  // Whatever landed in the version slot might still not actually be a
  // version (e.g. a stray component/product name with no matching numeric
  // column at all) - don't show that text as if it were a real version,
  // normalize it to "N/A" instead so it doesn't pollute the version list.
  if (!isEmptyish(version) && !looksLikeVersion(version)) {
    version = "N/A";
  }

  return { product: product, component: component, version: version, dataStartIdx: dataStartIdx };
}

// Every (product, version) pair across the whole dataset that matches the
// given category's regex - used both to populate the Version dropdown and
// to count advisories per product for the Product dropdown labels.
function getCategoryMatches(category) {
  const matches = [];
  RECORDS.forEach(function (rec) {
    splitMatrixRows(rec.FixedInfo).forEach(function (row) {
      const cols = splitCols(row);
      const pv = extractProductVersion(cols);
      const version = (pv.version || "").trim();
      if (!version || /^(n\/a|-)$/i.test(version)) return;
      const matchText = pv.component ? (pv.product + " " + pv.component) : pv.product;
      if (category.re.test(matchText)) matches.push({ record: rec, version: version });
    });
  });
  return matches;
}

// Full, exact version strings for the category (e.g. "8.0 U3", "7.0.3",
// "4.5.1") - every distinct version actually seen in the Response Matrix,
// not collapsed down to a major-version-only bucket, so the checkbox list
// shows the real version numbers the data contains.
function versionSortKey(v) {
  return (String(v).match(/\d+/g) || []).map(Number);
}
function compareVersionsDesc(a, b) {
  const ka = versionSortKey(a), kb = versionSortKey(b);
  const len = Math.max(ka.length, kb.length);
  for (let i = 0; i < len; i++) {
    const na = ka[i] || 0, nb = kb[i] || 0;
    if (na !== nb) return nb - na;
  }
  return String(b).localeCompare(String(a));
}

function getCategoryVersions(category) {
  const set = new Set();
  getCategoryMatches(category).forEach(function (m) { set.add(m.version); });
  return Array.from(set).sort(compareVersionsDesc);
}

function getCategoryAdvisoryCount(category) {
  const set = new Set();
  getCategoryMatches(category).forEach(function (m) { set.add(m.record.AdvisoryID); });
  return set.size;
}

function populateProductSelect() {
  const sel = document.getElementById("productSelect");
  CATEGORY_DEFS.forEach(function (cat) {
    const count = getCategoryAdvisoryCount(cat);
    const opt = document.createElement("option");
    opt.value = cat.name;
    opt.textContent = cat.name + " (" + count + ")";
    sel.appendChild(opt);
  });
}

function populateVersionCheckboxes(categoryName) {
  const container = document.getElementById("versionCheckboxes");
  if (!categoryName) {
    container.innerHTML = '<p class="muted">-- Select Product First --</p>';
    return;
  }
  const category = getCategoryByName(categoryName);
  const versions = getCategoryVersions(category);
  if (versions.length === 0) {
    container.innerHTML = '<p class="muted">-- No Versions Found --</p>';
    return;
  }
  let html = '<label class="version-check-item version-check-all">' +
    '<input type="checkbox" class="version-check" value="__ALL__" checked> ALL (' + versions.length + ' version(s))</label>';
  versions.forEach(function (v) {
    html += '<label class="version-check-item"><input type="checkbox" class="version-check" value="' + esc(v) + '"> ' + esc(v) + '</label>';
  });
  container.innerHTML = html;
}

// { isAll: true } means no specific versions are checked (or the ALL box
// itself is checked) - treat that as "show every version". Otherwise only
// the explicitly checked exact version strings are included.
function getVersionSelection() {
  const container = document.getElementById("versionCheckboxes");
  const allBox = container.querySelector('.version-check[value="__ALL__"]');
  const versionBoxes = Array.from(container.querySelectorAll('.version-check:not([value="__ALL__"])'));
  const checked = versionBoxes.filter(function (cb) { return cb.checked; }).map(function (cb) { return cb.value; });
  const isAll = !allBox || allBox.checked || checked.length === 0;
  return { isAll: isAll, versions: checked };
}

function onVersionCheckboxChange(e) {
  if (!e.target.classList.contains("version-check")) return;
  const container = document.getElementById("versionCheckboxes");
  const allBox = container.querySelector('.version-check[value="__ALL__"]');
  const versionBoxes = Array.from(container.querySelectorAll('.version-check:not([value="__ALL__"])'));
  if (e.target.value === "__ALL__") {
    if (e.target.checked) {
      versionBoxes.forEach(function (cb) { cb.checked = false; });
    }
  } else if (e.target.checked) {
    if (allBox) allBox.checked = false;
  } else {
    const anyChecked = versionBoxes.some(function (cb) { return cb.checked; });
    if (!anyChecked && allBox) allBox.checked = true;
  }
  renderFilteredList();
}

function recordMatchesSelection(rec, category, selection) {
  const rows = splitMatrixRows(rec.FixedInfo).map(splitCols);
  for (let i = 0; i < rows.length; i++) {
    const cols = rows[i];
    const pv = extractProductVersion(cols);
    const matchText = pv.component ? (pv.product + " " + pv.component) : pv.product;
    const rowVersion = (pv.version || "").trim();
    if (!category.re.test(matchText)) continue;
    if (selection.isAll) return true;
    if (selection.versions.indexOf(rowVersion) !== -1) return true;
  }
  return false;
}

function buildMatrixTable(fixedInfo) {
  const rows = splitMatrixRows(fixedInfo);
  if (rows.length === 0) {
    return '<p class="muted">No Response Matrix data available - see the advisory link for full details.</p>';
  }
  let html = '<div class="matrix-wrap"><table class="matrix-table"><thead><tr>' +
    MATRIX_HEADERS.map(function (h) { return "<th>" + esc(h) + "</th>"; }).join("") +
    "</tr></thead><tbody>";
  rows.forEach(function (row) {
    const mapped = mapRow(splitCols(row));
    const sevClass = sevClassFromText(mapped[5]);
    html += "<tr>" + mapped.map(function (val, idx) {
      return idx === 5 ? '<td class="' + sevClass + '">' + esc(val) + "</td>" : "<td>" + esc(val) + "</td>";
    }).join("") + "</tr>";
  });
  html += "</tbody></table></div>";
  return html;
}

function renderFilteredList() {
  const productName = document.getElementById("productSelect").value;
  const container = document.getElementById("filteredList");
  const summary = document.getElementById("filterSummary");
  const toolbar = document.getElementById("expandToolbar");

  if (!productName) {
    container.innerHTML = "";
    toolbar.style.display = "none";
    summary.textContent = "Select a product above to see the advisories that affect it.";
    renderSeveritySummary(RECORDS, "All Advisories");
    return;
  }

  const category = getCategoryByName(productName);
  const selection = getVersionSelection();
  const matched = RECORDS.filter(function (r) { return recordMatchesSelection(r, category, selection); });
  matched.sort(function (a, b) {
    const d = sevRank(b.Severity) - sevRank(a.Severity);
    if (d !== 0) return d;
    return String(b.Published).localeCompare(String(a.Published));
  });

  const versionLabel = selection.isAll ? "ALL" : selection.versions.join(", ");
  summary.textContent = "Product: " + productName + " | Version(s): " + versionLabel + " -> " + matched.length + " advisory(ies) found";
  toolbar.style.display = matched.length > 0 ? "flex" : "none";
  renderSeveritySummary(matched, "Selected: " + productName + " / " + versionLabel);

  container.innerHTML = matched.map(function (r) {
    return '<details class="advisory-card">' +
      '<summary>' +
        '<span class="badge ' + sevBadgeClass(r.Severity) + '">' + esc((r.Severity || "").toUpperCase()) + "</span>" +
        '<span class="advisory-id">' + esc(r.AdvisoryID) + "</span>" +
        '<span class="advisory-title-text">' + esc(r.Title) + "</span>" +
        '<span class="advisory-date">' + esc(r.Published) + "</span>" +
      "</summary>" +
      '<div class="advisory-body">' +
        '<div class="advisory-meta">CVSS: ' + esc(r.CVSS) + " &nbsp;|&nbsp; Published: " + esc(r.Published) +
          ' &nbsp;|&nbsp; <a href="' + esc(r.Link) + '" target="_blank" rel="noopener">Advisory Link</a></div>' +
        buildMatrixTable(r.FixedInfo) +
      "</div>" +
      "</details>";
  }).join("");
}

function init() {
  document.getElementById("totalCount").textContent = RECORDS.length;
  populateProductSelect();
  populateVersionCheckboxes("");

  document.getElementById("productSelect").addEventListener("change", function (e) {
    populateVersionCheckboxes(e.target.value);
    renderFilteredList();
  });
  document.getElementById("versionCheckboxes").addEventListener("change", onVersionCheckboxChange);
  document.getElementById("resetBtn").addEventListener("click", function () {
    document.getElementById("productSelect").value = "";
    populateVersionCheckboxes("");
    renderFilteredList();
  });
  document.getElementById("expandAllBtn").addEventListener("click", function () {
    document.querySelectorAll("#filteredList details").forEach(function (d) { d.open = true; });
  });
  document.getElementById("collapseAllBtn").addEventListener("click", function () {
    document.querySelectorAll("#filteredList details").forEach(function (d) { d.open = false; });
  });

  renderFilteredList();
}

document.addEventListener("DOMContentLoaded", init);
</script>
</body>
</html>
"@

Set-Content -Path $HtmlPath -Value $HtmlTemplate -Encoding UTF8
Write-Host "    -> HTML: $HtmlPath ($($HtmlRecords.Count) advisories embedded)" -ForegroundColor Gray

# =============================================================================
# 7. Split into a FIXED set of category CSVs - ESX, vCenter, VMware Cloud
#    Foundation, VMware vSphere Foundation, Operations, Automation, NSX,
#    Tools - based on the "VMware Product" column of each advisory's own
#    Response Matrix. Column 1 of each file is that category's affected
#    version(s) for the advisory in that row. An advisory can appear in more
#    than one category's file if its matrix covers more than one of them.
# =============================================================================
Write-Host "[7] Splitting CSVs by category (ESX / vCenter / Cloud Foundation / vSphere Foundation / Operations / Automation / NSX / Tools)..." -ForegroundColor Cyan

# Pulls every (Product, Version) pair out of a Response Matrix - one pair per
# row, straight from columns 1 and 2.
function Get-ProductVersionPairsFromFixedInfo {
    param([string]$FixedInfo)

    $Pairs = New-Object System.Collections.Generic.List[Object]
    if ([string]::IsNullOrWhiteSpace($FixedInfo) -or $FixedInfo -eq "Check Link for details") { return $Pairs }

    foreach ($row in ($FixedInfo -split "<br>")) {
        $Cols = @($row -split "\s*\|\s*" | ForEach-Object { $_.Trim() })
        if ($Cols.Count -lt 2) { continue }
        $product = $Cols[0]
        if ([string]::IsNullOrWhiteSpace($product) -or $product -match "^(N/A|-)$") { continue }

        # Most rows are "Product | Version | ...". Some (VMware Cloud
        # Foundation / vSphere Foundation bundle advisories) are instead
        # "Product | Component | Version | ..." - column 2 names the actual
        # affected component (e.g. "vCenter Server", "ESXi", "NSX") rather
        # than a version. Detect that shape by checking whether column 2
        # itself looks like a version (starts with a digit); if it doesn't,
        # treat it as a Component and read the Version from column 3 instead.
        $component = $null
        $version   = $null
        if ($Cols.Count -ge 3 -and $Cols[1] -notmatch "^\d" -and $Cols[1] -notmatch "^(N/A|-)$" -and $Cols[2] -match "^\d") {
            $component = $Cols[1]
            $version   = $Cols[2]
        } else {
            $version = $Cols[1]
        }

        # Whatever landed in the version slot might still not actually be a
        # version (e.g. a stray component/product name with no matching
        # numeric column at all) - normalize it to N/A instead of treating
        # that text as a real version, so it gets filtered out below rather
        # than polluting the category CSV's version list.
        if (-not [string]::IsNullOrWhiteSpace($version) -and $version -notmatch "^\d" -and $version -notmatch "^(N/A|-)$") {
            $version = "N/A"
        }
        if ([string]::IsNullOrWhiteSpace($version) -or $version -match "^(N/A|-)$") { continue }

        # What a category is matched against: Product plus Component (if
        # any), so e.g. a VCF row whose Component is "vCenter Server" still
        # lands in the vCenter category/CSV, using ITS OWN version.
        $matchText = if ($component) { "$product $component" } else { $product }

        $Pairs.Add([PSCustomObject]@{ Product = $product; Component = $component; Version = $version; MatchText = $matchText })
    }
    return $Pairs
}

function ConvertTo-SafeFileName {
    param([string]$Name)
    # Decode any leftover HTML entities first (e.g. "&#160;"/"&nbsp;" non-
    # breaking spaces, footnote markers copied from the page) so they don't
    # end up as literal "&#160;" text in the filename, then strip every
    # character that is unsafe on Windows OR that PowerShell's -Path treats
    # as a wildcard (*, ?, [, ]).
    $decoded = [System.Net.WebUtility]::HtmlDecode($Name)
    $safe = ($decoded -replace '[\\/:*?"<>|\[\]\(\)]', '_') -replace '\s+', '_' -replace '_+', '_'
    $safe = $safe.Trim('_')
    if ([string]::IsNullOrWhiteSpace($safe)) { $safe = "Unknown" }
    return $safe
}

# Fixed category name -> regex matched (case-insensitive) against each
# matrix row's Product cell. Order doesn't matter here - a row's Product text
# is tested against every category, so an advisory can land in more than one.
$CategoryDefs = [ordered]@{
    "ESX"                       = "\bESXi?\b"
    "vCenter"                   = "vcenter"
    "VMware Cloud Foundation"   = "cloud\s*foundation"
    "VMware vSphere Foundation" = "vsphere\s*foundation"
    "Operations"                = "operations"
    "Automation"                = "automation"
    "NSX"                       = "nsx"
    "Tools"                     = "tools"
}

# CategoryName -> AdvisoryID -> { Record; Versions (list) }
$CategoryMap = [ordered]@{}
foreach ($catName in $CategoryDefs.Keys) { $CategoryMap[$catName] = @{} }

foreach ($rec in $AllRecords) {
    $Pairs = Get-ProductVersionPairsFromFixedInfo -FixedInfo $rec.FixedInfo
    if ($Pairs.Count -eq 0) { continue }
    foreach ($catName in $CategoryDefs.Keys) {
        $pattern = $CategoryDefs[$catName]
        $MatchingVersions = @($Pairs | Where-Object { $_.MatchText -match "(?i)$pattern" } | Select-Object -ExpandProperty Version -Unique)
        if ($MatchingVersions.Count -eq 0) { continue }

        if (-not $CategoryMap[$catName].ContainsKey($rec.AdvisoryID)) {
            $CategoryMap[$catName][$rec.AdvisoryID] = [PSCustomObject]@{ Record = $rec; Versions = New-Object System.Collections.Generic.List[string] }
        }
        foreach ($v in $MatchingVersions) {
            if (-not $CategoryMap[$catName][$rec.AdvisoryID].Versions.Contains($v)) {
                $CategoryMap[$catName][$rec.AdvisoryID].Versions.Add($v)
            }
        }
    }
}

$CategoryCsvDir = Join-Path $CurrentDir "VMSA_By_Category_$Timestamp"
New-Item -ItemType Directory -Path $CategoryCsvDir -Force | Out-Null

$CategorySummary = New-Object System.Collections.Generic.List[Object]
foreach ($catName in $CategoryDefs.Keys) {
    $Entries  = $CategoryMap[$catName].Values
    $SafeName = ConvertTo-SafeFileName -Name $catName
    $CsvPath  = Join-Path $CategoryCsvDir "VMSA_$SafeName.csv"

    $i = 0
    $Rows = $Entries | Sort-Object { $_.Record.Published } -Descending | ForEach-Object {
        $i++
        $entry = $_
        $rec   = $entry.Record
        [PSCustomObject][ordered]@{
            Version    = ($entry.Versions -join "; ")
            No         = $i
            AdvisoryID = $rec.AdvisoryID
            Title      = $rec.Title
            Severity   = $rec.Severity
            CVSS       = $rec.CVSS
            Published  = $rec.Published
            CVEs       = ($rec.CveDescriptions | ForEach-Object { $_.CVE }) -join "; "
            Link       = $rec.Link
            FixedInfo  = $rec.FixedInfo
        }
    }
    $Rows | Export-Csv -LiteralPath $CsvPath -NoTypeInformation -Encoding UTF8
    $CategorySummary.Add([PSCustomObject]@{ Category = $catName; Count = $Rows.Count; File = $CsvPath })
}

Write-Host "    -> $($CategoryDefs.Keys.Count) category CSV file(s) written to $CategoryCsvDir" -ForegroundColor Gray
$CategorySummary | ForEach-Object {
    Write-Host ("       {0,-28} {1,4} advisories -> {2}" -f $_.Category, $_.Count, (Split-Path $_.File -Leaf)) -ForegroundColor Gray
}

Write-Host "`n[DONE] Total: $($AllRecords.Count) | New this run: $($NewRecords.Count) | Reused: $KnownCount | Unique CVEs: $($CveIndex.Count) | Category CSVs: $CategoryCsvDir" -ForegroundColor Green