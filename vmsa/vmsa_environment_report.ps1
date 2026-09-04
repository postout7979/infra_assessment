# =============================================================================
# VMSA Environment Report - Live vCenter/ESXi Version Matching
# -----------------------------------------------------------------------------
# Environment: Machine that can reach the target vCenter (does NOT need
#              internet access, unlike vmsa_fulllist_downloader.ps1, as long
#              as VMSA_FullList_Data.json already exists next to this script).
# Function:
# 0. Dataset (VMSA_FullList_Data.json):
#      - If it already exists next to this script, it is loaded directly -
#        no crawling, no internet access needed.
#      - If it does NOT exist, this script looks for
#        vmsa_fulllist_downloader.ps1 in the same folder and runs it to
#        generate the JSON file (same behavior/format as that script - see
#        its own header for details), then loads the result. If that
#        downloader script is not present either, this script stops with an
#        error explaining what to do (run the downloader once on a machine
#        with internet access, then copy VMSA_FullList_Data.json here).
# 1. Prompts (interactively, via Read-Host) for the vCenter host/IP, the
#    account, and the password - no credentials are ever passed as
#    parameters or written to disk.
# 2. Connects to that vCenter with PowerCLI (installing the VMware.PowerCLI
#    module for the current user if it isn't already present) and reads:
#      - the vCenter Server's own version/build
#      - every ESXi host's version/build (hosts sharing the same
#        version+build are grouped together so they are reported once)
#    The vCenter session is disconnected again as soon as this data has been
#    collected - it is not held open while the report is being built. The
#    vCenter/ESXi host identity that ends up in the report (HTML header, and
#    the "Source" column of the Detected Versions table) is masked before it
#    is stored: an IPv4 address has its first three octets replaced (e.g.
#    "192.168.1.50" -> "***.***.***.50"), and an FQDN has its domain
#    replaced with the fixed placeholder "vcf.local" (e.g.
#    "vc01.corp.example.com" -> "vc01.vcf.local") - see
#    Get-MaskedHostIdentity. This only affects the report; the real,
#    unmasked host/IP is still what PowerCLI actually connects to, and
#    console messages during the live run still show it as typed.
# 3. Matches every advisory's Response Matrix rows against the detected
#    vCenter version and every detected ESXi version (major.minor(.update)
#    prefix match - a row saying just "8.0" matches any detected 8.0.x
#    build; a row using an "x" wildcard segment such as "9.1.x.x" matches
#    any build in that line). Two kinds of match are tracked separately per
#    advisory:
#      - Direct match: the row's own Version lines up with the detected
#        build (this covers plain "VMware ESX"/"VMware vCenter Server" rows,
#        AND VCF 9.x / VVF 9.x bundle rows, since VMware unified VCF's own
#        version numbering with the underlying component version starting
#        with VCF/VVF 9.0 - so a VCF 9.x row's "9.1.x.x" IS the real vCenter/
#        ESXi version there).
#      - Wrapper-product rows: a row whose Product mentions "VMware Cloud
#        Foundation", "VMware vSphere Foundation", OR "VMware Tools" AND
#        whose Component is vCenter/ESX, but whose own Version doesn't
#        literally line up with the detected build. Two different real
#        situations land here: (a) pre-9.x VCF/VVF, where the bundle's own
#        version (e.g. "5.x") is simply a different number from the
#        vCenter/ESXi version it ships (e.g. VCF 5.x ships vCenter/ESXi
#        8.x), and (b) a "VMware Tools (ESXi)"-style row, where some
#        advisories list the VMware Tools build shipped WITH a given ESXi
#        release this way (Component = ESXi, Version = that ESXi release).
#        For (a), only the VCF/VVF bundle-row major that is actually
#        relevant to THIS target's detected major is ever surfaced - a
#        detected 9.x build only looks at 9.x bundle rows, a detected 8.x
#        build only looks at 5.x bundle rows (VCF/VVF 5.x ships vSphere 8.x
#        components), and a detected build with neither a known mapping nor
#        unified numbering (e.g. 6.x/7.x) surfaces no bundle rows at all
#        (see Get-RelevantBundleMajors). (b) has no such restriction, since
#        its Version is just the ESXi release the Tools build shipped with,
#        not a VCF/VVF bundle version. Either shape
#        is then checked against a small, user-editable $VcfVvfMajorVersionMap
#        table (currently just "5" -> "8", for VCF/VVF's release-to-
#        component-version offset) - a row whose major version IS in that
#        table and whose mapped component major matches the detected build
#        counts as a confirmed "Direct (via VCF/VVF version mapping)" match;
#        anything else (including "VMware Tools (ESXi)" rows, which need no
#        mapping and just fall back to this path when their own Version
#        simply isn't the detected build) is still surfaced, just clearly
#        labeled "possible / needs verification" instead of being silently
#        dropped or silently treated as confirmed - so you can check it
#        against the actual VCF/VVF release notes or Tools/ESXi pairing. In
#        the HTML report this "possible" table sits inside its own
#        click-to-expand block under each advisory, rather than being shown
#        automatically.
#    Beyond that per-version matching, VMware Tools ALSO gets its own fully
#    separate, unfiltered reference list (no live version detection): a VM's
#    Guest.ToolsVersion is an internal build number with no reliable public
#    mapping back to the dotted release number VMSA advisories use, so
#    instead of risking a wrong auto-match there, every advisory whose
#    Response Matrix mentions "VMware Tools" anywhere (standalone rows AND
#    rows bundled under a VCF/VVF/ESXi Product) is simply listed, regardless
#    of version, for manual cross-checking. VMware Cloud Foundation/vSphere
#    Foundation get the same kind of separate, unfiltered reference list too
#    (section 4c) - every advisory with a Cloud Foundation/vSphere Foundation
#    row on the 5.x or 9.x line is listed there regardless of whether it
#    matches a version detected live, independent of the per-target
#    Direct/Possible matching in section 3.
#    Response Matrix rows are parsed by column POSITION - "Product |
#    [Component |] Version | Running On | CVE | CVSSv3 | Severity | Fixed
#    Version | Workarounds | Additional Documentation" - since older
#    advisories omit the Component column entirely while newer ones include
#    it (sometimes as a real value like "vCenter"/"ESX", sometimes literally
#    "N/A" for a standalone, non-bundled product row - both are recognized as
#    "component present" so Version/Running On/etc. do not shift by one
#    column, see ConvertTo-MatrixColumns). A handful of older advisories also
#    carry stray non-matrix fragments in their FixedInfo text (a leftover
#    metadata label, the column header echoed back as data, a broken HTML/CSS
#    remnant) - these are recognized and skipped rather than parsed as a
#    bogus row (see Test-IsJunkMatrixRow).
# 4. Exports the matches to a CSV file and an HTML report (English UI,
#    Product/Version summary + one collapsible card per matched advisory,
#    each with its matching Response Matrix rows and its full CVE list).
#    Within each section, advisories are listed newest-first by VMSA number
#    (e.g. VMSA-2026-0015 before VMSA-2025-0031) rather than by severity/date.
#    The VMware Tools and VMware Cloud Foundation/vSphere Foundation
#    reference lists (4b/4c), and each advisory's "possible bundle product"
#    table, are all collapsed by default in the HTML report - click their
#    summary line to reveal the full table.
# 5. CVE Lookup enrichment (optional): if a subfolder named
#    "CVE_Lookup_<yyyyMMdd-HHmm>" (e.g. "CVE_Lookup_20260828-1932") exists
#    next to this script, the most recent one (by the date-time encoded in
#    its folder name) is used - this is exactly the output folder vmsa_
#    cve_lookup.ps1 (the companion NVD lookup script) writes its
#    CVE_Lookup_Results_<timestamp>.csv into. Every .csv/.json file inside
#    that folder is scanned for a CVE-ID column/key (any column whose
#    header starts with "CVE", case-insensitive, or - for a JSON object
#    keyed by CVE ID - the key itself); every other column is kept as
#    "NVD <ColumnName>" extra detail for that CVE (so vmsa_cve_lookup.ps1's
#    own Description/CVSSv3/Severity/Published/References columns show up
#    as NVD Description/NVD CVSSv3/NVD Severity/NVD Published/NVD
#    References), except its No/AdvisoryIDs/AdvisoryCount columns, which
#    are dropped as redundant - this report already knows the row number
#    and exactly which advisory it's looking at. The parsing itself stays
#    schema-generic (not hard-coded to those exact column names) so it
#    keeps working if that script's output columns ever change. If no
#    CVE_Lookup_<date-time> folder exists, this step is skipped entirely
#    and the report simply omits CVE Lookup detail - no error, no
#    placeholder text.
# =============================================================================

param(
    [string]$JsonFileName       = "VMSA_FullList_Data.json",
    [string]$DownloaderScriptName = "vmsa_fulllist_downloader.ps1",
    [string]$OutputFolderName  = "vmsa_environment",  # fixed subfolder (created next to this script) that the CSV/HTML outputs are saved into
    [bool]$IgnoreInvalidCertificate = $true,   # most internal vCenters use a self-signed/internal-CA certificate
    [switch]$SkipCveLookup                     # force-skip the CVE_Lookup_<date-time> folder even if one is present
)

$ErrorActionPreference = "Stop"
$ScriptDir = $PSScriptRoot
if ([string]::IsNullOrWhiteSpace($ScriptDir)) { $ScriptDir = Get-Location }

# The dataset (and the downloader that can generate it) are looked up next
# to the script itself, same as always - only the CSV/HTML OUTPUTS below go
# into their own fixed subfolder so repeated runs don't clutter the script's
# own folder.
$OutputDir = Join-Path $ScriptDir $OutputFolderName
New-Item -ItemType Directory -Path $OutputDir -Force | Out-Null

$Timestamp = Get-Date -Format "yyyyMMdd-HHmm"
$JsonPath  = Join-Path $ScriptDir $JsonFileName
$CsvPath   = Join-Path $OutputDir "VMSA_Environment_Match_$Timestamp.csv"
$HtmlPath  = Join-Path $OutputDir "VMSA_Environment_Match_$Timestamp.html"

$MatrixHeaders = @("VMware Product","Version","Running On","CVE","CVSSv3","Severity","Fixed Version","Workarounds","Additional Documentation")

# =============================================================================
# Helper functions
# =============================================================================

function Esc-Html {
    param([string]$Text)
    if ($null -eq $Text) { return "" }
    return [System.Net.WebUtility]::HtmlEncode($Text)
}

# Masks a vCenter/ESXi host identity before it goes into the report - only
# the report-facing copy is masked (see where $VcVersionInfo.Name and each
# ESXi host name are built in section 2 below); the real, unmasked value
# keeps being used everywhere the script actually talks to vCenter
# (Connect-VIServer, Get-VMHost, Disconnect-VIServer), and console status
# messages during the live run still show the real value too, since the
# person running the script already typed it in. An IPv4 address has its
# first three octets replaced (e.g. "192.168.1.50" -> "***.***.***.50"); an
# FQDN has everything from the first "." onward replaced with the fixed
# placeholder domain "vcf.local" (e.g. "vc01.corp.example.com" ->
# "vc01.vcf.local"). A bare short hostname with no dot has nothing to mask
# and is left as-is.
function Get-MaskedHostIdentity {
    param([string]$HostIdentity)
    if ([string]::IsNullOrWhiteSpace($HostIdentity)) { return $HostIdentity }
    $trimmed = $HostIdentity.Trim()
    if ($trimmed -match '^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$') {
        $octets = $trimmed -split '\.'
        return "***.***.***.$($octets[3])"
    }
    $dotIdx = $trimmed.IndexOf(".")
    if ($dotIdx -ge 0) {
        $shortName = $trimmed.Substring(0, $dotIdx)
        return "$shortName.***.***"
    }
    return $trimmed
}

# Pulls just the leading dotted-numeric (with optional 'x'/'X' wildcard
# segments) part of a version string, e.g. "9.1.x.x" -> 9,1,x,x /
# "8.0 U3" -> 8,0 / "7.0.3.00500" -> 7,0,3,00500. Anything after that (a
# trailing "U3", "build 12345", etc.) is ignored on purpose - only the dotted
# numeric prefix is compared.
function ConvertTo-VersionTokens {
    param([string]$VersionString)
    if ([string]::IsNullOrWhiteSpace($VersionString)) { return @() }
    $m = [Regex]::Match($VersionString.Trim(), '^\d+(\.(\d+|[xX]))*')
    if (-not $m.Success) { return @() }
    return @($m.Value -split '\.')
}

# True if the advisory row's affected-version pattern (RowVersion, which may
# use 'x' as a wildcard segment) is a prefix-compatible match for the
# actually detected version (DetectedVersion). Only as many segments as the
# row itself specifies are compared, so a row saying just "8.0" matches any
# detected 8.0.x build, and "9.1.x.x" matches any 9.1.*.* build. This is a
# best-effort heuristic - always double-check a match against the advisory
# link before acting on it.
function Test-VersionMatch {
    param([string]$RowVersion, [string]$DetectedVersion)
    $RowTokens = ConvertTo-VersionTokens -VersionString $RowVersion
    $DetTokens = ConvertTo-VersionTokens -VersionString $DetectedVersion
    if ($RowTokens.Count -eq 0 -or $DetTokens.Count -eq 0) { return $false }
    for ($i = 0; $i -lt $RowTokens.Count; $i++) {
        if ($i -ge $DetTokens.Count) { return $false }
        if ($RowTokens[$i] -eq 'x' -or $RowTokens[$i] -eq 'X') { continue }
        if ($RowTokens[$i] -ne $DetTokens[$i]) { return $false }
    }
    return $true
}

# True when a matrix row's (already-merged) "VMware Product" text names a
# VMware Cloud Foundation or VMware vSphere Foundation bundle row
# specifically - e.g. "VMware Cloud Foundation (vCenter)", "VMware Cloud
# Foundation, VMware vSphere Foundation (ESX)". See Test-IsToolsWrapperRow
# below for the separate "VMware Tools (ESXi)" case. Callers pair this with
# a per-target Get-RelevantBundleMajors filter (section 4) so only the one
# VCF/VVF bundle-row major relevant to the detected build is ever surfaced.
function Test-IsVcfVvfBundleRow {
    param([string]$ProductText)
    return $ProductText -match '(?i)cloud\s*foundation|vsphere\s*foundation'
}

# True for a "VMware Tools (ESXi)"-style row (some advisories list the
# VMware Tools build shipped WITH a given ESXi release this way, Component =
# ESXi/ESX). Unlike VCF/VVF bundle rows above, these are never restricted by
# Get-RelevantBundleMajors - the Version column here is simply the ESXi
# release the Tools build shipped with, not a VCF/VVF bundle version.
function Test-IsToolsWrapperRow {
    param([string]$ProductText)
    return $ProductText -match '(?i)vmware\s*tools'
}

# General "is this row ANY kind of wrapper row" check (Cloud Foundation,
# vSphere Foundation, or VMware Tools) - used to still surface these rows
# even when their Version doesn't line up with the detected build (see the
# header comment, section 3) instead of silently dropping them, for callers
# that don't need to tell the two kinds apart.
function Test-IsBundleWrapperRow {
    param([string]$ProductText)
    return (Test-IsVcfVvfBundleRow -ProductText $ProductText) -or (Test-IsToolsWrapperRow -ProductText $ProductText)
}

# Known VCF/VVF release-major -> underlying vCenter/ESXi/Tools component
# major version. VCF and VVF ship the same underlying vSphere components for
# a given release line, so one map covers both. VCF/VVF 9.x needs no entry
# here - as of 9.0 the bundle's own version number IS the component version
# (e.g. a VCF 9.1 row already reads "9.1.x.x"), so Test-VersionMatch already
# matches it directly ($VcfVvfUnifiedMinMajor below is what tells
# Get-RelevantBundleMajors that). Extend this table yourself for any other
# release line you track (e.g. add "4" = "7" for VCF/VVF 4.x on vSphere
# 7.x) - a bundle row whose major version isn't listed here (or covered by
# $VcfVvfUnifiedMinMajor) just isn't surfaced at all (see
# Get-RelevantBundleMajors below).
$VcfVvfMajorVersionMap = @{
    "5" = "8"   # VCF/VVF 5.x ships vCenter/ESXi/Tools from the vSphere 8.x line
}

# From this VCF/VVF release major onward, the bundle's own version number IS
# the component version (unified numbering, starting at VCF/VVF 9.0).
$VcfVvfUnifiedMinMajor = 9

# True when a VCF/VVF bundle row's own version (e.g. "5.x") is KNOWN (via
# $VcfVvfMajorVersionMap above) to correspond to the detected build's major
# version (e.g. detected ESXi 8.0.3 -> major "8"). Only the major version is
# compared - the Response Matrix's bundle-version cells are typically coarse
# ("5.x") rather than an exact VCF/VVF point release, so major-version
# equivalence is as precise as this can safely get.
function Test-VcfBundleVersionMatch {
    param([string]$RowVersion, [string]$DetectedVersion)
    $RowTokens = ConvertTo-VersionTokens -VersionString $RowVersion
    $DetTokens = ConvertTo-VersionTokens -VersionString $DetectedVersion
    if ($RowTokens.Count -eq 0 -or $DetTokens.Count -eq 0) { return $false }
    $bundleMajor = $RowTokens[0]
    if (-not $VcfVvfMajorVersionMap.ContainsKey($bundleMajor)) { return $false }
    return $VcfVvfMajorVersionMap[$bundleMajor] -eq $DetTokens[0]
}

# Given the detected build's major version (e.g. "8" for a detected ESXi
# 8.0.3, or "9" for a detected vCenter 9.1.x), returns the list of VCF/VVF
# bundle-row major versions worth reviewing for it - e.g. a detected 8.x
# build only cares about "5.x" bundle rows (VCF/VVF 5.x ships 8.x
# components, per $VcfVvfMajorVersionMap), and a detected 9.x build only
# cares about "9.x" bundle rows (unified numbering, per
# $VcfVvfUnifiedMinMajor). A detected major with neither a reverse mapping
# nor unified numbering (e.g. "6" or "7") returns an empty list - VCF/VVF
# does not ship those lines, so no Cloud Foundation/vSphere Foundation
# bundle row is ever surfaced for it. Fully driven by the two tables above,
# so extending $VcfVvfMajorVersionMap automatically extends this too.
function Get-RelevantBundleMajors {
    param([string]$DetectedMajor)
    $result = New-Object System.Collections.Generic.List[string]
    foreach ($kvp in $VcfVvfMajorVersionMap.GetEnumerator()) {
        if ($kvp.Value -eq $DetectedMajor) { $result.Add($kvp.Key) }
    }
    $detNum = 0
    if ([int]::TryParse($DetectedMajor, [ref]$detNum) -and $detNum -ge $VcfVvfUnifiedMinMajor) {
        $result.Add($DetectedMajor)
    }
    return @($result | Select-Object -Unique)
}

# Splits one "Product | [Component |] Version | ..." Response Matrix row
# (already-cleaned text, as stored in the JSON's FixedInfo field) into the
# same 9 mapped columns used by vmsa_fulllist_downloader.ps1's HTML/Excel
# output, so results here read exactly the same way. Reused as-is from that
# script so the two stay consistent.
function ConvertTo-MatrixColumns {
    param([string[]]$Cols)

    $out = @("","","","","","","","","")
    if ($Cols.Count -eq 0) { return $out }

    function Test-Emptyish($v) { return ([string]::IsNullOrWhiteSpace($v)) -or ($v -match '^(?i)(n/a|-)$') }
    function Test-LooksLikeVersion($v) { return (-not [string]::IsNullOrWhiteSpace($v)) -and ($v -match '^\d') }

    $col0 = $Cols[0]
    $col1 = if ($Cols.Count -gt 1) { $Cols[1] } else { "" }
    $col2 = if ($Cols.Count -gt 2) { $Cols[2] } else { "" }

    # Whether a Component column is present at all depends on which era this
    # advisory's Response Matrix came from - older rows are just
    # "Product | Version | Running On | ..." (no Component), newer ones are
    # "Product | Component | Version | Running On | ..." where Component can
    # itself literally be the text "N/A" for a standalone (non-bundled)
    # product row. The deciding signal is therefore NOT whether col1 is
    # "empty-ish" (an explicit "N/A" Component is exactly that, and wrongly
    # excluding it here used to shift every column after it by one - Version
    # would read "N/A" and Running On would read "<real version> / <real
    # running on>") - it is simply: does col1 fail to look like a version AND
    # does col2 look like one. That correctly recognizes a real component
    # name ("vCenter", "ESX") AND a literal "N/A"/blank component the same
    # way, while a genuine Component-less row (col1 IS the version) still
    # falls through to the no-component branch below.
    $component = $null
    $version   = ""
    $dataStart = 2
    if ($Cols.Count -ge 3 -and -not (Test-LooksLikeVersion $col1) -and (Test-LooksLikeVersion $col2)) {
        $component = $col1
        $version   = $col2
        $dataStart = 3
    } else {
        $version   = $col1
        $dataStart = 2
    }
    if (-not (Test-Emptyish $version) -and -not (Test-LooksLikeVersion $version)) { $version = "N/A" }

    # Only append the "(Component)" suffix when Component actually carries a
    # real value - an explicit "N/A"/blank Component is just "no component",
    # same as a row that never had the column at all, so it stays unsuffixed
    # ("VMware ESX", not "VMware ESX (N/A)").
    $out[0] = if ($component -and -not (Test-Emptyish $component)) { "$col0 ($component)" } else { $col0 }
    $out[1] = $version

    $cveIdx = -1
    $sevIdx = -1
    for ($i = $dataStart; $i -lt $Cols.Count; $i++) {
        if ($cveIdx -eq -1 -and $Cols[$i] -match 'CVE-\d{4}-\d{4,7}') { $cveIdx = $i }
    }
    for ($i = $dataStart; $i -lt $Cols.Count; $i++) {
        if ($Cols[$i] -match '^(?i)(critical|important|high|moderate|medium|low)$') { $sevIdx = $i; break }
    }

    if ($cveIdx -gt $dataStart) { $out[2] = ($Cols[$dataStart..($cveIdx - 1)] -join " / ") }
    if ($cveIdx -ne -1) { $out[3] = $Cols[$cveIdx] }

    if ($sevIdx -ne -1) {
        $out[5] = $Cols[$sevIdx]
        if (($sevIdx - 1) -ge $dataStart -and $Cols[$sevIdx - 1] -match '^\d+(\.\d+)?(\s*[-,]\s*\d+(\.\d+)?)*$') {
            $out[4] = $Cols[$sevIdx - 1]
        }
        $restStart = $sevIdx + 1
        $rest = if ($restStart -lt $Cols.Count) { @($Cols[$restStart..($Cols.Count - 1)]) } else { @() }
        $out[6] = if ($rest.Count -gt 0) { $rest[0] } else { "" }
        $out[7] = if ($rest.Count -gt 1) { $rest[1] } else { "" }
        $out[8] = if ($rest.Count -gt 2) { $rest[2] } else { "" }
    } else {
        $startIdx = if ($cveIdx -ne -1) { $cveIdx + 1 } else { $dataStart }
        $rest = if ($startIdx -lt $Cols.Count) { @($Cols[$startIdx..($Cols.Count - 1)]) } else { @() }
        $out[6] = if ($rest.Count -gt 0) { $rest[0] } else { "" }
        $out[7] = if ($rest.Count -gt 1) { $rest[1] } else { "" }
        $out[8] = if ($rest.Count -gt 2) { $rest[2] } else { "" }
    }

    return $out
}

# Turns one advisory's FixedInfo string into an array of mapped 9-column row
# objects (empty array = no usable Response Matrix data for this advisory).
# The FixedInfo text for a handful of older/oddly-scraped advisories carries
# stray non-matrix fragments alongside the real rows - a leftover metadata
# label ("Advisory ID: | VMSA-2025-0012.1", "CVSSv3 Range: | 5.9-7.5"), the
# column header itself echoed back as if it were a data row ("VMware
# Product | Version | Running On | ..."), or a broken HTML/CSS remnant
# ("#000000;">Workarounds:None."). None of these are an actual Response
# Matrix row, so they are filtered out here before ConvertTo-MatrixColumns
# ever sees them, rather than being force-parsed into a bogus "product".
function Test-IsJunkMatrixRow {
    param([string[]]$Cols)
    if ($Cols.Count -lt 4) { return $true }
    $first = $Cols[0].Trim()
    if ([string]::IsNullOrWhiteSpace($first)) { return $true }
    if ($first -match ':\s*$') { return $true }
    if ($first -match '(?i)^(VMware\s*Product|Product|Version|CVE\(s\))$') { return $true }
    if ($first -match '^#[0-9A-Fa-f]') { return $true }
    return $false
}

function Get-MatrixTableRows {
    param([string]$FixedInfo)

    $result = New-Object System.Collections.Generic.List[Object]
    if ([string]::IsNullOrWhiteSpace($FixedInfo) -or $FixedInfo -eq "Check Link for details") { return $result }

    foreach ($row in ($FixedInfo -split "<br\s*/?>")) {
        $rowTrim = $row.Trim()
        if ([string]::IsNullOrWhiteSpace($rowTrim)) { continue }
        $cols = @($rowTrim -split "\|" | ForEach-Object { $_.Trim() })
        if (Test-IsJunkMatrixRow -Cols $cols) { continue }
        $mapped = ConvertTo-MatrixColumns -Cols $cols
        if ([string]::IsNullOrWhiteSpace($mapped[0])) { continue }
        $result.Add([PSCustomObject][ordered]@{
            "VMware Product"           = $mapped[0]
            "Version"                  = $mapped[1]
            "Running On"               = $mapped[2]
            "CVE"                      = $mapped[3]
            "CVSSv3"                   = $mapped[4]
            "Severity"                 = $mapped[5]
            "Fixed Version"            = $mapped[6]
            "Workarounds"              = $mapped[7]
            "Additional Documentation" = $mapped[8]
        })
    }
    return $result
}

function Get-SeverityBadgeClass {
    param([string]$Severity)
    switch -Regex ($Severity) {
        '(?i)critical'          { return 'badge-critical' }
        '(?i)important|high'    { return 'badge-high' }
        '(?i)moderate|medium'   { return 'badge-medium' }
        '(?i)low'                { return 'badge-low' }
        default                  { return 'badge-default' }
    }
}

# Parses a "VMSA-YYYY-NNNN" (or "VMSA-YYYY-NNNN.N" revision) advisory ID into
# a single sortable number so the HTML report can list advisories
# newest/highest-number first, e.g. "VMSA-2026-0015" -> 2026000015,
# "VMSA-2025-0031.1" -> 2025000031.1 (the ".1" revision suffix is kept as a
# fractional part so a revised advisory still sorts right next to its
# original). An ID that doesn't match the expected shape sorts last (0)
# instead of erroring.
function Get-AdvisoryIdSortKey {
    param([string]$AdvisoryID)
    if ($AdvisoryID -match '(?i)VMSA-(\d+)-(\d+(?:\.\d+)?)') {
        $year = [double]$Matches[1]
        $seq  = [double]$Matches[2]
        return ($year * 1000000) + $seq
    }
    return 0
}

# Columns from a CVE Lookup results file that are either the CVE ID itself
# (handled separately) or per-run bookkeeping that would just repeat what
# this report already shows on its own (row number, and the VMSA advisory
# IDs/count that CVE_Lookup_Results_<timestamp>.csv carries through from its
# own input file - this report already knows exactly which advisory it's
# looking at). Matches vmsa_cve_lookup.ps1's own output columns (No, CVE,
# Description, CVSSv3, Severity, Published, References, AdvisoryIDs,
# AdvisoryCount) but is written loosely enough to also just ignore the same
# kind of noise in a differently-shaped lookup file.
function Test-SkipCveLookupColumn {
    param([string]$Name)
    return $Name -match '(?i)^(no|advisoryids?|advisorycount)$'
}

# =============================================================================
# 0. Load (or generate) the VMSA dataset
# =============================================================================
Write-Host "[0] VMSA dataset" -ForegroundColor Cyan
if (Test-Path $JsonPath) {
    Write-Host "    -> Found existing $JsonFileName - loading it directly (no download needed)." -ForegroundColor Gray
} else {
    Write-Host "    -> $JsonFileName not found next to this script." -ForegroundColor Yellow
    $DownloaderPath = Join-Path $ScriptDir $DownloaderScriptName
    if (Test-Path $DownloaderPath) {
        Write-Host "    -> Running $DownloaderScriptName to generate it (this calls the internet-facing Broadcom API - make sure this machine has that access) ..." -ForegroundColor Yellow
        & $DownloaderPath
        if (-not (Test-Path $JsonPath)) {
            Write-Error "$DownloaderScriptName ran but $JsonFileName still was not created. Aborting."
            exit
        }
    } else {
        Write-Error "$JsonFileName was not found and $DownloaderScriptName is not present next to this script, so the dataset cannot be generated automatically here. Either run $DownloaderScriptName on a machine with internet access and copy the resulting $JsonFileName next to this script, or place a copy of $DownloaderScriptName next to this script so it can be run automatically."
        exit
    }
}

try {
    $VmsaData = Get-Content -Path $JsonPath -Raw -Encoding UTF8 | ConvertFrom-Json
} catch {
    Write-Error "Failed to read/parse $JsonPath : $($_.Exception.Message)"
    exit
}
$AllAdvisories = @($VmsaData.Advisories)
Write-Host "    -> Loaded $($AllAdvisories.Count) advisories (dataset generated $($VmsaData.Metadata.GeneratedAt), last updated $($VmsaData.Metadata.LastUpdatedAt))." -ForegroundColor Green

# =============================================================================
# 1. Prompt for vCenter connection details
# =============================================================================
Write-Host "`n[1] vCenter connection" -ForegroundColor Cyan
$VcServer = Read-Host "    vCenter host/IP (FQDN or IP address)"
if ([string]::IsNullOrWhiteSpace($VcServer)) {
    Write-Error "No vCenter host/IP entered. Aborting."
    exit
}
$VcUser = Read-Host "    Username (e.g. administrator@vsphere.local)"
if ([string]::IsNullOrWhiteSpace($VcUser)) {
    Write-Error "No username entered. Aborting."
    exit
}
$VcSecurePassword = Read-Host "    Password" -AsSecureString
$VcCredential = New-Object System.Management.Automation.PSCredential($VcUser, $VcSecurePassword)

# =============================================================================
# 2. Connect with PowerCLI and collect vCenter + ESXi version info
# =============================================================================
Write-Host "`n[2] Connecting to vCenter and reading version info" -ForegroundColor Cyan

if (-not (Get-Module -ListAvailable -Name VMware.PowerCLI)) {
    Write-Host "    VMware.PowerCLI module not found - installing for current user ..." -ForegroundColor Yellow
    try {
        Install-Module -Name VMware.PowerCLI -Scope CurrentUser -Force -AllowClobber -ErrorAction Stop
    } catch {
        Write-Error "Could not install VMware.PowerCLI ($($_.Exception.Message)). Install it manually (Install-Module VMware.PowerCLI) and re-run this script."
        exit
    }
}
Import-Module VMware.PowerCLI -ErrorAction Stop

$CertAction = if ($IgnoreInvalidCertificate) { "Ignore" } else { "Warn" }
try {
    Set-PowerCLIConfiguration -InvalidCertificateAction $CertAction -ParticipateInCEIP:$false -Confirm:$false -Scope Session | Out-Null
} catch {
    Write-Warning "    Could not set PowerCLI configuration ($($_.Exception.Message)) - continuing anyway."
}

$VIConnection   = $null
$VcVersionInfo  = $null
$EsxVersionGroups = @()

try {
    Write-Host "    Connecting to $VcServer ..." -ForegroundColor Gray
    $VIConnection = Connect-VIServer -Server $VcServer -Credential $VcCredential -ErrorAction Stop
    Write-Host "    Connected: $($VIConnection.Name) - vCenter Server $($VIConnection.Version) (build $($VIConnection.Build))" -ForegroundColor Green

    $VcVersionInfo = [PSCustomObject]@{
        # Masked here (not the real $VIConnection.Name) since this is the copy
        # that flows into the HTML/CSV report - see Get-MaskedHostIdentity.
        Name    = Get-MaskedHostIdentity -HostIdentity $VIConnection.Name
        Version = "$($VIConnection.Version)"
        Build   = "$($VIConnection.Build)"
    }

    Write-Host "    Reading ESXi host inventory ..." -ForegroundColor Gray
    $EsxHosts = @(Get-VMHost -Server $VIConnection -ErrorAction Stop | Select-Object Name, Version, Build, ConnectionState)
    Write-Host "    -> $($EsxHosts.Count) host(s) found." -ForegroundColor Gray

    $EsxVersionGroups = @(
        $EsxHosts | Group-Object { "$($_.Version)|$($_.Build)" } | ForEach-Object {
            $first = $_.Group[0]
            [PSCustomObject]@{
                Version = "$($first.Version)"
                Build   = "$($first.Build)"
                # Masked here too, for the same reason - see above.
                Hosts   = @($_.Group | Select-Object -ExpandProperty Name | ForEach-Object { Get-MaskedHostIdentity -HostIdentity $_ })
            }
        }
    )
} catch {
    Write-Error "Failed while connecting to / reading from vCenter '$VcServer': $($_.Exception.Message)"
    exit
} finally {
    # Runs even after the exit above (finally always executes when leaving a
    # try/catch) - the session is disconnected exactly once either way, and
    # is never held open while the report below is being built.
    if ($VIConnection) {
        Disconnect-VIServer -Server $VIConnection -Confirm:$false -ErrorAction SilentlyContinue
        Write-Host "    Disconnected from $VcServer." -ForegroundColor Gray
    }
}

# Build the list of detected version "targets" to match VMSAs against - one
# for vCenter itself, and one per distinct ESXi Version+Build combination
# (hosts sharing the same version+build are reported once, together).
$DetectedTargets = New-Object System.Collections.Generic.List[Object]
$DetectedTargets.Add([PSCustomObject]@{
    Category    = "vCenter"
    Label       = "vCenter Server $($VcVersionInfo.Version) (build $($VcVersionInfo.Build))"
    Version     = $VcVersionInfo.Version
    Build       = $VcVersionInfo.Build
    SourceHosts = @($VcVersionInfo.Name)
})
foreach ($g in $EsxVersionGroups) {
    $DetectedTargets.Add([PSCustomObject]@{
        Category    = "ESX"
        Label       = "ESXi $($g.Version) (build $($g.Build)) - $($g.Hosts.Count) host(s)"
        Version     = $g.Version
        Build       = $g.Build
        SourceHosts = $g.Hosts
    })
}

Write-Host "    Detected versions:" -ForegroundColor Gray
foreach ($t in $DetectedTargets) { Write-Host "       [$($t.Category)] $($t.Label)" -ForegroundColor Gray }

# =============================================================================
# 3. Optional CVE Lookup enrichment - most recent CVE_Lookup_<yyyyMMdd-HHmm>
#    folder next to this script, if any.
# =============================================================================
Write-Host "`n[3] CVE Lookup folder" -ForegroundColor Cyan
$CveLookupData   = $null
$CveLookupFolder = $null

if ($SkipCveLookup) {
    Write-Host "    -> -SkipCveLookup specified - CVE Lookup detail will be omitted." -ForegroundColor Gray
} else {
    $CveLookupCandidates = @(
        Get-ChildItem -Path $ScriptDir -Directory -Filter "CVE_Lookup_*" -ErrorAction SilentlyContinue |
            ForEach-Object {
                if ($_.Name -match '^CVE_Lookup_(\d{8})-(\d{4})$') {
                    $parsed = [DateTime]::MinValue
                    $ok = [DateTime]::TryParseExact(
                        "$($Matches[1])$($Matches[2])", "yyyyMMddHHmm", $null,
                        [System.Globalization.DateTimeStyles]::None, [ref]$parsed)
                    if ($ok) { [PSCustomObject]@{ Folder = $_; Stamp = $parsed } }
                }
            } | Sort-Object Stamp -Descending
    )

    if ($CveLookupCandidates.Count -eq 0) {
        Write-Host "    -> No CVE_Lookup_<yyyyMMdd-HHmm> folder found next to this script - CVE Lookup detail will be omitted from the report." -ForegroundColor Gray
    } else {
        $CveLookupFolder = $CveLookupCandidates[0].Folder
        Write-Host "    -> Using most recent CVE Lookup folder: $($CveLookupFolder.Name) ($($CveLookupCandidates[0].Stamp))" -ForegroundColor Green

        $CveLookupData = @{}   # CVE ID -> ordered hashtable of extra fields found for it
        $LookupFiles = @(Get-ChildItem -Path $CveLookupFolder.FullName -File -Recurse -ErrorAction SilentlyContinue |
            Where-Object { $_.Extension -ieq ".csv" -or $_.Extension -ieq ".json" })

        foreach ($f in $LookupFiles) {
            try {
                if ($f.Extension -ieq ".csv") {
                    $rows = @(Import-Csv -LiteralPath $f.FullName)
                    foreach ($row in $rows) {
                        $cveCol = ($row.PSObject.Properties.Name | Where-Object { $_ -match '(?i)^cve' } | Select-Object -First 1)
                        if (-not $cveCol) { continue }
                        $cveVal = "$($row.$cveCol)".Trim()
                        if ($cveVal -notmatch '^CVE-\d{4}-\d{4,7}$') { continue }
                        if (-not $CveLookupData.ContainsKey($cveVal)) { $CveLookupData[$cveVal] = [ordered]@{} }
                        foreach ($p in $row.PSObject.Properties) {
                            if ($p.Name -eq $cveCol) { continue }
                            if (Test-SkipCveLookupColumn -Name $p.Name) { continue }
                            if (-not [string]::IsNullOrWhiteSpace("$($p.Value)")) { $CveLookupData[$cveVal]["NVD $($p.Name)"] = $p.Value }
                        }
                    }
                } else {
                    $jsonObj = Get-Content -LiteralPath $f.FullName -Raw -Encoding UTF8 | ConvertFrom-Json
                    if ($jsonObj -is [System.Array]) {
                        foreach ($item in $jsonObj) {
                            if (-not $item) { continue }
                            $cveProp = $item.PSObject.Properties | Where-Object { $_.Name -match '(?i)^cve' } | Select-Object -First 1
                            if (-not $cveProp) { continue }
                            $cveVal = "$($cveProp.Value)".Trim()
                            if ($cveVal -notmatch '^CVE-\d{4}-\d{4,7}$') { continue }
                            if (-not $CveLookupData.ContainsKey($cveVal)) { $CveLookupData[$cveVal] = [ordered]@{} }
                            foreach ($ip in $item.PSObject.Properties) {
                                if ($ip.Name -eq $cveProp.Name) { continue }
                                if (Test-SkipCveLookupColumn -Name $ip.Name) { continue }
                                if ($null -ne $ip.Value -and "$($ip.Value)" -ne "") { $CveLookupData[$cveVal]["NVD $($ip.Name)"] = $ip.Value }
                            }
                        }
                    } else {
                        # Object form - either { "CVE-....": {...}, ... } (CVE ID as the
                        # key itself) or { "items": [ {CVE:..., ...}, ... ] }-style; try
                        # both: use the property name as the CVE ID if it looks like one,
                        # otherwise look for a "cve*" property inside the value.
                        foreach ($p in $jsonObj.PSObject.Properties) {
                            $cveVal = $null
                            if ($p.Name -match '^CVE-\d{4}-\d{4,7}$') {
                                $cveVal = $p.Name
                            } elseif ($p.Value -and ($p.Value.PSObject.Properties.Name -match '(?i)^cve')) {
                                $innerCveProp = $p.Value.PSObject.Properties | Where-Object { $_.Name -match '(?i)^cve' } | Select-Object -First 1
                                $candidate = "$($innerCveProp.Value)".Trim()
                                if ($candidate -match '^CVE-\d{4}-\d{4,7}$') { $cveVal = $candidate }
                            }
                            if (-not $cveVal) { continue }
                            if (-not $CveLookupData.ContainsKey($cveVal)) { $CveLookupData[$cveVal] = [ordered]@{} }
                            if ($p.Value -is [System.Management.Automation.PSCustomObject]) {
                                foreach ($ip in $p.Value.PSObject.Properties) {
                                    if ($ip.Name -match '(?i)^cve') { continue }
                                    if (Test-SkipCveLookupColumn -Name $ip.Name) { continue }
                                    if ($null -ne $ip.Value -and "$($ip.Value)" -ne "") { $CveLookupData[$cveVal]["NVD $($ip.Name)"] = $ip.Value }
                                }
                            }
                        }
                    }
                }
            } catch {
                Write-Warning "    ! Could not parse $($f.Name) in $($CveLookupFolder.Name): $($_.Exception.Message)"
            }
        }
        Write-Host "    -> Loaded lookup detail for $($CveLookupData.Count) unique CVE(s) from $($LookupFiles.Count) file(s)." -ForegroundColor Gray
    }
}

# =============================================================================
# 4. Match every advisory against every detected version
# =============================================================================
Write-Host "`n[4] Matching $($AllAdvisories.Count) advisories against $($DetectedTargets.Count) detected version(s)" -ForegroundColor Cyan

$CategoryPatterns = @{
    "vCenter" = "vcenter"
    "ESX"     = "\bESXi?\b"
}

$MatchResults = New-Object System.Collections.Generic.List[Object]   # one entry per (Target, Advisory) match
foreach ($target in $DetectedTargets) {
    $pattern = $CategoryPatterns[$target.Category]

    # Which VCF/VVF bundle-row major version(s) are even relevant for THIS
    # target's detected major - e.g. detected 8.x -> only "5.x" bundle rows,
    # detected 9.x -> only "9.x" bundle rows (see Get-RelevantBundleMajors).
    # Computed once per target rather than per advisory below.
    $TargetMajor = ((ConvertTo-VersionTokens -VersionString $target.Version) + @(""))[0]
    $RelevantBundleMajors = @(Get-RelevantBundleMajors -DetectedMajor $TargetMajor)

    foreach ($rec in $AllAdvisories) {
        $Rows = Get-MatrixTableRows -FixedInfo $rec.FixedInfo
        $CategoryRows = @($Rows | Where-Object { $_.'VMware Product' -match "(?i)$pattern" })
        if ($CategoryRows.Count -eq 0) { continue }

        $MatchedRows = @($CategoryRows | Where-Object { Test-VersionMatch -RowVersion $_.Version -DetectedVersion $target.Version })

        # Rows that name a wrapper product (VCF/VVF, or VMware Tools shipped
        # WITH an ESXi release) for this category but whose own Version
        # didn't directly line up with the detected build. Split further:
        # ones a KNOWN VCF/VVF major-version mapping resolves (e.g. a "5.x"
        # bundle row against a detected 8.0.x build) count as confirmed,
        # just via that mapping rather than a literal version match;
        # anything else is surfaced as "possible / needs verification"
        # rather than being silently dropped (see header comment, section 3).
        $UnmatchedCategoryRows = @($CategoryRows | Where-Object { -not (Test-VersionMatch -RowVersion $_.Version -DetectedVersion $target.Version) })

        # Wrapper rows worth surfacing at all: a Cloud Foundation/vSphere
        # Foundation row only counts if its own version's major is one of
        # THIS target's $RelevantBundleMajors (e.g. only "5.x" rows for a
        # detected 8.x build, only "9.x" rows for a detected 9.x build - see
        # Get-RelevantBundleMajors above); any other VCF/VVF major (e.g. a
        # "5.x" row against a detected 7.x build) is dropped here instead of
        # being shown as an unverified guess. A VMware Tools (ESXi) row has
        # no such restriction - its Version is simply the ESXi release the
        # Tools build shipped with, not a VCF/VVF bundle version.
        $WrapperEligibleRows = @($UnmatchedCategoryRows | Where-Object {
            $productText = $_.'VMware Product'
            if (Test-IsVcfVvfBundleRow -ProductText $productText) {
                $verTokens = @(ConvertTo-VersionTokens -VersionString $_.Version)
                ($verTokens.Count -gt 0) -and ($RelevantBundleMajors -contains $verTokens[0])
            } elseif (Test-IsToolsWrapperRow -ProductText $productText) {
                $true
            } else {
                $false
            }
        })
        $MappedBundleRows = @($WrapperEligibleRows | Where-Object {
            Test-VcfBundleVersionMatch -RowVersion $_.Version -DetectedVersion $target.Version
        })
        $PossibleBundleRows = @($WrapperEligibleRows | Where-Object {
            -not (Test-VcfBundleVersionMatch -RowVersion $_.Version -DetectedVersion $target.Version)
        })

        if ($MatchedRows.Count -eq 0 -and $MappedBundleRows.Count -eq 0 -and $PossibleBundleRows.Count -eq 0) { continue }
        $MatchResults.Add([PSCustomObject]@{
            Target            = $target
            Advisory          = $rec
            MatchedRows       = $MatchedRows
            MappedBundleRows  = $MappedBundleRows
            PossibleBundleRows = $PossibleBundleRows
        })
    }
}
$DirectMatchCount = @($MatchResults | Where-Object { $_.MatchedRows.Count -gt 0 -or $_.MappedBundleRows.Count -gt 0 }).Count
$BundleOnlyCount  = @($MatchResults | Where-Object { $_.MatchedRows.Count -eq 0 -and $_.MappedBundleRows.Count -eq 0 -and $_.PossibleBundleRows.Count -gt 0 }).Count
Write-Host "    -> $($MatchResults.Count) advisory match(es) found across all detected versions ($DirectMatchCount direct, $BundleOnlyCount possible-only via a bundle product)." -ForegroundColor Green

# =============================================================================
# 4b. VMware Tools reference list (no live version detection - by design:
#     a VM's Guest.ToolsVersion is an internal build number, e.g. "12389",
#     with no reliable public mapping back to the dotted release number
#     (e.g. "12.3.5") that VMSA advisories use, so auto-matching it would
#     risk silently wrong results. Instead every advisory whose Response
#     Matrix mentions "VMware Tools" anywhere - standalone rows AND rows
#     bundled under a VCF/VVF Product with Component "VMware Tools" - is
#     listed here regardless of version, for you to cross-check by hand.
# =============================================================================
Write-Host "`n[4b] Building the VMware Tools reference list (no live version detection)" -ForegroundColor Cyan
$ToolsPattern = "tools"
$ToolsResults = New-Object System.Collections.Generic.List[Object]
foreach ($rec in $AllAdvisories) {
    $Rows = Get-MatrixTableRows -FixedInfo $rec.FixedInfo
    $ToolsRows = @($Rows | Where-Object { $_.'VMware Product' -match "(?i)$ToolsPattern" })
    if ($ToolsRows.Count -eq 0) { continue }
    $ToolsResults.Add([PSCustomObject]@{ Advisory = $rec; ToolsRows = $ToolsRows })
}
Write-Host "    -> $($ToolsResults.Count) advisory(ies) reference VMware Tools in their Response Matrix." -ForegroundColor Green

# =============================================================================
# 4c. VMware Cloud Foundation / vSphere Foundation reference list - the same
#     "reference list, independent of any detected target" idea as the
#     VMware Tools list above, but for Cloud Foundation/vSphere Foundation
#     bundle rows: every advisory with a Cloud Foundation/vSphere Foundation
#     row on the 5.x or 9.x release line (the only two lines this report
#     tracks - see $VcfVvfMajorVersionMap/$VcfVvfUnifiedMinMajor) is listed
#     here regardless of whether it happens to match a version detected live
#     above, for manual cross-check against your actual VCF/VVF release.
#     This is separate from the per-target "Also Listed Under a Bundle
#     Product" table under each matched advisory in section 6 - that one is
#     scoped to what is relevant to a SPECIFIC detected build; this one is
#     the full, unscoped reference list.
# =============================================================================
Write-Host "`n[4c] Building the VMware Cloud Foundation / vSphere Foundation reference list (5.x / 9.x only)" -ForegroundColor Cyan
$VcfVvfResults = New-Object System.Collections.Generic.List[Object]
foreach ($rec in $AllAdvisories) {
    $Rows = Get-MatrixTableRows -FixedInfo $rec.FixedInfo
    $VcfVvfRows = @($Rows | Where-Object {
        if (-not (Test-IsVcfVvfBundleRow -ProductText $_.'VMware Product')) { return $false }
        $verTokens = @(ConvertTo-VersionTokens -VersionString $_.Version)
        ($verTokens.Count -gt 0) -and ($verTokens[0] -eq '5' -or $verTokens[0] -eq '9')
    })
    if ($VcfVvfRows.Count -eq 0) { continue }
    $VcfVvfResults.Add([PSCustomObject]@{ Advisory = $rec; VcfVvfRows = $VcfVvfRows })
}
Write-Host "    -> $($VcfVvfResults.Count) advisory(ies) reference a VMware Cloud Foundation / vSphere Foundation 5.x or 9.x line." -ForegroundColor Green

# =============================================================================
# 5. Write the CSV
# =============================================================================
Write-Host "`n[5] Writing CSV ..." -ForegroundColor Cyan

# Builds the CveLookupInfo text for one advisory's CVE list - shared by both
# the version-matched rows below and the VMware Tools reference rows.
function Get-CveLookupNotes {
    param([object[]]$CveIds)
    if (-not $CveLookupData) { return "" }
    $noteParts = foreach ($cveId in $CveIds) {
        if ($CveLookupData.ContainsKey($cveId)) {
            $fields = @($CveLookupData[$cveId].GetEnumerator() | ForEach-Object { "$($_.Key)=$($_.Value)" })
            "$cveId [" + ($fields -join "; ") + "]"
        }
    }
    return ($noteParts -join " || ")
}

$i = 0
$MatchCsvRows = foreach ($m in $MatchResults) {
    $i++
    $cveIds  = @($m.Advisory.CveDescriptions | ForEach-Object { $_.CVE })
    $cveList = $cveIds -join "; "
    $lookupNotes = Get-CveLookupNotes -CveIds $cveIds

    $HasDirect = ($m.MatchedRows.Count -gt 0 -or $m.MappedBundleRows.Count -gt 0)
    $MatchType = if ($HasDirect -and $m.PossibleBundleRows.Count -gt 0) {
        "Direct + Possible (bundle product)"
    } elseif ($HasDirect) {
        if ($m.MappedBundleRows.Count -gt 0 -and $m.MatchedRows.Count -eq 0) { "Direct (via VCF/VVF version mapping)" } else { "Direct" }
    } else {
        "Possible only (bundle product - verify version)"
    }

    $AllDirectRows = @($m.MatchedRows) + @($m.MappedBundleRows)
    $MatchedFixVersions = @(($AllDirectRows | ForEach-Object { $_.'Fixed Version' } | Where-Object { $_ }) | Select-Object -Unique) -join "; "
    $MatchedRowsDetail = ($AllDirectRows | ForEach-Object {
        $row = $_
        ($MatrixHeaders | ForEach-Object { $row.$_ }) -join " | "
    }) -join " <br> "
    $BundleRowsDetail = ($m.PossibleBundleRows | ForEach-Object {
        $row = $_
        ($MatrixHeaders | ForEach-Object { $row.$_ }) -join " | "
    }) -join " <br> "

    [PSCustomObject][ordered]@{
        No                 = $i
        MatchedAgainst     = $m.Target.Label
        Category           = $m.Target.Category
        MatchType          = $MatchType
        AdvisoryID         = $m.Advisory.AdvisoryID
        Title              = $m.Advisory.Title
        Severity           = $m.Advisory.Severity
        CVSS               = $m.Advisory.CVSS
        Published          = $m.Advisory.Published
        CVEs               = $cveList
        MatchedFixVersions = $MatchedFixVersions
        MatchedRowsDetail  = $MatchedRowsDetail
        PossibleBundleRowsDetail = $BundleRowsDetail
        Link               = $m.Advisory.Link
        CveLookupInfo      = $lookupNotes
    }
}

# VMware Tools reference rows - no detected version to compare against (see
# section 4b above), so MatchType/MatchedFixVersions/PossibleBundleRowsDetail
# are left blank/labeled accordingly rather than implying a real match.
$ToolsCsvRows = foreach ($t in $ToolsResults) {
    $i++
    $cveIds  = @($t.Advisory.CveDescriptions | ForEach-Object { $_.CVE })
    $cveList = $cveIds -join "; "
    $lookupNotes = Get-CveLookupNotes -CveIds $cveIds

    $ToolsRowsDetail = ($t.ToolsRows | ForEach-Object {
        $row = $_
        ($MatrixHeaders | ForEach-Object { $row.$_ }) -join " | "
    }) -join " <br> "

    [PSCustomObject][ordered]@{
        No                 = $i
        MatchedAgainst     = "VMware Tools (reference - no live version detected)"
        Category           = "Tools"
        MatchType          = "Reference only (no live detection)"
        AdvisoryID         = $t.Advisory.AdvisoryID
        Title              = $t.Advisory.Title
        Severity           = $t.Advisory.Severity
        CVSS               = $t.Advisory.CVSS
        Published          = $t.Advisory.Published
        CVEs               = $cveList
        MatchedFixVersions = ""
        MatchedRowsDetail  = $ToolsRowsDetail
        PossibleBundleRowsDetail = ""
        Link               = $t.Advisory.Link
        CveLookupInfo      = $lookupNotes
    }
}

# VMware Cloud Foundation / vSphere Foundation reference rows - same idea as
# the VMware Tools reference rows above (see section 4c): no detected
# version to compare against here, so MatchType/MatchedFixVersions/
# PossibleBundleRowsDetail are left blank/labeled accordingly.
$VcfVvfCsvRows = foreach ($v in $VcfVvfResults) {
    $i++
    $cveIds  = @($v.Advisory.CveDescriptions | ForEach-Object { $_.CVE })
    $cveList = $cveIds -join "; "
    $lookupNotes = Get-CveLookupNotes -CveIds $cveIds

    $VcfVvfRowsDetail = ($v.VcfVvfRows | ForEach-Object {
        $row = $_
        ($MatrixHeaders | ForEach-Object { $row.$_ }) -join " | "
    }) -join " <br> "

    [PSCustomObject][ordered]@{
        No                 = $i
        MatchedAgainst     = "VMware Cloud Foundation / vSphere Foundation (reference - 5.x / 9.x only)"
        Category           = "VCF/VVF"
        MatchType          = "Reference only (not tied to a detected build)"
        AdvisoryID         = $v.Advisory.AdvisoryID
        Title              = $v.Advisory.Title
        Severity           = $v.Advisory.Severity
        CVSS               = $v.Advisory.CVSS
        Published          = $v.Advisory.Published
        CVEs               = $cveList
        MatchedFixVersions = ""
        MatchedRowsDetail  = $VcfVvfRowsDetail
        PossibleBundleRowsDetail = ""
        Link               = $v.Advisory.Link
        CveLookupInfo      = $lookupNotes
    }
}

$CsvRows = @($MatchCsvRows) + @($ToolsCsvRows) + @($VcfVvfCsvRows)
$CsvRows | Export-Csv -LiteralPath $CsvPath -NoTypeInformation -Encoding UTF8
Write-Host "    -> CSV: $CsvPath ($($CsvRows.Count) rows: $($MatchCsvRows.Count) version-matched + $($ToolsCsvRows.Count) VMware Tools reference + $($VcfVvfCsvRows.Count) VCF/VVF reference)" -ForegroundColor Gray

# =============================================================================
# 6. Write the HTML report
# =============================================================================
Write-Host "`n[6] Writing HTML report ..." -ForegroundColor Cyan

$GeneratedAtLabel    = Get-Date -Format "yyyy-MM-dd HH:mm"
$CveLookupSourceText = if ($CveLookupFolder) { $CveLookupFolder.Name } else { "(none found - CVE Lookup detail omitted)" }

$CssBlock = @'
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
  .muted { color:var(--muted); font-size:13px; }
  table.matrix-table { width:100%; border-collapse:collapse; font-size:12px; margin-top:4px; }
  table.matrix-table th { background:#f1f5f9; color:#334155; text-align:left; padding:7px 8px; border:1px solid var(--border); white-space:nowrap; }
  table.matrix-table td { padding:7px 8px; border:1px solid var(--border); vertical-align:top; }
  .badge { display:inline-block; padding:3px 10px; border-radius:20px; font-size:11px; font-weight:700; letter-spacing:.03em; }
  .badge-critical { background:var(--crit-bg); color:var(--crit-fg); }
  .badge-high { background:var(--high-bg); color:var(--high-fg); }
  .badge-medium { background:var(--med-bg); color:var(--med-fg); }
  .badge-low { background:var(--low-bg); color:var(--low-fg); }
  .badge-default { background:#e2e8f0; color:#475569; }
  .advisory-card { border:1px solid var(--border); border-radius:8px; margin-bottom:12px; overflow:hidden; }
  .advisory-card summary { cursor:pointer; padding:12px 16px; display:flex; align-items:center; gap:10px; flex-wrap:wrap; list-style:none; background:#f8fafc; }
  .advisory-card summary::-webkit-details-marker { display:none; }
  .advisory-card summary::before { content:"\25B8"; color:var(--muted); font-size:12px; margin-right:2px; }
  .advisory-card[open] summary::before { content:"\25BE"; }
  .advisory-card summary:hover { background:#eef2f7; }
  .advisory-id { font-weight:700; color:var(--navy); font-size:13px; }
  .advisory-title-text { font-size:13px; color:#1e293b; flex:1; min-width:160px; }
  .advisory-date { font-size:12px; color:var(--muted); }
  .advisory-body { padding:14px 16px 16px; border-top:1px solid var(--border); }
  .advisory-meta { font-size:12px; color:var(--muted); margin:0 0 12px 0; }
  .advisory-meta a { color:var(--navy); }
  .matrix-wrap { overflow-x:auto; }
  .cve-list { margin:14px 0 0; padding-left:18px; font-size:12px; }
  .cve-list li { margin-bottom:6px; }
  .cve-lookup-note { color:var(--muted); }
  h3.section-label { font-size:13px; color:var(--navy); margin:14px 0 6px; }
  .badge-bundle { background:#e0e7ff; color:#3730a3; }
  .bundle-note { font-size:12px; color:#3730a3; background:#eef2ff; border:1px solid #c7d2fe; border-radius:6px; padding:8px 10px; margin:10px 0; }
  .nested-toggle { border:1px solid var(--border); border-radius:8px; margin-top:12px; overflow:hidden; }
  .nested-toggle summary { cursor:pointer; padding:9px 12px; font-size:12.5px; font-weight:700; color:var(--navy); background:#f8fafc; list-style:none; }
  .nested-toggle summary::-webkit-details-marker { display:none; }
  .nested-toggle summary::before { content:"\25B8"; color:var(--muted); font-size:11px; margin-right:6px; }
  .nested-toggle[open] summary::before { content:"\25BE"; }
  .nested-toggle summary:hover { background:#eef2f7; }
  .nested-toggle-body { padding:12px; border-top:1px solid var(--border); }
</style>
'@

$sb = New-Object System.Text.StringBuilder
[void]$sb.Append('<!DOCTYPE html><html lang="en"><head><meta charset="UTF-8"><title>VMSA Environment Match Report</title>')
[void]$sb.Append($CssBlock)
[void]$sb.Append('</head><body>')
[void]$sb.Append("<header><h1>VMSA Environment Match Report</h1><p>Generated $(Esc-Html $GeneratedAtLabel) &nbsp;|&nbsp; vCenter: $(Esc-Html $VcVersionInfo.Name) &nbsp;|&nbsp; VMSA dataset: $($VmsaData.Metadata.TotalCount) advisories (last updated $(Esc-Html $VmsaData.Metadata.LastUpdatedAt)) &nbsp;|&nbsp; CVE Lookup source: $(Esc-Html $CveLookupSourceText)</p></header>")
[void]$sb.Append('<div class="wrap">')

# --- Detected versions summary ---
[void]$sb.Append('<div class="card"><h2>Detected Versions</h2><table class="matrix-table"><thead><tr><th>Category</th><th>Version</th><th>Build</th><th>Source</th><th>Direct Matches</th><th>Possible (bundle product)</th></tr></thead><tbody>')
foreach ($target in $DetectedTargets) {
    $targetResults    = @($MatchResults | Where-Object { $_.Target -eq $target })
    $directCount      = @($targetResults | Where-Object { $_.MatchedRows.Count -gt 0 -or $_.MappedBundleRows.Count -gt 0 }).Count
    $bundleOnlyCount   = @($targetResults | Where-Object { $_.MatchedRows.Count -eq 0 -and $_.MappedBundleRows.Count -eq 0 -and $_.PossibleBundleRows.Count -gt 0 }).Count
    $sourceLabel = ($target.SourceHosts -join ", ")
    [void]$sb.Append("<tr><td>$(Esc-Html $target.Category)</td><td>$(Esc-Html $target.Version)</td><td>$(Esc-Html $target.Build)</td><td>$(Esc-Html $sourceLabel)</td><td>$directCount</td><td>$bundleOnlyCount</td></tr>")
}
[void]$sb.Append('</tbody></table><p class="muted" style="margin:10px 0 0;">"Possible (bundle product)" = advisories that list this component only under a wrapper row - VMware Cloud Foundation or VMware vSphere Foundation (only the bundle-version line relevant to the detected major version - e.g. 5.x for a detected 8.x build, 9.x for a detected 9.x build; other VCF/VVF majors are not surfaced), or VMware Tools shipped with a given ESXi release - whose own version number does not line up with the detected build (normal for pre-9.x VCF/VVF, whose bundle version differs from the vCenter/ESXi version it ships) - verify these against your actual VCF/VVF release or Tools/ESXi pairing. See the click-to-expand "Also Listed Under a Bundle Product" section under each advisory below for the details.</p></div>')

# --- Matched advisories, grouped by detected version ---
foreach ($target in $DetectedTargets) {
    $targetMatches = @($MatchResults | Where-Object { $_.Target -eq $target } |
        Sort-Object -Property @{ Expression = { Get-AdvisoryIdSortKey $_.Advisory.AdvisoryID } ; Descending = $true })

    [void]$sb.Append("<div class=`"card`"><h2>$(Esc-Html $target.Label) - $($targetMatches.Count) matching advisory(ies)</h2>")
    if ($targetMatches.Count -eq 0) {
        [void]$sb.Append('<p class="muted">No VMSA advisories matched this version.</p>')
    } else {
        foreach ($m in $targetMatches) {
            $rec = $m.Advisory
            $badgeClass = Get-SeverityBadgeClass -Severity $rec.Severity
            $AllDirectRows = @($m.MatchedRows) + @($m.MappedBundleRows)
            $isBundleOnly = ($AllDirectRows.Count -eq 0 -and $m.PossibleBundleRows.Count -gt 0)

            [void]$sb.Append('<details class="advisory-card"><summary>')
            [void]$sb.Append("<span class=`"badge $badgeClass`">$(Esc-Html $rec.Severity)</span>")
            if ($isBundleOnly) { [void]$sb.Append('<span class="badge badge-bundle">POSSIBLE (BUNDLE PRODUCT)</span>') }
            [void]$sb.Append("<span class=`"advisory-id`">$(Esc-Html $rec.AdvisoryID)</span>")
            [void]$sb.Append("<span class=`"advisory-title-text`">$(Esc-Html $rec.Title)</span>")
            [void]$sb.Append("<span class=`"advisory-date`">$(Esc-Html $rec.Published)</span>")
            [void]$sb.Append('</summary><div class="advisory-body">')
            [void]$sb.Append("<div class=`"advisory-meta`">CVSS: $(Esc-Html $rec.CVSS) &nbsp;|&nbsp; Published: $(Esc-Html $rec.Published) &nbsp;|&nbsp; <a href=`"$(Esc-Html $rec.Link)`" target=`"_blank`" rel=`"noopener`">Advisory Link</a></div>")

            if ($AllDirectRows.Count -gt 0) {
                [void]$sb.Append('<h3 class="section-label">Matched Rows (version confirmed)</h3>')
                if ($m.MappedBundleRows.Count -gt 0) {
                    [void]$sb.Append('<p class="muted">Includes VMware Cloud Foundation / vSphere Foundation bundle row(s) resolved via the known VCF/VVF-to-component version mapping (see script header).</p>')
                }
                [void]$sb.Append('<div class="matrix-wrap"><table class="matrix-table"><thead><tr>')
                foreach ($h in $MatrixHeaders) { [void]$sb.Append("<th>$(Esc-Html $h)</th>") }
                [void]$sb.Append('</tr></thead><tbody>')
                foreach ($row in $AllDirectRows) {
                    [void]$sb.Append('<tr>')
                    foreach ($h in $MatrixHeaders) { [void]$sb.Append("<td>$(Esc-Html $row.$h)</td>") }
                    [void]$sb.Append('</tr>')
                }
                [void]$sb.Append('</tbody></table></div>')
            }

            if ($m.PossibleBundleRows.Count -gt 0) {
                [void]$sb.Append("<details class=`"nested-toggle`"><summary>Also Listed Under a Bundle Product (VMware Cloud Foundation / vSphere Foundation - bundle line relevant to this build only / VMware Tools) - $($m.PossibleBundleRows.Count) row(s) - click to show</summary><div class=`"nested-toggle-body`">")
                [void]$sb.Append('<p class="bundle-note">The row(s) below show a wrapper-product version with no known mapping to the detected build - not necessarily the vCenter/ESXi build detected in your environment (a VCF/VVF release number with no entry in $VcfVvfMajorVersionMap, or a VMware Tools-shipped-with-ESXi row whose ESXi version does not match). Verify against your actual VCF/VVF release or Tools/ESXi pairing before assuming this applies.</p>')
                [void]$sb.Append('<div class="matrix-wrap"><table class="matrix-table"><thead><tr>')
                foreach ($h in $MatrixHeaders) { [void]$sb.Append("<th>$(Esc-Html $h)</th>") }
                [void]$sb.Append('</tr></thead><tbody>')
                foreach ($row in $m.PossibleBundleRows) {
                    [void]$sb.Append('<tr>')
                    foreach ($h in $MatrixHeaders) { [void]$sb.Append("<td>$(Esc-Html $row.$h)</td>") }
                    [void]$sb.Append('</tr>')
                }
                [void]$sb.Append('</tbody></table></div></div></details>')
            }

            [void]$sb.Append('<h3 class="section-label">CVEs</h3><ul class="cve-list">')
            foreach ($cd in $rec.CveDescriptions) {
                [void]$sb.Append("<li><b>$(Esc-Html $cd.CVE)</b>: $(Esc-Html $cd.Description)")
                if ($CveLookupData) {
                    if ($CveLookupData.ContainsKey($cd.CVE)) {
                        $pairs = @($CveLookupData[$cd.CVE].GetEnumerator() | ForEach-Object { "<b>$(Esc-Html $_.Key)</b>: $(Esc-Html $_.Value)" })
                        [void]$sb.Append('<br><span class="cve-lookup-note">' + ($pairs -join ' &nbsp;|&nbsp; ') + '</span>')
                    } else {
                        [void]$sb.Append('<br><span class="cve-lookup-note">(no CVE Lookup match for this ID)</span>')
                    }
                }
                [void]$sb.Append('</li>')
            }
            [void]$sb.Append('</ul></div></details>')
        }
    }
    [void]$sb.Append('</div>')
}

# --- VMware Tools reference list (no live version detection - see 4b) ---
$ToolsSorted = @($ToolsResults | Sort-Object -Property @{ Expression = { Get-AdvisoryIdSortKey $_.Advisory.AdvisoryID } ; Descending = $true })
[void]$sb.Append("<div class=`"card`"><h2>VMware Tools - Reference List - $($ToolsSorted.Count) advisory(ies)</h2>")
[void]$sb.Append("<details class=`"nested-toggle`"><summary>Show full VMware Tools reference list ($($ToolsSorted.Count) advisory(ies)) - click to expand</summary><div class=`"nested-toggle-body`">")
[void]$sb.Append('<p class="bundle-note">No VMware Tools version was detected live from your environment (the internal Guest.ToolsVersion build number PowerCLI reports per VM has no reliable public mapping back to the dotted release number VMSA advisories use). Every advisory below mentions VMware Tools somewhere in its Response Matrix, regardless of version - cross-check the Version column against your own VM Tools versions by hand.</p>')
if ($ToolsSorted.Count -eq 0) {
    [void]$sb.Append('<p class="muted">No advisories reference VMware Tools.</p>')
} else {
    foreach ($t in $ToolsSorted) {
        $rec = $t.Advisory
        $badgeClass = Get-SeverityBadgeClass -Severity $rec.Severity

        [void]$sb.Append('<details class="advisory-card"><summary>')
        [void]$sb.Append("<span class=`"badge $badgeClass`">$(Esc-Html $rec.Severity)</span>")
        [void]$sb.Append("<span class=`"advisory-id`">$(Esc-Html $rec.AdvisoryID)</span>")
        [void]$sb.Append("<span class=`"advisory-title-text`">$(Esc-Html $rec.Title)</span>")
        [void]$sb.Append("<span class=`"advisory-date`">$(Esc-Html $rec.Published)</span>")
        [void]$sb.Append('</summary><div class="advisory-body">')
        [void]$sb.Append("<div class=`"advisory-meta`">CVSS: $(Esc-Html $rec.CVSS) &nbsp;|&nbsp; Published: $(Esc-Html $rec.Published) &nbsp;|&nbsp; <a href=`"$(Esc-Html $rec.Link)`" target=`"_blank`" rel=`"noopener`">Advisory Link</a></div>")

        [void]$sb.Append('<div class="matrix-wrap"><table class="matrix-table"><thead><tr>')
        foreach ($h in $MatrixHeaders) { [void]$sb.Append("<th>$(Esc-Html $h)</th>") }
        [void]$sb.Append('</tr></thead><tbody>')
        foreach ($row in $t.ToolsRows) {
            [void]$sb.Append('<tr>')
            foreach ($h in $MatrixHeaders) { [void]$sb.Append("<td>$(Esc-Html $row.$h)</td>") }
            [void]$sb.Append('</tr>')
        }
        [void]$sb.Append('</tbody></table></div>')

        [void]$sb.Append('<h3 class="section-label">CVEs</h3><ul class="cve-list">')
        foreach ($cd in $rec.CveDescriptions) {
            [void]$sb.Append("<li><b>$(Esc-Html $cd.CVE)</b>: $(Esc-Html $cd.Description)")
            if ($CveLookupData) {
                if ($CveLookupData.ContainsKey($cd.CVE)) {
                    $pairs = @($CveLookupData[$cd.CVE].GetEnumerator() | ForEach-Object { "<b>$(Esc-Html $_.Key)</b>: $(Esc-Html $_.Value)" })
                    [void]$sb.Append('<br><span class="cve-lookup-note">' + ($pairs -join ' &nbsp;|&nbsp; ') + '</span>')
                } else {
                    [void]$sb.Append('<br><span class="cve-lookup-note">(no CVE Lookup match for this ID)</span>')
                }
            }
            [void]$sb.Append('</li>')
        }
        [void]$sb.Append('</ul></div></details>')
    }
}
[void]$sb.Append('</div></details>')
[void]$sb.Append('</div>')

# --- VMware Cloud Foundation / vSphere Foundation reference list (5.x / 9.x
#     only, not tied to a detected build - see 4c) ---
$VcfVvfSorted = @($VcfVvfResults | Sort-Object -Property @{ Expression = { Get-AdvisoryIdSortKey $_.Advisory.AdvisoryID } ; Descending = $true })
[void]$sb.Append("<div class=`"card`"><h2>VMware Cloud Foundation / vSphere Foundation - Reference List (5.x / 9.x only) - $($VcfVvfSorted.Count) advisory(ies)</h2>")
[void]$sb.Append("<details class=`"nested-toggle`"><summary>Show full VMware Cloud Foundation / vSphere Foundation reference list ($($VcfVvfSorted.Count) advisory(ies)) - click to expand</summary><div class=`"nested-toggle-body`">")
[void]$sb.Append('<p class="bundle-note">Every advisory below has a VMware Cloud Foundation or VMware vSphere Foundation row on the 5.x or 9.x release line somewhere in its Response Matrix - the only two lines this report tracks (see $VcfVvfMajorVersionMap / $VcfVvfUnifiedMinMajor in the script header). This list is independent of the versions detected live above - it is not filtered to what matches your environment, so cross-check the Version column against your actual VCF/VVF release by hand.</p>')
if ($VcfVvfSorted.Count -eq 0) {
    [void]$sb.Append('<p class="muted">No advisories reference a VMware Cloud Foundation / vSphere Foundation 5.x or 9.x line.</p>')
} else {
    foreach ($v in $VcfVvfSorted) {
        $rec = $v.Advisory
        $badgeClass = Get-SeverityBadgeClass -Severity $rec.Severity

        [void]$sb.Append('<details class="advisory-card"><summary>')
        [void]$sb.Append("<span class=`"badge $badgeClass`">$(Esc-Html $rec.Severity)</span>")
        [void]$sb.Append("<span class=`"advisory-id`">$(Esc-Html $rec.AdvisoryID)</span>")
        [void]$sb.Append("<span class=`"advisory-title-text`">$(Esc-Html $rec.Title)</span>")
        [void]$sb.Append("<span class=`"advisory-date`">$(Esc-Html $rec.Published)</span>")
        [void]$sb.Append('</summary><div class="advisory-body">')
        [void]$sb.Append("<div class=`"advisory-meta`">CVSS: $(Esc-Html $rec.CVSS) &nbsp;|&nbsp; Published: $(Esc-Html $rec.Published) &nbsp;|&nbsp; <a href=`"$(Esc-Html $rec.Link)`" target=`"_blank`" rel=`"noopener`">Advisory Link</a></div>")

        [void]$sb.Append('<div class="matrix-wrap"><table class="matrix-table"><thead><tr>')
        foreach ($h in $MatrixHeaders) { [void]$sb.Append("<th>$(Esc-Html $h)</th>") }
        [void]$sb.Append('</tr></thead><tbody>')
        foreach ($row in $v.VcfVvfRows) {
            [void]$sb.Append('<tr>')
            foreach ($h in $MatrixHeaders) { [void]$sb.Append("<td>$(Esc-Html $row.$h)</td>") }
            [void]$sb.Append('</tr>')
        }
        [void]$sb.Append('</tbody></table></div>')

        [void]$sb.Append('<h3 class="section-label">CVEs</h3><ul class="cve-list">')
        foreach ($cd in $rec.CveDescriptions) {
            [void]$sb.Append("<li><b>$(Esc-Html $cd.CVE)</b>: $(Esc-Html $cd.Description)")
            if ($CveLookupData) {
                if ($CveLookupData.ContainsKey($cd.CVE)) {
                    $pairs = @($CveLookupData[$cd.CVE].GetEnumerator() | ForEach-Object { "<b>$(Esc-Html $_.Key)</b>: $(Esc-Html $_.Value)" })
                    [void]$sb.Append('<br><span class="cve-lookup-note">' + ($pairs -join ' &nbsp;|&nbsp; ') + '</span>')
                } else {
                    [void]$sb.Append('<br><span class="cve-lookup-note">(no CVE Lookup match for this ID)</span>')
                }
            }
            [void]$sb.Append('</li>')
        }
        [void]$sb.Append('</ul></div></details>')
    }
}
[void]$sb.Append('</div></details>')
[void]$sb.Append('</div>')

[void]$sb.Append('</div></body></html>')

Set-Content -Path $HtmlPath -Value $sb.ToString() -Encoding UTF8
Write-Host "    -> HTML: $HtmlPath" -ForegroundColor Gray

Write-Host "`n[DONE] Detected versions: $($DetectedTargets.Count) | Matched advisories: $($MatchResults.Count) ($DirectMatchCount direct, $BundleOnlyCount possible-only via a bundle product) | VMware Tools reference: $($ToolsResults.Count) advisory(ies) (no live detection) | VCF/VVF reference: $($VcfVvfResults.Count) advisory(ies) (5.x/9.x only) | CVE Lookup: $CveLookupSourceText" -ForegroundColor Green
Write-Host "       CSV : $CsvPath" -ForegroundColor Green
Write-Host "       HTML: $HtmlPath" -ForegroundColor Green
