# =============================================================================
# [Script 1] VMSA Downloader for Air-Gapped Environment
# -----------------------------------------------------------------------------
# Environment: Internet-connected PC
# Function:
# 1. Fetches the latest security advisories from Broadcom API.
# 2. Crawls detail pages to extract 'Fixed Version' (Matrix) and 'CVSS' (Table).
# 3. Collects ALL advisories for vCenter/ESXi regardless of specific version.
# 4. Generates 'VMSA_Offline_Data.json' for transfer to the internal network.
# =============================================================================

$ErrorActionPreference = "Stop"
$CurrentDir = $PSScriptRoot
if ([string]::IsNullOrWhiteSpace($CurrentDir)) { $CurrentDir = Get-Location }

$JsonPath = Join-Path $CurrentDir "VMSA_Offline_Data.json"
$Timestamp = Get-Date -Format "yyyy-MM-dd HH:mm"

Write-Host "[1] Collecting Broadcom Security Advisories..." -ForegroundColor Cyan

# 1. Call API (Get List)
try {
    $ApiUrl = "https://support.broadcom.com/web/ecx/security-advisory/-/securityadvisory/getSecurityAdvisoryList"
    $Payload = @{
        pageNumber = 0; pageSize = 50; searchVal = ""; segment = "VC";
        sortInfo = @{ column = "published"; order = "DESC" }
    }
    [System.Net.ServicePointManager]::SecurityProtocol = [System.Net.SecurityProtocolType]::Tls12
    $Response = Invoke-RestMethod -Uri $ApiUrl -Method Post -Body ($Payload | ConvertTo-Json) -ContentType "application/json" -TimeoutSec 15
    $RawList = $Response.data.list
    Write-Host "    -> List collection complete ($($RawList.Count) items)" -ForegroundColor Green
} catch {
    Write-Error "API Call Failed: Please check your internet connection. ($($_.Exception.Message))"
    exit
}

# 2. Detail Crawling & Data Processing
Write-Host "[2] Crawling details (CVSS Base Score & Matrix)..." -ForegroundColor Cyan

$ProcessedList = @()
$Counter = 0
$Total = $RawList.Count

# Target Keywords (Collect ALL related to these products)
$TargetRegex = "ESXi|vCenter|vSphere|Cloud Foundation|VMware Tools"

foreach ($item in $RawList) {
    $Counter++
    
    # Check title for relevant products (Broad match)
    if ($item.title -match $TargetRegex) {
        $ProgressMsg = "[$Counter/$Total] Analyzing $($item.documentId)..."
        Write-Progress -Activity "VMSA Data Mining" -Status $ProgressMsg -PercentComplete (($Counter / $Total) * 100)

        # 2-1. Fetch Detail Page HTML
        $HtmlContent = ""
        try {
            $WebReq = Invoke-WebRequest -Uri $item.notificationUrl -UseBasicParsing -TimeoutSec 10 -ErrorAction SilentlyContinue
            # Normalize HTML: Remove newlines for robust regex matching
            $HtmlContent = $WebReq.Content -replace "`r", " " -replace "`n", " "
        } catch {
            Write-Warning "    ! Failed to access detail page: $($item.documentId)"
            continue
        }

        # 2-2. Information Extraction Logic
        
        # A. CVSS Score (Table-Aware Extraction)
        $CvssText = "N/A"
        
        # Parse all Table Rows
        $AllRows = [Regex]::Matches($HtmlContent, "<tr.*?>(.*?)<\/tr>", [System.Text.RegularExpressions.RegexOptions]::IgnoreCase)
        
        # Method 1: Look for "CVSSv3 Range" or "Base Score" in the first column of a table row
        foreach ($row in $AllRows) {
            $rowHtml = $row.Groups[1].Value
            # Extract cells (td or th)
            $Cells = [Regex]::Matches($rowHtml, "<t[dh].*?>(.*?)<\/t[dh]>", [System.Text.RegularExpressions.RegexOptions]::IgnoreCase)
            
            if ($Cells.Count -ge 2) {
                # Get first column text
                $col1 = $Cells[0].Groups[1].Value -replace "<.*?>", "" -replace "&nbsp;", " "
                $col1 = $col1.Trim()
                
                # Check if it matches our target labels
                if ($col1 -match "(?i)CVSS.*?Range" -or $col1 -match "(?i)Base\s*Score") {
                    # Capture the second column text
                    $col2 = $Cells[1].Groups[1].Value -replace "<.*?>", "" -replace "&nbsp;", " "
                    $CvssText = $col2.Trim()
                    break # Found it, stop searching rows
                }
            }
        }

        # Method 2: Regex Fallback (If table structure was not found)
        if ($CvssText -eq "N/A") {
            # Capture text after "Base Score:"
            if ($HtmlContent -match "(?i)CVSS\s*(?:v3)?\s*Base\s*Score\s*[:\s-]*\s*([^<]*)") {
                 $CvssText = $matches[1].Trim()
            } 
            # Capture text after "CVSSv3 Range:"
            elseif ($HtmlContent -match "(?i)CVSSv3\s*Range\s*[:\s-]*\s*([^<]*)") {
                 $CvssText = $matches[1].Trim()
            }
            # Fallback to API severity if everything failed
            if ($CvssText -eq "N/A" -and $item.severity) { $CvssText = $item.severity }
        }

        # B. Fixed Version Info (Capture ALL Response Matrix Info)
        $FixedInfoText = @()
        
        foreach ($row in $AllRows) {
            $rowContent = $row.Groups[1].Value
            
            # Identify target rows (Broad matching)
            if ($rowContent -match "(ESXi|vCenter\s*Server|Cloud\s*Foundation)") {
                 
                 # Extract individual cells (td)
                 $Cells = [Regex]::Matches($rowContent, "<td.*?>(.*?)<\/td>", [System.Text.RegularExpressions.RegexOptions]::IgnoreCase)
                 $RowValues = @()
                 
                 foreach ($cell in $Cells) {
                     # Clean tag and whitespace
                     $txt = $cell.Groups[1].Value -replace "<.*?>", "" -replace "&nbsp;", " " 
                     $txt = $txt.Trim()
                     if (-not [string]::IsNullOrWhiteSpace($txt)) {
                        $RowValues += $txt
                     }
                 }
                 
                 # Join ALL cells in the row with a separator
                 if ($RowValues.Count -gt 0) {
                     $FixedInfoText += ($RowValues -join " | ")
                 }
            }
        }
        
        # Text Fallback (if Matrix parsing found nothing)
        if ($FixedInfoText.Count -eq 0) {
            if ($HtmlContent -match "(?i)Fixed Version.*?(:|<\/strong>|<\/b>)(.*?)(<br>|<\/p>|<\/td>)") {
                $rawText = $matches[2] -replace "<.*?>", "" -replace "&nbsp;", " "
                if (-not [string]::IsNullOrWhiteSpace($rawText)) { $FixedInfoText += $rawText.Trim() }
            }
        }
        
        # Join multiple rows with HTML break for display
        $FixedStr = if ($FixedInfoText.Count -gt 0) { $FixedInfoText -join "<br>" } else { "Check Link for details" }
        
        # Limit length if excessive
        if ($FixedStr.Length -gt 3000) { $FixedStr = $FixedStr.Substring(0, 2997) + "..." }

        # Create Data Object
        $ProcessedList += [PSCustomObject][ordered]@{
            AdvisoryID       = $item.documentId
            Title            = $item.title
            Severity         = $item.severity
            CVSS             = $CvssText
            FixedInfo        = $FixedStr
            Link             = $item.notificationUrl
            Published        = $item.published
        }
    }
}
Write-Progress -Activity "VMSA Data Mining" -Completed

# 3. Save to JSON
$ExportData = @{
    Metadata = @{
        GeneratedAt = $Timestamp
        Source      = "Broadcom Support Portal"
        TotalCount  = $ProcessedList.Count
    }
    Advisories = $ProcessedList
}

$ExportData | ConvertTo-Json -Depth 4 | Set-Content -Path $JsonPath -Encoding UTF8
Write-Host "`n[DONE] Data file created: $JsonPath" -ForegroundColor Green
Write-Host "-> Copy this file to your Air-gapped PC and run '2_VMSA_Auditor_AirGapped.ps1'." -ForegroundColor Yellow