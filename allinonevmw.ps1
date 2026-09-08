#Requires -Version 7.0
<#
    Script Name : allinonevmw.ps1
    Description : All-in-one launcher for the infra_assessment repo (postout7979/infra_assessment)
                  tool scripts, selected from a menu.
                    [1] vcf_9_upgrade      - VCF9 pre-check / NVMe memory tiering analysis
                    [2] Operations         - VCF Operations report
                    [3] security-hardening - Security hardening audit + VMSA version check + KISA audit
                                             (consolidated into one menu entry - all three need a vCenter
                                             login, so this entry logs in once and runs all three in turn)
                    [4] vcenter            - vCenter daily comprehensive report
                    [5] vmsa               - VMSA vulnerability management toolkit
                    [6] kisa_esx           - Folded into [3] above (kept here only as historical reference)

                  Unlike earlier versions, this file does not call each folder's .ps1 as a separate
                  process. All tool logic is inlined as functions (Invoke-*Tool) directly 'inside'
                  this file (full inline merge). So all that is needed to run it is this file plus
                  the two data folders/files below - the original repo's individual script folders
                  (vcf_9_upgrade, Operations, security-hardening, vcenter, vmsa, kisa_esx) are no
                  longer needed at run time (they can stay as historical reference of past runs).

                  security-hardening\vmware-tools\remediate-esxi-8.ps1 / remediate-vcenter-8.ps1 /
                  remediate-vm-8.ps1 are out of scope for this merge (still run standalone as before).
                  scg-common.psm1, which those 3 scripts still reference, must stay at its original
                  location (security-hardening\vmware-tools\).

    Setup       : Put this script at the root of the infra_assessment repo, then move the 2 items
                  below to that root (subfolders that used to live under each tool's own folder move
                  to the root along with the change in execution location):

                  infra_assessment\                      <- git clone https://github.com/postout7979/infra_assessment
                   |- allinonevmw.ps1                    <- this file
                   |- hcl\                               <- (moved) from vcf_9_upgrade\hcl\
                   |- vmware-vsphere-security-configuration-guide-8-controls.csv  <- (moved) from security-hardening\
                   |- VMSA_FullList_Data.json            <- auto-created/updated here by menu [5] (persistent cache,
                   |                                         not under output\ - survives an output\ cleanup)
                   |- CVE_Lookup_Cache.json              <- auto-created/updated here by menu [5] (persistent cache,
                   |                                         not under output\ - survives an output\ cleanup)
                   \- output\                            <- run results, auto-created per tool subfolder
                       |- vcf_9_upgrade\
                       |- Operations\
                       |- security-hardening\
                       |- vcenter\
                       |- vmsa\
                       \- kisa_esx\

                  To use a different location, set the VMWTOOLS_INFRA_PATH environment variable to
                  the root path.

    How to run  : .\allinonevmw.ps1
                  (Set-ExecutionPolicy -Scope CurrentUser RemoteSigned may be required)

    Note        : On startup this script automatically runs Unblock-File across itself and the whole
                  repo root (hcl\, output\, etc). If you downloaded a GitHub ZIP, Windows marks the
                  files as "downloaded from the internet", which causes an "is not digitally signed"
                  error under the RemoteSigned policy. If you still see that error, run this manually:

                    Get-ChildItem -Path . -Recurse | Unblock-File
#>

param()

Set-StrictMode -Off
$ErrorActionPreference = "Continue"

# ============================================================
# 0. Path setup - infra_assessment repo root / unified output root
# ============================================================
$RepoRoot   = if ($env:VMWTOOLS_INFRA_PATH) { $env:VMWTOOLS_INFRA_PATH } else { $PSScriptRoot }
$OutputRoot = Join-Path $RepoRoot "output"

# ============================================================
# 0.5 Automatically clear Windows' "downloaded from the internet" block (Unblock-File)
# ============================================================
if (Test-Path -LiteralPath $RepoRoot) {
    try {
        Get-ChildItem -Path $RepoRoot -Recurse -File -Include *.ps1, *.psm1, *.psd1, *.csv -ErrorAction SilentlyContinue |
            Unblock-File -ErrorAction SilentlyContinue
    }
    catch { }
}

function Invoke-Vcf9PrecheckToolkitTool {
param(
    [string]$MenuChoice,
    [string]$ExistingInventoryPath,
    [switch]$AutoChainToNvmeTiering
)

# ============================================================
#  vcf9-precheck-toolkit.ps1
#  VCF 9 Pre-check Integrated Script (Inventory Collection + HCL Compatibility Check)
# ============================================================
#  Running this script displays a menu.
#    [1] Inventory collection (vCenter connection) + HCL compatibility check, run automatically in sequence
#        -> Creates a collection folder (vSphere_Inventory_YYYYMMDD_HHMM),
#           reads the CSVs inside it directly to run the HCL check, then
#           saves the results to a new folder (compatibility_YYYYMMDD_HHMM).
#    [2] Run inventory collection only (vCenter connection)
#        -> Creates only the collection folder (vSphere_Inventory_YYYYMMDD_HHMM).
#    [3] Specify an existing collection folder and run only the HCL compatibility check
#        -> Prompts for the folder name (or path) created by Menu [2],
#           runs the HCL check, and saves the results to a new folder (compatibility_YYYYMMDD_HHMM).
#
#  Place the 4 HCL CSV files (CPU_All_Models, IO_Devices, Systems_Servers, vSAN_IO_Controller)
#  in an 'hcl' folder next to this script (case-insensitive; a different path can be set via -HCLPath).
# ============================================================

Set-StrictMode -Off
$ErrorActionPreference = "Continue"

# ============================================================
# HELPER: Sanitize host names collected during inventory collection
#   - If the name is an FQDN (contains a dot and is not an IPv4 address),
#     the domain suffix is stripped, keeping only the short host name.
#   - If the name is an IPv4 address, the first 6 characters are masked
#     with '*' (e.g. "192.168.10.55" -> "******0.10.55").
#   - Any other value (already a short host name) is returned unchanged.
# ============================================================
function Get-SanitizedHostName {
    param([string]$Name)

    if ([string]::IsNullOrWhiteSpace($Name)) { return $Name }

    $Trimmed = $Name.Trim()

    # IPv4 address check (e.g. 192.168.10.55)
    if ($Trimmed -match '^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$') {
        if ($Trimmed.Length -le 6) {
            return ('*' * $Trimmed.Length)
        }
        return ('*' * 6) + $Trimmed.Substring(6)
    }

    # FQDN check -> strip the domain suffix, keep only the short host name
    if ($Trimmed -match '\.') {
        return $Trimmed.Split('.')[0]
    }

    return $Trimmed
}

# ============================================================
# SHARED HTML REPORT HELPERS (used by the HCL check and performance report)
# ============================================================
function ConvertTo-SafeHtmlShared { param([string]$Text); if ($null -eq $Text) { return "" }; return [System.Net.WebUtility]::HtmlEncode($Text) }
function Get-SafeFileNameShared { param([string]$Text); if ([string]::IsNullOrWhiteSpace($Text)) { return "unknown" }; return ($Text -replace '[^a-zA-Z0-9_\-]', '_') }
function ConvertTo-PctNumber {
    param([string]$Text)
    if ([string]::IsNullOrWhiteSpace($Text)) { return 0 }
    $Clean = ($Text -replace '[^0-9.\-]', '')
    if ([string]::IsNullOrWhiteSpace($Clean)) { return 0 }
    $Val = 0.0
    if ([double]::TryParse($Clean, [ref]$Val)) { return $Val }
    return 0
}
function ConvertTo-NumberOrZero {
    param([string]$Text)
    if ([string]::IsNullOrWhiteSpace($Text)) { return 0 }
    $Val = 0.0
    if ([double]::TryParse($Text, [ref]$Val)) { return $Val }
    return 0
}

function Get-SharedReportCss {
    return @"
:root{--bg:#f0f2f5;--surface:#fff;--border:#e2e8f0;--primary:#1e3a5f;--primary-lt:#e8edf5;--green:#16a34a;--green-lt:#dcfce7;--green-dk:#14532d;--red:#dc2626;--red-lt:#fee2e2;--red-dk:#7f1d1d;--yellow:#d97706;--yellow-lt:#fef3c7;--gray:#64748b;--gray-lt:#f8fafc;--radius:12px;--shadow:0 1px 3px rgba(0,0,0,.08),0 4px 16px rgba(0,0,0,.06);font-family:'Malgun Gothic','Apple SD Gothic Neo',Arial,sans-serif}
*{box-sizing:border-box;margin:0;padding:0}body{background:var(--bg);color:#1e293b;padding:28px 32px;font-size:14px;line-height:1.6}
.page-header{margin-bottom:32px;display:flex;align-items:center;justify-content:space-between;flex-wrap:wrap;gap:10px}.page-header h1{font-size:22px;font-weight:700;color:var(--primary);margin-bottom:4px}.page-meta{color:var(--gray);font-size:12px}
.back-link{font-size:13px;font-weight:600;color:var(--primary);text-decoration:none;background:var(--primary-lt);padding:7px 14px;border-radius:8px;white-space:nowrap}.back-link:hover{background:var(--primary);color:#fff}
.home-link{font-size:13px;font-weight:600;color:var(--primary);text-decoration:none;background:var(--primary-lt);padding:7px 14px;border-radius:8px;white-space:nowrap}.home-link:hover{background:var(--primary);color:#fff}
.nav-bar{display:flex;align-items:center;gap:8px}.nav-select{font-size:13px;font-weight:600;color:var(--primary);background:var(--surface);border:1.5px solid var(--primary-lt);border-radius:8px;padding:7px 10px;cursor:pointer}
.section-title{font-size:15px;font-weight:700;color:var(--primary);margin:28px 0 14px;display:flex;align-items:center;gap:8px}.section-title::before{content:'';display:inline-block;width:4px;height:18px;background:var(--primary);border-radius:2px}
.version-block{display:flex;gap:24px;margin-bottom:12px;width:100%}.ver-group{display:flex;flex-direction:column;gap:8px;flex:1;min-width:0}.ver-label{font-size:12px;font-weight:700;color:var(--primary);letter-spacing:.05em;text-transform:uppercase;padding:4px 0}.card-row{display:flex;gap:12px;width:100%}
.kpi-card{display:flex;align-items:center;gap:16px;background:var(--surface);border-radius:var(--radius);padding:20px 24px;box-shadow:var(--shadow);flex:1;min-width:0;border-left:5px solid}.kpi-card.green{border-color:var(--green)}.kpi-card.red{border-color:var(--red)}.kpi-card.blue{border-color:var(--primary)}.kpi-card.yellow{border-color:var(--yellow)}.kpi-icon{font-size:22px;font-weight:900}.kpi-card.green .kpi-icon{color:var(--green)}.kpi-card.red .kpi-icon{color:var(--red)}.kpi-card.blue .kpi-icon{color:var(--primary)}.kpi-card.yellow .kpi-icon{color:var(--yellow)}.kpi-val{font-size:30px;font-weight:700;line-height:1}.kpi-sub{font-size:12px;font-weight:600;color:var(--gray);margin-top:4px}.kpi-detail{font-size:17px;font-weight:700;color:#1e293b;margin-top:4px}
.cluster-section{background:var(--surface);border-radius:var(--radius);box-shadow:var(--shadow);padding:22px 24px;margin-bottom:24px}.cluster-header{display:flex;align-items:center;justify-content:space-between;margin-bottom:16px;flex-wrap:wrap;gap:8px}.cluster-name{font-size:15px;font-weight:700;color:var(--primary)}.cluster-name a{color:var(--primary);text-decoration:none;border-bottom:1.5px dashed var(--primary)}.cluster-name a:hover{color:#0f2440;border-bottom-style:solid}.cluster-cards{display:flex;gap:16px;width:100%;margin-bottom:18px;flex-wrap:wrap}
.summary-table-wrap{overflow-x:auto;margin-bottom:16px}.summary-table-wrap table{width:100%;border-collapse:collapse;font-size:13px}.summary-table-wrap th{background:var(--primary);color:#fff;padding:8px 12px;font-weight:600;text-align:left}.summary-table-wrap td{padding:7px 12px;border-bottom:1px solid var(--border)}.summary-table-wrap tr:last-child td{font-weight:700;background:var(--gray-lt)}.summary-table-wrap tr:hover td{background:var(--primary-lt)}
.cat-section{margin-bottom:20px}.cat-title{font-size:13px;font-weight:700;color:var(--primary);margin-bottom:8px;padding:6px 12px;background:var(--primary-lt);border-radius:6px;display:inline-block}
.table-wrap{overflow-x:auto}.table-wrap table{width:100%;border-collapse:collapse;font-size:12px}.table-wrap th{background:var(--primary);color:#fff;padding:7px 10px;font-weight:600;white-space:nowrap;text-align:left}.table-wrap td{padding:6px 10px;border-bottom:1px solid var(--border);vertical-align:top}.table-wrap .note{max-width:340px;font-size:11px;color:var(--gray)}
.tag-total{display:inline-block;padding:2px 8px;border-radius:4px;background:var(--primary-lt);color:var(--primary);font-size:11px;font-weight:600}
.badge{display:inline-flex;align-items:center;padding:2px 9px;border-radius:20px;font-size:11px;font-weight:700;letter-spacing:.02em}.badge.ok{background:var(--green-lt);color:var(--green-dk)}.badge.miss{background:var(--red-lt);color:var(--red-dk)}.badge.warn{background:var(--yellow-lt);color:#92400e}
.hi-usage{color:var(--red-dk);font-weight:700}.mid-usage{color:#92400e;font-weight:600}
"@
}

# ============================================================
# FUNCTION 1: Inventory collection (formerly vcf9-precheck-script-cs.ps1)
#   Return value: the created inventory folder path ($ReportDir) on success, $null on failure
# ============================================================
function Invoke-VCF9Precheck {
    param(
        [switch]$ShowStandaloneHint
    )

Write-Host "===============================================================================" -ForegroundColor Cyan
Write-Host "          vSphere Inventory Report - Initial Environment Setup & Module Check" -ForegroundColor Cyan
Write-Host "===============================================================================" -ForegroundColor Cyan

# 1. Change script execution policy (avoid being blocked; current session scope only)
if ((Get-ExecutionPolicy) -match "Restricted") {
    Write-Host "[INIT] Changing PowerShell execution policy to RemoteSigned..." -ForegroundColor Yellow
    Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope Process -Confirm:$false -Force
}

# 2. Enable modern security protocol (TLS 1.2) - required for module downloads
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

# 3. Check whether the VMware.PowerCLI module exists and auto-install if needed
if (-not (Get-Module -ListAvailable -Name VMware.PowerCLI)) {
    Write-Host "[INIT] VMware.PowerCLI module not found. Attempting automatic installation..." -ForegroundColor Yellow
    
    # Check whether the NuGet package provider is installed, and install if needed
    if (-not (Get-PackageProvider -Name NuGet -ErrorAction SilentlyContinue)) {
        Write-Host " -> Installing NuGet package provider first..." -ForegroundColor Gray
        Install-PackageProvider -Name NuGet -MinimumVersion 2.8.5.201 -Force | Out-Null
    }

    # Set PSGallery as a trusted repository
    Set-PSRepository -Name PSGallery -InstallationPolicy Trusted -ErrorAction SilentlyContinue

    # Install PowerCLI (requires internet connection)
    Write-Host " -> Installing VMware.PowerCLI module from PSGallery..." -ForegroundColor Gray
    Write-Host "    (This may take 3-5 minutes depending on your environment. Do not close this window.)" -ForegroundColor DarkGray
    try {
        Install-Module -Name VMware.PowerCLI -Scope CurrentUser -AllowClobber -Force | Out-Null
        Write-Host "[SUCCESS] VMware.PowerCLI module installed successfully!" -ForegroundColor Green
    } catch {
        Write-Host "===============================================================================" -ForegroundColor Red
        Write-Host "[ERROR] No internet connection, or automatic module installation failed." -ForegroundColor Red
        Write-Host ""
        Write-Host "[Offline (Air-Gapped) Installation Guide]" -ForegroundColor Cyan
        Write-Host "Official guide: https://techdocs.broadcom.com/us/en/vmware-cis/vcf/power-cli/latest/powercli/installing-vmware-vsphere-powercli/install-powercli-offline.html" -ForegroundColor DarkGray
        Write-Host ""
        Write-Host " [Step 1] Download the PowerCLI ZIP file on a PC with internet access:" -ForegroundColor Yellow
        Write-Host "          https://developer.broadcom.com/tools/vmware-powercli/latest/" -ForegroundColor Yellow
        Write-Host "          (Download the ZIP from the Broadcom Developer Portal above and transfer it to this server)" -ForegroundColor DarkGray
        Write-Host ""
        Write-Host " [Step 2] Check the module install path in PowerShell on this server:" -ForegroundColor Yellow
        Write-Host "          `$env:PSModulePath" -ForegroundColor Yellow
        Write-Host "          (Extract the ZIP contents into one of the paths shown)" -ForegroundColor DarkGray
        Write-Host "          (e.g. C:\Program Files\WindowsPowerShell\Modules)" -ForegroundColor DarkGray
        Write-Host ""
        Write-Host " [Step 3] Unblock the copied files (required on Windows):" -ForegroundColor Yellow
        Write-Host "          Get-ChildItem -Path '<extracted path>' -Recurse | Unblock-File" -ForegroundColor Yellow
        Write-Host ""
        Write-Host " [Step 4] Verify installation:" -ForegroundColor Yellow
        Write-Host "          Get-Module VMware* -ListAvailable" -ForegroundColor Yellow
        Write-Host "          (If the VMware module list is displayed, installation is complete. Re-run this script afterward)" -ForegroundColor DarkGray
        Write-Host "===============================================================================" -ForegroundColor Red
        return $null
    }
} else {
    Write-Host "[OK] VMware.PowerCLI module is already installed." -ForegroundColor Green
}

# 4. Configure PowerCLI session settings (ignore invalid certificates, disable CEIP)
Write-Host "[INIT] Configuring PowerCLI connection security settings..." -ForegroundColor Gray
Set-PowerCLIConfiguration -InvalidCertificateAction Ignore -Confirm:$false -Scope Session -WarningAction SilentlyContinue | Out-Null
Set-PowerCLIConfiguration -ParticipateInCEIP $false -Confirm:$false -Scope User -WarningAction SilentlyContinue | Out-Null
[Net.ServicePointManager]::ServerCertificateValidationCallback = {$true}


# ----------------------------------------------------
# 0. vCenter Connection Settings & Environment Setup
# ----------------------------------------------------
Write-Host "`n===============================================================================" -ForegroundColor Cyan
Write-Host "                  vSphere Inventory Report - vCenter Connection" -ForegroundColor Cyan
Write-Host "===============================================================================" -ForegroundColor Cyan

$vCenter = Read-Host "> Enter the vCenter IP or FQDN"
if ([string]::IsNullOrWhiteSpace($vCenter)) {
    Write-Host "[ERROR] The vCenter address cannot be empty." -ForegroundColor Red
    return $null
}

Write-Host "`n> Enter the vCenter login account (e.g. administrator@vsphere.local) and password..." -ForegroundColor Yellow
$Credential = Get-Credential

$TimeStamp = Get-Date -Format "yyyyMMdd_HHmm"
$DirName   = "vSphere_Inventory_$TimeStamp"
    $ReportDir = Join-Path $OutputRoot "vcf_9_upgrade\$DirName"
$ZipPath   = "$ReportDir.zip"

if (-not (Test-Path $ReportDir)) { New-Item -ItemType Directory -Path $ReportDir | Out-Null }

try {
    Write-Host "`nConnecting to vCenter ($vCenter)..." -ForegroundColor Cyan
    $DefaultServer = Connect-VIServer -Server $vCenter -Credential $Credential -WarningAction SilentlyContinue
} catch {
    Write-Host "[ERROR] Failed to connect to vCenter. Check the address, credentials, or network status." -ForegroundColor Red
    return $null
}

# ----------------------------------------------------
# Pre-fetch Base Data & Optimization
# ----------------------------------------------------
Write-Host "Fetching Base Infrastructure Data (This may take a moment)..." -ForegroundColor Cyan
$Clusters      = @(Get-Cluster)
$VMHosts       = @(Get-VMHost)
$AllVMs        = @(Get-VM)
$AllDatastores = @(Get-Datastore)
Write-Host "       Clusters: $($Clusters.Count)  |  Hosts: $($VMHosts.Count)  |  VMs: $($AllVMs.Count)  |  Datastores: $($AllDatastores.Count)" -ForegroundColor DarkGray

Write-Host "Building Memory Lookup Tables for Fast Processing..." -ForegroundColor Cyan
# Group-Object -AsHashTable returns $null (not an empty hashtable) when its input is empty
# (e.g. a fresh vCenter/cluster with no hosts or VMs yet) - normalize to @{} so later
# hashtable lookups such as $VMsByCluster[$Cluster.Name] never index into $null.
$HostsByCluster = $VMHosts | Group-Object -Property @{Expression={$_.Parent.Name}} -AsHashTable -AsString
$VMsByCluster   = $AllVMs | Group-Object -Property @{Expression={$_.VMHost.Parent.Name}} -AsHashTable -AsString
$VMsByHost      = $AllVMs | Group-Object -Property @{Expression={$_.VMHost.Name}} -AsHashTable -AsString
if (-not $HostsByCluster) { $HostsByCluster = @{} }
if (-not $VMsByCluster)   { $VMsByCluster   = @{} }
if (-not $VMsByHost)      { $VMsByHost      = @{} }

# ----------------------------------------------------
# vCenter Server Component Version Extraction
# ----------------------------------------------------
Write-Host "Extracting vCenter Server Details..." -ForegroundColor Cyan
$vcInstance = $DefaultServer[0]
$vCenterReport = [PSCustomObject]@{
    "vCenter_Instance" = $vcInstance.Name
    "Version"          = $vcInstance.Version
    "BuildNumber"      = $vcInstance.Build
    "User"             = $vcInstance.User
}
$vCenterReport | Export-Csv -Path "$ReportDir\vCenter_Info.csv" -NoTypeInformation -Encoding UTF8

# ----------------------------------------------------
# 1. Extract Cluster Status
# ----------------------------------------------------
Write-Host "[1/12] Extracting Cluster info..." -ForegroundColor Cyan
$ClusterReport = foreach ($Cluster in $Clusters) {
    $HostsInCluster = $HostsByCluster[$Cluster.Name]
    $VMsInCluster   = $VMsByCluster[$Cluster.Name]
    
    $TotalCapGB  = 0; $TotalFreeGB = 0; $DSNames = "N/A"
    
    if ($HostsInCluster) {
        $Datastores = $HostsInCluster | Get-Datastore | Select-Object -Unique
        if ($Datastores) {
            $DSNames     = ($Datastores.Name) -join ", "
            $TotalCapGB  = [Math]::Round(($Datastores.CapacityGB | Measure-Object -Sum).Sum, 2)
            $TotalFreeGB = [Math]::Round(($Datastores.FreeSpaceGB | Measure-Object -Sum).Sum, 2)
        }
    }
    
    [PSCustomObject]@{
        "ClusterName"         = $Cluster.Name
        "HostCount"           = if ($HostsInCluster) { @($HostsInCluster).Count } else { 0 }
        "VMCount"             = if ($VMsInCluster) { @($VMsInCluster).Count } else { 0 }
        "TotalCPUCores"       = if ($HostsInCluster) { ($HostsInCluster.NumCpu | Measure-Object -Sum).Sum } else { 0 }
        "TotalMemoryGB"       = if ($HostsInCluster) { [Math]::Round(($HostsInCluster.MemoryTotalGB | Measure-Object -Sum).Sum, 2) } else { 0 }
        "ConnectedDatastores" = $DSNames
        "DS_TotalCapacityGB"  = $TotalCapGB
        "DS_TotalUsedGB"      = [Math]::Round(($TotalCapGB - $TotalFreeGB), 2)
        "DS_TotalFreeGB"      = $TotalFreeGB
    }
}
if ($ClusterReport) { $ClusterReport | Export-Csv -Path "$ReportDir\Clusters.csv" -NoTypeInformation -Encoding UTF8 }

# ----------------------------------------------------
# 2. Extract Host Level Status & Hardware
# ----------------------------------------------------
# --- License keys: bulk-query all at once by passing $null, then cache in a hashtable (avoids per-host calls) ---
$LicenseLookup = @{}
try {
    $SI = Get-View ServiceInstance -ErrorAction Stop
    $LicManager = Get-View $SI.Content.LicenseManager -ErrorAction Stop
    if ($LicManager.LicenseAssignmentManager) {
        $LicAssignMgr = Get-View $LicManager.LicenseAssignmentManager -ErrorAction Stop
        # Passing $null returns all entity assignment info at once (verified method on vSphere 8)
        $AllAssignments = $LicAssignMgr.QueryAssignedLicenses($null)
        foreach ($A in $AllAssignments) {
            $LicenseLookup[$A.EntityId] = $A.AssignedLicense.LicenseKey
        }
        Write-Host "[INFO] License key bulk query complete ($($LicenseLookup.Count) entries)" -ForegroundColor Gray
    }
} catch {
    Write-Host "[WARN] Failed to retrieve license assignment info, treating as N/A: $($_.Exception.Message)" -ForegroundColor Yellow
}

Write-Host "[2/12] Extracting Host Performance & Hardware Info..." -ForegroundColor Cyan
$HostReport = @(); $HWReport = @()
$TotalHosts = @($VMHosts).Count
$Count = 0

# Host CPU Ready is collected separately via Get-Stat (based on a realtime 20-second sample)
# cpu.ready.summation unit: ms per 20-second interval -> %Ready = (Value / 20000) x 100
$HostReadyLookup = @{}
if (@($VMHosts).Count -gt 0) {
    try {
        $HostReadyStats = Get-Stat -Entity $VMHosts -Stat "cpu.ready.summation" -MaxSamples 1 -Realtime -WarningAction SilentlyContinue -ErrorAction SilentlyContinue
        foreach ($S in $HostReadyStats) {
            # Host-level cpu.ready is the sum across all pCPUs -> divide by NumCpu to get the average %Ready
            $NumCpu = ($VMHosts | Where-Object { $_.Id -eq $S.Entity.Id } | Select-Object -First 1).NumCpu
            if (-not $NumCpu -or $NumCpu -eq 0) { $NumCpu = 1 }
            $HostReadyLookup[$S.Entity.Id] = [Math]::Round(($S.Value / ($NumCpu * 20000)) * 100, 2)
        }
    } catch {}
}

foreach ($HostObj in $VMHosts) {
    $Count++
    Write-Progress -Activity "Processing Hosts" -Status "Host: $($HostObj.Name)" -PercentComplete (($Count / $TotalHosts) * 100)

    $CpuUsageMhz = $HostObj.CpuUsageMhz
    $CpuUsagePct = if ($HostObj.CpuTotalMhz -gt 0) { [Math]::Round(($HostObj.CpuUsageMhz / $HostObj.CpuTotalMhz * 100), 2) } else { 0 }
    $MemUsageGB  = [Math]::Round($HostObj.MemoryUsageGB, 2)
    $MemUsagePct = if ($HostObj.MemoryTotalGB -gt 0) { [Math]::Round(($HostObj.MemoryUsageGB / $HostObj.MemoryTotalGB * 100), 2) } else { 0 }
    $HostReadyPct = if ($HostReadyLookup.ContainsKey($HostObj.Id)) { $HostReadyLookup[$HostObj.Id] } else { "N/A" }

    $HostReport += [PSCustomObject]@{
        "HostName"       = (Get-SanitizedHostName -Name $HostObj.Name)
        "Cluster"        = $HostObj.Parent.Name
        "State"          = $HostObj.ConnectionState
        "ESXi_Version"   = $HostObj.Version
        "BuildNumber"    = $HostObj.Build
        "CPU_Usage_MHz"  = $CpuUsageMhz
        "CPU_Usage_Pct"  = "$CpuUsagePct %"
        "CPU_Ready_Pct"  = if ($HostReadyPct -ne "N/A") { "$HostReadyPct %" } else { "N/A" }
        "Mem_Usage_GB"   = $MemUsageGB
        "Mem_Usage_Pct"  = "$MemUsagePct %"
    }

    if ($HostObj.ConnectionState -eq "Connected") {
        $SysInfo = $HostObj.ExtensionData.Hardware.SystemInfo
        $CpuInfo = $HostObj.ExtensionData.Hardware.CpuInfo
        $BiosInfo = $HostObj.ExtensionData.Hardware.BiosInfo
        
        $ServiceTag = ($SysInfo.OtherIdentifyingInfo | Where-Object {$_.IdentifierType.Key -eq "ServiceTag"}).IdentifierValue
        if (-not $ServiceTag) { $ServiceTag = $SysInfo.Uuid }

        $HWReport += [PSCustomObject]@{
            "HostName"           = (Get-SanitizedHostName -Name $HostObj.Name)
            "Cluster"            = $HostObj.Parent.Name
            "Vendor"             = $SysInfo.Vendor
            "Model"              = $SysInfo.Model
            "ServiceTag_UUID"    = $ServiceTag
            "License_Key"        = if ($LicenseLookup.ContainsKey($HostObj.ExtensionData.MoRef.Value)) { $LicenseLookup[$HostObj.ExtensionData.MoRef.Value] } else { "N/A" }
            "CPU_Model"          = if ($HostObj.ExtensionData.Hardware.CpuPkg) { $HostObj.ExtensionData.Hardware.CpuPkg[0].Description } else { "N/A" }
            "CPU_Vendor"         = if ($HostObj.ExtensionData.Hardware.CpuPkg) { $HostObj.ExtensionData.Hardware.CpuPkg[0].Vendor } else { "N/A" }
            "CPU_Sockets"        = $CpuInfo.NumCpuPackages
            "CPU_CoresPerSocket" = if ($CpuInfo.NumCpuPackages -gt 0) { $CpuInfo.NumCpuCores / $CpuInfo.NumCpuPackages } else { 0 }
            "Total_Cores"        = $CpuInfo.NumCpuCores
            "CPU_Usage_MHz"      = $CpuUsageMhz
            "CPU_Usage_Pct"      = "$CpuUsagePct %"
            "CPU_Ready_Pct"      = if ($HostReadyPct -ne "N/A") { "$HostReadyPct %" } else { "N/A" }
            "Mem_Total_GB"       = [Math]::Round($HostObj.ExtensionData.Hardware.MemorySize / 1GB, 2)
            "Mem_Usage_GB"       = $MemUsageGB
            "Mem_Usage_Pct"      = "$MemUsagePct %"
            "Memory_GB"          = [Math]::Round($HostObj.ExtensionData.Hardware.MemorySize / 1GB, 2)
            "BIOS_Version"       = $BiosInfo.BiosVersion
            "ESXi_FullVersion"   = $HostObj.ExtensionData.Config.Product.FullName
        }
    }
}
if ($HostReport) { $HostReport | Export-Csv -Path "$ReportDir\Hosts_Perf.csv" -NoTypeInformation -Encoding UTF8 }
if ($HWReport) { $HWReport | Export-Csv -Path "$ReportDir\Hosts_Hardware.csv" -NoTypeInformation -Encoding UTF8 }

# ----------------------------------------------------
# 3. Extract VM Level Status & Disk (VMTools info added)
# ----------------------------------------------------
Write-Host "[3/12] Extracting VM Status & Disks (with VMTools Versions)..." -ForegroundColor Cyan
$VMReport = @(); $DiskReport = @()
$PoweredOnVMs = @($AllVMs | Where-Object {$_.PowerState -eq "PoweredOn"})

$Stats = $null
if ($PoweredOnVMs.Count -gt 0) {
    try {
        $Stats = Get-Stat -Entity $PoweredOnVMs -Stat "cpu.ready.summation","cpu.costop.summation" -MaxSamples 1 -Realtime -WarningAction SilentlyContinue -ErrorAction SilentlyContinue
    } catch {
        $Stats = $null
    }
}
$StatsLookup = if ($Stats) { $Stats | Group-Object -Property @{Expression={$_.Entity.Id}} -AsHashTable } else { @{} }

$TotalVMs = @($AllVMs).Count
$Count = 0

foreach ($VM in $AllVMs) {
    $Count++
    if ($Count % 10 -eq 0) { Write-Progress -Activity "Processing VMs" -Status "VM: $($VM.Name)" -PercentComplete (($Count / $TotalVMs) * 100) }

    $ReadyPct = 0; $CostopPct = 0; $CpuUsageMhz = 0; $MemActiveMB = 0; $MemConsumedMB = 0; $MemColdMB = 0

    if ($VM.PowerState -eq "PoweredOn") {
        $VMStats = $StatsLookup[$VM.Id]
        if ($VMStats) {
            $ReadyMs  = ($VMStats | Where-Object {$_.MetricId -eq "cpu.ready.summation"}  | Measure-Object Value -Sum).Sum
            $CostopMs = ($VMStats | Where-Object {$_.MetricId -eq "cpu.costop.summation"} | Measure-Object Value -Sum).Sum
            # Exact formula: (summation_ms / (NumCPU x 20000ms)) x 100
            # cpu.ready.summation is the sum across all vCPUs, so divide by NumCPU to get the average %Ready
            $NumCpuDivisor = if ($VM.NumCpu -gt 0) { $VM.NumCpu } else { 1 }
            $ReadyPct  = if ($ReadyMs)  { [Math]::Round(($ReadyMs  / ($NumCpuDivisor * 20000)) * 100, 2) } else { 0 }
            $CostopPct = if ($CostopMs) { [Math]::Round(($CostopMs / ($NumCpuDivisor * 20000)) * 100, 2) } else { 0 }
        }

        $QStats = $VM.ExtensionData.Summary.QuickStats
        $CpuUsageMhz = $QStats.OverallCpuUsage
        $MemActiveMB = $QStats.GuestMemoryUsage
        $MemConsumedMB = $QStats.HostMemoryUsage
        $MemColdMB = if (($MemConsumedMB - $MemActiveMB) -gt 0) { $MemConsumedMB - $MemActiveMB } else { 0 }
    }

    # Bind detailed VM Tools info
    $ToolsVersion = if ($VM.ExtensionData.Guest.ToolsVersion) { $VM.ExtensionData.Guest.ToolsVersion } else { "N/A" }
    $ToolsStatus  = if ($VM.ExtensionData.Guest.ToolsStatus) { $VM.ExtensionData.Guest.ToolsStatus } else { "N/A" }

    $VMReport += [PSCustomObject]@{
        "VMName"          = $VM.Name
        "PowerState"      = $VM.PowerState
        "Cluster"         = if ($VM.VMHost) { $VM.VMHost.Parent.Name } else { "N/A" }
        "ESXi_Host"       = if ($VM.VMHost) { Get-SanitizedHostName -Name $VM.VMHost.Name } else { "N/A" }
        "NumCPU"          = $VM.NumCpu
        "MemoryGB"        = $VM.MemoryGB
        "VMTools_Version" = $ToolsVersion  # Requirement: add VM Tools version
        "VMTools_Status"  = $ToolsStatus   # Requirement: add VM Tools status (e.g. toolsOk, toolsOld)
        "CPU_Ready_Pct"   = "$ReadyPct %"
        "CPU_Costop_Pct"  = "$CostopPct %"
        "CPU_Usage_MHz"   = $CpuUsageMhz
        "Mem_Active_MB"   = $MemActiveMB
        "Mem_Consumed_MB" = $MemConsumedMB
        "Mem_Cold_MB"     = $MemColdMB
        "ProvisionedGB"   = [Math]::Round($VM.ProvisionedSpaceGB, 2)
        "UsedSpaceGB"     = [Math]::Round($VM.UsedSpaceGB, 2)
    }

    foreach ($Device in $VM.ExtensionData.Config.Hardware.Device) {
        if ($Device -is [VMware.Vim.VirtualDisk]) {
            $IsRDM = $Device.Backing -is [VMware.Vim.VirtualDiskRawDiskMappingVer1BackingInfo]
            $IsShared = ($Device.Backing.Sharing -eq "sharingMultiWriter")
            $IsThick = ($Device.Backing -is [VMware.Vim.VirtualDiskFlatVer2BackingInfo] -and $Device.Backing.ThinProvisioned -eq $false)

            if ($IsRDM -or $IsShared -or $IsThick) {
                $CapacityGB = if ($Device.CapacityInBytes) { [Math]::Round($Device.CapacityInBytes / 1GB, 2) } else { [Math]::Round($Device.CapacityInKB / 1MB, 2) }
                $DiskType = if ($IsRDM) { "RDM" } elseif ($IsShared) { "Shared" } else { "Thick" }
                
                $DiskReport += [PSCustomObject]@{
                    "VMName"     = $VM.Name
                    "Cluster"    = $VM.VMHost.Parent.Name
                    "DiskName"   = $Device.DeviceInfo.Label
                    "DiskType"   = $DiskType
                    "CapacityGB" = $CapacityGB
                    "IsRDM"      = $IsRDM
                    "IsShared"   = $IsShared
                    "IsThick"    = $IsThick
                }
            }
        }
    }
}
Write-Progress -Activity "Processing VMs" -Completed
if ($VMReport) { $VMReport | Export-Csv -Path "$ReportDir\VMs_Status.csv" -NoTypeInformation -Encoding UTF8 }
if ($DiskReport) { $DiskReport | Export-Csv -Path "$ReportDir\Special_Disks(RDM_Shared_Thick).csv" -NoTypeInformation -Encoding UTF8 }

# ----------------------------------------------------
# 4. Extract Datastores Status
# ----------------------------------------------------
Write-Host "[4/12] Building Advanced Storage/LUN Mapping Lookup Tables..." -ForegroundColor Cyan
$LUNLookup = @{}
$ConnectedHosts = @($VMHosts | Where-Object {$_.ConnectionState -eq "Connected"})

foreach ($H in $ConnectedHosts) {
    $storageDevice = $H.ExtensionData.Config.StorageDevice
    if (-not $storageDevice) { continue }
    
    $KeyToLunId = @{}
    foreach ($adapter in $storageDevice.ScsiTopology.Adapter) {
        foreach ($target in $adapter.Target) {
            foreach ($tLun in $target.Lun) {
                $KeyToLunId[$tLun.ScsiLun] = $tLun.Lun
            }
        }
    }
    
    $PathInfo = @{}
    foreach ($mpLun in $storageDevice.MultipathInfo.Lun) {
        $PathInfo[$mpLun.Id] = @{
            Policy = $mpLun.Policy.Policy
            SATP   = $mpLun.StorageArrayTypePolicy
        }
    }
    
    foreach ($lun in $storageDevice.ScsiLun) {
        if ([string]::IsNullOrWhiteSpace($lun.CanonicalName)) { continue }
        if ($LUNLookup.ContainsKey($lun.CanonicalName)) { continue } 
        
        $lunId = if ($KeyToLunId.ContainsKey($lun.Key)) { $KeyToLunId[$lun.Key] } else { "N/A" }
        $mp = if ($PathInfo.ContainsKey($lun.CanonicalName)) { $PathInfo[$lun.CanonicalName] } else { $null }
        
        $LUNLookup[$lun.CanonicalName] = @{
            LunId           = $lunId
            Vendor          = $lun.Vendor
            Model           = $lun.Model
            MultipathPolicy = if ($mp) { $mp.Policy } else { "N/A" }
            SATP            = if ($mp) { $mp.SATP } else { "N/A" }
        }
    }
}

Write-Host "Fetching Bulk Datastore IOPS Performance Counters (Past 2 Hours)..." -ForegroundColor Cyan
$DSStats = $null
if (@($AllDatastores).Count -gt 0) {
    try {
        $DSStats = Get-Stat -Entity $AllDatastores -Stat "datastore.numberReadAveraged.average","datastore.numberWriteAveraged.average" -Start (Get-Date).AddHours(-2) -ErrorAction SilentlyContinue
    } catch {
        $DSStats = $null
    }
}

if ($DSStats) {
    $DSStatsLookup = $DSStats | Group-Object -Property @{Expression={$_.Entity.Id}} -AsHashTable -AsString
} else {
    $DSStatsLookup = @{}
}

Write-Host "Extracting All Datastores with Comprehensive Storage & IOPS Details..." -ForegroundColor Cyan
$DSReport = foreach ($DS in $AllDatastores) {
    $AssignedCluster = ($Clusters | Where-Object {$_.ExtensionData.Datastore -contains $DS.Id}).Name | Select-Object -First 1
    $CapGB   = [Math]::Round($DS.CapacityGB, 2)
    $FreeGB  = [Math]::Round($DS.FreeSpaceGB, 2)
    $UsedGB  = [Math]::Round(($CapGB - $FreeGB), 2)
    $FreePct = if ($CapGB -gt 0) { [Math]::Round(($FreeGB / $CapGB) * 100, 2) } else { 0 }

    $ReadIOPS = 0; $WriteIOPS = 0; $TotalIOPS = 0
    $MyStats = $DSStatsLookup[$DS.Id]
    if ($MyStats) {
        $ReadSamples = $MyStats | Where-Object { $_.MetricId -eq "datastore.numberReadAveraged.average" } | Measure-Object -Property Value -Average
        $WriteSamples = $MyStats | Where-Object { $_.MetricId -eq "datastore.numberWriteAveraged.average" } | Measure-Object -Property Value -Average
        
        if ($ReadSamples.Average) { $ReadIOPS = [Math]::Round($ReadSamples.Average, 2) }
        if ($WriteSamples.Average) { $WriteIOPS = [Math]::Round($WriteSamples.Average, 2) }
        $TotalIOPS = [Math]::Round(($ReadIOPS + $WriteIOPS), 2)
    }

    $VMFS_Version    = "N/A"; $BlockSizeMB     = "N/A"
    $RemoteHost      = "N/A"; $RemotePath      = "N/A"
    $CanonicalNames  = "N/A"; $LUN_IDs         = "N/A"
    $DiskVendors     = "N/A"; $DiskModels      = "N/A"
    $MultipathPolicy = "N/A"; $SATP            = "N/A"

    $dsInfo = $DS.ExtensionData.Info
    if ($DS.Type -match "VMFS") {
        if ($dsInfo.Vmfs) {
            $VMFS_Version = $dsInfo.Vmfs.Version
            $BlockSizeMB  = $dsInfo.Vmfs.BlockSizeMb
            
            $cNames = @(); $lIds = @(); $vendors = @(); $models = @(); $mpPolicies = @(); $satps = @()

            foreach ($extent in $dsInfo.Vmfs.Extent) {
                $cName = $extent.DiskName
                $cNames += $cName
                
                if ($LUNLookup.ContainsKey($cName)) {
                    $lunData = $LUNLookup[$cName]
                    $lIds += $lunData.LunId
                    if ($lunData.Vendor) { $vendors += $lunData.Vendor.Trim() }
                    if ($lunData.Model) { $models += $lunData.Model.Trim() }
                    $mpPolicies += $lunData.MultipathPolicy
                    $satps += $lunData.SATP
                }
            }

            $CanonicalNames  = ($cNames | Select-Object -Unique) -join ", "
            $LUN_IDs         = ($lIds | Select-Object -Unique) -join ", "
            $DiskVendors     = ($vendors | Select-Object -Unique) -join ", "
            $DiskModels      = ($models | Select-Object -Unique) -join ", "
            $MultipathPolicy = ($mpPolicies | Select-Object -Unique) -join ", "
            $SATP            = ($satps | Select-Object -Unique) -join ", "
        }
    }
    elseif ($DS.Type -match "NFS") {
        if ($dsInfo.Nas) {
            $RemoteHost = $dsInfo.Nas.RemoteHost
            $RemotePath = $dsInfo.Nas.RemotePath
        }
    }
    elseif ($DS.Type -match "vSAN") {
        $CanonicalNames  = "Internal vSAN Object Block"
        $MultipathPolicy = "vSAN Default Storage Policy Driven"
    }

    [PSCustomObject]@{
        "Cluster"             = if ($AssignedCluster) { $AssignedCluster } else { "N/A" }
        "DatastoreName"       = $DS.Name
        "Storage_Type"        = $DS.Type
        "Total_Cap_GB"        = $CapGB
        "Used_GB"             = $UsedGB
        "Free_GB"             = $FreeGB
        "Free_Percentage"     = "$FreePct %"
        "Read_IOPS_Avg"       = $ReadIOPS
        "Write_IOPS_Avg"      = $WriteIOPS
        "Total_IOPS_Avg"      = $TotalIOPS
        "LUN_IDs"             = $LUN_IDs
        "CanonicalNames"      = $CanonicalNames
        "Storage_Vendor"      = $DiskVendors
        "Storage_Model"       = $DiskModels
        "Multipath_Policy"    = $MultipathPolicy
        "SATP_Policy"         = $SATP
        "VMFS_Version"        = $VMFS_Version
        "BlockSizeMB"         = $BlockSizeMB
        "RemoteHost_NFS"      = $RemoteHost
        "RemotePath_NFS"      = $RemotePath
        "SIOC_Enabled"        = $DS.StorageIOControlEnabled
        "Thin_Provision_Supp" = $DS.ExtensionData.Capability.ThinProvisioningSupported
    }
}
if ($DSReport) { $DSReport | Export-Csv -Path "$ReportDir\Datastores.csv" -NoTypeInformation -Encoding UTF8 }

# ----------------------------------------------------
# 5. Extract Virtual Switches
# ----------------------------------------------------
Write-Host "[5/12] Extracting Virtual Switches & VDS Versions..." -ForegroundColor Cyan
$VswitchReport = @()

$VDSSwitches = Get-VDSwitch -ErrorAction SilentlyContinue
$VDSCache = @{}
foreach ($vds in $VDSSwitches) {
    $VDSCache[$vds.Name] = $vds.Version
}

foreach ($H in $VMHosts) {
    if ($H.ConnectionState -eq "Connected") {
        $Switches = Get-VirtualSwitch -VMHost $H -ErrorAction SilentlyContinue
        foreach ($vSwitch in $Switches) {
            
            $IsDVS = $vSwitch.GetType().Name -match "Distributed"
            $SwitchType = if ($IsDVS) { "DVS (VDS)" } else { "Standard" }
            $SwitchVersion = "N/A"
            if ($IsDVS -and $VDSCache.ContainsKey($vSwitch.Name)) {
                $SwitchVersion = $VDSCache[$vSwitch.Name]
            }

            $VswitchReport += [PSCustomObject]@{
                "Cluster"        = $H.Parent.Name
                "HostName"       = (Get-SanitizedHostName -Name $H.Name)
                "SwitchName"     = $vSwitch.Name
                "SwitchType"     = $SwitchType
                "Switch_Version" = $SwitchVersion
                "NumPorts"       = $vSwitch.NumPorts
                "MTU"            = $vSwitch.Mtu
            }
        }
    }
}
if ($VswitchReport) { $VswitchReport | Export-Csv -Path "$ReportDir\Virtual_Switches.csv" -NoTypeInformation -Encoding UTF8 }

# ----------------------------------------------------
# 6. Build ESXCLI Cache for Advanced Hardware Queries
# ----------------------------------------------------
Write-Host "[6/12] Building Advanced ESXCLI Cache for Driver/Firmware Versions (Takes time)..." -ForegroundColor Cyan
$EsxCliCache = @{}
$VibCache = @{}
$TotalEsx = @($ConnectedHosts).Count
$CountEsx = 0

foreach ($H in $ConnectedHosts) {
    $CountEsx++
    Write-Progress -Activity "Caching ESXCLI Data" -Status "Host: $($H.Name)" -PercentComplete (($CountEsx / $TotalEsx) * 100)
    
    $cli = Get-EsxCli -VMHost $H -V2 -ErrorAction SilentlyContinue
    $EsxCliCache[$H.Name] = $cli
    if ($cli) {
        try { $VibCache[$H.Name] = $cli.software.vib.list.Invoke() } catch {}
    }
}
Write-Progress -Activity "Caching ESXCLI Data" -Completed

# ----------------------------------------------------
# 7. Extract Physical NIC Details
# ----------------------------------------------------
Write-Host "[7/12] Extracting Physical NICs..." -ForegroundColor Cyan
$PnicReport = @()
foreach ($H in $ConnectedHosts) {
    $esxcli = $EsxCliCache[$H.Name]
    # Index nic.list results by name into a hashtable (enables O(1) lookups afterward)
    $NicListHash = @{}
    if ($esxcli) {
        try {
            $NicList = $esxcli.network.nic.list.Invoke()
            foreach ($n in $NicList) { $NicListHash[$n.Name] = $n }
        } catch {}
    }

    foreach ($P in $H.ExtensionData.Config.Network.Pnic) {
        $Model = "N/A"; $MTU = "N/A"; $Driver = "N/A"; $AutoNeg = "N/A"
        $DriverVersion = "N/A"; $FirmwareVersion = "N/A"

        $PciDev = $H.ExtensionData.Hardware.PciDevice | Where-Object { $_.Id -eq $P.Pci }
        if ($PciDev) { $Model = "$($PciDev.VendorName) $($PciDev.DeviceName)" }

        # O(1) lookup from the nic.list cache (avoids individual nic.get API calls)
        $nicCli = $NicListHash[$P.Device]
        if ($nicCli) {
            $MTU    = $nicCli.MTU
            $Driver = $nicCli.Driver
            if ([string]::IsNullOrWhiteSpace($Model) -or $Model -eq "N/A") { $Model = $nicCli.Description }
            # Use Speed and AutoNegotiate info when included in nic.list
            if ($null -ne $nicCli.AutoNegotiate) { $AutoNeg = $nicCli.AutoNegotiate }
        }

        # Extract driver version/firmware from ExtensionData (already loaded data) - no extra API calls
        $PnicInfo = $H.ExtensionData.Config.Network.Pnic | Where-Object { $_.Device -eq $P.Device }
        if ($PnicInfo) {
            if ($PnicInfo.Driver) { $Driver = $PnicInfo.Driver }
        }
        # No dedicated ExtensionData key for firmware version, so estimate it from the ESXCLI VIB cache by driver name (when possible)
        if ($DriverVersion -eq "N/A" -and $Driver -ne "N/A" -and $VibCache[$H.Name]) {
            $DriverVib = $VibCache[$H.Name] | Where-Object { $_.Name -like "*$Driver*" } | Select-Object -First 1
            if ($DriverVib) { $DriverVersion = $DriverVib.Version }
        }

        $PnicReport += [PSCustomObject]@{
            "Cluster"          = $H.Parent.Name
            "HostName"         = (Get-SanitizedHostName -Name $H.Name)
            "Device"           = $P.Device
            "Model"            = $Model
            "MAC"              = $P.Mac
            "MTU"              = $MTU
            "AutoNeg"          = $AutoNeg
            "Driver"           = $Driver
            "Driver_Version"   = $DriverVersion
            "Firmware_Version" = $FirmwareVersion
            "PCIe_ID"          = $P.Pci
        }
    }
}
if ($PnicReport) { $PnicReport | Export-Csv -Path "$ReportDir\Physical_NICs.csv" -NoTypeInformation -Encoding UTF8 }

# ----------------------------------------------------
# 8. Extract Physical HBAs (Fibre Channel)
# ----------------------------------------------------
Write-Host "[8/12] Extracting Physical HBAs (FibreChannel)..." -ForegroundColor Cyan
$HbaReport = foreach ($H in $ConnectedHosts) {
    $esxcli = $EsxCliCache[$H.Name]
    $vibs = $VibCache[$H.Name]
    $StorageSystem = Get-View $H.ExtensionData.ConfigManager.StorageSystem
    
    foreach ($Hba in $StorageSystem.StorageDeviceInfo.HostBusAdapter) {
        if ($Hba -is [VMware.Vim.HostFibreChannelHba]) {
            $DriverVersion = "N/A"
            $FirmwareVersion = if ($Hba.FirmwareVersion) { $Hba.FirmwareVersion } else { "N/A" }
            $DriverName = $Hba.DriverName
            
            if ($esxcli -and $DriverName) {
                try {
                    $modArgs = $esxcli.system.module.get.CreateArgs()
                    $modArgs.module = $DriverName
                    $modInfo = $esxcli.system.module.get.Invoke($modArgs)
                    if ($modInfo -and $modInfo.Version) { $DriverVersion = $modInfo.Version }
                } catch {}
                
                if ($DriverVersion -eq "N/A" -and $vibs) {
                    $safeName = $DriverName.Replace("_","-")
                    $matchedVib = $vibs | Where-Object { $_.Name -match $safeName } | Select-Object -First 1
                    if ($matchedVib) { $DriverVersion = $matchedVib.Version }
                }
            }

            $wwnString = "N/A"
            if ($Hba.PortWorldWideName) {
                $wwnString = ('{0:x16}' -f $Hba.PortWorldWideName) -replace '(..)(?!$)', '$1:'
            }

            [PSCustomObject]@{
                "Cluster"          = $H.Parent.Name
                "HostName"         = (Get-SanitizedHostName -Name $H.Name)
                "Device"           = $Hba.Device
                "Model"            = $Hba.Model
                "Driver"           = $DriverName
                "Driver_Version"   = $DriverVersion
                "Firmware_Version" = $FirmwareVersion
                "Speed_Gbps"       = if ($Hba.Speed) { $Hba.Speed / 1000 } else { "N/A" }
                "Status"           = $Hba.Status
                "WWN"              = $wwnString
            }
        }
    }
}
if ($HbaReport) { $HbaReport | Export-Csv -Path "$ReportDir\HBA_Cards.csv" -NoTypeInformation -Encoding UTF8 }

# ----------------------------------------------------
# 9. Extract RAID Controllers
# ----------------------------------------------------
Write-Host "[9/12] Extracting Physical RAID Controllers..." -ForegroundColor Cyan
$RaidReport = foreach ($H in $ConnectedHosts) {
    $esxcli = $EsxCliCache[$H.Name]
    $vibs = $VibCache[$H.Name]
    $StorageSystem = Get-View $H.ExtensionData.ConfigManager.StorageSystem
    
    foreach ($Hba in $StorageSystem.StorageDeviceInfo.HostBusAdapter) {
        if ($Hba -is [VMware.Vim.HostHostBusAdapter] -and $Hba -isnot [VMware.Vim.HostFibreChannelHba] -and $Hba -isnot [VMware.Vim.HostInternetScsiHba]) {
            
            $Model = $Hba.Model
            if ([string]::IsNullOrWhiteSpace($Model)) {
                $PciDev = $H.ExtensionData.Hardware.PciDevice | Where-Object { $_.Id -eq $Hba.Pci }
                if ($PciDev) { $Model = "$($PciDev.VendorName) $($PciDev.DeviceName)" }
            }

            $DriverName = if ($Hba.DriverName) { $Hba.DriverName } elseif ($Hba.Driver) { $Hba.Driver } else { "N/A" }
            $DriverVersion = "N/A"
            $FirmwareVersion = "N/A" 
            
            if ($Hba.FirmwareVersion) { $FirmwareVersion = $Hba.FirmwareVersion }

            if ($esxcli -and $DriverName -ne "N/A") {
                try {
                    $modArgs = $esxcli.system.module.get.CreateArgs()
                    $modArgs.module = $DriverName
                    $modInfo = $esxcli.system.module.get.Invoke($modArgs)
                    if ($modInfo -and $modInfo.Version) { $DriverVersion = $modInfo.Version }
                } catch {}
                
                if ($DriverVersion -eq "N/A" -and $vibs) {
                    $safeName = $DriverName.Replace("_","-")
                    $matchedVib = $vibs | Where-Object { $_.Name -match $safeName } | Select-Object -First 1
                    if ($matchedVib) { $DriverVersion = $matchedVib.Version }
                }
            }

            [PSCustomObject]@{
                "Cluster"          = $H.Parent.Name
                "HostName"         = (Get-SanitizedHostName -Name $H.Name)
                "Device"           = $Hba.Device
                "Model"            = if ($Model) { $Model } else { "N/A" }
                "Driver"           = $DriverName
                "Driver_Version"   = $DriverVersion
                "Firmware_Version" = $FirmwareVersion
                "PCIDeviceID"      = $Hba.Pci
            }
        }
    }
}
if ($RaidReport) { $RaidReport | Export-Csv -Path "$ReportDir\RAID_Controllers.csv" -NoTypeInformation -Encoding UTF8 }

# ----------------------------------------------------
# 10. ESX Memory Page Info (for NVMe Memory Tiering)
# ----------------------------------------------------
# Collects per-host real-time memory page breakdown:
#   Allocated / Consumed / Active / Cold (= Consumed - Active)
# Cold memory is the primary candidate for NVMe tiering offload.
# Uses Realtime Get-Stat counters first; falls back to QuickStats if unavailable.
Write-Host "[10/12] Collecting ESX Memory Page Info (NVMe Memory Tiering assessment)..." -ForegroundColor Cyan

$MemPageReport = @()
$TotalHostsMP  = @($VMHosts).Count
$CountMP       = 0

# Bulk fetch realtime mem stats for all hosts in one call (performance optimisation)
$MemStats = $null
if (@($VMHosts).Count -gt 0) {
    try {
        $MemStats = Get-Stat -Entity $VMHosts -Stat "mem.consumed.average","mem.active.average" `
                             -Realtime -MaxSamples 1 -ErrorAction SilentlyContinue -WarningAction SilentlyContinue
    } catch {}
}

$MemStatsLookup = @{}
if ($MemStats) {
    foreach ($S in $MemStats) {
        $id = $S.Entity.Id
        if (-not $MemStatsLookup.ContainsKey($id)) { $MemStatsLookup[$id] = @() }
        $MemStatsLookup[$id] += $S
    }
}

foreach ($H in $VMHosts) {
    $CountMP++
    Write-Progress -Activity "ESX Memory Page" -Status "Host: $($H.Name)" -PercentComplete (($CountMP / $TotalHostsMP) * 100)

    $ConsumedMB = 0; $ActiveMB = 0; $StatSource = "QuickStats"

    $HostStats = $MemStatsLookup[$H.Id]
    if ($HostStats) {
        $cKB = ($HostStats | Where-Object { $_.MetricId -eq "mem.consumed.average" } | Select-Object -First 1).Value
        $aKB = ($HostStats | Where-Object { $_.MetricId -eq "mem.active.average"   } | Select-Object -First 1).Value
        if ($cKB -gt 0) {
            $ConsumedMB = $cKB / 1024
            $ActiveMB   = if ($aKB) { $aKB / 1024 } else { 0 }
            $StatSource = "Realtime"
        }
    }

    # Fallback: QuickStats (already cached in ExtensionData)
    if ($StatSource -eq "QuickStats") {
        $QS = $H.ExtensionData.Summary.QuickStats
        $ConsumedMB = if ($QS.MemoryUsage)  { $QS.MemoryUsage  } else { 0 }
        $ActiveMB   = if ($QS.ActiveMemory) { $QS.ActiveMemory } else { 0 }
    }

    $AllocatedGB  = [Math]::Round($H.MemoryTotalGB, 2)
    $ConsumedGB   = [Math]::Round($ConsumedMB / 1024, 2)
    $ActiveGB     = [Math]::Round($ActiveMB   / 1024, 2)
    $ColdGB       = [Math]::Round([Math]::Max($ConsumedGB - $ActiveGB, 0), 2)
    $MemUsagePct  = if ($AllocatedGB -gt 0) { [Math]::Round(($ConsumedGB / $AllocatedGB) * 100, 2) } else { 0 }
    $ActivePct    = if ($ConsumedGB  -gt 0) { [Math]::Round(($ActiveGB   / $ConsumedGB)  * 100, 2) } else { 0 }
    $ColdPct      = if ($ConsumedGB  -gt 0) { [Math]::Round(($ColdGB     / $ConsumedGB)  * 100, 2) } else { 0 }

    # Determine NVMe tiering candidacy (candidate if Cold ratio >= 20%)
    $TieringCandidate = if ($ColdGB -ge 1 -and $ColdPct -ge 20) { "Yes" } else { "No" }

    $MemPageReport += [PSCustomObject]@{
        "Cluster"              = $H.Parent.Name
        "HostName"             = (Get-SanitizedHostName -Name $H.Name)
        "Allocated_Mem_GB"     = $AllocatedGB
        "Consumed_Mem_GB"      = $ConsumedGB
        "Mem_Usage_Pct"        = "$MemUsagePct %"
        "Active_Mem_GB"        = $ActiveGB
        "Active_Pct_of_Consumed" = "$ActivePct %"
        "Cold_Mem_GB"          = $ColdGB
        "Cold_Pct_of_Consumed" = "$ColdPct %"
        "NVMe_Tiering_Candidate" = $TieringCandidate
        "Stat_Source"          = $StatSource
    }
}
Write-Progress -Activity "ESX Memory Page" -Completed
if ($MemPageReport) { $MemPageReport | Export-Csv -Path "$ReportDir\ESX_Memory_Page.csv" -NoTypeInformation -Encoding UTF8 }

# ----------------------------------------------------
# 11 & 12. Finalize
# ----------------------------------------------------
Write-Host "[11/12] Disconnecting from vCenter..." -ForegroundColor Cyan
Disconnect-VIServer -Server $vCenter -Confirm:$false | Out-Null

Write-Host "===============================================================================" -ForegroundColor Green
Write-Host "[12/12] SUCCESS: All inventory reports have been saved." -ForegroundColor Green
Write-Host "Output Folder: $ReportDir" -ForegroundColor Yellow
Write-Host ""

if ($ShowStandaloneHint) {
    Write-Host "-------------------------------------------------------------------------------" -ForegroundColor Cyan
    Write-Host " Hardware Compatibility Check (HCL)" -ForegroundColor Cyan
    Write-Host "-------------------------------------------------------------------------------" -ForegroundColor Cyan
    Write-Host " Compatibility check is not performed by this menu option (Menu 2)." -ForegroundColor White
    Write-Host " To run the HCL compatibility check later, choose Menu 3 and enter this folder:" -ForegroundColor White
    Write-Host ""
    Write-Host "   $ReportDir" -ForegroundColor Yellow
    Write-Host ""
    Write-Host " Requirements:" -ForegroundColor DarkGray
    Write-Host "   - Place HCL CSV files (CPU_All_Models, IO_Devices, Systems_Servers, vSAN_IO_Controller)" -ForegroundColor DarkGray
    Write-Host "     in the 'hcl' subfolder next to this script" -ForegroundColor DarkGray
    Write-Host "   - ESXi 9.0 / 9.1 version-specific files: use filenames containing '9_0' or '9_1'" -ForegroundColor DarkGray
    Write-Host "-------------------------------------------------------------------------------" -ForegroundColor Cyan
}
Write-Host "===============================================================================" -ForegroundColor Green

return $ReportDir
}

# ============================================================
# FUNCTION 2: HCL compatibility check (formerly vcf9-hcl-check.ps1)
#   Return value: the created results folder path ($ReportDir) on success, $null on failure
# ============================================================
function Invoke-VCF9HCLCheck {
    param(
        [Parameter(Mandatory = $true)]
        [string]$InventoryPath,

        [Parameter(Mandatory = $false)]
        [string]$HCLPath
    )

# ============================================================
# vcf9-hcl-check.ps1  -  Standalone HCL Compatibility Checker
# ============================================================
# Usage example:
#   .\vcf9-hcl-check.ps1 -InventoryPath "C:\powercli\vSphere_Inventory_20260629_1627"
#
#   -InventoryPath : Output folder path created by the inventory collection step (required)
#                    The folder must contain Hosts_Hardware.csv, Physical_NICs.csv,
#                    HBA_Cards.csv, and RAID_Controllers.csv.
#   -HCLPath       : Folder path containing the 4 VMware HCL CSV files (optional)
#                    If not specified, the 'hcl' subfolder next to this script is used automatically.
#                    If the 'hcl' folder is missing, the check exits with an error message.
#   Warning: do not add a trailing backslash (\) to the path. (e.g. "C:\hcl" OK / "C:\hcl\" wrong)
#
# Recommended folder structure:
#   C:\powercli\
#    |-- vcf9-precheck-script-cs.ps1
#    |-- vcf9-hcl-check.ps1
#    `-- hcl\
#        |-- CPU_Series_9_0.csv
#        |-- CPU_Series_9_1.csv
#        |-- IO_Devices_9_0.csv
#        |-- IO_Devices_9_1.csv
#        |-- Systems_Servers_9_0.csv
#        |-- Systems_Servers_9_1.csv
#        |-- vSAN_IO_Controller_9_0.csv
#        `-- vSAN_IO_Controller_9_1.csv

Set-StrictMode -Off
$ErrorActionPreference = "Continue"

Write-Host "===============================================================================" -ForegroundColor Cyan
Write-Host "  VCF9 Standalone Hardware Compatibility Checker" -ForegroundColor Cyan
Write-Host "===============================================================================" -ForegroundColor Cyan

# -- Validate input folder --
$InventoryPath = $InventoryPath.Trim().TrimEnd('\', '/')
if (-not (Test-Path $InventoryPath)) {
    Write-Host "[ERROR] Inventory folder not found: '$InventoryPath'" -ForegroundColor Red
    return $null
}

$HWFile     = Join-Path $InventoryPath "Hosts_Hardware.csv"
$NICFile    = Join-Path $InventoryPath "Physical_NICs.csv"
$HBAFile    = Join-Path $InventoryPath "HBA_Cards.csv"
$RAIDFile   = Join-Path $InventoryPath "RAID_Controllers.csv"

if (-not (Test-Path $HWFile)) {
    Write-Host "[ERROR] Hosts_Hardware.csv not found in '$InventoryPath'." -ForegroundColor Red
    Write-Host "        Please specify the folder generated by vcf9-precheck-script-cs.ps1." -ForegroundColor Red
    return $null
}

Write-Host "[INFO] Loading inventory data from: $InventoryPath" -ForegroundColor Gray
$HWReport   = Import-Csv -Path $HWFile   -Encoding UTF8
$PnicReport = if (Test-Path $NICFile)  { Import-Csv -Path $NICFile  -Encoding UTF8 } else { @() }
$HbaReport  = if (Test-Path $HBAFile)  { Import-Csv -Path $HBAFile  -Encoding UTF8 } else { @() }
$RaidReport = if (Test-Path $RAIDFile) { Import-Csv -Path $RAIDFile -Encoding UTF8 } else { @() }

Write-Host "       Hosts: $(@($HWReport).Count)  |  NICs: $(@($PnicReport).Count)  |  HBAs: $(@($HbaReport).Count)  |  RAID Controllers: $(@($RaidReport).Count)" -ForegroundColor DarkGray

# Results folder: create and save a compatibility_YYYYMMDD_HHMM folder next to the script
$ScriptBase  = if ($PSScriptRoot) { $PSScriptRoot } else { Split-Path -Parent $MyInvocation.MyCommand.Definition }
$TimeStamp   = Get-Date -Format "yyyyMMdd_HHmm"
    $ReportDir   = Join-Path $OutputRoot "vcf_9_upgrade\compatibility_$TimeStamp"
if (-not (Test-Path $ReportDir)) { New-Item -ItemType Directory -Path $ReportDir | Out-Null }
Write-Host "[INFO] Results will be saved to: $ReportDir" -ForegroundColor Gray

$vCenter   = "N/A (standalone run)"

# -- Locate the HCL folder --
# Default: the 'hcl' subfolder next to the script (case-insensitive)
# If specified explicitly via -HCLPath, that path takes priority.
if (-not [string]::IsNullOrWhiteSpace($HCLPath)) {
    $HCLPath = $HCLPath.Trim().TrimEnd('\', '/')
}

if ([string]::IsNullOrWhiteSpace($HCLPath)) {
    $ScriptDir = if ($PSScriptRoot) { $PSScriptRoot } else { Split-Path -Parent $MyInvocation.MyCommand.Definition }
    # Allow any case variant of the 'hcl' folder name (hcl / HCL / Hcl)
    $HCLCandidate = Get-ChildItem -Path $ScriptDir -Directory -ErrorAction SilentlyContinue |
                    Where-Object { $_.Name -ieq 'hcl' } |
                    Select-Object -First 1
    if ($HCLCandidate) {
        $HCLPath = $HCLCandidate.FullName
        Write-Host "[INFO] HCL folder auto-detected: $HCLPath" -ForegroundColor Gray
    } else {
        Write-Host ""
        Write-Host "[ERROR] HCL data folder not found." -ForegroundColor Red
        Write-Host "        Expected location: $(Join-Path $ScriptDir 'hcl')" -ForegroundColor Red
        Write-Host "        Please create an 'hcl' subfolder next to this script and place the" -ForegroundColor Red
        Write-Host "        HCL CSV files inside it (CPU_Series, IO_Devices, Systems_Servers, vSAN_IO_Controller)," -ForegroundColor Red
        Write-Host "        or specify the path explicitly with -HCLPath `"C:\your\hcl\folder`"." -ForegroundColor Red
        return $null
    }
}

# ============================================================
# HCL function definitions (identical to the main script)
# ============================================================

function Format-ReleaseText {
    param([string]$Text)
    if ([string]::IsNullOrWhiteSpace($Text)) { return "N/A" }
    return ($Text -replace '[\r\n]+', ', ').Trim()
}

function Get-Tokens {
    param([string]$Text, [string[]]$NoiseWords = @())
    if ([string]::IsNullOrWhiteSpace($Text)) { return @() }
    $Base = @(($Text.ToLower() -split '[^a-z0-9]+') | Where-Object { $_.Length -ge 2 })
    if ($NoiseWords.Count -gt 0) { return @($Base | Where-Object { $_ -notin $NoiseWords }) }
    return $Base
}

function Get-TokenWeight {
    param([string]$Token)
    # Mixed alphanumeric token (model number): weight 5 / numeric only: 3 / regular word: 1
    if ($Token -match '^[0-9]+[a-z]+|^[a-z]+[0-9]') { return 5 }
    if ($Token -match '^[0-9]+$') { return 3 }
    return 1
}

# Noise words for IO devices (NIC/Storage)
$Script:IONoise = [System.Collections.Generic.HashSet[string]]@(
    'adapter','controller','device','card','module','port','interface',
    'gigabit','ethernet','fiber','fibre','channel','sata','pcie','pci',
    'nvme','sas','ssd','hdd','series','express','gen',
    'for','and','with','the','by','of'
)

# Noise words for server matching (removes vendor names/modifiers, focuses on model numbers)
$Script:ServerNoise = [System.Collections.Generic.HashSet[string]]@(
    'inc','llc','ltd','corp','corporation','technologies','technology',
    'systems','system','group','server','rack','blade','tower',
    'vsan','ready','node','generation','edition','enterprise',
    'the','and','with','for','of','by'
)

function Get-SimilarityScore {
    param([string]$Detected, [string]$HCLValue, [string[]]$NoiseWords = @())

    $hTokens = @(Get-Tokens -Text $HCLValue -NoiseWords $NoiseWords)
    if ($hTokens.Count -eq 0) { return 0 }
    $dTokens = @(Get-Tokens -Text $Detected  -NoiseWords $NoiseWords)

    $TotalWeight = 0; $MatchWeight = 0
    foreach ($t in $hTokens) {
        $w = Get-TokenWeight -Token $t
        $TotalWeight += $w
        if ($dTokens -contains $t) { $MatchWeight += $w }
    }
    if ($TotalWeight -eq 0) { return 0 }
    $Score = [Math]::Round(($MatchWeight / $TotalWeight) * 100, 0)

    # -- Numeric token conflict penalty --
    # Compare the HCL-side numeric token set against the detected-value numeric token set;
    # if the numbers differ (e.g. S1 vs S2, HBA330 vs HBA355), halve the score
    $hNum = @($hTokens | Where-Object { $_ -match '[0-9]' })
    $dNum = @($dTokens | Where-Object { $_ -match '[0-9]' })
    if ($hNum.Count -gt 0 -and $dNum.Count -gt 0) {
        $commonNum = @($hNum | Where-Object { $dNum -contains $_ })
        if ($commonNum.Count -eq 0) {
            # Numeric tokens exist on both sides but none overlap -> completely different model number
            $Score = [Math]::Min($Score, [Math]::Round($Score * 0.5, 0))
        }
    }
    return $Score
}

function Find-BestHCLMatch {
    param([array]$Table, [hashtable]$Index, [string]$Detected,
          [string[]]$Fields, [string[]]$NoiseWords = @())
    if (-not $Table -or @($Table).Count -eq 0) { return $null }

    # Detected-value tokens: after removing noise, prioritize tokens containing digits
    $AllDetTok = @(Get-Tokens -Text $Detected -NoiseWords $NoiseWords)
    $NumTok    = @($AllDetTok | Where-Object { $_ -match '[0-9]' } | Sort-Object Length -Descending)
    $WordTok   = @($AllDetTok | Where-Object { $_ -notmatch '[0-9]' } | Sort-Object Length -Descending)

    # Gather candidates from the index: intersect using multiple numeric tokens to narrow candidates precisely
    $Candidates = $null
    if ($Index -and $Index.Count -gt 0) {
        $CandSets = [System.Collections.Generic.List[object]]::new()
        foreach ($t in ($NumTok + $WordTok)) {
            if ($Index.ContainsKey($t)) {
                $CandSets.Add($Index[$t])
                if ($CandSets.Count -ge 3) { break }  # Collect up to 3 keys max
            }
        }
        if ($CandSets.Count -gt 0) {
            # Within the first candidate set, prioritize rows that also appear under other keys
            $First = [System.Collections.Generic.HashSet[object]]::new($CandSets[0])
            if ($CandSets.Count -gt 1) {
                $Intersect = [System.Collections.Generic.List[object]]::new()
                foreach ($Row in $First) {
                    $InAll = $true
                    for ($i = 1; $i -lt $CandSets.Count; $i++) {
                        if (-not $CandSets[$i].Contains($Row)) { $InAll = $false; break }
                    }
                    if ($InAll) { $Intersect.Add($Row) }
                }
                $Candidates = if ($Intersect.Count -gt 0) { $Intersect } else { $First }
            } else {
                $Candidates = $First
            }
        }
    }

    # Search candidates for the highest similarity
    $Best = $null; $BestScore = -1
    $SearchSet = if ($Candidates) { $Candidates } else { $Table }
    foreach ($Row in $SearchSet) {
        $HCLText = ($Fields | ForEach-Object { $Row.$_ }) -join ' '
        $Score = Get-SimilarityScore -Detected $Detected -HCLValue $HCLText -NoiseWords $NoiseWords
        if ($Score -gt $BestScore) { $BestScore = $Score; $Best = $Row }
    }

    # If not found in the candidate set, fall back to the full table (covers index misses)
    if ($Candidates -and ($null -eq $Best -or $BestScore -lt $MatchThreshold)) {
        foreach ($Row in $Table) {
            $HCLText = ($Fields | ForEach-Object { $Row.$_ }) -join ' '
            $Score = Get-SimilarityScore -Detected $Detected -HCLValue $HCLText -NoiseWords $NoiseWords
            if ($Score -gt $BestScore) { $BestScore = $Score; $Best = $Row }
        }
    }

    if ($null -eq $Best) { return $null }
    return [PSCustomObject]@{ Row = $Best; Score = $BestScore }
}

function Build-HCLIndex {
    param([array]$Table, [string[]]$Fields, [string[]]$NoiseWords = @())
    $Index = @{}
    if (-not $Table -or @($Table).Count -eq 0) { return $Index }
    foreach ($Row in $Table) {
        $HCLText = ($Fields | ForEach-Object { $Row.$_ }) -join ' '
        $Tokens  = @(Get-Tokens -Text $HCLText -NoiseWords $NoiseWords)
        foreach ($t in $Tokens) {
            if (-not $Index.ContainsKey($t)) { $Index[$t] = [System.Collections.Generic.List[object]]::new() }
            [void]$Index[$t].Add($Row)
        }
    }
    return $Index
}

function Normalize-CpuText {
    param([string]$Text)
    if ([string]::IsNullOrWhiteSpace($Text)) { return "" }
    # Remove frequency patterns: "@ 2.70GHz", "2.70GHz", "@ 2700MHz", etc.
    $Text = $Text -replace '@\s*[\d\.]+\s*[GM][Hh][Zz]', ''
    $Text = $Text -replace '[\d\.]+\s*[GM][Hh][Zz]', ''
    # Remove CPU/core count patterns: "64-Core", "96-Core", "32C/64T", etc.
    $Text = $Text -replace '\d+[-\s]?[Cc]ore[s]?', ''
    $Text = $Text -replace '\d+[Cc]/\d+[Tt]', ''
    # Normalize
    return ($Text.ToLower() -replace '[^a-z0-9]', ' ' -replace '\s+', ' ').Trim()
}

function Get-CpuTokens {
    param([string]$NormalizedText)
    # Remove noise words (words that don't help identify the CPU model)
    $NoiseWords = [System.Collections.Generic.HashSet[string]]@(
        'cpu','processor','core','cores','ghz','mhz','r','v','s',
        'genuineintel','authenticamd','at','the','gen'
    )
    return @($NormalizedText.Split(' ') | Where-Object {
        $_.Length -ge 2 -and -not $NoiseWords.Contains($_)
    })
}

function Find-CpuModelMatch {
    param([string]$DetectedModel, [array]$CpuTable, [hashtable]$CpuIndex)
    if (-not $CpuTable -or @($CpuTable).Count -eq 0 -or [string]::IsNullOrWhiteSpace($DetectedModel)) { return $null }

    $DetNorm   = Normalize-CpuText -Text $DetectedModel
    $DetTokens = Get-CpuTokens -NormalizedText $DetNorm

    if ($DetTokens.Count -eq 0) { return $null }

    # Narrow index candidates: prioritize tokens containing digits (model numbers), sorted by descending length
    $PriorityTokens = @($DetTokens | Where-Object { $_ -match '[0-9]' } | Sort-Object Length -Descending)
    $OtherTokens    = @($DetTokens | Where-Object { $_ -notmatch '[0-9]' } | Sort-Object Length -Descending)
    $LookupOrder    = $PriorityTokens + $OtherTokens

    $Candidates = $null
    $IndexKey   = $null
    foreach ($t in $LookupOrder) {
        if ($CpuIndex -and $CpuIndex.ContainsKey($t)) {
            $Candidates = $CpuIndex[$t]
            $IndexKey = $t
            break
        }
    }
    if (-not $Candidates) { $Candidates = $CpuTable }

    # Pass 1: direct match on the Model column (all valid tokens of the HCL Model are contained in the detected value)
    foreach ($Row in $Candidates) {
        $ModelNorm   = Normalize-CpuText -Text $Row.Model
        $ModelTokens = Get-CpuTokens -NormalizedText $ModelNorm
        if ($ModelTokens.Count -eq 0) { continue }
        $AllMatch = $true
        foreach ($t in $ModelTokens) {
            # Word-boundary matching: prevents "30" from incorrectly matching as part of "6330"
            if ($DetNorm -notmatch "(?<![a-z0-9])$([regex]::Escape($t))(?![a-z0-9])") {
                $AllMatch = $false; break
            }
        }
        if ($AllMatch) { return [PSCustomObject]@{ Row = $Row; MatchType = "ModelDirect" } }
    }

    # Pass 2: retry against the full table without the index (covers cases missed by candidate narrowing)
    if ($Candidates.Count -lt $CpuTable.Count) {
        foreach ($Row in $CpuTable) {
            $ModelNorm   = Normalize-CpuText -Text $Row.Model
            $ModelTokens = Get-CpuTokens -NormalizedText $ModelNorm
            if ($ModelTokens.Count -eq 0) { continue }
            $AllMatch = $true
            foreach ($t in $ModelTokens) {
                if ($DetNorm -notmatch "(?<![a-z0-9])$([regex]::Escape($t))(?![a-z0-9])") {
                    $AllMatch = $false; break
                }
            }
            if ($AllMatch) { return [PSCustomObject]@{ Row = $Row; MatchType = "ModelFullScan" } }
        }
    }

    # Pass 3: SKU number + suffix fallback (6548N, 7763, etc.)
    $SkuRaw = [regex]::Matches($DetectedModel, '[0-9]{4,5}[A-Za-z]*') | ForEach-Object { $_.Value }
    foreach ($Sku in $SkuRaw) {
        $SkuKey = $Sku.ToLower()
        $SkuCandidates = if ($CpuIndex -and $CpuIndex.ContainsKey($SkuKey)) { $CpuIndex[$SkuKey] } else { $CpuTable }
        foreach ($Row in $SkuCandidates) {
            if ($Row.Model -match "(?i)(?<![a-z0-9])$([regex]::Escape($Sku))(?![a-z0-9])") {
                return [PSCustomObject]@{ Row = $Row; MatchType = "SKUMatch" }
            }
        }
        # Compare digits-only extraction (handles differing suffixes: 6548N vs 6548)
        $SkuNum = $Sku -replace '[^0-9]', ''
        if ($SkuNum.Length -ge 4) {
            $NumKey = $SkuNum
            $NumCandidates = if ($CpuIndex -and $CpuIndex.ContainsKey($NumKey)) { $CpuIndex[$NumKey] } else { $CpuTable }
            foreach ($Row in $NumCandidates) {
                if (($Row.Model -replace '[^0-9]', '') -eq $SkuNum) {
                    return [PSCustomObject]@{ Row = $Row; MatchType = "SKUNumeric" }
                }
            }
        }
    }

    # Pass 4: series-level fallback (if the model isn't found but enough detected tokens match the series text, return the series)
    $BestSeriesRow = $null; $BestSeriesScore = 0
    foreach ($Row in $CpuTable) {
        $SeriesNorm   = Normalize-CpuText -Text $Row.Series
        $SeriesTokens = Get-CpuTokens -NormalizedText $SeriesNorm
        $MatchCount   = ($SeriesTokens | Where-Object {
            $DetNorm -match "(?<![a-z0-9])$([regex]::Escape($_))(?![a-z0-9])"
        }).Count
        if ($MatchCount -gt $BestSeriesScore) {
            $BestSeriesScore = $MatchCount; $BestSeriesRow = $Row
        }
    }
    if ($BestSeriesRow -and $BestSeriesScore -ge 2) {
        return [PSCustomObject]@{ Row = $BestSeriesRow; MatchType = "SeriesFallback(score=$BestSeriesScore)" }
    }

    return $null
}

function Get-VersionedCpuMatch {
    param([array]$CpuTable, [hashtable]$CpuIndex, [string]$DetectedModel, [string]$Vendor)
    $Match = Find-CpuModelMatch -DetectedModel $DetectedModel -CpuTable $CpuTable -CpuIndex $CpuIndex
    $Status = if ($Match) { "OK" } else { "MISMATCH" }
    return [PSCustomObject]@{ Status90 = $Status; Status91 = $Status; Match90 = $Match; Match91 = $Match; Best = $Match }
}

function Get-VersionedMatch {
    param([array]$Table90, [array]$Table91, [hashtable]$Index90, [hashtable]$Index91,
          [string]$Detected, [string[]]$Fields, [int]$Threshold, [string[]]$NoiseWords = @())
    $Match90 = Find-BestHCLMatch -Table $Table90 -Index $Index90 -Detected $Detected -Fields $Fields -NoiseWords $NoiseWords
    $Match91 = Find-BestHCLMatch -Table $Table91 -Index $Index91 -Detected $Detected -Fields $Fields -NoiseWords $NoiseWords
    $Status90 = if ($Match90 -and $Match90.Score -ge $Threshold) { "OK" } else { "MISMATCH" }
    $Status91 = if ($Match91 -and $Match91.Score -ge $Threshold) { "OK" } else { "MISMATCH" }
    $Best = $null
    if ($Match90 -and $Match91) { $Best = if ($Match90.Score -ge $Match91.Score) { $Match90 } else { $Match91 } }
    elseif ($Match90) { $Best = $Match90 } elseif ($Match91) { $Best = $Match91 }
    return [PSCustomObject]@{ Status90 = $Status90; Status91 = $Status91; Match90 = $Match90; Match91 = $Match91; Best = $Best }
}


function Get-HCLFileType {
    param([string]$FilePath)
    try { $HeaderLine = Get-Content -Path $FilePath -TotalCount 1 -Encoding UTF8 -ErrorAction Stop } catch { return $null }
    if ([string]::IsNullOrWhiteSpace($HeaderLine)) { return $null }
    # CPU is handled separately via the CPU_All_Models file, so it is not recognized here
    if ($HeaderLine -match 'Partner Name')                                 { return "Server" }
    if ($HeaderLine -match 'Device Type')                                  { return "IODevice" }
    if ($HeaderLine -match 'Brand Name' -and $HeaderLine -match 'Feature') { return "vSAN" }
    return $null
}

function Get-HCLFileVersion {
    param([string]$FileName)
    $Has90 = $FileName -match '9[_\.]0'
    $Has91 = $FileName -match '9[_\.]1'
    if ($Has90 -and -not $Has91) { return "9.0" }
    if ($Has91 -and -not $Has90) { return "9.1" }
    return "Both"
}

function Import-HCLData {
    param([string]$Path)
    $Result = [PSCustomObject]@{
        IODevice90 = @(); IODevice91 = @()
        Server90 = @(); Server91 = @(); vSAN90 = @(); vSAN91 = @(); FoundFiles = @()
    }
    if (-not (Test-Path $Path)) { return $Result }
    $CsvFiles = Get-ChildItem -Path $Path -Filter "*.csv" -File -ErrorAction SilentlyContinue
    foreach ($File in $CsvFiles) {
        $Type = Get-HCLFileType -FilePath $File.FullName
        if (-not $Type) { continue }
        try { $Data = Import-Csv -Path $File.FullName -Encoding UTF8 -ErrorAction Stop } catch { continue }
        $Version = Get-HCLFileVersion -FileName $File.Name
        switch ($Type) {
            "IODevice" { if ($Version -ne "9.1") { $Result.IODevice90 += $Data }; if ($Version -ne "9.0") { $Result.IODevice91 += $Data } }
            "Server"   { if ($Version -ne "9.1") { $Result.Server90   += $Data }; if ($Version -ne "9.0") { $Result.Server91   += $Data } }
            "vSAN"     { if ($Version -ne "9.1") { $Result.vSAN90     += $Data }; if ($Version -ne "9.0") { $Result.vSAN91     += $Data } }
        }
        $Result.FoundFiles += "$($File.Name) -> $Type / ESXi $Version"
    }
    return $Result
}

# -- Load HCL data --
Write-Host "[1/3] Loading HCL data from: $HCLPath" -ForegroundColor Cyan

# Locate the CPU All Models file: filename containing "CPU_All_Models", or a headerless 6-column AMD/Intel CSV
$CpuAllModelsFile = Get-ChildItem -Path $HCLPath -Filter "*.csv" -File -ErrorAction SilentlyContinue |
                    Where-Object { $_.Name -match '(?i)CPU_All_Models' } |
                    Select-Object -First 1
if (-not $CpuAllModelsFile) {
    $CpuAllModelsFile = Get-ChildItem -Path $HCLPath -Filter "*.csv" -File -ErrorAction SilentlyContinue |
                        Where-Object {
                            try {
                                $first = Get-Content $_.FullName -TotalCount 1 -Encoding UTF8 -ErrorAction Stop
                                $first -match '^(AMD|Intel),' -and ($first -split ',').Count -ge 5
                            } catch { $false }
                        } | Select-Object -First 1
}
$CpuAllModels = $null
$CpuIndex     = $null
if ($CpuAllModelsFile) {
    try {
        $CpuAllModels = Import-Csv -Path $CpuAllModelsFile.FullName -Encoding UTF8 `
                        -Header "Vendor","Series","Model","Cores","Freq","TDP" -ErrorAction Stop
        Write-Host "[INFO] CPU All Models: $($CpuAllModelsFile.Name) ($(@($CpuAllModels).Count) models, applied to both 9.0/9.1)" -ForegroundColor Gray
    } catch {
        Write-Host "[WARN] Failed to load CPU All Models: $($_.Exception.Message)" -ForegroundColor Yellow
    }
} else {
    Write-Host "[WARN] CPU_All_Models CSV not found in '$HCLPath'. Skipping the CPU compatibility check." -ForegroundColor Yellow
}

$HCLData     = Import-HCLData -Path $HCLPath
$IOHCL90     = $HCLData.IODevice90; $IOHCL91     = $HCLData.IODevice91
$SystemHCL90 = $HCLData.Server90;   $SystemHCL91 = $HCLData.Server91
$VsanHCL90   = $HCLData.vSAN90;     $VsanHCL91   = $HCLData.vSAN91

$HasAnyHCLData = ($null -ne $CpuAllModels) -or
                 (@($IOHCL90 + $IOHCL91 + $SystemHCL90 + $SystemHCL91 + $VsanHCL90 + $VsanHCL91).Count -gt 0)
if (-not $HasAnyHCLData) {
    Write-Host ""
    Write-Host "[INFO] Hardware compatibility check was skipped: no HCL data files were found at '$HCLPath'." -ForegroundColor Cyan
    Write-Host "       Required files in the hcl folder:" -ForegroundColor Cyan
    Write-Host "         CPU  : CPU_All_Models_*.csv (headerless 6 columns: Vendor, Series, Model, Cores, Freq, TDP)" -ForegroundColor Cyan
    Write-Host "         IO / Server / vSAN: VMware HCL CSV export files" -ForegroundColor Cyan
    return $null
}

if ($HCLData.FoundFiles.Count -gt 0) {
    Write-Host "[INFO] Recognized HCL files:" -ForegroundColor Gray
    $HCLData.FoundFiles | ForEach-Object { Write-Host "       - $_" -ForegroundColor DarkGray }
}

Write-Host "[2/3] Building HCL index..." -ForegroundColor Cyan
$MatchThreshold = 50
$ServerFields  = @('Partner Name', 'Model'); $IOFields = @('Brand Name', 'Model')
$Idx_Server90  = Build-HCLIndex -Table $SystemHCL90 -Fields $ServerFields -NoiseWords $Script:ServerNoise
$Idx_Server91  = Build-HCLIndex -Table $SystemHCL91 -Fields $ServerFields -NoiseWords $Script:ServerNoise
$Idx_Net90     = Build-HCLIndex -Table @($IOHCL90 | Where-Object { $_.'Device Type' -match 'Network' })    -Fields $IOFields -NoiseWords $Script:IONoise
$Idx_Net91     = Build-HCLIndex -Table @($IOHCL91 | Where-Object { $_.'Device Type' -match 'Network' })    -Fields $IOFields -NoiseWords $Script:IONoise
$Idx_Storage90 = Build-HCLIndex -Table @($IOHCL90 | Where-Object { $_.'Device Type' -notmatch 'Network' }) -Fields $IOFields -NoiseWords $Script:IONoise
$Idx_Storage91 = Build-HCLIndex -Table @($IOHCL91 | Where-Object { $_.'Device Type' -notmatch 'Network' }) -Fields $IOFields -NoiseWords $Script:IONoise
# CPU All Models index: build a reverse index based on tokens in the Model column (including numeric model codes)
$CpuIndex      = Build-HCLIndex -Table $CpuAllModels -Fields @('Model')
Write-Host "       Index build complete. (CPU models: $(@($CpuAllModels).Count), index keys: $($CpuIndex.Count))" -ForegroundColor DarkGray

# -- Compatibility check --
Write-Host "[3/3] Running compatibility checks..." -ForegroundColor Cyan

$IOHCL_Network_90 = @($IOHCL90 | Where-Object { $_.'Device Type' -match 'Network' })
$IOHCL_Network_91 = @($IOHCL91 | Where-Object { $_.'Device Type' -match 'Network' })
$IOHCL_Storage_90 = @($IOHCL90 | Where-Object { $_.'Device Type' -notmatch 'Network' })
$IOHCL_Storage_91 = @($IOHCL91 | Where-Object { $_.'Device Type' -notmatch 'Network' })

# --------------------------------------------------------------
#  Pre-batch matching by unique model
#  Even if the same model appears across multiple hosts, the HCL comparison runs only once per model.
#  Cache the result in a hashtable; subsequent loops only look it up.
# --------------------------------------------------------------

# Server: unique key based on the Vendor|Model combination
$ServerMatchCache = @{}
$UniqueServerKeys = $HWReport | ForEach-Object { "$($_.Vendor)|$($_.Model)" } | Select-Object -Unique
            Write-Host "       Server  : $(@($HWReport).Count) rows -> $($UniqueServerKeys.Count) unique models" -ForegroundColor DarkGray
foreach ($Key in $UniqueServerKeys) {
    $Parts   = $Key -split '\|', 2
    $Vendor  = $Parts[0]; $Model = $Parts[1]
    $Detected = "$Vendor $Model"
    $ServerMatchCache[$Key] = Get-VersionedMatch `
        -Table90 $SystemHCL90 -Table91 $SystemHCL91 `
        -Index90 $Idx_Server90 -Index91 $Idx_Server91 `
        -Detected $Detected -Fields $ServerFields `
        -Threshold $MatchThreshold -NoiseWords $Script:ServerNoise
}

# CPU: unique key based on CPU_Model
$CpuMatchCache = @{}
$UniqueCpuModels = $HWReport | ForEach-Object { $_.CPU_Model } | Where-Object { -not [string]::IsNullOrWhiteSpace($_) } | Select-Object -Unique
        Write-Host "       CPU     : $(@($HWReport).Count) rows -> $($UniqueCpuModels.Count) unique models" -ForegroundColor DarkGray
foreach ($CpuModel in $UniqueCpuModels) {
    $SampleRow = $HWReport | Where-Object { $_.CPU_Model -eq $CpuModel } | Select-Object -First 1
    $CpuMatchCache[$CpuModel] = Get-VersionedCpuMatch `
        -CpuTable $CpuAllModels -CpuIndex $CpuIndex `
        -DetectedModel $CpuModel -Vendor $SampleRow.CPU_Vendor
}

# NIC: unique key based on Model (excluding USB)
$NicMatchCache = @{}
$UniqueNicModels = $PnicReport | Where-Object { $_.Model -notmatch '(?i)\bUSB\b' } `
                               | ForEach-Object { $_.Model } | Select-Object -Unique
            Write-Host "       NIC     : $(@($PnicReport).Count) rows -> $($UniqueNicModels.Count) unique models (USB excluded)" -ForegroundColor DarkGray
foreach ($NicModel in $UniqueNicModels) {
    $NicMatchCache[$NicModel] = Get-VersionedMatch `
        -Table90 $IOHCL_Network_90 -Table91 $IOHCL_Network_91 `
        -Index90 $Idx_Net90 -Index91 $Idx_Net91 `
        -Detected $NicModel -Fields $IOFields `
        -Threshold $MatchThreshold -NoiseWords $Script:IONoise
}

# Storage Controller: unique key based on Model (excluding USB)
$StorageMatchCache = @{}
$AllStorageRows    = @($HbaReport) + @($RaidReport)
$UniqueStorageModels = $AllStorageRows | Where-Object { $_.Model -notmatch '(?i)\bUSB\b' } `
                                       | ForEach-Object { $_.Model } | Select-Object -Unique
            Write-Host "       Storage : $(@($AllStorageRows).Count) rows -> $($UniqueStorageModels.Count) unique models (USB excluded)" -ForegroundColor DarkGray
foreach ($StModel in $UniqueStorageModels) {
    $StorageMatchCache[$StModel] = [PSCustomObject]@{
        Ctrl = Get-VersionedMatch `
            -Table90 $IOHCL_Storage_90 -Table91 $IOHCL_Storage_91 `
            -Index90 $Idx_Storage90 -Index91 $Idx_Storage91 `
            -Detected $StModel -Fields $IOFields `
            -Threshold $MatchThreshold -NoiseWords $Script:IONoise
    }
}
Write-Host "       Pre-batch matching complete." -ForegroundColor DarkGray

$ComplianceReport = @()
$SkippedReport    = @()   # Items excluded from the check (e.g. USB) - excluded from both aggregation and HTML display

# --- Server & CPU (cache lookup) ---
foreach ($HW in $HWReport) {
    $DetectedServerText = "$($HW.Vendor) $($HW.Model)"
    $ServerCacheKey     = "$($HW.Vendor)|$($HW.Model)"
    $ServerMatch        = $ServerMatchCache[$ServerCacheKey]

    $ServerScore   = if ($ServerMatch.Best) { $ServerMatch.Best.Score } else { 0 }
    $ServerHCLText = if ($ServerMatch.Best) { "$($ServerMatch.Best.Row.'Partner Name') $($ServerMatch.Best.Row.Model)" } else { "N/A" }
    $ServerNote    = if ($ServerMatch.Best) { "VCF Supported: $($ServerMatch.Best.Row.'VCF Supported. Confirm w/Vendor')  /  Releases: $(Format-ReleaseText $ServerMatch.Best.Row.'Supported Releases')" } else { "No matching entry in HCL Systems/Servers" }
    if ($ServerMatch.Status90 -eq "MISMATCH" -or $ServerMatch.Status91 -eq "MISMATCH") { $ServerNote = "[Best candidate, manual verification required] " + $ServerNote }

    $Sockets           = if ($HW.CPU_Sockets -and [int]$HW.CPU_Sockets -gt 0) { [int]$HW.CPU_Sockets } else { 0 }
    $CoresPerSocket    = if ($HW.CPU_CoresPerSocket -and [int]$HW.CPU_CoresPerSocket -gt 0) { [int]$HW.CPU_CoresPerSocket } else { 0 }
    $EffCoresPerSocket = if ($CoresPerSocket -lt 16) { 16 } else { $CoresPerSocket }
    $EffTotalCores     = $Sockets * $EffCoresPerSocket
    $CoreNote          = if ($CoresPerSocket -lt 16 -and $Sockets -gt 0) { "(actual ${CoresPerSocket} cores/socket -> raised to minimum 16)" } else { "" }

    $ComplianceReport += [PSCustomObject]@{
        "Cluster"               = if ($HW.Cluster) { $HW.Cluster } else { "N/A" }
        "HostName"              = $HW.HostName
        "Category"              = "Server"
        "Detected"              = $DetectedServerText
        "CPU_Sockets"           = $Sockets
        "CoresPerSocket_Actual" = $CoresPerSocket
        "CoresPerSocket_Eff"    = $EffCoresPerSocket
        "Total_Cores_Eff"       = $EffTotalCores
        "Core_Note"             = $CoreNote
        "HCL_Match"             = $ServerHCLText
        "Match_Score(%)"        = $ServerScore
        "ESXi_9.0"              = $ServerMatch.Status90
        "ESXi_9.1"              = $ServerMatch.Status91
        "Note"                  = $ServerNote
    }

    $DetectedCpuText = "$($HW.CPU_Vendor) / $($HW.CPU_Model)"
    $CpuMatch        = $CpuMatchCache[$HW.CPU_Model]
    $CpuScore   = if ($CpuMatch.Best) { 100 } else { 0 }
    $CpuHCLText = if ($CpuMatch.Best) { "$($CpuMatch.Best.Row.Series) / $($CpuMatch.Best.Row.Model)" } else { "N/A" }
    $CpuNote    = if ($CpuMatch.Best) {
        $MatchTypeLabel = switch ($CpuMatch.Best.MatchType) {
            "ModelDirect" { "Direct model name match" }
            "SKUFallback" { "SKU code match" }
            "SKUNumeric"  { "Numeric SKU match" }
            default       { "Match" }
        }
        "$MatchTypeLabel : '$($HW.CPU_Model)' -> '$($CpuMatch.Best.Row.Model)' in '$($CpuMatch.Best.Row.Series)'"
    } elseif ($null -ne $CpuAllModels) {
        "No matching model found in CPU_All_Models list (manual verification required)"
    } else { "CPU_All_Models data not available" }

    $ComplianceReport += [PSCustomObject]@{
        "Cluster"        = if ($HW.Cluster) { $HW.Cluster } else { "N/A" }
        "HostName"       = $HW.HostName
        "Category"       = "CPU"
        "Detected"       = $DetectedCpuText
        "HCL_Match"      = $CpuHCLText
        "Match_Score(%)" = $CpuScore
        "ESXi_9.0"       = $CpuMatch.Status90
        "ESXi_9.1"       = $CpuMatch.Status91
        "Note"           = $CpuNote
    }
}

# --- NIC ---
foreach ($Nic in $PnicReport) {
    $DetectedNicText = "$($Nic.Device) / $($Nic.Model)"

    # USB devices are excluded from the HCL compatibility check (e.g. internal USB NICs like iDRAC Virtual NIC)
    # USB devices are excluded from HCL compatibility check (e.g., iDRAC Virtual NIC USB)
    if ($Nic.Model -match '(?i)\bUSB\b') {
        $SkippedReport += [PSCustomObject]@{
            "Cluster"  = if ($Nic.Cluster) { $Nic.Cluster } else { "N/A" }
            "HostName" = $Nic.HostName
            "Category" = "NIC"
            "Detected" = $DetectedNicText
            "Reason"   = "USB device excluded from HCL compatibility check"
        }
        continue
    }

    $NicMatch    = $NicMatchCache[$Nic.Model]
    $NicScore    = if ($NicMatch.Best) { $NicMatch.Best.Score } else { 0 }
    $NicHCLText  = if ($NicMatch.Best) { "$($NicMatch.Best.Row.'Brand Name') $($NicMatch.Best.Row.Model)" } else { "N/A" }
    $NicNote     = if ($NicMatch.Best) { "Releases: $(Format-ReleaseText $NicMatch.Best.Row.'Supported Releases')" } else { "No matching entry in IO Devices (Network)" }
    if ($NicMatch.Status90 -eq "MISMATCH" -or $NicMatch.Status91 -eq "MISMATCH") { $NicNote = "[Best candidate, manual verification required] " + $NicNote }

    $ComplianceReport += [PSCustomObject]@{
        "Cluster"        = if ($Nic.Cluster) { $Nic.Cluster } else { "N/A" }
        "HostName"       = $Nic.HostName
        "Category"       = "NIC"
        "Detected"       = $DetectedNicText
        "HCL_Match"      = $NicHCLText
        "Match_Score(%)" = $NicScore
        "ESXi_9.0"       = $NicMatch.Status90
        "ESXi_9.1"       = $NicMatch.Status91
        "Note"           = $NicNote
    }
}

# --- Storage Controller (HBA + RAID) ---
foreach ($Ctrl in (@($HbaReport) + @($RaidReport))) {
    $DetectedCtrlText = "$($Ctrl.Device) / $($Ctrl.Model)"

    # USB-based storage devices are excluded from the HCL check
    # USB-based storage devices are excluded from HCL compatibility check
    if ($Ctrl.Model -match '(?i)\bUSB\b') {
        $SkippedReport += [PSCustomObject]@{
            "Cluster"  = if ($Ctrl.Cluster) { $Ctrl.Cluster } else { "N/A" }
            "HostName" = $Ctrl.HostName
            "Category" = "Storage_Controller"
            "Detected" = $DetectedCtrlText
            "Reason"   = "USB device excluded from HCL compatibility check"
        }
        continue
    }

    $Cached    = $StorageMatchCache[$Ctrl.Model]
    $CtrlMatch = $Cached.Ctrl

    $CtrlScore   = if ($CtrlMatch.Best) { $CtrlMatch.Best.Score } else { 0 }
    $CtrlHCLText = if ($CtrlMatch.Best) { "$($CtrlMatch.Best.Row.'Brand Name') $($CtrlMatch.Best.Row.Model)" } else { "N/A" }
    $CtrlNote    = if ($CtrlMatch.Best) { "ESXi Releases: $(Format-ReleaseText $CtrlMatch.Best.Row.'Supported Releases')" } else { "No matching entry in IO Devices" }
    if ($CtrlMatch.Status90 -eq "MISMATCH" -or $CtrlMatch.Status91 -eq "MISMATCH") { $CtrlNote = "[Best candidate, manual verification required] " + $CtrlNote }

    $ComplianceReport += [PSCustomObject]@{
        "Cluster"        = if ($Ctrl.Cluster) { $Ctrl.Cluster } else { "N/A" }
        "HostName"       = $Ctrl.HostName
        "Category"       = "Storage_Controller"
        "Detected"       = $DetectedCtrlText
        "HCL_Match"      = $CtrlHCLText
        "Match_Score(%)" = $CtrlScore
        "ESXi_9.0"       = $CtrlMatch.Status90
        "ESXi_9.1"       = $CtrlMatch.Status91
        "Note"           = $CtrlNote
    }
}

# -- CSV output --
if ($ComplianceReport) {
    # SKIP items are excluded from ComplianceReport and saved separately by category
    $ComplianceReport | Where-Object { $_.'ESXi_9.0' -ne "SKIP" } | Group-Object Category | ForEach-Object {
        $SafeName = $_.Name -replace '[^a-zA-Z0-9]', ''
        $_.Group | Export-Csv -Path "$ReportDir\Compatibility_$SafeName.csv" -NoTypeInformation -Encoding UTF8
    }
}
# Items excluded from the check (e.g. USB) are recorded in a separate file (for reference, not included in aggregation)
if ($SkippedReport) {
    $SkippedReport | Export-Csv -Path "$ReportDir\Compatibility_Skipped_USB.csv" -NoTypeInformation -Encoding UTF8
    Write-Host "[INFO] USB excluded items saved to: Compatibility_Skipped_USB.csv ($(@($SkippedReport).Count) items)" -ForegroundColor DarkGray
}

# -- HTML report --
# HTML helper functions
function ConvertTo-SafeHtml { param([string]$Text); if ($null -eq $Text) { return "" }; return [System.Net.WebUtility]::HtmlEncode($Text) }
function Get-Badge { param([string]$Status); if ($Status -eq "OK") { return '<span class="badge ok">OK</span>' } else { return '<span class="badge miss">MISMATCH</span>' } }
function Get-RowClass { param([string]$s90,[string]$s91); if ($s90 -eq "OK" -and $s91 -eq "OK") { "tr-ok" } elseif ($s90 -eq "MISMATCH" -and $s91 -eq "MISMATCH") { "tr-miss" } else { "tr-partial" } }
function Get-SafeFileName { param([string]$Text); if ([string]::IsNullOrWhiteSpace($Text)) { return "unknown" }; return ($Text -replace '[^a-zA-Z0-9_\-]', '_') }
function New-VersionCardPair {
    param([int]$FullCount,[int]$FullCores,[int]$MisCount,[int]$MisCores,[string]$Version)
    return @"
<div class="ver-group">
  <div class="ver-label">ESXi $Version</div>
  <div class="card-row">
    <div class="kpi-card green"><div class="kpi-icon">&#10003;</div><div class="kpi-body"><div class="kpi-val">$FullCount</div><div class="kpi-sub">100% Match Hosts</div><div class="kpi-detail">$FullCores physical cores total</div></div></div>
    <div class="kpi-card red"><div class="kpi-icon">&#10007;</div><div class="kpi-body"><div class="kpi-val">$MisCount</div><div class="kpi-sub">Mismatch Hosts</div><div class="kpi-detail">$MisCores physical cores total</div></div></div>
  </div>
</div>
"@
}

function New-CategoryTableHtml {
    param([array]$Rows, [string]$Category = "")
    $sb = New-Object System.Text.StringBuilder
    [void]$sb.AppendLine('<div class="table-wrap"><table>')
    if ($Category -eq "Server") {
        [void]$sb.AppendLine('<thead><tr><th>Host</th><th>Detected</th><th>Sockets</th><th>Cores/Socket(Actual)</th><th>Cores/Socket(Eff)</th><th>Total Cores(Eff)</th><th>Core Note</th><th>HCL Best Match</th><th>Score</th><th>ESXi 9.0</th><th>ESXi 9.1</th><th>Note</th></tr></thead><tbody>')
        foreach ($R in $Rows) {
            $rc = Get-RowClass -s90 $R.'ESXi_9.0' -s91 $R.'ESXi_9.1'
            $cn = if (-not [string]::IsNullOrWhiteSpace($R.Core_Note)) { "<span style=`"color:#b45309;font-weight:600`">$(ConvertTo-SafeHtml $R.Core_Note)</span>" } else { "" }
            [void]$sb.AppendLine("<tr class=`"$rc`"><td>$(ConvertTo-SafeHtml $R.HostName)</td><td>$(ConvertTo-SafeHtml $R.Detected)</td><td>$($R.CPU_Sockets)</td><td>$($R.CoresPerSocket_Actual)</td><td>$($R.CoresPerSocket_Eff)</td><td><strong>$($R.Total_Cores_Eff)</strong></td><td class=`"note`">$cn</td><td>$(ConvertTo-SafeHtml $R.HCL_Match)</td><td>$($R.'Match_Score(%)')%</td><td>$(Get-Badge $R.'ESXi_9.0')</td><td>$(Get-Badge $R.'ESXi_9.1')</td><td class=`"note`">$(ConvertTo-SafeHtml $R.Note)</td></tr>")
        }
    } else {
        [void]$sb.AppendLine('<thead><tr><th>Host</th><th>Detected</th><th>HCL Best Match</th><th>Score</th><th>ESXi 9.0</th><th>ESXi 9.1</th><th>Note</th></tr></thead><tbody>')
        foreach ($R in $Rows) {
            $rc = Get-RowClass -s90 $R.'ESXi_9.0' -s91 $R.'ESXi_9.1'
            [void]$sb.AppendLine("<tr class=`"$rc`"><td>$(ConvertTo-SafeHtml $R.HostName)</td><td>$(ConvertTo-SafeHtml $R.Detected)</td><td>$(ConvertTo-SafeHtml $R.HCL_Match)</td><td>$($R.'Match_Score(%)')%</td><td>$(Get-Badge $R.'ESXi_9.0')</td><td>$(Get-Badge $R.'ESXi_9.1')</td><td class=`"note`">$(ConvertTo-SafeHtml $R.Note)</td></tr>")
        }
    }
    [void]$sb.AppendLine('</tbody></table></div>')
    return $sb.ToString()
}

$SharedCss = @"
:root{--bg:#f0f2f5;--surface:#fff;--border:#e2e8f0;--primary:#1e3a5f;--primary-lt:#e8edf5;--green:#16a34a;--green-lt:#dcfce7;--green-dk:#14532d;--red:#dc2626;--red-lt:#fee2e2;--red-dk:#7f1d1d;--yellow:#d97706;--yellow-lt:#fef3c7;--gray:#64748b;--gray-lt:#f8fafc;--radius:12px;--shadow:0 1px 3px rgba(0,0,0,.08),0 4px 16px rgba(0,0,0,.06);font-family:'Malgun Gothic','Apple SD Gothic Neo',Arial,sans-serif}
*{box-sizing:border-box;margin:0;padding:0}body{background:var(--bg);color:#1e293b;padding:28px 32px;font-size:14px;line-height:1.6}
.page-header{margin-bottom:32px;display:flex;align-items:center;justify-content:space-between;flex-wrap:wrap;gap:10px}.page-header h1{font-size:22px;font-weight:700;color:var(--primary);margin-bottom:4px}.page-meta{color:var(--gray);font-size:12px}
.back-link{font-size:13px;font-weight:600;color:var(--primary);text-decoration:none;background:var(--primary-lt);padding:7px 14px;border-radius:8px;white-space:nowrap}.back-link:hover{background:var(--primary);color:#fff}
.section-title{font-size:15px;font-weight:700;color:var(--primary);margin:28px 0 14px;display:flex;align-items:center;gap:8px}.section-title::before{content:'';display:inline-block;width:4px;height:18px;background:var(--primary);border-radius:2px}
.version-block{display:flex;gap:24px;margin-bottom:12px;width:100%}.ver-group{display:flex;flex-direction:column;gap:8px;flex:1;min-width:0}.ver-label{font-size:12px;font-weight:700;color:var(--primary);letter-spacing:.05em;text-transform:uppercase;padding:4px 0}.card-row{display:flex;gap:12px;width:100%}
.kpi-card{display:flex;align-items:center;gap:16px;background:var(--surface);border-radius:var(--radius);padding:20px 24px;box-shadow:var(--shadow);flex:1;min-width:0;border-left:5px solid}.kpi-card.green{border-color:var(--green)}.kpi-card.red{border-color:var(--red)}.kpi-icon{font-size:22px;font-weight:900}.kpi-card.green .kpi-icon{color:var(--green)}.kpi-card.red .kpi-icon{color:var(--red)}.kpi-val{font-size:30px;font-weight:700;line-height:1}.kpi-sub{font-size:12px;font-weight:600;color:var(--gray);margin-top:4px}.kpi-detail{font-size:17px;font-weight:700;color:#1e293b;margin-top:4px}
.cluster-section{background:var(--surface);border-radius:var(--radius);box-shadow:var(--shadow);padding:22px 24px;margin-bottom:24px}.cluster-header{display:flex;align-items:center;justify-content:space-between;margin-bottom:16px;flex-wrap:wrap;gap:8px}.cluster-name{font-size:15px;font-weight:700;color:var(--primary)}.cluster-name a{color:var(--primary);text-decoration:none;border-bottom:1.5px dashed var(--primary)}.cluster-name a:hover{color:#0f2440;border-bottom-style:solid}.cluster-cards{display:flex;gap:16px;width:100%;margin-bottom:18px}.cluster-ver-group{display:flex;flex-direction:column;gap:6px;flex:1;min-width:0}.cluster-ver-label{font-size:11px;font-weight:700;color:var(--gray);letter-spacing:.05em}.cluster-card-row{display:flex;gap:8px;width:100%}.c-card{display:flex;align-items:center;gap:10px;border-radius:10px;padding:12px 16px;flex:1;min-width:0;border:1.5px solid}.c-card.green{background:var(--green-lt);border-color:var(--green)}.c-card.red{background:var(--red-lt);border-color:var(--red)}.c-icon{font-size:17px;font-weight:900}.c-card.green .c-icon{color:var(--green)}.c-card.red .c-icon{color:var(--red)}.c-val{font-size:22px;font-weight:700;line-height:1}.c-sub{font-size:11px;color:var(--gray);margin-top:2px}.c-detail{font-size:15px;font-weight:700;color:#1e293b;margin-top:2px}
.summary-table-wrap{overflow-x:auto;margin-bottom:16px}.summary-table-wrap table{width:100%;border-collapse:collapse;font-size:13px}.summary-table-wrap th{background:var(--primary);color:#fff;padding:8px 12px;font-weight:600;text-align:left}.summary-table-wrap td{padding:7px 12px;border-bottom:1px solid var(--border)}.summary-table-wrap tr:last-child td{font-weight:700;background:var(--gray-lt)}.summary-table-wrap tr:hover td{background:var(--primary-lt)}
.cat-section{margin-bottom:20px}.cat-title{font-size:13px;font-weight:700;color:var(--primary);margin-bottom:8px;padding:6px 12px;background:var(--primary-lt);border-radius:6px;display:inline-block}
.table-wrap{overflow-x:auto}.table-wrap table{width:100%;border-collapse:collapse;font-size:12px}.table-wrap th{background:var(--primary);color:#fff;padding:7px 10px;font-weight:600;white-space:nowrap;text-align:left}.table-wrap td{padding:6px 10px;border-bottom:1px solid var(--border);vertical-align:top}.table-wrap .note{max-width:340px;font-size:11px;color:var(--gray)}
.tr-ok:hover td{background:#f0fdf4}.tr-miss td{background:#fff5f5}.tr-miss:hover td{background:#fee2e2}.tr-partial td{background:#fffbeb}.tr-partial:hover td{background:#fef3c7}
.badge{display:inline-flex;align-items:center;padding:2px 9px;border-radius:20px;font-size:11px;font-weight:700;letter-spacing:.02em}.badge.ok{background:var(--green-lt);color:var(--green-dk)}.badge.miss{background:var(--red-lt);color:var(--red-dk)}
.tag-total{display:inline-block;padding:2px 8px;border-radius:4px;background:var(--primary-lt);color:var(--primary);font-size:11px;font-weight:600}
.nav-bar{display:flex;align-items:center;gap:8px}.nav-select{font-size:13px;font-weight:600;color:var(--primary);background:var(--surface);border:1.5px solid var(--primary-lt);border-radius:8px;padding:7px 10px;cursor:pointer}
.home-link{font-size:13px;font-weight:600;color:var(--primary);text-decoration:none;background:var(--primary-lt);padding:7px 14px;border-radius:8px;white-space:nowrap}.home-link:hover{background:var(--primary);color:#fff}
"@

# Aggregation
$HWLookup = @{}; foreach ($hw in $HWReport) { $HWLookup[$hw.HostName] = $hw }
$HostSummary = $ComplianceReport | Group-Object HostName | ForEach-Object {
    $Rows = $_.Group; $hw = $HWLookup[$_.Name]
    $Cores = if ($hw -and $hw.Total_Cores) { [int]$hw.Total_Cores } else { 0 }
    [PSCustomObject]@{ HostName = $_.Name; Cluster = ($Rows | Select-Object -First 1).Cluster; Cores = $Cores
        AllOk90 = (@($Rows | Where-Object { $_.'ESXi_9.0' -ne "OK" -and $_.'ESXi_9.0' -ne "SKIP" }).Count -eq 0)
        AllOk91 = (@($Rows | Where-Object { $_.'ESXi_9.1' -ne "OK" -and $_.'ESXi_9.1' -ne "SKIP" }).Count -eq 0) }
}
$Full90Hosts = @($HostSummary | Where-Object { $_.AllOk90 }); $Mis90Hosts = @($HostSummary | Where-Object { -not $_.AllOk90 })
$Full91Hosts = @($HostSummary | Where-Object { $_.AllOk91 }); $Mis91Hosts = @($HostSummary | Where-Object { -not $_.AllOk91 })
$Full90Cores = ($Full90Hosts | Measure-Object -Property Cores -Sum).Sum; if ($null -eq $Full90Cores) { $Full90Cores = 0 }
$Mis90Cores  = ($Mis90Hosts  | Measure-Object -Property Cores -Sum).Sum; if ($null -eq $Mis90Cores)  { $Mis90Cores  = 0 }
$Full91Cores = ($Full91Hosts | Measure-Object -Property Cores -Sum).Sum; if ($null -eq $Full91Cores) { $Full91Cores = 0 }
$Mis91Cores  = ($Mis91Hosts  | Measure-Object -Property Cores -Sum).Sum; if ($null -eq $Mis91Cores)  { $Mis91Cores  = 0 }

$ClusterHostSummary = $HostSummary | Group-Object Cluster | ForEach-Object {
    $cH = $_.Group
    $cf90 = @($cH | Where-Object { $_.AllOk90 }); $cm90 = @($cH | Where-Object { -not $_.AllOk90 })
    $cf91 = @($cH | Where-Object { $_.AllOk91 }); $cm91 = @($cH | Where-Object { -not $_.AllOk91 })
    $cf90c = ($cf90 | Measure-Object -Property Cores -Sum).Sum; if ($null -eq $cf90c) { $cf90c = 0 }
    $cm90c = ($cm90 | Measure-Object -Property Cores -Sum).Sum; if ($null -eq $cm90c) { $cm90c = 0 }
    $cf91c = ($cf91 | Measure-Object -Property Cores -Sum).Sum; if ($null -eq $cf91c) { $cf91c = 0 }
    $cm91c = ($cm91 | Measure-Object -Property Cores -Sum).Sum; if ($null -eq $cm91c) { $cm91c = 0 }
    [PSCustomObject]@{ Cluster = $_.Name; TotalHosts = $cH.Count
        Full90Count = $cf90.Count; Full90Cores = $cf90c; Mis90Count = $cm90.Count; Mis90Cores = $cm90c; Mis90HostNames = ($cm90 | ForEach-Object { $_.HostName }) -join ', '
        Full91Count = $cf91.Count; Full91Cores = $cf91c; Mis91Count = $cm91.Count; Mis91Cores = $cm91c; Mis91HostNames = ($cm91 | ForEach-Object { $_.HostName }) -join ', ' }
} | Sort-Object Cluster

$CategorySummary = $ComplianceReport | Where-Object { $_.'ESXi_9.0' -ne "SKIP" } | Group-Object Category | ForEach-Object {
    $Ok90 = @($_.Group | Where-Object { $_.'ESXi_9.0' -eq "OK" }).Count
    $Ok91 = @($_.Group | Where-Object { $_.'ESXi_9.1' -eq "OK" }).Count
    [PSCustomObject]@{ Category = $_.Name; Total = $_.Count; Ok90 = $Ok90; Mis90 = $_.Count - $Ok90; Rate90 = if ($_.Count -gt 0) { [Math]::Round(($Ok90/$_.Count)*100,0) } else { 0 }; Ok91 = $Ok91; Mis91 = $_.Count - $Ok91; Rate91 = if ($_.Count -gt 0) { [Math]::Round(($Ok91/$_.Count)*100,0) } else { 0 } }
}
$ActiveReport  = @($ComplianceReport | Where-Object { $_.'ESXi_9.0' -ne "SKIP" })
$TotalAll = $ActiveReport.Count
$TotalOk90 = @($ActiveReport | Where-Object { $_.'ESXi_9.0' -eq "OK" }).Count; $TotalMis90 = $TotalAll - $TotalOk90
$TotalOk91 = @($ActiveReport | Where-Object { $_.'ESXi_9.1' -eq "OK" }).Count; $TotalMis91 = $TotalAll - $TotalOk91
$TotalRate90 = if ($TotalAll -gt 0) { [Math]::Round(($TotalOk90/$TotalAll)*100,0) } else { 0 }
$TotalRate91 = if ($TotalAll -gt 0) { [Math]::Round(($TotalOk91/$TotalAll)*100,0) } else { 0 }

# Main HTML report
$ClusterNavOptions = New-Object System.Text.StringBuilder
[void]$ClusterNavOptions.Append('<option value="">Jump to cluster...</option>')
foreach ($CHS in $ClusterHostSummary) {
    $NavFileName = "Compatibility_Cluster_$(Get-SafeFileName $CHS.Cluster).html"
    [void]$ClusterNavOptions.Append("<option value=`"$NavFileName`">$(ConvertTo-SafeHtml $CHS.Cluster)</option>")
}

$Html = New-Object System.Text.StringBuilder
[void]$Html.AppendLine(@"
<!DOCTYPE html><html lang="ko"><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>VCF9 HCL Compatibility Check</title><style>$SharedCss</style></head><body>
<div class="page-header"><div><h1>VCF9 Hardware Compatibility Check</h1><div class="page-meta">Generated: $(Get-Date -Format "yyyy-MM-dd HH:mm:ss") &nbsp;|&nbsp; Source: $(ConvertTo-SafeHtml $InventoryPath) &nbsp;|&nbsp; Threshold: ${MatchThreshold}% = OK &nbsp;|&nbsp; ESXi 9.0 / 9.1 judged independently</div></div>
<div class="nav-bar"><select class="nav-select" onchange="if(this.value){window.location.href=this.value;}">$($ClusterNavOptions.ToString())</select></div>
</div>
<div class="section-title">Overall Host Compatibility</div>
<div class="version-block">$(New-VersionCardPair -FullCount $Full90Hosts.Count -FullCores $Full90Cores -MisCount $Mis90Hosts.Count -MisCores $Mis90Cores -Version "9.0")$(New-VersionCardPair -FullCount $Full91Hosts.Count -FullCores $Full91Cores -MisCount $Mis91Hosts.Count -MisCores $Mis91Cores -Version "9.1")</div>
<div class="section-title">Per-Cluster Host Compatibility</div>
"@)

foreach ($CHS in $ClusterHostSummary) {
    $ClusterFileName = "Compatibility_Cluster_$(Get-SafeFileName $CHS.Cluster).html"
    [void]$Html.AppendLine('<div class="cluster-section">')
    [void]$Html.AppendLine("<div class=`"cluster-header`"><span class=`"cluster-name`">Cluster: <a href=`"$ClusterFileName`">$(ConvertTo-SafeHtml $CHS.Cluster)</a></span><span class=`"tag-total`">$($CHS.TotalHosts) hosts</span></div>")
    [void]$Html.AppendLine('<div class="cluster-cards">')
    foreach ($ver in @(@{V="9.0";fc=$CHS.Full90Count;fco=$CHS.Full90Cores;mc=$CHS.Mis90Count;mco=$CHS.Mis90Cores;mh=$CHS.Mis90HostNames},@{V="9.1";fc=$CHS.Full91Count;fco=$CHS.Full91Cores;mc=$CHS.Mis91Count;mco=$CHS.Mis91Cores;mh=$CHS.Mis91HostNames})) {
        $misLabel    = if ([string]::IsNullOrWhiteSpace($ver.mh)) { "None" } else { $ver.mh }
        $misHostHtml = if ($ver.mc -gt 0) {
            '<div style="font-size:11px;color:#7f1d1d;margin-top:4px">Mismatch hosts: ' + (ConvertTo-SafeHtml $misLabel) + '</div>'
        } else { "" }
        [void]$Html.AppendLine(
            "<div class=`"cluster-ver-group`">" +
            "<div class=`"cluster-ver-label`">ESXi $($ver.V)</div>" +
            "<div class=`"cluster-card-row`">" +
            "<div class=`"c-card green`"><div class=`"c-icon`">&#10003;</div><div><div class=`"c-val`">$($ver.fc)</div><div class=`"c-sub`">100% Match</div><div class=`"c-detail`">$($ver.fco) cores</div></div></div>" +
            "<div class=`"c-card red`"><div class=`"c-icon`">&#10007;</div><div><div class=`"c-val`">$($ver.mc)</div><div class=`"c-sub`">Mismatch</div><div class=`"c-detail`">$($ver.mco) cores</div></div></div>" +
            "</div>$misHostHtml</div>"
        )
    }
    [void]$Html.AppendLine('</div></div>')
}

[void]$Html.AppendLine('<div class="section-title">Part Summary</div><div class="summary-table-wrap"><table>')
[void]$Html.AppendLine('<thead><tr><th>Part</th><th>Total</th><th>9.0 OK</th><th>9.0 MISS</th><th>9.0 Rate</th><th>9.1 OK</th><th>9.1 MISS</th><th>9.1 Rate</th></tr></thead><tbody>')
foreach ($S in $CategorySummary) { [void]$Html.AppendLine("<tr><td>$(ConvertTo-SafeHtml $S.Category)</td><td>$($S.Total)</td><td>$($S.Ok90)</td><td>$($S.Mis90)</td><td>$($S.Rate90)%</td><td>$($S.Ok91)</td><td>$($S.Mis91)</td><td>$($S.Rate91)%</td></tr>") }
[void]$Html.AppendLine("<tr><td>Total</td><td>$TotalAll</td><td>$TotalOk90</td><td>$TotalMis90</td><td>$TotalRate90%</td><td>$TotalOk91</td><td>$TotalMis91</td><td>$TotalRate91%</td></tr></tbody></table></div>")
[void]$Html.AppendLine('</body></html>')

$Html.ToString() | Out-File -FilePath "$ReportDir\Compatibility_Report.html" -Encoding UTF8

# Per-cluster detail HTML
$CategoryOrder = @("Server","CPU","NIC","Storage_Controller")
$ClusterGroups = $ComplianceReport | Group-Object Cluster | Sort-Object Name
$ClusterFileList = @()

foreach ($CG in $ClusterGroups) {
    $ClusterFileName = "Compatibility_Cluster_$(Get-SafeFileName $CG.Name).html"
    $ClusterFileList += $ClusterFileName
    $CluNavOptions = New-Object System.Text.StringBuilder
    [void]$CluNavOptions.Append('<option value="">Jump to cluster...</option>')
    foreach ($CHS2 in $ClusterHostSummary) {
        $NavFileName2 = "Compatibility_Cluster_$(Get-SafeFileName $CHS2.Cluster).html"
        $NavSelected  = if ($CHS2.Cluster -eq $CG.Name) { ' selected' } else { '' }
        [void]$CluNavOptions.Append("<option value=`"$NavFileName2`"$NavSelected>$(ConvertTo-SafeHtml $CHS2.Cluster)</option>")
    }
    $CluHtml = New-Object System.Text.StringBuilder
    [void]$CluHtml.AppendLine("<!DOCTYPE html><html lang=`"ko`"><head><meta charset=`"UTF-8`"><meta name=`"viewport`" content=`"width=device-width,initial-scale=1`"><title>VCF9 HCL - $(ConvertTo-SafeHtml $CG.Name)</title><style>$SharedCss</style></head><body>")
    [void]$CluHtml.AppendLine("<div class=`"page-header`"><div><h1>Cluster: $(ConvertTo-SafeHtml $CG.Name) - Compatibility Detail</h1><div class=`"page-meta`">Generated: $(Get-Date -Format "yyyy-MM-dd HH:mm:ss") &nbsp;|&nbsp; Source: $(ConvertTo-SafeHtml $InventoryPath)</div></div><div class=`"nav-bar`"><select class=`"nav-select`" onchange=`"if(this.value){window.location.href=this.value;}`">$($CluNavOptions.ToString())</select><a class=`"home-link`" href=`"Compatibility_Report.html`">&#8962; Home</a></div></div>")
    $ExistingCats = @($CG.Group.Category | Select-Object -Unique)
    $OrderedCats  = @($CategoryOrder | Where-Object { $ExistingCats -contains $_ })
    $OtherCats    = @($ExistingCats | Where-Object { $CategoryOrder -notcontains $_ })
    foreach ($Cat in (@($OrderedCats)+@($OtherCats))) {
        $CatRows = @($CG.Group | Where-Object { $_.Category -eq $Cat } | Sort-Object HostName)
        [void]$CluHtml.AppendLine("<div class=`"cat-section`"><div class=`"cat-title`">$(ConvertTo-SafeHtml $Cat) <span class=`"tag-total`">$($CatRows.Count) items</span></div>")
        [void]$CluHtml.AppendLine((New-CategoryTableHtml -Rows $CatRows -Category $Cat))
        [void]$CluHtml.AppendLine('</div>')
    }
    [void]$CluHtml.AppendLine('</body></html>')
    $CluHtml.ToString() | Out-File -FilePath "$ReportDir\$ClusterFileName" -Encoding UTF8
}

# Console summary
$Mismatches = $ComplianceReport | Where-Object { ($_.'ESXi_9.0' -eq "MISMATCH" -or $_.'ESXi_9.1' -eq "MISMATCH") -and $_.'ESXi_9.0' -ne "SKIP" }
Write-Host ""
Write-Host "===============================================================================" -ForegroundColor Yellow
Write-Host " VCF9 Hardware Compatibility Check Summary (ESXi 9.0 / 9.1)" -ForegroundColor Yellow
Write-Host "===============================================================================" -ForegroundColor Yellow
Write-Host " Total checked: $($ComplianceReport.Count)  |  ESXi 9.0 MISMATCH: $TotalMis90  |  ESXi 9.1 MISMATCH: $TotalMis91  |  Threshold: $MatchThreshold%" -ForegroundColor Gray
if ($Mismatches) {
    $Mismatches | Sort-Object HostName, Category | ForEach-Object {
        Write-Host (" [MISMATCH] {0,-25} {1,-20} {2,-45} (9.0:{3} / 9.1:{4})" -f $_.HostName, $_.Category, $_.Detected, $_.'ESXi_9.0', $_.'ESXi_9.1') -ForegroundColor Red
        Write-Host ("            -> Best HCL candidate: {0} ({1}%)" -f $_.HCL_Match, $_.'Match_Score(%)') -ForegroundColor DarkGray
    }
} else {
    Write-Host " All items match the HCL for both ESXi 9.0 and 9.1." -ForegroundColor Green
}
Write-Host "===============================================================================" -ForegroundColor Yellow
Write-Host " NOTE: CPU matching is based on model series (generation), not exact SKU." -ForegroundColor DarkGray
Write-Host " NOTE: All other parts use weighted token similarity scoring (best-effort)." -ForegroundColor DarkGray
Write-Host " CSV files: Compatibility_Server / CPU / NIC / StorageController.csv" -ForegroundColor Gray
Write-Host " HTML summary: Compatibility_Report.html" -ForegroundColor Gray
Write-Host " Cluster detail HTML ($($ClusterFileList.Count) files): $($ClusterFileList -join ', ')" -ForegroundColor Gray
Write-Host " Source inventory: $InventoryPath" -ForegroundColor Gray
Write-Host " Output folder:    $ReportDir" -ForegroundColor Gray
Write-Host "===============================================================================" -ForegroundColor Yellow

return $ReportDir

}

# ============================================================
# FUNCTION 3: Performance report (Menu 4)
#   Return value: the created performance report folder path ($ReportDir) on success, $null on failure
# ============================================================
function Invoke-VCF9PerformanceReport {
    param(
        [Parameter(Mandatory = $true)]
        [string]$InventoryPath
    )

    Set-StrictMode -Off

    $InventoryPath = $InventoryPath.Trim().TrimEnd('\', '/')
    if (-not (Test-Path $InventoryPath)) {
        Write-Host "[ERROR] Inventory folder not found: '$InventoryPath'" -ForegroundColor Red
        return $null
    }

    $HostPerfFile = Join-Path $InventoryPath "Hosts_Perf.csv"
    $HostHwFile   = Join-Path $InventoryPath "Hosts_Hardware.csv"
    $VMFile       = Join-Path $InventoryPath "VMs_Status.csv"
    $DSFile       = Join-Path $InventoryPath "Datastores.csv"
    $ClusterFile  = Join-Path $InventoryPath "Clusters.csv"

    if (-not (Test-Path $HostPerfFile)) {
        Write-Host "[ERROR] Hosts_Perf.csv not found in '$InventoryPath'." -ForegroundColor Red
        Write-Host "        Please specify the folder generated by the inventory collection step (Menu 2)." -ForegroundColor Red
        return $null
    }

    Write-Host "[INFO] Loading performance data from: $InventoryPath" -ForegroundColor Gray
    $HostPerf    = Import-Csv -Path $HostPerfFile -Encoding UTF8
    $HostHw      = if (Test-Path $HostHwFile)  { Import-Csv -Path $HostHwFile  -Encoding UTF8 } else { @() }
    $VMs         = if (Test-Path $VMFile)      { Import-Csv -Path $VMFile      -Encoding UTF8 } else { @() }
    $Datastores  = if (Test-Path $DSFile)      { Import-Csv -Path $DSFile      -Encoding UTF8 } else { @() }
    $ClustersCsv = if (Test-Path $ClusterFile) { Import-Csv -Path $ClusterFile -Encoding UTF8 } else { @() }

    Write-Host "       Hosts: $(@($HostPerf).Count)  |  VMs: $(@($VMs).Count)  |  Datastores: $(@($Datastores).Count)  |  Clusters: $(@($ClustersCsv).Count)" -ForegroundColor DarkGray

    $ScriptBasePR = if ($PSScriptRoot) { $PSScriptRoot } else { Split-Path -Parent $MyInvocation.MyCommand.Definition }
    $TimeStampPR  = Get-Date -Format "yyyyMMdd_HHmm"
    $ReportDir    = Join-Path $OutputRoot "vcf_9_upgrade\performance_$TimeStampPR"
    if (-not (Test-Path $ReportDir)) { New-Item -ItemType Directory -Path $ReportDir | Out-Null }
    Write-Host "[INFO] Results will be saved to: $ReportDir" -ForegroundColor Gray

    $Css = Get-SharedReportCss

    function New-PerfKpiCard {
        param([string]$Label,[string]$Value,[string]$Detail = "",[string]$Color = "blue")
        $DetailHtml = if ($Detail) { "<div class=`"kpi-detail`">$Detail</div>" } else { "" }
        return "<div class=`"kpi-card $Color`"><div><div class=`"kpi-val`">$Value</div><div class=`"kpi-sub`">$Label</div>$DetailHtml</div></div>"
    }

    function Get-UsageClass {
        param([double]$Pct)
        if ($Pct -ge 80) { return ' class="hi-usage"' }
        if ($Pct -ge 60) { return ' class="mid-usage"' }
        return ''
    }

    function Get-UsageColor {
        param([double]$Pct)
        if ($Pct -ge 80) { return "red" }
        if ($Pct -ge 60) { return "yellow" }
        return "green"
    }

    # -- Build lookups --
    $HwLookup = @{}
    foreach ($HwRow in $HostHw) { $HwLookup[$HwRow.HostName] = $HwRow }

    # -- Enrich host rows with numeric fields + hardware info --
    $HostRows = foreach ($HP in $HostPerf) {
        $Hw = $HwLookup[$HP.HostName]
        [PSCustomObject]@{
            HostName          = $HP.HostName
            Cluster           = $HP.Cluster
            State             = $HP.State
            ESXi_Version      = $HP.ESXi_Version
            CPU_Usage_Pct_Num = ConvertTo-PctNumber $HP.CPU_Usage_Pct
            CPU_Usage_Pct     = $HP.CPU_Usage_Pct
            CPU_Ready_Pct_Num = ConvertTo-PctNumber $HP.CPU_Ready_Pct
            CPU_Ready_Pct     = $HP.CPU_Ready_Pct
            Mem_Usage_Pct_Num = ConvertTo-PctNumber $HP.Mem_Usage_Pct
            Mem_Usage_Pct     = $HP.Mem_Usage_Pct
            Mem_Usage_GB      = $HP.Mem_Usage_GB
            Vendor            = if ($Hw) { $Hw.Vendor } else { "N/A" }
            Model             = if ($Hw) { $Hw.Model } else { "N/A" }
            Mem_Total_GB      = if ($Hw) { $Hw.Mem_Total_GB } else { "N/A" }
            Total_Cores       = if ($Hw) { $Hw.Total_Cores } else { "N/A" }
        }
    }

    # -- Enrich VM rows with numeric fields --
    $VMRows = foreach ($VM in $VMs) {
        [PSCustomObject]@{
            VMName             = $VM.VMName
            PowerState         = $VM.PowerState
            Cluster            = $VM.Cluster
            ESXi_Host          = $VM.ESXi_Host
            NumCPU             = $VM.NumCPU
            MemoryGB           = $VM.MemoryGB
            CPU_Ready_Pct_Num  = ConvertTo-PctNumber $VM.CPU_Ready_Pct
            CPU_Ready_Pct      = $VM.CPU_Ready_Pct
            CPU_Costop_Pct_Num = ConvertTo-PctNumber $VM.CPU_Costop_Pct
            CPU_Costop_Pct     = $VM.CPU_Costop_Pct
            CPU_Usage_MHz      = $VM.CPU_Usage_MHz
            Mem_Consumed_MB    = $VM.Mem_Consumed_MB
            Mem_Cold_MB        = $VM.Mem_Cold_MB
            VMTools_Status     = $VM.VMTools_Status
        }
    }

    # -- Enrich datastore rows with numeric free % --
    $DSRows = foreach ($DS in $Datastores) {
        [PSCustomObject]@{
            Cluster         = $DS.Cluster
            DatastoreName   = $DS.DatastoreName
            Storage_Type    = $DS.Storage_Type
            Total_Cap_GB    = $DS.Total_Cap_GB
            Used_GB         = $DS.Used_GB
            Free_GB         = $DS.Free_GB
            Free_Pct_Num    = ConvertTo-PctNumber $DS.Free_Percentage
            Free_Percentage = $DS.Free_Percentage
            Total_IOPS_Avg  = $DS.Total_IOPS_Avg
        }
    }

    # -- Overall KPIs --
    $TotalHosts          = @($HostRows).Count
    $ConnectedHostsCount = @($HostRows | Where-Object { $_.State -eq "Connected" }).Count
    $AvgCpuPct = if ($TotalHosts -gt 0) { [Math]::Round((($HostRows | Measure-Object -Property CPU_Usage_Pct_Num -Average).Average), 1) } else { 0 }
    $AvgMemPct = if ($TotalHosts -gt 0) { [Math]::Round((($HostRows | Measure-Object -Property Mem_Usage_Pct_Num -Average).Average), 1) } else { 0 }
    $TotalVMs  = @($VMRows).Count
    $VMsOn     = @($VMRows | Where-Object { $_.PowerState -eq "PoweredOn" }).Count
    $VMsOff    = $TotalVMs - $VMsOn

    $TotalDSCapGB  = ($DSRows | Measure-Object -Property Total_Cap_GB -Sum).Sum;  if (-not $TotalDSCapGB)  { $TotalDSCapGB  = 0 }
    $TotalDSUsedGB = ($DSRows | Measure-Object -Property Used_GB -Sum).Sum;       if (-not $TotalDSUsedGB) { $TotalDSUsedGB = 0 }
    $TotalDSFreeGB = ($DSRows | Measure-Object -Property Free_GB -Sum).Sum;       if (-not $TotalDSFreeGB) { $TotalDSFreeGB = 0 }
    $TotalDSCapGB  = [Math]::Round($TotalDSCapGB, 2)
    $TotalDSUsedGB = [Math]::Round($TotalDSUsedGB, 2)
    $TotalDSFreeGB = [Math]::Round($TotalDSFreeGB, 2)
    $LowFreeDS     = @($DSRows | Where-Object { $_.Free_Pct_Num -lt 15 } | Sort-Object Free_Pct_Num)

    # -- Per-cluster aggregation --
    $ClusterPerf = $HostRows | Group-Object Cluster | ForEach-Object {
        $ClusterName = $_.Name
        $CH   = $_.Group
        $CVMs = @($VMRows | Where-Object { $_.Cluster -eq $ClusterName })
        $CDS  = @($DSRows | Where-Object { $_.Cluster -eq $ClusterName })
        $CVMsOn  = @($CVMs | Where-Object { $_.PowerState -eq "PoweredOn" })
        $CDSCap  = ($CDS | Measure-Object -Property Total_Cap_GB -Sum).Sum; if (-not $CDSCap)  { $CDSCap  = 0 }
        $CDSUsed = ($CDS | Measure-Object -Property Used_GB -Sum).Sum;      if (-not $CDSUsed) { $CDSUsed = 0 }
        $CDSFree = ($CDS | Measure-Object -Property Free_GB -Sum).Sum;     if (-not $CDSFree) { $CDSFree = 0 }
        [PSCustomObject]@{
            Cluster   = $ClusterName
            HostCount = $CH.Count
            VMCount   = $CVMs.Count
            VMsOn     = $CVMsOn.Count
            AvgCpuPct = [Math]::Round((($CH | Measure-Object -Property CPU_Usage_Pct_Num -Average).Average), 1)
            AvgMemPct = [Math]::Round((($CH | Measure-Object -Property Mem_Usage_Pct_Num -Average).Average), 1)
            DSCapGB   = [Math]::Round($CDSCap, 2)
            DSUsedGB  = [Math]::Round($CDSUsed, 2)
            DSFreeGB  = [Math]::Round($CDSFree, 2)
        }
    } | Sort-Object Cluster

    # -- Cluster jump dropdown options (shared across summary + all cluster pages) --
    $NavOptions = New-Object System.Text.StringBuilder
    [void]$NavOptions.Append('<option value="">Jump to cluster...</option>')
    foreach ($CP in $ClusterPerf) {
        $NavFile = "Performance_Cluster_$(Get-SafeFileNameShared $CP.Cluster).html"
        [void]$NavOptions.Append("<option value=`"$NavFile`">$(ConvertTo-SafeHtmlShared $CP.Cluster)</option>")
    }

    # ============================================================
    # Summary report: Performance_Report.html
    # ============================================================
    $PHtml = New-Object System.Text.StringBuilder
    [void]$PHtml.AppendLine(@"
<!DOCTYPE html><html lang="ko"><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>VCF9 Performance Report</title><style>$Css</style></head><body>
<div class="page-header"><div><h1>VCF9 Performance Report</h1><div class="page-meta">Generated: $(Get-Date -Format "yyyy-MM-dd HH:mm:ss") &nbsp;|&nbsp; Source: $(ConvertTo-SafeHtmlShared $InventoryPath)</div></div>
<div class="nav-bar"><select class="nav-select" onchange="if(this.value){window.location.href=this.value;}">$($NavOptions.ToString())</select></div>
</div>
<div class="section-title">Overall Summary</div>
<div class="card-row">
$(New-PerfKpiCard -Label "Total Hosts" -Value "$TotalHosts" -Detail "$ConnectedHostsCount connected" -Color "blue")
$(New-PerfKpiCard -Label "Avg CPU Usage" -Value "$AvgCpuPct%" -Color (Get-UsageColor $AvgCpuPct))
$(New-PerfKpiCard -Label "Avg Memory Usage" -Value "$AvgMemPct%" -Color (Get-UsageColor $AvgMemPct))
$(New-PerfKpiCard -Label "Total VMs" -Value "$TotalVMs" -Detail "$VMsOn on / $VMsOff off" -Color "blue")
$(New-PerfKpiCard -Label "Datastore Capacity" -Value "$TotalDSCapGB GB" -Detail "$TotalDSUsedGB GB used / $TotalDSFreeGB GB free" -Color "blue")
</div>
"@)

    [void]$PHtml.AppendLine('<div class="section-title">Per-Cluster Performance</div><div class="summary-table-wrap"><table>')
    [void]$PHtml.AppendLine('<thead><tr><th>Cluster</th><th>Hosts</th><th>VMs (On/Off)</th><th>Avg CPU%</th><th>Avg Mem%</th><th>DS Capacity (GB)</th><th>DS Used (GB)</th><th>DS Free (GB)</th></tr></thead><tbody>')
    foreach ($CP in $ClusterPerf) {
        $CPFile = "Performance_Cluster_$(Get-SafeFileNameShared $CP.Cluster).html"
        $CpuCls = Get-UsageClass $CP.AvgCpuPct
        $MemCls = Get-UsageClass $CP.AvgMemPct
        [void]$PHtml.AppendLine("<tr><td><a href=`"$CPFile`">$(ConvertTo-SafeHtmlShared $CP.Cluster)</a></td><td>$($CP.HostCount)</td><td>$($CP.VMsOn) / $($CP.VMCount - $CP.VMsOn)</td><td$CpuCls>$($CP.AvgCpuPct)%</td><td$MemCls>$($CP.AvgMemPct)%</td><td>$($CP.DSCapGB)</td><td>$($CP.DSUsedGB)</td><td>$($CP.DSFreeGB)</td></tr>")
    }
    [void]$PHtml.AppendLine('</tbody></table></div>')

    [void]$PHtml.AppendLine('<div class="section-title">Top 10 Hosts by CPU Usage</div><div class="table-wrap"><table>')
    [void]$PHtml.AppendLine('<thead><tr><th>Host</th><th>Cluster</th><th>CPU Usage</th><th>Mem Usage</th><th>CPU Ready</th><th>Vendor / Model</th></tr></thead><tbody>')
    $TopCpuHosts = $HostRows | Sort-Object CPU_Usage_Pct_Num -Descending | Select-Object -First 10
    foreach ($R in $TopCpuHosts) {
        [void]$PHtml.AppendLine("<tr><td>$(ConvertTo-SafeHtmlShared $R.HostName)</td><td>$(ConvertTo-SafeHtmlShared $R.Cluster)</td><td>$($R.CPU_Usage_Pct)</td><td>$($R.Mem_Usage_Pct)</td><td>$($R.CPU_Ready_Pct)</td><td>$(ConvertTo-SafeHtmlShared $R.Vendor) $(ConvertTo-SafeHtmlShared $R.Model)</td></tr>")
    }
    [void]$PHtml.AppendLine('</tbody></table></div>')

    [void]$PHtml.AppendLine('<div class="section-title">Top 10 Hosts by Memory Usage</div><div class="table-wrap"><table>')
    [void]$PHtml.AppendLine('<thead><tr><th>Host</th><th>Cluster</th><th>Mem Usage</th><th>CPU Usage</th><th>Mem Total (GB)</th><th>Vendor / Model</th></tr></thead><tbody>')
    $TopMemHosts = $HostRows | Sort-Object Mem_Usage_Pct_Num -Descending | Select-Object -First 10
    foreach ($R in $TopMemHosts) {
        [void]$PHtml.AppendLine("<tr><td>$(ConvertTo-SafeHtmlShared $R.HostName)</td><td>$(ConvertTo-SafeHtmlShared $R.Cluster)</td><td>$($R.Mem_Usage_Pct)</td><td>$($R.CPU_Usage_Pct)</td><td>$($R.Mem_Total_GB)</td><td>$(ConvertTo-SafeHtmlShared $R.Vendor) $(ConvertTo-SafeHtmlShared $R.Model)</td></tr>")
    }
    [void]$PHtml.AppendLine('</tbody></table></div>')

    [void]$PHtml.AppendLine('<div class="section-title">Top 10 VMs by CPU Ready %</div><div class="table-wrap"><table>')
    [void]$PHtml.AppendLine('<thead><tr><th>VM</th><th>Cluster</th><th>Host</th><th>Power State</th><th>CPU Ready</th><th>CPU Costop</th><th>NumCPU</th></tr></thead><tbody>')
    $TopReadyVMs = $VMRows | Where-Object { $_.PowerState -eq "PoweredOn" } | Sort-Object CPU_Ready_Pct_Num -Descending | Select-Object -First 10
    foreach ($R in $TopReadyVMs) {
        [void]$PHtml.AppendLine("<tr><td>$(ConvertTo-SafeHtmlShared $R.VMName)</td><td>$(ConvertTo-SafeHtmlShared $R.Cluster)</td><td>$(ConvertTo-SafeHtmlShared $R.ESXi_Host)</td><td>$($R.PowerState)</td><td>$($R.CPU_Ready_Pct)</td><td>$($R.CPU_Costop_Pct)</td><td>$($R.NumCPU)</td></tr>")
    }
    [void]$PHtml.AppendLine('</tbody></table></div>')

    if ($LowFreeDS.Count -gt 0) {
        [void]$PHtml.AppendLine('<div class="section-title">Datastores Below 15% Free Space</div><div class="table-wrap"><table>')
        [void]$PHtml.AppendLine('<thead><tr><th>Datastore</th><th>Cluster</th><th>Type</th><th>Capacity (GB)</th><th>Used (GB)</th><th>Free (GB)</th><th>Free %</th></tr></thead><tbody>')
        foreach ($R in $LowFreeDS) {
            [void]$PHtml.AppendLine("<tr><td>$(ConvertTo-SafeHtmlShared $R.DatastoreName)</td><td>$(ConvertTo-SafeHtmlShared $R.Cluster)</td><td>$($R.Storage_Type)</td><td>$($R.Total_Cap_GB)</td><td>$($R.Used_GB)</td><td>$($R.Free_GB)</td><td class=`"hi-usage`">$($R.Free_Percentage)</td></tr>")
        }
        [void]$PHtml.AppendLine('</tbody></table></div>')
    }

    [void]$PHtml.AppendLine('</body></html>')
    $PHtml.ToString() | Out-File -FilePath "$ReportDir\Performance_Report.html" -Encoding UTF8

    # ============================================================
    # Per-cluster detail pages: Performance_Cluster_<name>.html
    # ============================================================
    $ClusterFileListPR = @()
    foreach ($CP in $ClusterPerf) {
        $CPFile = "Performance_Cluster_$(Get-SafeFileNameShared $CP.Cluster).html"
        $ClusterFileListPR += $CPFile

        $CHtml = New-Object System.Text.StringBuilder
        [void]$CHtml.AppendLine("<!DOCTYPE html><html lang=`"ko`"><head><meta charset=`"UTF-8`"><meta name=`"viewport`" content=`"width=device-width,initial-scale=1`"><title>VCF9 Performance - $(ConvertTo-SafeHtmlShared $CP.Cluster)</title><style>$Css</style></head><body>")
        [void]$CHtml.AppendLine("<div class=`"page-header`"><div><h1>Cluster: $(ConvertTo-SafeHtmlShared $CP.Cluster) - Performance Detail</h1><div class=`"page-meta`">Generated: $(Get-Date -Format "yyyy-MM-dd HH:mm:ss") &nbsp;|&nbsp; Source: $(ConvertTo-SafeHtmlShared $InventoryPath)</div></div><div class=`"nav-bar`"><select class=`"nav-select`" onchange=`"if(this.value){window.location.href=this.value;}`">$($NavOptions.ToString())</select><a class=`"home-link`" href=`"Performance_Report.html`">&#8962; Home</a></div></div>")

        $CHosts = @($HostRows | Where-Object { $_.Cluster -eq $CP.Cluster } | Sort-Object CPU_Usage_Pct_Num -Descending)
        [void]$CHtml.AppendLine("<div class=`"cat-section`"><div class=`"cat-title`">Hosts <span class=`"tag-total`">$($CHosts.Count) hosts</span></div><div class=`"table-wrap`"><table>")
        [void]$CHtml.AppendLine('<thead><tr><th>Host</th><th>State</th><th>ESXi Version</th><th>CPU Usage</th><th>CPU Ready</th><th>Mem Usage</th><th>Mem Total (GB)</th><th>Vendor / Model</th></tr></thead><tbody>')
        foreach ($R in $CHosts) {
            $CpuCls = Get-UsageClass $R.CPU_Usage_Pct_Num
            $MemCls = Get-UsageClass $R.Mem_Usage_Pct_Num
            [void]$CHtml.AppendLine("<tr><td>$(ConvertTo-SafeHtmlShared $R.HostName)</td><td>$($R.State)</td><td>$($R.ESXi_Version)</td><td$CpuCls>$($R.CPU_Usage_Pct)</td><td>$($R.CPU_Ready_Pct)</td><td$MemCls>$($R.Mem_Usage_Pct)</td><td>$($R.Mem_Total_GB)</td><td>$(ConvertTo-SafeHtmlShared $R.Vendor) $(ConvertTo-SafeHtmlShared $R.Model)</td></tr>")
        }
        [void]$CHtml.AppendLine('</tbody></table></div></div>')

        $CVMs = @($VMRows | Where-Object { $_.Cluster -eq $CP.Cluster } | Sort-Object CPU_Ready_Pct_Num -Descending)
        [void]$CHtml.AppendLine("<div class=`"cat-section`"><div class=`"cat-title`">Virtual Machines <span class=`"tag-total`">$($CVMs.Count) VMs</span></div><div class=`"table-wrap`"><table>")
        [void]$CHtml.AppendLine('<thead><tr><th>VM</th><th>Power State</th><th>Host</th><th>NumCPU</th><th>Memory (GB)</th><th>CPU Usage (MHz)</th><th>CPU Ready</th><th>CPU Costop</th><th>Mem Consumed (MB)</th><th>VMTools</th></tr></thead><tbody>')
        foreach ($R in $CVMs) {
            [void]$CHtml.AppendLine("<tr><td>$(ConvertTo-SafeHtmlShared $R.VMName)</td><td>$($R.PowerState)</td><td>$(ConvertTo-SafeHtmlShared $R.ESXi_Host)</td><td>$($R.NumCPU)</td><td>$($R.MemoryGB)</td><td>$($R.CPU_Usage_MHz)</td><td>$($R.CPU_Ready_Pct)</td><td>$($R.CPU_Costop_Pct)</td><td>$($R.Mem_Consumed_MB)</td><td>$($R.VMTools_Status)</td></tr>")
        }
        [void]$CHtml.AppendLine('</tbody></table></div></div>')

        $CDatastores = @($DSRows | Where-Object { $_.Cluster -eq $CP.Cluster } | Sort-Object Free_Pct_Num)
        if ($CDatastores.Count -gt 0) {
            [void]$CHtml.AppendLine("<div class=`"cat-section`"><div class=`"cat-title`">Datastores <span class=`"tag-total`">$($CDatastores.Count) datastores</span></div><div class=`"table-wrap`"><table>")
            [void]$CHtml.AppendLine('<thead><tr><th>Datastore</th><th>Type</th><th>Capacity (GB)</th><th>Used (GB)</th><th>Free (GB)</th><th>Free %</th><th>Total IOPS (Avg)</th></tr></thead><tbody>')
            foreach ($R in $CDatastores) {
                $FreeCls = if ($R.Free_Pct_Num -lt 15) { ' class="hi-usage"' } else { '' }
                [void]$CHtml.AppendLine("<tr><td>$(ConvertTo-SafeHtmlShared $R.DatastoreName)</td><td>$($R.Storage_Type)</td><td>$($R.Total_Cap_GB)</td><td>$($R.Used_GB)</td><td>$($R.Free_GB)</td><td$FreeCls>$($R.Free_Percentage)</td><td>$($R.Total_IOPS_Avg)</td></tr>")
            }
            [void]$CHtml.AppendLine('</tbody></table></div></div>')
        }

        [void]$CHtml.AppendLine('</body></html>')
        $CHtml.ToString() | Out-File -FilePath "$ReportDir\$CPFile" -Encoding UTF8
    }

    Write-Host ""
    Write-Host "===============================================================================" -ForegroundColor Yellow
    Write-Host " VCF9 Performance Report Summary" -ForegroundColor Yellow
    Write-Host "===============================================================================" -ForegroundColor Yellow
    Write-Host " Hosts: $TotalHosts  |  VMs: $TotalVMs ($VMsOn on / $VMsOff off)  |  Clusters: $($ClusterPerf.Count)" -ForegroundColor Gray
    Write-Host " Avg CPU Usage: $AvgCpuPct%  |  Avg Memory Usage: $AvgMemPct%" -ForegroundColor Gray
    Write-Host " Datastore Capacity: $TotalDSCapGB GB  ($TotalDSUsedGB GB used / $TotalDSFreeGB GB free)" -ForegroundColor Gray
    if ($LowFreeDS.Count -gt 0) {
        Write-Host " WARNING: $($LowFreeDS.Count) datastore(s) below 15% free space" -ForegroundColor Red
    }
    Write-Host " HTML summary: Performance_Report.html" -ForegroundColor Gray
    Write-Host " Cluster detail HTML ($($ClusterFileListPR.Count) files): $($ClusterFileListPR -join ', ')" -ForegroundColor Gray
    Write-Host " Source inventory: $InventoryPath" -ForegroundColor Gray
    Write-Host " Output folder:    $ReportDir" -ForegroundColor Gray
    Write-Host "===============================================================================" -ForegroundColor Yellow

    return $ReportDir
}

# ============================================================
# Main menu
# ============================================================
$ScriptDirMain = Join-Path $OutputRoot "vcf_9_upgrade"

if (-not $MenuChoice) {
    Write-Host "===============================================================================" -ForegroundColor Cyan
    Write-Host "                    VCF 9 Pre-check Integrated Tool" -ForegroundColor Cyan
    Write-Host "===============================================================================" -ForegroundColor Cyan
    Write-Host " [1] Inventory collection + HCL compatibility check (run automatically in sequence)" -ForegroundColor White
    Write-Host " [2] Run inventory collection only (vCenter connection, CSV output only)" -ForegroundColor White
    Write-Host " [3] Specify an existing inventory folder -> run HCL compatibility check only" -ForegroundColor White
    Write-Host " [4] Specify an existing inventory folder -> generate a performance report only" -ForegroundColor White
    Write-Host "===============================================================================" -ForegroundColor Cyan
    $MenuChoice = Read-Host "> Enter a menu number (1/2/3/4)"
}

switch ($MenuChoice.Trim()) {

    "1" {
        Write-Host ""
        Write-Host "[MENU 1] Starting inventory collection..." -ForegroundColor Cyan
        $InvDir = Invoke-VCF9Precheck
        if (-not $InvDir) {
            Write-Host "[ERROR] Inventory collection failed, so the HCL compatibility check will not proceed." -ForegroundColor Red
            break
        }

        Write-Host ""
        Write-Host "[MENU 1] Running the HCL compatibility check against the collected inventory ($InvDir)..." -ForegroundColor Cyan
        $CompDir = Invoke-VCF9HCLCheck -InventoryPath $InvDir
        if ($CompDir) {
            Write-Host ""
            Write-Host "[MENU 1] Completed." -ForegroundColor Green
            Write-Host "  Inventory folder             : $InvDir" -ForegroundColor Yellow
            Write-Host "  Compatibility results folder : $CompDir" -ForegroundColor Yellow

            # Archive both output folders into a single zip next to the script.
            # The original folders are NOT deleted or modified - the zip is an extra copy.
            try {
                $ZipTimeStamp = Get-Date -Format "yyyyMMdd_HHmm"
                $ZipPath = Join-Path $ScriptDirMain "VCF9_Precheck_$ZipTimeStamp.zip"
                Compress-Archive -Path $InvDir, $CompDir -DestinationPath $ZipPath -Force -ErrorAction Stop
                Write-Host "  Zip archive                  : $ZipPath" -ForegroundColor Yellow
            } catch {
                Write-Host "[WARN] Failed to create the zip archive: $($_.Exception.Message)" -ForegroundColor Yellow
                Write-Host "        The inventory and compatibility folders above are still intact." -ForegroundColor Yellow
            }
        } else {
            Write-Host "[ERROR] A problem occurred while running the HCL compatibility check." -ForegroundColor Red
        }

        if ($AutoChainToNvmeTiering -and $InvDir) {
            Write-Host ""
            Write-Host "[AUTO] Continuing automatically with NVMe memory tiering analysis on '$InvDir'..." -ForegroundColor Cyan
            Invoke-Vcf9NvmeTieringTool -InventoryPath $InvDir
        }
    }

    "2" {
        Write-Host ""
        Write-Host "[MENU 2] Running inventory collection only..." -ForegroundColor Cyan
        $InvDir = Invoke-VCF9Precheck -ShowStandaloneHint
        if ($InvDir) {
            Write-Host ""
            Write-Host "[MENU 2] Completed. Created folder: $InvDir" -ForegroundColor Green
            Write-Host "         Later, enter this folder name in Menu [3] to run the HCL compatibility check." -ForegroundColor Gray
        } else {
            Write-Host "[ERROR] Inventory collection failed." -ForegroundColor Red
        }
    }

    "3" {
        Write-Host ""
        $InputPath = if ($ExistingInventoryPath) { $ExistingInventoryPath } else { Read-Host "> Enter the inventory folder name (or full path) created by Menu [2]" }
        if ([string]::IsNullOrWhiteSpace($InputPath)) {
            Write-Host "[ERROR] The folder path cannot be empty." -ForegroundColor Red
            break
        }
        $InputPath = $InputPath.Trim().Trim('"').TrimEnd('\', '/')

        # If only a folder name (not a full path) was entered, resolve it automatically relative to this script location
        if (-not (Test-Path $InputPath)) {
            $CandidatePath = Join-Path $ScriptDirMain $InputPath
            if (Test-Path $CandidatePath) {
                $InputPath = $CandidatePath
                Write-Host "[INFO] Using the folder relative to the script location: $InputPath" -ForegroundColor Gray
            }
        }

        Write-Host "[MENU 3] Running the HCL compatibility check against the folder '$InputPath'..." -ForegroundColor Cyan
        $CompDir = Invoke-VCF9HCLCheck -InventoryPath $InputPath
        if ($CompDir) {
            Write-Host ""
            Write-Host "[MENU 3] Completed. Results folder: $CompDir" -ForegroundColor Green
        } else {
            Write-Host "[ERROR] A problem occurred while running the HCL compatibility check." -ForegroundColor Red
        }
    }

    "4" {
        Write-Host ""
        $InputPath4 = if ($ExistingInventoryPath) { $ExistingInventoryPath } else { Read-Host "> Enter the inventory folder name (or full path) created by Menu [2]" }
        if ([string]::IsNullOrWhiteSpace($InputPath4)) {
            Write-Host "[ERROR] The folder path cannot be empty." -ForegroundColor Red
            break
        }
        $InputPath4 = $InputPath4.Trim().Trim('"').TrimEnd('\', '/')

        # If only a folder name (not a full path) was entered, resolve it automatically relative to this script location
        if (-not (Test-Path $InputPath4)) {
            $CandidatePath4 = Join-Path $ScriptDirMain $InputPath4
            if (Test-Path $CandidatePath4) {
                $InputPath4 = $CandidatePath4
                Write-Host "[INFO] Using the folder relative to the script location: $InputPath4" -ForegroundColor Gray
            }
        }

        Write-Host "[MENU 4] Generating a performance report for the folder '$InputPath4'..." -ForegroundColor Cyan
        $PerfDir = Invoke-VCF9PerformanceReport -InventoryPath $InputPath4
        if ($PerfDir) {
            Write-Host ""
            Write-Host "[MENU 4] Completed. Results folder: $PerfDir" -ForegroundColor Green
        } else {
            Write-Host "[ERROR] A problem occurred while generating the performance report." -ForegroundColor Red
        }
    }

    default {
        Write-Host "[ERROR] Invalid selection. Please enter 1, 2, 3, or 4." -ForegroundColor Red
    }
}
}

function Invoke-Vcf9NvmeTieringTool {
param(
    [Parameter(Mandatory = $true)]
    [string]$InventoryPath,

    [Parameter(Mandatory = $false)]
    [double]$MaxCpuPct = 80.0,

    [Parameter(Mandatory = $false)]
    [double]$MaxActiveRatioPct = 40.0,

    [Parameter(Mandatory = $false)]
    [double]$PhysMemFactor = 2.0
)

# ============================================================
# vcf9-nvme-tiering-analysis.ps1  -  NVMe Memory Tiering Benefit Analysis
# ============================================================
# vcf9-precheck-script-cs.ps1 이 생성한 인벤토리 폴더를 입력받아
# NVMe 메모리 티어링 전환 시 호스트별 VM 밀도 증가 효과를 분석합니다.
#
# 사용 예시:
#   .\vcf9-nvme-tiering-analysis.ps1 -InventoryPath "C:\inventory\vSphere_Inventory_20260707_1430"
#
# 옵션:
#   -InventoryPath    : 인벤토리 폴더 경로 (필수)
#   -MaxCpuPct        : CPU 사용률 상한 (기본값: 80%)
#   -MaxActiveRatioPct: VM 총 할당 메모리 대비 Active 메모리 최대 비율 (기본값: 40%)
#   -PhysMemFactor    : 물리 메모리 / Active 메모리 최소 배율 (기본값: 2.0배)

Set-StrictMode -Off
$ErrorActionPreference = "Continue"

Write-Host "===============================================================================" -ForegroundColor Cyan
Write-Host "  VCF9 NVMe Memory Tiering Benefit Analysis" -ForegroundColor Cyan
Write-Host "===============================================================================" -ForegroundColor Cyan
Write-Host " Settings: Max CPU $MaxCpuPct%  |  Max Active/Alloc $MaxActiveRatioPct%  |  Phys >= Active x $PhysMemFactor" -ForegroundColor Gray

# ── 입력 파일 로드 ──
$InventoryPath = $InventoryPath.Trim().TrimEnd('\','/')
foreach ($Required in @('Hosts_Perf.csv','Hosts_Hardware.csv','VMs_Status.csv')) {
    if (-not (Test-Path (Join-Path $InventoryPath $Required))) {
        Write-Host "[ERROR] Required file not found: $Required in '$InventoryPath'" -ForegroundColor Red
        return
    }
}

$HostsPerf = Import-Csv -Path (Join-Path $InventoryPath 'Hosts_Perf.csv')     -Encoding UTF8
$HostsHW   = Import-Csv -Path (Join-Path $InventoryPath 'Hosts_Hardware.csv') -Encoding UTF8
$VmsStatus = Import-Csv -Path (Join-Path $InventoryPath 'VMs_Status.csv')     -Encoding UTF8

Write-Host " Loaded: $(@($HostsPerf).Count) hosts | $(@($VmsStatus).Count) VMs" -ForegroundColor Gray

# ── 숫자 변환 헬퍼 (단위 문자 제거 후 파싱) ──
function Parse-Num {
    param([string]$Value)
    if ([string]::IsNullOrWhiteSpace($Value) -or $Value -eq 'N/A') { return 0.0 }
    $Clean = $Value -replace '[^0-9\.\-]', ''
    $Result = 0.0
    if ([double]::TryParse($Clean, [ref]$Result)) { return $Result }
    return 0.0
}

# ── Hosts_Hardware에서 호스트별 물리 메모리 총용량 매핑 ──
$PhysMemLookup = @{}
foreach ($HW in $HostsHW) {
    $MemField = if ($HW.PSObject.Properties['Mem_Total_GB']) { $HW.Mem_Total_GB } else { $HW.Memory_GB }
    $GB = Parse-Num $MemField
    if ($GB -gt 0) { $PhysMemLookup[$HW.HostName] = $GB }
}

# ── VMs_Status에서 PoweredOn VM만 호스트별로 그룹핑 ──
$HostVMs = @{}
foreach ($VM in ($VmsStatus | Where-Object { $_.PowerState -eq 'PoweredOn' })) {
    $EsxiHost = $VM.ESXi_Host
    if (-not $HostVMs.ContainsKey($EsxiHost)) { $HostVMs[$EsxiHost] = @() }
    $HostVMs[$EsxiHost] += $VM
}

# ── 분석 결과 수집 ──
$Results     = @()
$RawHostData = @()   # JavaScript 실시간 재계산용 원시 숫자 데이터
$MaxActive   = $MaxActiveRatioPct / 100.0

foreach ($H in $HostsPerf) {
    $HostName = $H.HostName
    $Cluster  = $H.Cluster

    $PhysMemGB = $PhysMemLookup[$HostName]
    if (-not $PhysMemGB -or $PhysMemGB -eq 0) { continue }

    $CpuPct      = Parse-Num $H.CPU_Usage_Pct
    $HostMemUsedGB = Parse-Num $H.Mem_Usage_GB   # ESXi 레벨 소비량

    $HVMs = if ($HostVMs.ContainsKey($HostName)) { $HostVMs[$HostName] } else { @() }
    $VmCount = @($HVMs).Count

    if ($VmCount -eq 0) {
        # VM 없는 호스트는 정보만 기록
        $Results += [PSCustomObject]@{
            Cluster = $Cluster; HostName = $HostName
            Phys_Mem_GB = $PhysMemGB; CPU_Usage_Pct = "$CpuPct %"
            VM_Count = 0; VM_Alloc_GB = 0; VM_Active_GB = 0; VM_Consumed_GB = 0; VM_Cold_GB = 0
            Active_Ratio_Pct = "N/A"; Avg_VM_Alloc_GB = 0; Avg_VM_Active_GB = 0; Avg_VM_Consumed_GB = 0
            Current_AddVM = 0; Current_Limit_Reason = "No VMs"
            NVMe_Eligible = "N/A"; NVMe_AddVM = 0; NVMe_Limit_Reason = "No VMs"
            NVMe_Gain = 0; NVMe_Total_VM = 0
            NVMe_Check_PhysMem = "N/A"; NVMe_Check_ActiveRatio = "N/A"; NVMe_Check_CPU = "N/A"
        }
        continue
    }

    # VM 집계
    $VmAllocGB    = [Math]::Round(($HVMs | ForEach-Object { Parse-Num $_.MemoryGB }       | Measure-Object -Sum).Sum, 2)
    $VmActiveMB   = ($HVMs | ForEach-Object { Parse-Num $_.Mem_Active_MB   } | Measure-Object -Sum).Sum
    $VmConsumedMB = ($HVMs | ForEach-Object { Parse-Num $_.Mem_Consumed_MB } | Measure-Object -Sum).Sum
    $VmColdMB     = ($HVMs | ForEach-Object { Parse-Num $_.Mem_Cold_MB     } | Measure-Object -Sum).Sum
    $VmActiveGB   = [Math]::Round($VmActiveMB   / 1024, 2)
    $VmConsumedGB = [Math]::Round($VmConsumedMB / 1024, 2)
    $VmColdGB     = [Math]::Round($VmColdMB     / 1024, 2)

    # VM당 평균 프로파일 (추가 VM 계산 기준)
    $AvgAllocGB    = if ($VmCount -gt 0) { $VmAllocGB   / $VmCount } else { 0 }
    $AvgActiveGB   = if ($VmCount -gt 0) { $VmActiveGB  / $VmCount } else { 0 }
    $AvgConsumedGB = if ($VmCount -gt 0) { $VmConsumedGB/ $VmCount } else { 0 }

    $ActiveRatioPct = if ($VmAllocGB -gt 0) { [Math]::Round($VmActiveGB / $VmAllocGB * 100, 1) } else { 0 }

    # ────────────────────────────────────────────────────────
    #  현재 상태 추가 가능 VM 수
    #  제약: (1) 소비 메모리 기준 물리 한도, (2) CPU 80% 상한
    # ────────────────────────────────────────────────────────
    # 현재 상태 추가 가능: 물리 메모리 70% 상한 대비 VM 할당 메모리 기준
    $MemCap70         = $PhysMemGB * 0.70
    $CurrMemHeadroom  = $MemCap70 - $VmAllocGB
    $AddByCurrMem     = if ($AvgAllocGB -gt 0) { [Math]::Max(0, [Math]::Floor($CurrMemHeadroom / $AvgAllocGB)) } else { 0 }

    if ($CpuPct -ge $MaxCpuPct) {
        $AddByCpu = 0
    } elseif ($CpuPct -gt 0) {
        $AddByCpu = [Math]::Floor(($MaxCpuPct - $CpuPct) / $CpuPct * $VmCount)
    } else {
        $AddByCpu = 999
    }

    $CurrAdd = [Math]::Max(0, [Math]::Min($AddByCurrMem, $AddByCpu))
    $CurrLimitReason = if ($AddByCurrMem -le $AddByCpu) { "Memory" } else { "CPU" }
    if ($CpuPct -ge $MaxCpuPct) { $CurrLimitReason = "CPU(Exceeded)" }

    # ────────────────────────────────────────────────────────
    #  NVMe 티어링 전환 후 추가 가능 VM 수
    #
    #  조건 A: 물리 메모리 >= Active × PhysMemFactor
    #    → (VmActiveGB + add_n × AvgActiveGB) × Factor ≤ PhysMemGB
    #    → add_n ≤ (PhysMemGB/Factor - VmActiveGB) / AvgActiveGB
    #
    #  조건 B: Active ≤ TotalAlloc × MaxActive
    #    → (VmActiveGB + add_n × AvgActiveGB) ≤ (VmAllocGB + add_n × AvgAllocGB) × MaxActive
    #    → add_n × (AvgActiveGB - MaxActive × AvgAllocGB) ≤ MaxActive × VmAllocGB - VmActiveGB
    #    ▷ 케이스별: 좌변 계수 부호에 따라 분기
    #
    #  조건 C: CPU ≤ MaxCpuPct (동일)
    # ────────────────────────────────────────────────────────

    # 조건 A
    $NvmeAddByMem = if ($AvgActiveGB -gt 0) {
        [Math]::Max(0, [Math]::Floor(($PhysMemGB / $PhysMemFactor - $VmActiveGB) / $AvgActiveGB))
    } else { 999 }

    # 조건 B
    $BCoeff = $AvgActiveGB - $MaxActive * $AvgAllocGB   # 좌변 계수
    $BRhs   = $MaxActive * $VmAllocGB - $VmActiveGB     # 우변
    if ($BCoeff -gt 0.0001) {
        $NvmeAddByRatio = if ($BRhs -ge 0) { [Math]::Floor($BRhs / $BCoeff) } else { 0 }
    } elseif ($BCoeff -lt -0.0001) {
        # 계수 음수 → VM 추가할수록 조건이 완화 → 비구속 (∞)
        $NvmeAddByRatio = 999
    } else {
        # 계수 ≈ 0 → VM당 Active 비율이 정확히 MaxActive → 어느 쪽도 제약 없음
        $NvmeAddByRatio = 999
    }

    # 현재 NVMe 조건 충족 여부 확인 (전환 전제 조건)
    $CheckPhysMem    = $VmActiveGB * $PhysMemFactor -le $PhysMemGB
    $CheckActiveRatio= ($VmAllocGB -eq 0) -or ($VmActiveGB / $VmAllocGB * 100 -le $MaxActiveRatioPct)
    $CheckCpu        = $CpuPct -lt $MaxCpuPct

    $NvmeEligible = $CheckPhysMem -and $CheckActiveRatio -and $CheckCpu

    # 전환 가능한 경우만 NVMe 추가 VM 산출 (현재 조건 이미 초과인 경우 CPU만 고려)
    if (-not $CheckCpu) {
        $NvmeAdd = 0
        $NvmeLimitReason = "CPU(Exceeded)"
    } elseif (-not $CheckPhysMem) {
        $NvmeAdd = 0
        $NvmeLimitReason = "Active Memory exceeds Phys/$PhysMemFactor — NVMe config needed"
    } elseif (-not $CheckActiveRatio) {
        $NvmeAdd = 0
        $NvmeLimitReason = "Active > $MaxActiveRatioPct% of Allocated — reduce VM density first"
    } else {
        $NvmeAdd = [Math]::Max(0, [Math]::Min($NvmeAddByMem, [Math]::Min($NvmeAddByRatio, $AddByCpu)))
        $BindingVal = [Math]::Min($NvmeAddByMem, [Math]::Min($NvmeAddByRatio, $AddByCpu))
        if ($BindingVal -ge 999)              { $NvmeLimitReason = "No constraint binding" }
        elseif ($NvmeAddByMem -le $NvmeAddByRatio -and $NvmeAddByMem -le $AddByCpu) { $NvmeLimitReason = "Active x $PhysMemFactor <= PhysMem" }
        elseif ($NvmeAddByRatio -le $AddByCpu) { $NvmeLimitReason = "Active <= $MaxActiveRatioPct% of Alloc" }
        else                                  { $NvmeLimitReason = "CPU" }
    }

    $NvmeGain    = $NvmeAdd - $CurrAdd
    $NvmeTotalVM = $VmCount + $NvmeAdd

    $Results += [PSCustomObject]@{
        "Cluster"                  = $Cluster
        "HostName"                 = $HostName
        "Phys_Mem_GB"              = $PhysMemGB
        "CPU_Usage_Pct"            = "$CpuPct %"
        "VM_Count"                 = $VmCount
        "VM_Alloc_GB"              = $VmAllocGB
        "VM_Active_GB"             = $VmActiveGB
        "VM_Consumed_GB"           = $VmConsumedGB
        "VM_Cold_GB"               = $VmColdGB
        "Active_Ratio_Pct"         = "$ActiveRatioPct %"
        "Avg_VM_Alloc_GB"          = [Math]::Round($AvgAllocGB, 1)
        "Avg_VM_Active_GB"         = [Math]::Round($AvgActiveGB, 2)
        "Avg_VM_Consumed_GB"       = [Math]::Round($AvgConsumedGB, 2)
        "Current_AddVM"            = $CurrAdd
        "Current_Limit_Reason"     = $CurrLimitReason
        "NVMe_Eligible"            = if ($NvmeEligible) { "Yes" } else { "No" }
        "NVMe_Check_PhysMem"       = if ($CheckPhysMem)     { "OK (Active×$PhysMemFactor=$([Math]::Round($VmActiveGB*$PhysMemFactor,1))GB ≤ ${PhysMemGB}GB)" } else { "FAIL" }
        "NVMe_Check_ActiveRatio"   = if ($CheckActiveRatio) { "OK ($ActiveRatioPct% ≤ $MaxActiveRatioPct%)" } else { "FAIL ($ActiveRatioPct% > $MaxActiveRatioPct%)" }
        "NVMe_Check_CPU"           = if ($CheckCpu)         { "OK ($CpuPct% < $MaxCpuPct%)" }               else { "FAIL ($CpuPct% ≥ $MaxCpuPct%)" }
        "NVMe_AddVM"               = $NvmeAdd
        "NVMe_Gain"                = $NvmeGain
        "NVMe_Total_VM"            = $NvmeTotalVM
        "NVMe_Limit_Reason"        = $NvmeLimitReason
    }

    # JavaScript 슬라이더 재계산에 필요한 원시 데이터 수집
    $AvgVcpu = if ($VmCount -gt 0) {
        [Math]::Round(($HVMs | ForEach-Object { [double](Parse-Num $_.NumCPU) } | Measure-Object -Sum).Sum / $VmCount, 1)
    } else { 0 }
    $RawHostData += [PSCustomObject]@{
        h   = $HostName
        cl  = $Cluster
        p   = $PhysMemGB
        c   = [Math]::Round($CpuPct, 2)
        mu  = [Math]::Round($HostMemUsedGB, 2)
        n   = $VmCount
        al  = $VmAllocGB
        ac  = $VmActiveGB
        co  = $VmConsumedGB
        aVc = $AvgVcpu
        aAl = [Math]::Round($AvgAllocGB, 4)
        aAc = [Math]::Round($AvgActiveGB, 4)
        aCo = [Math]::Round($AvgConsumedGB, 4)
    }
}

if ($Results.Count -eq 0) {
    Write-Host "[WARN] No results generated. Check InventoryPath or data." -ForegroundColor Yellow
    return
}

# ── 출력 폴더 생성 ──
$ScriptBase = if ($PSScriptRoot) { $PSScriptRoot } else { Split-Path -Parent $MyInvocation.MyCommand.Definition }
$TimeStamp  = Get-Date -Format "yyyyMMdd_HHmm"
$OutDir     = Join-Path $OutputRoot "vcf_9_upgrade\nvme_tiering_$TimeStamp"
if (-not (Test-Path $OutDir)) { New-Item -ItemType Directory -Path $OutDir | Out-Null }

# ── CSV 출력 ──
$CsvPath = Join-Path $OutDir "NVMe_Tiering_Analysis_$TimeStamp.csv"
$Results | Export-Csv -Path $CsvPath -NoTypeInformation -Encoding UTF8
Write-Host " CSV : $CsvPath" -ForegroundColor Gray

# ─────────────────────────────────────────────
#  HTML 리포트 생성
# ─────────────────────────────────────────────
function Safe { param([string]$T); if ($null -eq $T) { return "" }; return [System.Net.WebUtility]::HtmlEncode($T) }

# 클러스터별 집계
$ClusterSummary = $Results | Where-Object { $_.VM_Count -gt 0 } | Group-Object Cluster | ForEach-Object {
    $g = $_.Group
    $ClHosts        = $g.Count
    $ClTotalVMs     = ($g | Measure-Object -Property VM_Count       -Sum).Sum
    # NVMe 전환 후 호스트당 평균 수용 가능 VM 수 (VM_Count + NVMe_AddVM 의 클러스터 합산 기준)
    $ClNvmeCapacity = ($g | Measure-Object -Property NVMe_Total_VM  -Sum).Sum
    $ClAvgCapPerHost = if ($ClHosts -gt 0) { $ClNvmeCapacity / $ClHosts } else { 0 }
    # 현재 VM 운영 수량을 유지한 채 NVMe 전환 시 필요한 호스트 수 (VM 재배치 가능 가정)
    $ClHostsNeeded  = if ($ClAvgCapPerHost -gt 0) { [Math]::Ceiling($ClTotalVMs / $ClAvgCapPerHost) } else { $ClHosts }
    $ClHostReduction = [Math]::Max(0, $ClHosts - $ClHostsNeeded)
    [PSCustomObject]@{
        Cluster         = $_.Name
        Hosts           = $ClHosts
        TotalVMs        = $ClTotalVMs
        TotalPhysGB     = ($g | Measure-Object -Property Phys_Mem_GB   -Sum).Sum
        TotalAllocGB    = ($g | Measure-Object -Property VM_Alloc_GB   -Sum).Sum
        TotalActiveGB   = ($g | Measure-Object -Property VM_Active_GB  -Sum).Sum
        TotalConsumedGB = ($g | Measure-Object -Property VM_Consumed_GB -Sum).Sum
        TotalColdGB     = ($g | Measure-Object -Property VM_Cold_GB    -Sum).Sum
        CurrAddVM       = ($g | Measure-Object -Property Current_AddVM -Sum).Sum
        NvmeAddVM       = ($g | Measure-Object -Property NVMe_AddVM -Sum).Sum
        NvmeGain        = ($g | Measure-Object -Property NVMe_Gain -Sum).Sum
        EligibleHosts   = @($g | Where-Object { $_.NVMe_Eligible -eq "Yes" }).Count
        NvmeCapacityVM  = $ClNvmeCapacity
        HostsNeeded     = $ClHostsNeeded
        HostReduction   = $ClHostReduction
    }
} | Sort-Object Cluster

# 클러스터 요약 CSV 출력 (호스트 축소 가능 수량 포함)
$ClusterCsvPath = Join-Path $OutDir "NVMe_Tiering_ClusterSummary_$TimeStamp.csv"
$ClusterSummary | Export-Csv -Path $ClusterCsvPath -NoTypeInformation -Encoding UTF8
Write-Host " CSV (cluster summary): $ClusterCsvPath" -ForegroundColor Gray

$TotalVMs        = [int]($Results | Where-Object { $_.VM_Count -gt 0 } | Measure-Object -Property VM_Count -Sum).Sum
$TotalCurrAdd    = [int]($Results | Measure-Object -Property Current_AddVM -Sum).Sum
$TotalNvmeAdd    = [int]($Results | Measure-Object -Property NVMe_AddVM    -Sum).Sum
$TotalNvmeGain   = [int]($Results | Measure-Object -Property NVMe_Gain     -Sum).Sum
if ($null -eq $TotalVMs)     { $TotalVMs     = 0 }
if ($null -eq $TotalCurrAdd) { $TotalCurrAdd = 0 }
if ($null -eq $TotalNvmeAdd) { $TotalNvmeAdd = 0 }
if ($null -eq $TotalNvmeGain){ $TotalNvmeGain= 0 }
$TotalEligible   = @($Results | Where-Object { $_.NVMe_Eligible -eq "Yes" }).Count

# ── 전체 기준 호스트 축소 가능 수량 (현재 VM 수량 유지 + NVMe 전환 + VM 재배치 가정) ──
$TotalHostsWithVMs   = ($ClusterSummary | Measure-Object -Property Hosts -Sum).Sum
$TotalNvmeCapacityVM = ($ClusterSummary | Measure-Object -Property NvmeCapacityVM -Sum).Sum
if ($null -eq $TotalHostsWithVMs)   { $TotalHostsWithVMs   = 0 }
if ($null -eq $TotalNvmeCapacityVM) { $TotalNvmeCapacityVM = 0 }
$TotalAvgCapPerHost  = if ($TotalHostsWithVMs -gt 0) { $TotalNvmeCapacityVM / $TotalHostsWithVMs } else { 0 }
$TotalHostsNeeded    = if ($TotalAvgCapPerHost -gt 0) { [Math]::Ceiling($TotalVMs / $TotalAvgCapPerHost) } else { $TotalHostsWithVMs }
$TotalHostReduction  = [Math]::Max(0, $TotalHostsWithVMs - $TotalHostsNeeded)

$Html = New-Object System.Text.StringBuilder

# JavaScript 재계산용 JSON (원시 데이터) 및 파라미터 변수
$JsJson      = ($RawHostData | ConvertTo-Json -Compress -Depth 3)
$JsMaxCpu    = $MaxCpuPct
$JsInitRatio = $MaxActiveRatioPct
$JsFactor    = $PhysMemFactor

[void]$Html.AppendLine(@"
<!DOCTYPE html>
<html lang="ko">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>NVMe Memory Tiering Benefit Analysis</title>
<style>
:root{--bg:#f0f2f5;--surface:#fff;--border:#e2e8f0;--primary:#1e3a5f;--primary-lt:#e8edf5;
--green:#16a34a;--green-lt:#dcfce7;--green-dk:#14532d;--blue:#2563eb;--blue-lt:#dbeafe;
--orange:#d97706;--orange-lt:#fef3c7;--red:#dc2626;--red-lt:#fee2e2;--red-dk:#7f1d1d;
--gray:#64748b;--gray-lt:#f8fafc;--radius:12px;
--shadow:0 1px 3px rgba(0,0,0,.08),0 4px 16px rgba(0,0,0,.06);
font-family:'Malgun Gothic','Apple SD Gothic Neo',Arial,sans-serif}
*{box-sizing:border-box;margin:0;padding:0}
body{background:var(--bg);color:#1e293b;padding:28px 32px;font-size:14px;line-height:1.6}
h1{font-size:22px;font-weight:700;color:var(--primary);margin-bottom:4px}
.meta{color:var(--gray);font-size:12px;margin-bottom:12px}
.ctrl-box{background:var(--surface);border-radius:var(--radius);box-shadow:var(--shadow);
  padding:16px 24px;margin-bottom:24px;display:flex;align-items:center;gap:24px;flex-wrap:wrap}
.ctrl-label{font-size:13px;font-weight:600;color:var(--primary);white-space:nowrap}
.ctrl-row{display:flex;align-items:center;gap:12px}
.slider{-webkit-appearance:none;width:260px;height:6px;border-radius:3px;background:#e2e8f0;outline:none;cursor:pointer}
.slider::-webkit-slider-thumb{-webkit-appearance:none;width:18px;height:18px;border-radius:50%;background:var(--primary);cursor:pointer;box-shadow:0 1px 4px rgba(0,0,0,.25)}
.ctrl-val{font-size:20px;font-weight:700;color:var(--primary);min-width:52px}
.ctrl-hint{font-size:11px;color:var(--gray)}
.ctrl-reset{padding:5px 14px;border-radius:8px;border:1.5px solid var(--primary);background:transparent;color:var(--primary);font-size:12px;font-weight:600;cursor:pointer}
.ctrl-reset:hover{background:var(--primary);color:#fff}
.section-title{font-size:15px;font-weight:700;color:var(--primary);margin:28px 0 14px;
  display:flex;align-items:center;gap:8px}
.section-title::before{content:'';display:inline-block;width:4px;height:18px;
  background:var(--primary);border-radius:2px}
.kpi-row{display:flex;gap:16px;flex-wrap:wrap;margin-bottom:24px}
.kpi-card{flex:1;min-width:160px;background:var(--surface);border-radius:var(--radius);
  padding:18px 22px;box-shadow:var(--shadow);border-top:4px solid}
.kpi-card.blue{border-color:var(--blue)}.kpi-card.green{border-color:var(--green)}
.kpi-card.orange{border-color:var(--orange)}
.kpi-val{font-size:32px;font-weight:700;line-height:1.1}
.kpi-sub{font-size:12px;color:var(--gray);margin-top:4px;font-weight:600}
.kpi-detail{font-size:11px;color:var(--gray);margin-top:2px}
.cluster-block{background:var(--surface);border-radius:var(--radius);box-shadow:var(--shadow);
  padding:20px 24px;margin-bottom:20px}
.cluster-header{display:flex;align-items:center;gap:12px;margin-bottom:14px;flex-wrap:wrap}
.cluster-name{font-size:15px;font-weight:700;color:var(--primary)}
.tag{display:inline-block;padding:2px 10px;border-radius:20px;font-size:11px;font-weight:600}
.tag-green{background:var(--green-lt);color:var(--green-dk)}
.tag-blue{background:var(--blue-lt);color:var(--blue)}
.tag-orange{background:var(--orange-lt);color:var(--orange)}
.tbl-wrap{overflow-x:auto;margin-top:12px}
table{width:100%;border-collapse:collapse;font-size:12px}
thead th{background:var(--primary);color:#fff;padding:7px 10px;text-align:left;white-space:nowrap}
tbody td{padding:6px 10px;border-bottom:1px solid var(--border);vertical-align:top}
tbody tr:hover td{background:var(--primary-lt)}
.row-eligible td{background:#f0fdf4}
.row-cpu-limited td{background:#fff5f5}
.bar-wrap{width:100px;height:10px;background:#e2e8f0;border-radius:5px;display:inline-block;vertical-align:middle}
.bar{height:100%;border-radius:5px}
.bar-green{background:var(--green)}.bar-orange{background:var(--orange)}.bar-red{background:var(--red)}
.badge-ok{background:var(--green-lt);color:var(--green-dk);padding:1px 8px;border-radius:10px;font-size:11px;font-weight:700}
.badge-fail{background:var(--red-lt);color:var(--red-dk);padding:1px 8px;border-radius:10px;font-size:11px;font-weight:700}
.badge-na{background:#f1f5f9;color:var(--gray);padding:1px 8px;border-radius:10px;font-size:11px}
.gain-pos{color:var(--green);font-weight:700}.gain-zero{color:var(--gray)}
.cond-ok{color:var(--green)}.cond-fail{color:var(--red);font-weight:700}
</style>
<script>
const HOST_DATA  = $JsJson;
const MAX_CPU    = $JsMaxCpu;
const PHY_FACTOR = $JsFactor;
function safeId(s){ return 'r-'+s.replace(/[^a-zA-Z0-9]/g,'-'); }

// 신규 VM 스펙 읽기 (빈 값이면 null → 호스트 평균 사용)
function getVmSpec(){
  const vc = parseFloat(document.getElementById('inp-vcpu').value);
  const al = parseFloat(document.getElementById('inp-alloc').value);
  const ar = parseFloat(document.getElementById('inp-active-vm').value);
  return {
    vcpu:    isNaN(vc)||vc<=0 ? null : vc,
    allocGB: isNaN(al)||al<=0 ? null : al,
    activeRatioPct: isNaN(ar)||ar<0 ? null : ar
  };
}

function calcHost(h, activeRatioLimit, vmSpec){
  if(h.n===0) return {currAdd:0,nvmeAdd:0,gain:0,eligible:false,chkP:false,chkR:false,chkC:false};

  // 신규 VM 리소스 단위 (지정 없으면 호스트 평균)
  const newVcpu     = (vmSpec&&vmSpec.vcpu!=null)           ? vmSpec.vcpu    : h.aVc;
  const newAllocGB  = (vmSpec&&vmSpec.allocGB!=null)        ? vmSpec.allocGB : h.aAl;
  const newActiveGB = (vmSpec&&vmSpec.activeRatioPct!=null)
                    ? newAllocGB * vmSpec.activeRatioPct / 100
                    : h.aAc;

  // CPU 제약 — 신규 VM vCPU가 다르면 현재 평균 대비 비율로 스케일
  const vcpuScale = (h.aVc>0&&newVcpu>0) ? newVcpu/h.aVc : 1;
  const cpuPerVm  = h.n>0 ? (h.c/h.n)*vcpuScale : 0;
  const addByCpu  = h.c>=MAX_CPU ? 0 : (cpuPerVm>0 ? Math.floor((MAX_CPU-h.c)/cpuPerVm) : 999);

  // 현재 상태 추가 가능 (물리 메모리 70% 상한 대비 VM 할당 메모리 기준)
  const MEM_CAP_RATIO = 0.70;
  const currMemHd     = h.p * MEM_CAP_RATIO - h.al;
  const addByCurrMem  = newAllocGB>0 ? Math.max(0,Math.floor(currMemHd/newAllocGB)) : 0;
  const currAdd       = Math.max(0,Math.min(addByCurrMem,addByCpu));

  // NVMe 조건 확인 (현재 호스트 상태 기준)
  const maxA = activeRatioLimit/100;
  const chkP = h.ac*PHY_FACTOR<=h.p;
  const chkR = h.al===0||(h.ac/h.al*100)<=activeRatioLimit;
  const chkC = h.c<MAX_CPU;
  let nvmeAdd=0;
  if(chkP&&chkR&&chkC){
    // 조건 A: (현재Active + add_n×newActive) × factor ≤ physMem
    const aM = newActiveGB>0 ? Math.max(0,Math.floor((h.p/PHY_FACTOR-h.ac)/newActiveGB)) : 999;
    // 조건 B: (현재Active + add_n×newActive) ≤ (현재Alloc + add_n×newAlloc) × maxActive
    const bc=newActiveGB-maxA*newAllocGB, br=maxA*h.al-h.ac;
    const aR=bc>0.0001?(br>=0?Math.floor(br/bc):0):999;
    nvmeAdd=Math.max(0,Math.min(aM,aR,addByCpu));
  }
  return {currAdd,nvmeAdd,gain:nvmeAdd-currAdd,eligible:chkP&&chkR&&chkC,chkP,chkR,chkC};
}

function c(v){return v?'<span class="cond-ok">&#10003;</span>':'<span class="cond-fail">&#10007;</span>';}
function badge(e,n){
  if(n===0) return '<span class="badge-na">N/A</span>';
  return e?'<span class="badge-ok">가능</span>':'<span class="badge-fail">조건미충족</span>';
}

function updateAll(){
  const ratio   = parseFloat(document.getElementById('sl').value);
  const vmSpec  = getVmSpec();
  let tC=0,tN=0,tG=0,tE=0,tCap=0,tVM=0,tHosts=0;
  const clMap={};
  HOST_DATA.forEach(h=>{
    const r=calcHost(h,ratio,vmSpec);
    tC+=r.currAdd;tN+=r.nvmeAdd;tG+=r.gain;if(r.eligible)tE++;
    if(!clMap[h.cl])clMap[h.cl]={c:0,n:0,g:0,e:0,cap:0,vm:0,hosts:0};
    clMap[h.cl].c+=r.currAdd;clMap[h.cl].n+=r.nvmeAdd;clMap[h.cl].g+=r.gain;
    if(r.eligible)clMap[h.cl].e++;
    // 호스트 축소 계산용: 호스트별 NVMe 전환 후 수용 가능 VM 수(n+nvmeAdd) 및 VM 운영 대수 누적 (VM 있는 호스트만 카운트)
    if(h.n>0){
      clMap[h.cl].cap+=(h.n+r.nvmeAdd); clMap[h.cl].vm+=h.n; clMap[h.cl].hosts+=1;
      tCap+=(h.n+r.nvmeAdd); tVM+=h.n; tHosts+=1;
    }
    const row=document.getElementById(safeId(h.h));
    if(!row)return;
    const td=row.cells;
    const ar=h.al>0?(h.ac/h.al*100).toFixed(1):'0';
    td[7].textContent=ar+' %';
    td[8].innerHTML=c(r.chkP)+' '+c(r.chkR)+' '+c(r.chkC)+' '+badge(r.eligible,h.n);
    td[9].textContent='+'+r.currAdd;
    td[10].textContent='+'+r.nvmeAdd;
    td[11].className=r.gain>0?'gain-pos':'gain-zero';
    td[11].textContent='+'+r.gain;
    row.className=r.eligible?'row-eligible':(r.chkC?'':'row-cpu-limited');
  });
  const q=id=>document.getElementById(id);
  if(q('kpi-curr'))q('kpi-curr').textContent='+'+tC;
  if(q('kpi-nvme'))q('kpi-nvme').textContent='+'+tN;
  if(q('kpi-gain'))q('kpi-gain').textContent='+'+tG;
  if(q('kpi-elig-det'))q('kpi-elig-det').textContent=tE+'개 호스트 전환 가능';
  // 전체 기준 호스트 축소 가능 수량 재계산
  const tAvgCap = tHosts>0 ? tCap/tHosts : 0;
  const tHostsNeeded = tAvgCap>0 ? Math.ceil(tVM/tAvgCap) : tHosts;
  const tHostRed = Math.max(0, tHosts-tHostsNeeded);
  if(q('kpi-hostred'))q('kpi-hostred').textContent='-'+tHostRed;
  if(q('kpi-hostred-det'))q('kpi-hostred-det').textContent=tHosts+'대 → '+tHostsNeeded+'대 (VM '+tVM+'개 유지 기준)';
  Object.keys(clMap).forEach(cl=>{
    const rid='cl-'+cl.replace(/[^a-zA-Z0-9]/g,'-');
    const row=document.getElementById(rid);if(!row)return;
    const td=row.cells;
    td[2].textContent=clMap[cl].e;
    td[8].textContent='+'+clMap[cl].c;
    td[9].textContent='+'+clMap[cl].n;
    td[10].className=clMap[cl].g>0?'gain-pos':'gain-zero';
    td[10].textContent='+'+clMap[cl].g;
    // 클러스터별 호스트 축소 가능 수량 재계산
    const clAvgCap = clMap[cl].hosts>0 ? clMap[cl].cap/clMap[cl].hosts : 0;
    const clHostsNeeded = clAvgCap>0 ? Math.ceil(clMap[cl].vm/clAvgCap) : clMap[cl].hosts;
    const clHostRed = Math.max(0, clMap[cl].hosts-clHostsNeeded);
    td[11].textContent=clHostsNeeded;
    td[12].className=clHostRed>0?'gain-pos':'gain-zero';
    td[12].textContent='-'+clHostRed;
  });
  // 신규 VM 스펙 라벨 업데이트
  const sp=vmSpec;
  const lbl = '신규 VM 기준: vCPU '+(sp.vcpu?sp.vcpu+'개':'평균')+
              ' / Alloc '+(sp.allocGB?sp.allocGB+' GB':'평균')+
              ' / Active '+(sp.activeRatioPct!=null?sp.activeRatioPct+'%':'평균');
  if(q('vm-spec-lbl'))q('vm-spec-lbl').textContent=lbl;
}

function resetAll(){
  document.getElementById('sl').value=$JsInitRatio;
  document.getElementById('slVal').textContent='$JsInitRatio';
  document.getElementById('inp-vcpu').value='';
  document.getElementById('inp-alloc').value='';
  document.getElementById('inp-active-vm').value='';
  document.getElementById('active-vm-val').textContent='-';
  updateAll();
}

document.addEventListener('DOMContentLoaded',()=>{
  document.getElementById('sl').addEventListener('input',function(){
    document.getElementById('slVal').textContent=this.value; updateAll();
  });
  document.getElementById('inp-vcpu').addEventListener('input',updateAll);
  document.getElementById('inp-alloc').addEventListener('input',updateAll);
  document.getElementById('inp-active-vm').addEventListener('input',function(){
    const v=parseFloat(this.value);
    document.getElementById('active-vm-val').textContent=isNaN(v)?'-':v+'%';
    updateAll();
  });
});
</script>
</head>
<body>
<h1>&#9889; NVMe Memory Tiering Benefit Analysis</h1>
<div class="meta">
  Generated: $(Get-Date -Format "yyyy-MM-dd HH:mm:ss") &nbsp;|&nbsp;
  Source: $(Safe $InventoryPath) &nbsp;|&nbsp;
  Base: CPU &#8804; $MaxCpuPct% / Phys &#8805; Active &#215; $PhysMemFactor
</div>
<div class="ctrl-box">
  <div style="flex:0 0 100%;margin-bottom:4px">
    <div class="ctrl-label">&#128295; 분석 조건 조정 — 값을 바꾸면 모든 수치가 실시간 재계산됩니다.</div>
    <div class="ctrl-hint" id="vm-spec-lbl" style="margin-top:3px;color:var(--primary)">신규 VM 기준: vCPU 평균 / Alloc 평균 / Active 평균</div>
  </div>
  <div class="ctrl-row" style="flex-wrap:wrap;gap:20px;width:100%">
    <!-- NVMe Active 비율 상한 -->
    <div>
      <div class="ctrl-hint">NVMe Active 상한 (VM 총할당 대비)</div>
      <div style="display:flex;align-items:center;gap:8px;margin-top:4px">
        <input class="slider" type="range" id="sl" min="10" max="70" step="1" value="$JsInitRatio" style="width:180px">
        <span class="ctrl-val"><span id="slVal">$JsInitRatio</span>%</span>
      </div>
    </div>
    <!-- 구분선 -->
    <div style="width:1px;background:var(--border);align-self:stretch"></div>
    <!-- 신규 VM vCPU -->
    <div>
      <div class="ctrl-hint">신규 VM vCPU <span style="color:var(--gray)">(빈 값 = 현재 평균)</span></div>
      <div style="display:flex;align-items:center;gap:6px;margin-top:4px">
        <input id="inp-vcpu" type="number" min="1" max="128" step="1" placeholder="평균"
          style="width:80px;padding:5px 8px;border:1.5px solid var(--border);border-radius:8px;font-size:13px;color:var(--primary)">
        <span class="ctrl-hint">vCPU</span>
      </div>
    </div>
    <!-- 신규 VM 할당 메모리 -->
    <div>
      <div class="ctrl-hint">신규 VM 할당 메모리 <span style="color:var(--gray)">(빈 값 = 현재 평균)</span></div>
      <div style="display:flex;align-items:center;gap:6px;margin-top:4px">
        <input id="inp-alloc" type="number" min="1" max="4096" step="1" placeholder="평균"
          style="width:80px;padding:5px 8px;border:1.5px solid var(--border);border-radius:8px;font-size:13px;color:var(--primary)">
        <span class="ctrl-hint">GB</span>
      </div>
    </div>
    <!-- 신규 VM Active 비율 -->
    <div>
      <div class="ctrl-hint">신규 VM Active 비율 <span style="color:var(--gray)">(빈 값 = 현재 평균)</span></div>
      <div style="display:flex;align-items:center;gap:6px;margin-top:4px">
        <input id="inp-active-vm" type="number" min="0" max="100" step="1" placeholder="평균"
          style="width:80px;padding:5px 8px;border:1.5px solid var(--border);border-radius:8px;font-size:13px;color:var(--primary)">
        <span class="ctrl-val" style="font-size:15px"><span id="active-vm-val">-</span></span>
      </div>
    </div>
    <!-- 초기화 버튼 -->
    <div style="display:flex;align-items:flex-end">
      <button class="ctrl-reset" onclick="resetAll()">전체 초기화</button>
    </div>
  </div>
</div>

<div class="section-title">전체 요약</div>
<div class="kpi-row">
  <div class="kpi-card blue">
    <div class="kpi-val">$TotalVMs</div>
    <div class="kpi-sub">현재 운영 중인 VM</div>
    <div class="kpi-detail">PoweredOn 기준</div>
  </div>
  <div class="kpi-card orange">
    <div class="kpi-val" id="kpi-curr">+$TotalCurrAdd</div>
    <div class="kpi-sub">현재 추가 가능 VM</div>
    <div class="kpi-detail">물리 메모리 / CPU 한도 기준</div>
  </div>
  <div class="kpi-card green">
    <div class="kpi-val" id="kpi-nvme">+$TotalNvmeAdd</div>
    <div class="kpi-sub">NVMe 전환 후 추가 가능 VM</div>
    <div class="kpi-detail">Active 메모리 기준 한도</div>
  </div>
  <div class="kpi-card green">
    <div class="kpi-val" id="kpi-gain">+$TotalNvmeGain</div>
    <div class="kpi-sub">NVMe 전환 순 증가</div>
    <div class="kpi-detail" id="kpi-elig-det">$TotalEligible개 호스트 전환 가능</div>
  </div>
  <div class="kpi-card orange">
    <div class="kpi-val" id="kpi-hostred">-$TotalHostReduction</div>
    <div class="kpi-sub">축소 가능 물리 호스트</div>
    <div class="kpi-detail" id="kpi-hostred-det">$TotalHostsWithVMs 대 → $TotalHostsNeeded 대 (VM $TotalVMs개 유지 기준)</div>
  </div>
</div>

<div class="section-title">클러스터별 요약</div>
<div class="tbl-wrap"><table>
<thead><tr>
  <th>클러스터</th><th>호스트</th><th>전환가능 호스트</th><th>현재 VM</th><th>물리 메모리 합</th><th>VM 할당 합 (GB)</th>
  <th>Active 합 (GB)</th><th>Cold 합 (GB)</th>
  <th>현재 추가 가능 (VM)</th><th>NVMe 후 추가 (VM)</th><th>순 증가 (VM)</th>
  <th>필요 호스트(NVMe)</th><th>축소 가능 호스트</th>
</tr></thead><tbody>
"@)
foreach ($CS in $ClusterSummary) {
    $SafeClId  = 'cl-' + ($CS.Cluster -replace '[^a-zA-Z0-9]', '-')
    $GainClass = if ($CS.NvmeGain -gt 0) { "gain-pos" } else { "gain-zero" }
    $HostRedClass = if ($CS.HostReduction -gt 0) { "gain-pos" } else { "gain-zero" }
    [void]$Html.AppendLine("<tr id=`"$SafeClId`"><td><strong>$(Safe $CS.Cluster)</strong></td><td>$($CS.Hosts)</td><td>$($CS.EligibleHosts)</td><td>$($CS.TotalVMs)</td><td>$($CS.TotalPhysGB) GB</td><td>$([Math]::Round($CS.TotalAllocGB,1)) GB</td><td>$([Math]::Round($CS.TotalActiveGB,1))</td><td>$([Math]::Round($CS.TotalColdGB,1))</td><td>+$($CS.CurrAddVM)</td><td>+$($CS.NvmeAddVM)</td><td class=`"$GainClass`">+$($CS.NvmeGain)</td><td>$($CS.HostsNeeded)</td><td class=`"$HostRedClass`">-$($CS.HostReduction)</td></tr>")
}
[void]$Html.AppendLine("</tbody></table></div>")

# 클러스터별 호스트 상세
$AllClusters = $Results | Select-Object -ExpandProperty Cluster | Sort-Object -Unique

[void]$Html.AppendLine('<div class="section-title">클러스터별 호스트 상세</div>')

foreach ($ClName in $AllClusters) {
    $ClRows = @($Results | Where-Object { $_.Cluster -eq $ClName } | Sort-Object HostName)
    $ClVMs   = ($ClRows | Where-Object {$_.VM_Count -gt 0} | Measure-Object -Property VM_Count -Sum).Sum
    $ClNvme  = ($ClRows | Measure-Object -Property NVMe_AddVM -Sum).Sum
    $ClElig  = @($ClRows | Where-Object { $_.NVMe_Eligible -eq 'Yes' }).Count

    [void]$Html.AppendLine('<div class="cluster-block">')
    [void]$Html.AppendLine("<div class=`"cluster-header`"><span class=`"cluster-name`">📦 클러스터: $(Safe $ClName)</span><span class=`"tag tag-blue`">VM $ClVMs개</span><span class=`"tag tag-green`">NVMe 가능 $ClElig 호스트</span><span class=`"tag tag-orange`">전환 후 +$ClNvme VM</span></div>")
    [void]$Html.AppendLine('<div class="tbl-wrap"><table><thead><tr>
<th>Host</th><th>물리 메모리</th><th>CPU</th><th>VM 수</th>
<th>할당 합(GB)</th><th>Active(GB)</th><th>Cold(GB)</th><th>Active 비율</th>
<th>조건 검사</th>
<th>현재 추가 (VM)</th><th>NVMe 추가 (VM)</th><th>순 증가 (VM)</th><th>제약 요인</th>
</tr></thead><tbody>')

    foreach ($R in $ClRows) {
        $RowClass = if ($R.NVMe_Eligible -eq 'Yes') { 'row-eligible' } elseif ($R.NVMe_Check_CPU -match 'FAIL') { 'row-cpu-limited' } else { '' }
        $EligBadge = if ($R.NVMe_Eligible -eq 'Yes') { '<span class="badge-ok">가능</span>' } elseif ($R.NVMe_Eligible -eq 'No') { '<span class="badge-fail">조건미충족</span>' } else { '<span class="badge-na">N/A</span>' }

        # 조건 체크 아이콘
        $C1 = if ($R.NVMe_Check_PhysMem -match '^OK') { '<span class="cond-ok">✓</span>' } else { '<span class="cond-fail">✗</span>' }
        $C2 = if ($R.NVMe_Check_ActiveRatio -match '^OK') { '<span class="cond-ok">✓</span>' } else { '<span class="cond-fail">✗</span>' }
        $C3 = if ($R.NVMe_Check_CPU -match '^OK') { '<span class="cond-ok">✓</span>' } else { '<span class="cond-fail">✗</span>' }

        # title 속성용 툴팁 텍스트를 별도 변수로 조립 (이중따옴표 내 서브식 파서 오류 방지)
        $FactorLabel  = "${PhysMemFactor}x"
        $TipPhys      = "Phys/$FactorLabel : " + (Safe $R.NVMe_Check_PhysMem)
        $TipActive    = "Active% : " + (Safe $R.NVMe_Check_ActiveRatio)
        $TipCpu       = "CPU : " + (Safe $R.NVMe_Check_CPU)
        $TipText      = "$TipPhys&#10;$TipActive&#10;$TipCpu"

        # CPU 바 (N/A나 빈 값 대응)
        $CpuRawStr = ($R.CPU_Usage_Pct -replace '[^0-9.]', '').Trim()
        $CpuNum = 0
        if ($CpuRawStr -ne '' -and $CpuRawStr -ne '.') {
            $CpuParsed = 0.0
            if ([double]::TryParse($CpuRawStr, [ref]$CpuParsed)) { $CpuNum = [int]$CpuParsed }
        }
        $BarColor = if ($CpuNum -ge 80) { 'bar-red' } elseif ($CpuNum -ge 60) { 'bar-orange' } else { 'bar-green' }
        $CpuBar = "<span class=`"bar-wrap`"><span class=`"bar $BarColor`" style=`"width:$([Math]::Min($CpuNum,100))%`"></span></span> $($R.CPU_Usage_Pct)"

        $GainClass = if ($R.NVMe_Gain -gt 0) { 'gain-pos' } else { 'gain-zero' }

        $SafeRowId = 'r-' + ($R.HostName -replace '[^a-zA-Z0-9]', '-')
        [void]$Html.AppendLine("<tr id=`"$SafeRowId`" class=`"$RowClass`">")
        [void]$Html.AppendLine("<td>$(Safe $R.HostName)</td>")
        [void]$Html.AppendLine("<td>$($R.Phys_Mem_GB) GB</td>")
        [void]$Html.AppendLine("<td>$CpuBar</td>")
        [void]$Html.AppendLine("<td>$($R.VM_Count)</td>")
        [void]$Html.AppendLine("<td>$($R.VM_Alloc_GB)</td>")
        [void]$Html.AppendLine("<td>$($R.VM_Active_GB)</td>")
        [void]$Html.AppendLine("<td>$($R.VM_Cold_GB)</td>")
        [void]$Html.AppendLine("<td>$(Safe $R.Active_Ratio_Pct)</td>")
        [void]$Html.AppendLine("<td title=`"$TipText`">$C1 $C2 $C3 $EligBadge</td>")
        [void]$Html.AppendLine("<td>+$($R.Current_AddVM)</td>")
        [void]$Html.AppendLine("<td>+$($R.NVMe_AddVM)</td>")
        [void]$Html.AppendLine("<td class=`"$GainClass`">+$($R.NVMe_Gain)</td>")
        [void]$Html.AppendLine("<td style=`"font-size:11px;color:var(--gray)`">$(Safe $R.NVMe_Limit_Reason)</td>")
        [void]$Html.AppendLine("</tr>")
    }
    [void]$Html.AppendLine("</tbody></table></div></div>")
}

[void]$Html.AppendLine(@"
<div style="margin-top:24px;padding:14px 18px;background:var(--primary-lt);border-radius:var(--radius);font-size:12px;color:var(--gray)">
  <strong>분석 조건 설명</strong><br>
  ✓ <strong>Phys / $PhysMemFactor 배</strong>: 물리 메모리 ≥ Active 메모리 × $PhysMemFactor (NVMe 티어링 기준)<br>
  ✓ <strong>Active $MaxActiveRatioPct%</strong>: VM 총 할당 메모리 대비 Active 메모리 ≤ $MaxActiveRatioPct%<br>
  ✓ <strong>CPU $MaxCpuPct%</strong>: CPU 사용률 ≤ $MaxCpuPct%<br>
  <br>
  <em>추가 VM 수는 현재 VM들의 평균 프로파일(할당/Active/소비 비율)이 유지된다고 가정했을 때의 이론적 최대값입니다.
  실제 환경에서는 VM별 워크로드 특성, ESXi 오버헤드, vSAN 여유 공간 등을 함께 고려해야 합니다.</em>
  <br><br>
  <strong>축소 가능 물리 호스트 산정 방식</strong><br>
  현재 운영 중인 VM 수량을 그대로 유지한다고 가정할 때, NVMe 전환 후 호스트당 평균 수용 가능 VM 수(클러스터 내 호스트별 [현재 VM + NVMe 추가 가능 VM]의 합계 ÷ 호스트 수)를 기준으로
  필요 호스트 수 = 현재 VM 수 ÷ 호스트당 평균 수용량(올림) 으로 계산하고, 축소 가능 호스트 수 = 현재 호스트 수 − 필요 호스트 수 로 산출합니다.<br>
  <em>이 계산은 클러스터 내 VM을 자유롭게 재배치(vMotion/DRS)할 수 있다는 가정에 기반한 이론적 수치이며,
  장애 대응을 위한 여유 호스트(N+1 등)나 유지보수 여유분은 반영되어 있지 않으므로 실제 축소 대수 산정 시에는 별도로 고려가 필요합니다.</em>
</div>
</body></html>
"@)

$HtmlPath = Join-Path $OutDir "NVMe_Tiering_Analysis_$TimeStamp.html"
$Html.ToString() | Out-File -FilePath $HtmlPath -Encoding UTF8

# ── 콘솔 요약 ──
Write-Host ""
Write-Host "===============================================================================" -ForegroundColor Yellow
Write-Host " NVMe Memory Tiering Conversion Effect Summary" -ForegroundColor Yellow
Write-Host "===============================================================================" -ForegroundColor Yellow
Write-Host " Current running VMs: $TotalVMs" -ForegroundColor Gray
Write-Host " Additional capacity today: +$TotalCurrAdd" -ForegroundColor Gray
Write-Host " Additional capacity after NVMe tiering: +$TotalNvmeAdd (net gain: +$TotalNvmeGain)" -ForegroundColor Green
Write-Host " Hosts eligible for NVMe tiering: $TotalEligible / $(@($Results).Count)" -ForegroundColor Gray
Write-Host " Host reduction possible while keeping the current VM count: $TotalHostsWithVMs -> $TotalHostsNeeded hosts (reduction: -$TotalHostReduction)" -ForegroundColor Green
Write-Host " (Note: assumes free VM placement within the cluster / theoretical figure, does not account for HA spare (N+1) hosts)" -ForegroundColor DarkGray
Write-Host "-------------------------------------------------------------------------------" -ForegroundColor Yellow
$ClusterSummary | Format-Table @{L='클러스터';E={$_.Cluster}},
    @{L='호스트';E={$_.Hosts}}, @{L='현재VM';E={$_.TotalVMs}},
    @{L='현재추가';E={"+$($_.CurrAddVM)"}}, @{L='NVMe추가';E={"+$($_.NvmeAddVM)"}},
    @{L='순증가';E={"+$($_.NvmeGain)"}},
    @{L='필요호스트';E={$_.HostsNeeded}}, @{L='축소가능';E={"-$($_.HostReduction)"}} -AutoSize
Write-Host "===============================================================================" -ForegroundColor Yellow
Write-Host " CSV (per host)       : $CsvPath" -ForegroundColor Gray
Write-Host " CSV (cluster summary): $ClusterCsvPath" -ForegroundColor Gray
Write-Host " HTML: $HtmlPath" -ForegroundColor Gray
Write-Host "===============================================================================" -ForegroundColor Yellow
}

function Invoke-OperationsReportTool {
[CmdletBinding()]
param(
    # ---- 데이터 소스 ----
    [switch]$Mock,
    [string]$HostUrl = $env:VCFOPS_HOST,
    [string]$Username = $env:VCFOPS_USERNAME,
    [string]$Password = $env:VCFOPS_PASSWORD,
    [string]$AuthSource = $(if ($env:VCFOPS_AUTH_SOURCE) { $env:VCFOPS_AUTH_SOURCE } else { "LOCAL" }),
    [switch]$SkipCertCheck,
    [int]$MaxVMs = 0,                       # 0 = 제한 없음 (테스트 시 예: 50)

    # ---- 출력 ----
    [string]$OutputDir = (Join-Path $OutputRoot "Operations\output"),
    [string]$CustomerName = $(if ($env:VCFOPS_CUSTOMER_NAME) { $env:VCFOPS_CUSTOMER_NAME } else { "Customer" }),
    [string]$ScopeLabel = $(if ($env:VCFOPS_SCOPE_LABEL) { $env:VCFOPS_SCOPE_LABEL } else { "All vCenters" }),

    # ---- 동작 옵션 ----
    # CompareDays: N일 전 시점과 비교. 0(기본값) 또는 미입력 시 비교 없이 현재값만 출력.
    # 해당 시점의 데이터가 없으면(보존기간 초과 등) 자동으로 비교 없이 처리됩니다.
    [int]$CompareDays = 0,
    [string]$SnapshotCacheDir = (Join-Path $OutputRoot "Operations\snapshots"),
    [switch]$SkipData,                        # Excel/CSV 데이터 출력을 모두 건너뛰려면 지정
    [switch]$SkipPdf,                         # PDF 변환을 건너뛰려면 지정

    # ---- 이메일(SMTP) 발송 ----
    [switch]$SendEmail,                                            # 생성된 리포트를 이메일로 발송하려면 지정
    [string]$SmtpServer = $env:VCFOPS_SMTP_SERVER,
    [int]$SmtpPort = $(if ($env:VCFOPS_SMTP_PORT) { [int]$env:VCFOPS_SMTP_PORT } else { 587 }),
    [string]$SmtpFrom = $env:VCFOPS_SMTP_FROM,
    [string[]]$SmtpTo = $(if ($env:VCFOPS_SMTP_TO) { $env:VCFOPS_SMTP_TO -split "[,;]" } else { @() }),
    [string[]]$SmtpCc = @(),
    [string]$SmtpUsername = $env:VCFOPS_SMTP_USERNAME,
    [string]$SmtpPassword = $env:VCFOPS_SMTP_PASSWORD,
    [switch]$SmtpNoSsl,                                            # 기본은 SSL/TLS 사용, 끄려면 지정
    [string]$EmailSubject,
    [switch]$EmailHtmlInBody                                       # HTML을 첨부 대신 메일 본문에 직접 삽입하려면 지정
)

# ---- inlined from Operations/Modules/VCFOpsProgress.psm1 ----
# VCFOpsProgress.psm1
# -----------------------------------------------------------------------------
# 콘솔에 "[n/총단계] 메시지" 형식으로 진행률을 표시하는 단순 헬퍼.
# Write-Progress(진행률 바)는 호스트/리다이렉션 환경에 따라 표시가 들쭉날쭉해서,
# 어떤 콘솔/로그 환경에서도 동일하게 보이는 텍스트 기반 방식을 사용합니다.
# -----------------------------------------------------------------------------

$Script:StepCurrent = 0
$Script:StepTotal = 0

function Initialize-VCFOpsProgress {
    [CmdletBinding()]
    param([int]$Total)
    $Script:StepCurrent = 0
    $Script:StepTotal = $Total
}

function Write-VCFOpsStep {
    # 상위 단계 ("[2/6] HTML 리포트 생성 중...")
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$Message, [switch]$NoIncrement)
    if (-not $NoIncrement) { $Script:StepCurrent++ }
    $prefix = if ($Script:StepTotal -gt 0) { "[$($Script:StepCurrent)/$($Script:StepTotal)]" } else { "[*]" }
    Write-Host "$prefix $Message" -ForegroundColor Cyan
}

function Write-VCFOpsSubStep {
    # 하위 진행 내역 (들여쓰기, 회색) - 단계 번호 증가 없음
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$Message)
    Write-Host "    - $Message" -ForegroundColor DarkGray
}

function Write-VCFOpsStepDone {
    [CmdletBinding()]
    param([string]$Message = "Done")
    Write-Host "    ✓ $Message" -ForegroundColor Green
}


# ---- inlined from Operations/Modules/VCFOpsTheme.psm1 ----
# VCFOpsTheme.psm1
# -----------------------------------------------------------------------------
# 모던 + 파스텔 톤 디자인 토큰. Python 버전(report/theme.py)과 동일한 값으로 맞춰
# HTML 결과물의 색감/임계치가 동일하게 유지되도록 합니다.
# -----------------------------------------------------------------------------

$Colors = @{
    bg             = "F5F6FB"
    surface        = "FFFFFF"
    surface_alt    = "F0F2FA"
    border         = "E3E6F2"

    text_primary   = "2E3148"
    text_secondary = "6B7090"
    text_muted     = "9498B0"

    primary        = "6C7FE8"
    primary_dark   = "4C5FCB"
    primary_tint   = "E7EAFB"

    mint           = "7FD8C4"
    mint_dark      = "2F9C82"
    mint_tint      = "E3F7F1"

    peach          = "F6B88A"
    peach_dark     = "C97A33"
    peach_tint     = "FCEADC"

    coral          = "F08C8C"
    coral_dark     = "C84B4B"
    coral_tint     = "FCE3E3"

    sky            = "8FC7F2"
    sky_dark       = "3E7FB0"
    sky_tint       = "E7F3FC"

    lilac          = "C6A8E8"
}

$StatusColor = @{
    normal   = @{ fg = $Colors.mint_dark;  bg = $Colors.mint_tint;  label = "정상" }
    warning  = @{ fg = $Colors.peach_dark; bg = $Colors.peach_tint; label = "주의" }
    critical = @{ fg = $Colors.coral_dark; bg = $Colors.coral_tint; label = "위험" }
}

$Threshold = @{
    cpu_warning               = 70
    cpu_critical              = 85
    mem_warning               = 70
    mem_critical              = 85
    storage_warning           = 70
    storage_critical          = 85
    cpu_contention_warning    = 5
    cpu_contention_critical   = 10
    disk_latency_warning_ms   = 15
    disk_latency_critical_ms  = 30
    snapshot_age_warning_days = 7
}

function Get-StatusFromPct {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][double]$Value,
        [Parameter(Mandatory)][double]$Warning,
        [Parameter(Mandatory)][double]$Critical
    )
    if ($Value -ge $Critical) { return "critical" }
    if ($Value -ge $Warning) { return "warning" }
    return "normal"
}

function Get-RangeLabel {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][double]$Warning,
        [Parameter(Mandatory)][double]$Critical,
        [string]$Unit = "%"
    )
    return [PSCustomObject]@{
        Normal = "< $Warning$Unit"
        Warning = "$Warning~$Critical$Unit"
        Critical = "≥ $Critical$Unit"
    }
}

function Format-Number {
    # Python의 f"{v:,.{nd}f}" 와 동일한 결과(천단위 콤마 + 고정 소수점)를 만들기 위해
    # 시스템 로캘에 영향받지 않도록 InvariantCulture를 사용합니다.
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]$Value,
        [int]$Decimals = 1
    )
    $num = 0.0
    try { $num = [double]$Value } catch { $num = 0.0 }
    $fmt = "{0:N$Decimals}"
    return [string]::Format([System.Globalization.CultureInfo]::InvariantCulture, $fmt, $num)
}

function ConvertTo-SafeDouble {
    [CmdletBinding()]
    param($Value, [double]$Default = 0.0)
    if ($null -eq $Value) { return $Default }
    try { return [double]$Value } catch { return $Default }
}


# ---- inlined from Operations/Modules/VCFOpsStatKeys.psm1 ----
# VCFOpsStatKeys.psm1
# -----------------------------------------------------------------------------
# VCF Operations (Aria Operations / vRealize Operations) suite-api statKey 매핑
#
# [중요] statKey/property 이름은 vCenter Adapter 버전, 설치된 Management Pack,
# VCF Operations 버전에 따라 달라질 수 있습니다. 아래 값은 vSphere(VMWARE) 어댑터
# 환경에서 가장 보편적으로 쓰이는 기본값이며, 실제 연동 전 반드시 사용자 환경에서
# 검증하세요.
#
# 검증 방법(suite-api):
#   GET /suite-api/api/adapterkinds/VMWARE/resourcekinds/{ResourceKind}/statkeys
#   GET /suite-api/api/resources/{resourceId}/stats
#   GET /suite-api/api/resources/{resourceId}/properties
#
# 키가 환경과 다르면 이 파일만 수정하면 되고, 나머지 스크립트는 변경할 필요가 없습니다.
# -----------------------------------------------------------------------------

$ResourceKind = @{
    datacenter = "Datacenter"
    cluster    = "ClusterComputeResource"
    host       = "HostSystem"
    vm         = "VirtualMachine"
    datastore  = "Datastore"
}

$AdapterKindVMware = "VMWARE"

$StatKeysCluster = @{
    cpu_usage_pct       = "cpu|capacity_usagepct_average"   # 확인됨: usagemhz_average/capacity_provisioned 와 일치
    cpu_capacity_mhz    = "cpu|capacity_provisioned"        # 확인됨
    cpu_contention_pct  = "cpu|capacity_contentionPct"      # 확인됨
    mem_usage_pct       = "mem|usage_average"               # 확인됨
    mem_capacity_kb     = "mem|host_provisioned"            # 확인됨 (consumed_average와 교차검증 일치)
    storage_used_gb     = "diskspace|used"                  # 확인됨 (※ _average 접미사 없음)
    storage_total_gb    = "diskspace|total_capacity"        # 확인됨
    storage_latency_ms  = "disk|totalLatency_average"       # 확인됨 (namespace가 datastore가 아니라 disk)
}

# Datastore 리소스 레벨 statKey.
# 확인됨 - 실제 환경에서 capacity|total_capacity / capacity|used_space / capacity|available_space
# 세 값이 (총량 - 사용량 = 가용량) 으로 정확히 교차검증되었습니다.
# (이전에 추정했던 "diskspace|total_capacity"는 Datastore에 존재하지 않았고,
#  "diskspace|used"는 존재해도 값이 부정확했습니다.)
$StatKeysDatastore = @{
    capacity_gb = "capacity|total_capacity"
    used_gb     = "capacity|used_space"
    free_gb     = "capacity|available_space"
}

# Datastore property 키.
# ⚠️ 미확인 - "summary|isLocal" 로 추정(다른 summary|* 키들과 동일한 네이밍 패턴).
#    uuid_url은 vSphere 표준 객체모델의 summary.url(예: "ds:///vmfs/volumes/<UUID>/")에
#    UUID가 포함되어 있어, 같은 물리 데이터스토어가 여러 vCenter/리소스로 중복 발견되는
#    경우를 식별하는 키로 추정했습니다. 정확한 값은 Test-VmProperties.ps1 -ResourceKind
#    Datastore 로 확인 가능합니다.
$PropertyKeysDatastore = @{
    is_local = "summary|isLocal"
    uuid_url = "summary|url"
}

# "vSphere World" 리소스(인프라 전체를 대표하는 단일 객체) 레벨 statKey.
# 출처: https://www.brockpeterson.com/post/pulling-vsphere-world-metrics-from-vcf-operations
# 클러스터/호스트/VM 등 인벤토리 "수량"의 시계열 비교는 이 객체 하나에서 직접 조회합니다
# (클러스터별로 합산하는 방식이 아님 - 더 정확하고 공식적으로 확인된 방법).
$StatKeysWorld = @{
    vcenter_count    = "summary|total_number_vcenters"
    datacenter_count = "summary|total_number_datacenters"
    cluster_count    = "summary|total_number_clusters"
    host_count       = "summary|total_number_hosts"
    vm_count         = "summary|total_number_vms"
}

$StatKeysHost = @{
    cpu_usage_pct      = "cpu|usage_average"         # 확인됨
    mem_usage_pct      = "mem|usage_average"         # 확인됨
    cpu_contention_pct = "cpu|max_cpu_ready"         # 확인됨 (호스트엔 contentionPct 키가 없어 ready% 로 대체)
    mem_contention_pct = "mem|host_contentionPct"    # 확인됨
}

$StatKeysVM = @{
    cpu_usage_pct          = "cpu|usage_average"        # 확인됨
    cpu_ready_pct          = "cpu|readyPct"             # 확인됨 (※ _average 접미사 없음)
    mem_usage_pct          = "mem|usage_average"        # 확인됨
    mem_active_kb          = "mem|active_average"       # 확인됨
    disk_latency_ms        = "virtualDisk:Aggregate of all instances|totalLatency"               # 확인됨
    disk_read_latency_ms   = "virtualDisk:Aggregate of all instances|totalReadLatency_average"    # 확인됨
    disk_write_latency_ms  = "virtualDisk:Aggregate of all instances|totalWriteLatency_average"   # 확인됨
    disk_read_iops         = "virtualDisk:Aggregate of all instances|numberReadAveraged_average"  # 확인됨 (read+write 합산해서 IOPS로 사용)
    disk_write_iops        = "virtualDisk:Aggregate of all instances|numberWriteAveraged_average" # 확인됨
    net_throughput_kbps    = "net|usage_average"        # 확인됨 (throughput_usage_average는 존재하지 않았음)
}

$PropertyKeysVM = @{
    guest_os                    = "config|guestFullName"            # 확인됨
    hw_version                  = "config|version"                  # 확인됨 (실제 데이터로 검증, vmx-15 등 반환)
    vmtools_version              = "summary|guest|toolsVersion"       # 확인됨 (12.4.5)
    vmtools_status               = "summary|guest|toolsRunningStatus" # 확인됨 ("Guest Tools Running")
    vmtools_version_status      = "summary|guest|toolsVersionStatus2" # 확인됨 (※ 끝에 "2" 붙음, "Guest Tools Unmanaged")
    power_state                 = "summary|runtime|powerState"        # 확인됨 ("Powered On")
    vcpu_num                    = "config|hardware|numCpu"            # 확인됨
    vmem_kb                      = "config|hardware|memoryKB"          # 확인됨 (※ MB가 아니라 KB, 단위 변환 수정 필요)
}

# 디스크는 "config|hardware|disk{N}|..." 형태가 아니라
# "virtualDisk:scsi0:0|..." (SCSI 컨트롤러:유닛 표기) 형태로 확인되었습니다.
$DiskPropertySuffix = @{
    capacity_gb    = "configuredGB"        # 확인됨 (※ 이미 GB 단위, 추가 변환 불필요)
    provisioning   = "provisioning_type"   # 확인됨 (문자열, 예: "Thin Provision")
    datastore      = "datastore"           # 확인됨
    label          = "label"               # 확인됨 (예: "Hard disk 1")
    shared         = "shared"              # ⚠️ 미확인 - 이 VM은 공유디스크가 없어 예시가 없었음. 없으면 false로 처리됨(공유 아닌 디스크엔 정상 동작)
}

# 스냅샷은 "summary|snapshot|*" 가 아니라 "diskspace|snapshot|*" 형태였습니다.
$PropertyKeysSnapshot = @{
    snapshot_age_days = "diskspace|snapshot|snapshotAge"   # 확인됨 (값이 -1이면 스냅샷 없음, 0 이상이면 보존일수)
}
# 스냅샷 용량은 property가 아니라 stat(시계열)으로 확인되었습니다 ("diskspace|snapshot", VM stats).
$StatKeySnapshotSizeGb = "diskspace|snapshot"


# ---- inlined from Operations/Modules/VCFOpsApiClient.psm1 ----
# VCFOpsApiClient.psm1
# -----------------------------------------------------------------------------
# VCF Operations (Aria Operations / vRealize Operations) suite-api 클라이언트
#
#   인증:        POST /suite-api/api/auth/token/acquire
#   리소스 목록:  GET  /suite-api/api/resources
#   관계(상하위): GET  /suite-api/api/resources/{id}/relationships
#   속성:        GET  /suite-api/api/resources/{id}/properties
#   통계(다건):   POST /suite-api/api/resources/stats/query   (대량 조회는 이 엔드포인트 권장)
#
# PowerShell 7+ 기준으로 작성했습니다(Invoke-RestMethod -SkipCertificateCheck 사용).
# Windows PowerShell 5.1에서 자체서명 인증서를 건너뛰려면 별도의 인증서 콜백 설정이
# 필요하니, 가능하면 PowerShell 7+ (pwsh) 사용을 권장합니다.
# -----------------------------------------------------------------------------

$Script:VCFOpsSession = $null

function Connect-VCFOps {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$HostUrl,
        [Parameter(Mandatory)][string]$Username,
        [Parameter(Mandatory)][string]$Password,
        [string]$AuthSource = "LOCAL",
        [switch]$SkipCertCheck,
        [int]$TimeoutSec = 60
    )
    $base = $HostUrl.TrimEnd('/')
    $bodyObj = @{ username = $Username; password = $Password; authSource = $AuthSource }
    $bodyJson = $bodyObj | ConvertTo-Json

    $irmParams = @{
        Method      = "POST"
        Uri         = "$base/suite-api/api/auth/token/acquire"
        Body        = $bodyJson
        ContentType = "application/json"
        Headers     = @{ Accept = "application/json" }
        TimeoutSec  = $TimeoutSec
    }
    if ($SkipCertCheck) { $irmParams["SkipCertificateCheck"] = $true }

    try {
        $resp = Invoke-RestMethod @irmParams
    }
    catch {
        throw "VCF Operations Login failed: $($_.Exception.Message)"
    }

    $token = $resp.token
    if (-not $token) {
        throw "Could not find a token in the login response: $($resp | ConvertTo-Json -Depth 3 -Compress)"
    }

    $Script:VCFOpsSession = @{
        BaseUrl       = $base
        Token         = $token
        Username      = $Username
        Password      = $Password
        AuthSource    = $AuthSource
        SkipCertCheck = [bool]$SkipCertCheck
        TimeoutSec    = $TimeoutSec
    }
    Write-Verbose "VCF Operations login succeeded ($base)"
    return $Script:VCFOpsSession
}

function Disconnect-VCFOps {
    [CmdletBinding()]
    param()
    if (-not $Script:VCFOpsSession) { return }
    try {
        Invoke-VCFOpsApi -Method POST -Path "/suite-api/api/auth/token/release" -AllowRetry:$false | Out-Null
        Write-Verbose "VCF Operations logout complete"
    }
    catch {
        Write-Verbose "Error during logout (ignored): $($_.Exception.Message)"
    }
    $Script:VCFOpsSession = $null
}

function Invoke-VCFOpsApi {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$Method,
        [Parameter(Mandatory)][string]$Path,
        [hashtable]$QueryParams,
        $Body,
        [switch]$AllowRetry = $true
    )
    if (-not $Script:VCFOpsSession) {
        throw "Not connected to VCF Operations. Call Connect-VCFOps first."
    }

    $uri = "$($Script:VCFOpsSession.BaseUrl)$Path"
    $headers = @{
        Authorization = "vRealizeOpsToken $($Script:VCFOpsSession.Token)"
        Accept        = "application/json"
    }

    $irmParams = @{
        Method      = $Method
        Uri         = $uri
        Headers     = $headers
        ContentType = "application/json"
        TimeoutSec  = $Script:VCFOpsSession.TimeoutSec
    }
    if ($Script:VCFOpsSession.SkipCertCheck) { $irmParams["SkipCertificateCheck"] = $true }
    if ($QueryParams) { $irmParams["Body"] = $QueryParams }                      # GET -> 쿼리스트링 자동 변환
    if ($null -ne $Body) { $irmParams["Body"] = ($Body | ConvertTo-Json -Depth 8) }  # POST -> JSON 본문

    try {
        return Invoke-RestMethod @irmParams
    }
    catch {
        $statusCode = $null
        if ($_.Exception.Response) {
            try { $statusCode = [int]$_.Exception.Response.StatusCode } catch { $statusCode = $null }
        }
        if ($statusCode -eq 401 -and $AllowRetry) {
            Write-Verbose "Token expired - attempting to log in again"
            Connect-VCFOps -HostUrl $Script:VCFOpsSession.BaseUrl -Username $Script:VCFOpsSession.Username `
                -Password $Script:VCFOpsSession.Password -AuthSource $Script:VCFOpsSession.AuthSource `
                -SkipCertCheck:$Script:VCFOpsSession.SkipCertCheck -TimeoutSec $Script:VCFOpsSession.TimeoutSec | Out-Null
            return Invoke-VCFOpsApi -Method $Method -Path $Path -QueryParams $QueryParams -Body $Body -AllowRetry:$false
        }
        throw "VCFOps API call failed [$Method $Path]: $($_.Exception.Message)"
    }
}

function Get-VCFOpsResources {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$ResourceKind,
        [string]$AdapterKind = "VMWARE",
        [int]$PageSize = 1000,
        [int]$MaxPages = 50
    )
    $results = @()
    $page = 0
    while ($page -lt $MaxPages) {
        $q = @{ resourceKind = $ResourceKind; adapterKind = $AdapterKind; pageSize = $PageSize; page = $page }
        $data = Invoke-VCFOpsApi -Method GET -Path "/suite-api/api/resources" -QueryParams $q
        $chunk = @($data.resourceList)
        $results += $chunk
        $totalPages = 1
        if ($data.pageInfo -and $data.pageInfo.totalPages) { $totalPages = $data.pageInfo.totalPages }
        $page++
        if ($page -ge $totalPages -or $chunk.Count -eq 0) { break }
    }
    Write-Verbose "Queried $($results.Count) $ResourceKind resource(s)"
    return $results
}

function Get-VCFOpsChildren {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$ResourceId,
        [Parameter(Mandatory)][string]$ChildResourceKind,
        [int]$PageSize = 1000,
        [int]$MaxPages = 20
    )
    $out = @()
    $page = 0
    while ($page -lt $MaxPages) {
        try {
            $data = Invoke-VCFOpsApi -Method GET -Path "/suite-api/api/resources/$ResourceId/relationships" `
                -QueryParams @{ relationshipType = "CHILD"; page = $page; pageSize = $PageSize }
        }
        catch {
            Write-Warning "Failed to query relationships ($ResourceId): $($_.Exception.Message)"
            return $out
        }
        $chunk = @($data.resourceList)
        foreach ($r in $chunk) {
            if ($r.resourceKey.resourceKindKey -eq $ChildResourceKind) { $out += $r.identifier }
        }
        $totalPages = 1
        if ($data.pageInfo -and $data.pageInfo.totalPages) { $totalPages = $data.pageInfo.totalPages }
        $page++
        if ($page -ge $totalPages -or $chunk.Count -eq 0) { break }
    }
    return $out
}

function Get-VCFOpsProperties {
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$ResourceId)
    $data = Invoke-VCFOpsApi -Method GET -Path "/suite-api/api/resources/$ResourceId/properties"
    $out = @{}
    foreach ($p in @($data.property)) {
        $out[$p.name] = $p.value
    }
    return $out
}

function Get-VCFOpsStatsQuery {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string[]]$ResourceIds,
        [Parameter(Mandatory)][string[]]$StatKeys,
        [Parameter(Mandatory)][long]$BeginMs,
        [Parameter(Mandatory)][long]$EndMs,
        [string]$RollUpType = "AVG",
        [string]$IntervalType = "HOURS",
        [int]$IntervalQuantity = 1,
        [int]$BatchSize = 200
    )
    $out = @{}
    if (-not $ResourceIds -or $ResourceIds.Count -eq 0) { return $out }

    for ($i = 0; $i -lt $ResourceIds.Count; $i += $BatchSize) {
        $endIdx = [Math]::Min($i + $BatchSize, $ResourceIds.Count) - 1
        $chunk = $ResourceIds[$i..$endIdx]
        $body = @{
            resourceId       = @($chunk)
            statKey          = @($StatKeys)
            begin            = $BeginMs
            end              = $EndMs
            rollUpType       = $RollUpType
            intervalType     = $IntervalType
            intervalQuantity = $IntervalQuantity
        }
        $data = Invoke-VCFOpsApi -Method POST -Path "/suite-api/api/resources/stats/query" -Body $body
        foreach ($v in @($data.values)) {
            $rid = $v.resourceId
            if (-not $out.ContainsKey($rid)) { $out[$rid] = @{} }
            foreach ($s in @($v.'stat-list'.stat)) {
                $key = $s.statKey.key
                $out[$rid][$key] = @($s.data)
            }
        }
    }
    return $out
}

function Get-VCFOpsStatsLatest {
    # 최신 값 - cpu/mem 현재 사용률 등에 사용
    # 윈도우를 3시간으로 넉넉히 잡은 이유: 클러스터 레벨 등 일부 supermetric은
    # 집계 주기가 길어 30분 윈도우로는 값이 비어있는 경우가 실제 환경에서 확인됨.
    [CmdletBinding()]
    param(
        [string[]]$ResourceIds,
        [Parameter(Mandatory)][string[]]$StatKeys,
        [int]$BatchSize = 200,
        [int]$WindowMinutes = 180
    )
    $out = @{}
    if (-not $ResourceIds -or $ResourceIds.Count -eq 0) { return $out }

    $endMs = [DateTimeOffset]::UtcNow.ToUnixTimeMilliseconds()
    $beginMs = $endMs - ($WindowMinutes * 60 * 1000)
    $raw = Get-VCFOpsStatsQuery -ResourceIds $ResourceIds -StatKeys $StatKeys -BeginMs $beginMs -EndMs $endMs `
        -IntervalType "MINUTES" -IntervalQuantity 5 -BatchSize $BatchSize

    foreach ($rid in $raw.Keys) {
        $out[$rid] = @{}
        foreach ($k in $raw[$rid].Keys) {
            $vals = $raw[$rid][$k]
            $out[$rid][$k] = if ($vals.Count -gt 0) { [double]$vals[$vals.Count - 1] } else { 0.0 }
        }
    }
    return $out
}

function Get-VCFOpsStatsPointInTime {
    # 특정 시점(예: 7일 전) 기준 평균값 조회 - WoW 비교용
    [CmdletBinding()]
    param(
        [string[]]$ResourceIds,
        [Parameter(Mandatory)][string[]]$StatKeys,
        [Parameter(Mandatory)][long]$AtMs,
        [int]$WindowMinutes = 60,
        [int]$BatchSize = 200
    )
    $out = @{}
    if (-not $ResourceIds -or $ResourceIds.Count -eq 0) { return $out }

    $beginMs = $AtMs - ($WindowMinutes * 60 * 1000)
    $endMs = $AtMs + ($WindowMinutes * 60 * 1000)
    $raw = Get-VCFOpsStatsQuery -ResourceIds $ResourceIds -StatKeys $StatKeys -BeginMs $beginMs -EndMs $endMs `
        -IntervalType "MINUTES" -IntervalQuantity 5 -BatchSize $BatchSize

    foreach ($rid in $raw.Keys) {
        $out[$rid] = @{}
        foreach ($k in $raw[$rid].Keys) {
            $vals = $raw[$rid][$k]
            $out[$rid][$k] = if ($vals.Count -gt 0) { ($vals | Measure-Object -Average).Average } else { 0.0 }
        }
    }
    return $out
}


# ---- inlined from Operations/Modules/VCFOpsSnapshotCache.psm1 ----
# VCFOpsSnapshotCache.psm1
# -----------------------------------------------------------------------------
# 인벤토리 수량(DC/클러스터/호스트/VM 대수) 및 평균 성능치는 vROps/Aria Operations에
# 깨끗한 시계열로 노출되지 않는 경우가 많아, 매 실행 시점의 값을 로컬 JSON으로
# 저장해두고 다음 실행에서 N일 전 저장본과 비교하는 방식을 사용합니다.
#
# 운영 시나리오: 주 1회(예: Windows 작업 스케줄러, cron) 이 스크립트를 실행하면
# snapshots/YYYY-MM-DD.json 파일이 누적되고, 항상 직전 실행과 자동 비교됩니다.
# -----------------------------------------------------------------------------

function Save-InventorySnapshot {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][datetime]$Date,
        [Parameter(Mandatory)][hashtable]$Payload,
        [string]$CacheDir = "./snapshots"
    )
    if (-not (Test-Path -Path $CacheDir)) {
        New-Item -ItemType Directory -Path $CacheDir -Force | Out-Null
    }
    $path = Join-Path $CacheDir ("{0:yyyy-MM-dd}.json" -f $Date)
    $Payload | ConvertTo-Json -Depth 8 | Set-Content -Path $path -Encoding utf8
}

function Get-ClosestSnapshot {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][datetime]$TargetDate,
        [string]$CacheDir = "./snapshots",
        [int]$ToleranceDays = 3
    )
    if (-not (Test-Path -Path $CacheDir)) { return $null }

    $best = $null
    $bestDiff = $null
    $files = Get-ChildItem -Path $CacheDir -Filter "*.json" -ErrorAction SilentlyContinue
    foreach ($file in $files) {
        $name = $file.BaseName
        $d = [datetime]::MinValue
        $ok = [datetime]::TryParseExact(
            $name, "yyyy-MM-dd",
            [System.Globalization.CultureInfo]::InvariantCulture,
            [System.Globalization.DateTimeStyles]::None,
            [ref]$d
        )
        if (-not $ok) { continue }
        $diff = [Math]::Abs(($d - $TargetDate).Days)
        if ($diff -le $ToleranceDays -and ($null -eq $bestDiff -or $diff -lt $bestDiff)) {
            $best = $file.FullName
            $bestDiff = $diff
        }
    }
    if (-not $best) { return $null }
    return (Get-Content -Path $best -Raw -Encoding utf8 | ConvertFrom-Json)
}


# ---- inlined from Operations/Modules/VCFOpsCollector.psm1 ----
# VCFOpsCollector.psm1
# -----------------------------------------------------------------------------
# VCFOpsApiClient 모듈을 사용해 실제 VCF Operations 환경에서 리포트 데이터를
# 구성합니다. (Python 버전 vcfops/collector.py 와 동일한 처리 단계)
#
#   1) 리소스 인벤토리 조회 + 관계(상하위) 매핑
#   2) 인벤토리 수량 WoW 비교 (SnapshotCache)
#   3) 클러스터/호스트 성능 통계 일괄 조회
#   4) VM 성능 통계 일괄 조회 -> Top10 도출
#   5) VM properties 일괄 조회 (인벤토리 상세)
#
# 성능 주의: VM properties 조회는 리소스 1건당 API 1회 호출이 필요해 VM 수가
# 많을수록 시간이 걸립니다. -MaxVMs 로 범위를 제한해 먼저 테스트하세요.
# PowerShell 7+ 사용 시 ForEach-Object -Parallel 로 가속할 수 있습니다(README 참조).
# -----------------------------------------------------------------------------


# 확인된 실제 포맷: "virtualDisk:scsi0:0|attr" (SCSI 컨트롤러:유닛 표기), "config|hardware|disk{N}|..." 아님
$Script:DiskPropPattern = '^virtualDisk:([^|]+)\|(.+)$'

function Protect-VCFOpsHostIdentifier {
    # ESXi 호스트 식별자(리소스명)를 리포트에 내보내기 전에 마스킹합니다.
    #   - FQDN (예: esx01.corp.local)  -> 호스트명은 유지하고 도메인만 "vcf.local"로 치환 (esx01.vcf.local)
    #   - IPv4 주소 (예: 192.168.10.55) -> 앞 3옥텟을 "***"로 마스킹, 마지막 옥텟만 유지 (***.***.***.55)
    #   - 도메인이 없는 짧은 이름(예: esx-prd1-01)은 그대로 반환
    # 리포트(HTML/Excel/CSV)에 실제 사내 도메인/IP가 노출되지 않도록, 호스트 식별자가
    # 파이프라인에 들어오는 지점(아래 $hostName 매핑) 한 곳에서만 적용해 이후 모든 화면
    # (ESXi 호스트 Top10, VM 인벤토리의 Host 컬럼, VM Top 리스트의 Host 컬럼 등)에 일괄 반영됩니다.
    [CmdletBinding()]
    param([string]$Value)

    if ([string]::IsNullOrWhiteSpace($Value)) { return $Value }

    # IPv4 주소 형태 - 4개 옥텟 전체가 숫자인 경우만 매칭 (FQDN보다 먼저 검사)
    if ($Value -match '^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$') {
        return "***.***.***.$($Matches[4])"
    }

    # FQDN 형태 - 첫 번째 라벨(호스트명)만 유지하고 나머지 도메인 부분을 vcf.local로 치환
    if ($Value -match '^([^.]+)\.(.+)$') {
        return "$($Matches[1]).***.***"
    }

    return $Value
}

function Get-MapValueOrDefault {
    param([hashtable]$Map, $Key, $Default = "")
    if ($Map -and $Map.ContainsKey($Key)) { return $Map[$Key] }
    return $Default
}

function ConvertTo-VDiskList {
    param([hashtable]$Props)
    $byIdx = [ordered]@{}
    foreach ($key in $Props.Keys) {
        if ($key -match $Script:DiskPropPattern) {
            $idx = $Matches[1]; $attr = $Matches[2]
            if (-not $byIdx.Contains($idx)) { $byIdx[$idx] = @{} }
            $byIdx[$idx][$attr] = $Props[$key]
        }
    }
    $disks = @()
    foreach ($idx in $byIdx.Keys) {
        $attrs = $byIdx[$idx]
        $capGb = ConvertTo-SafeDouble (Get-MapValueOrDefault $attrs $DiskPropertySuffix.capacity_gb)
        $provRaw = "$(Get-MapValueOrDefault $attrs $DiskPropertySuffix.provisioning '')"
        $isThin = $provRaw -match "(?i)thin"
        $shared = ("$(Get-MapValueOrDefault $attrs $DiskPropertySuffix.shared)").ToLower() -in @("true", "yes")
        $datastore = Get-MapValueOrDefault $attrs $DiskPropertySuffix.datastore ""
        $label = Get-MapValueOrDefault $attrs $DiskPropertySuffix.label "Disk $idx"

        # 이미 삭제(Deleted) 처리된 디스크는 라벨/유형/데이터스토어 중 어딘가에 "deleted"가
        # 남아있는 경우가 있어, 어느 필드든 포함되어 있으면 목록에서 제외합니다.
        $isDeleted = "$label $provRaw $datastore" -match "(?i)deleted"
        if ($isDeleted) { continue }

        $disks += [PSCustomObject]@{
            Label = $label; CapacityGb = [Math]::Round($capGb, 1)
            Provisioning = if ($provRaw) { $provRaw } elseif ($isThin) { "Thin" } else { "Thick" }
            ProvisioningKind = if ($isThin) { "Thin" } else { "Thick" }
            Datastore = $datastore; Shared = $shared
        }
    }
    return $disks
}

function Get-VCenterCount {
    # vCenter(어댑터 인스턴스) 수량. /suite-api/api/adapters 가 환경에 따라 다를 수 있어
    # 실패 시 0으로 처리하고 경고만 남깁니다.
    [CmdletBinding()]
    param()
    try {
        $data = Invoke-VCFOpsApi -Method GET -Path "/suite-api/api/adapters" -QueryParams @{ adapterKindKey = "VMWARE" }
        $items = @($data.adapterInstancesInfoDto)
        if (-not $items -or $items.Count -eq 0) { $items = @($data.'adapter-instances') }
        if (-not $items -or $items.Count -eq 0) { $items = @($data) }
        return [int]$items.Count
    }
    catch {
        Write-Warning "Failed to query vCenter (adapter) count - check the /suite-api/api/adapters response shape: $($_.Exception.Message)"
        return 0
    }
}

function Find-VCFOpsWorldResource {
    # "vSphere World"(인프라 전체를 대표하는 단일 리소스)를 찾습니다.
    # 1차: resourceKind를 UI 표시명과 동일한 "vSphere World"로 직접 시도
    # 2차: adapterKind=VMWARE 전체에서 resourceKindKey에 "world"가 포함된 리소스를 탐색 (폴백)
    [CmdletBinding()]
    param()

    try {
        $data = Invoke-VCFOpsApi -Method GET -Path "/suite-api/api/resources" `
            -QueryParams @{ resourceKind = "vSphere World"; pageSize = 10 }
        $found = @($data.resourceList) | Select-Object -First 1
        if ($found) { return $found }
    }
    catch { }

    try {
        $page = 0
        while ($page -lt 5) {
            $data = Invoke-VCFOpsApi -Method GET -Path "/suite-api/api/resources" `
                -QueryParams @{ adapterKind = "VMWARE"; pageSize = 1000; page = $page }
            foreach ($r in @($data.resourceList)) {
                if ($r.resourceKey.resourceKindKey -match "(?i)world") { return $r }
            }
            $totalPages = 1
            if ($data.pageInfo -and $data.pageInfo.totalPages) { $totalPages = $data.pageInfo.totalPages }
            $page++
            if ($page -ge $totalPages) { break }
        }
    }
    catch {
        Write-Warning "Failed to discover the vSphere World resource: $($_.Exception.Message)"
    }
    return $null
}

function Get-InventoryCountsWithDelta {
    param($DcList, $ClusterList, $HostList, $VmList, [int]$VCenterCount, [datetime]$Now,
          [int]$CompareDaysAgo, [string]$CacheDir, [bool]$CompareEnabled)

    $curr = [ordered]@{
        "vCenter"     = $VCenterCount
        "데이터센터"  = $DcList.Count
        "클러스터"    = $ClusterList.Count
        "ESXi 호스트" = $HostList.Count
        "가상머신"    = $VmList.Count
    }
    $labelToMetricKey = [ordered]@{
        "vCenter"     = $StatKeysWorld.vcenter_count
        "데이터센터"  = $StatKeysWorld.datacenter_count
        "클러스터"    = $StatKeysWorld.cluster_count
        "ESXi 호스트" = $StatKeysWorld.host_count
        "가상머신"    = $StatKeysWorld.vm_count
    }

    # 1) "vSphere World" 리소스에서 5개 수량을 모두 한 번에 시도 (넓은 조회 윈도우 사용)
    $metricPrev = @{}
    if ($CompareEnabled) {
        $world = Find-VCFOpsWorldResource
        if ($world) {
            Write-Verbose "Found the vSphere World resource: $($world.resourceKey.name) ($($world.identifier))"
            $atMs = [DateTimeOffset]::new($Now.AddDays(-$CompareDaysAgo)).ToUnixTimeMilliseconds()
            $keys = @($labelToMetricKey.Values)
            $lookup = $null
            try {
                $lookup = Get-VCFOpsStatsPointInTime -ResourceIds @($world.identifier) -StatKeys $keys -AtMs $atMs -WindowMinutes 720
            }
            catch { Write-Warning "Failed to query vSphere World statistics: $($_.Exception.Message)" }

            if ($lookup -and $lookup.ContainsKey($world.identifier)) {
                $vals = $lookup[$world.identifier]
                foreach ($label in $labelToMetricKey.Keys) {
                    $mk = $labelToMetricKey[$label]
                    if ($vals.ContainsKey($mk)) {
                        $metricPrev[$label] = [int][Math]::Round((ConvertTo-SafeDouble $vals[$mk]))
                    }
                }
            }
            if ($metricPrev.Count -gt 0) {
                Write-Verbose "Inventory counts - compared using vSphere World metrics: $($metricPrev.Keys -join ', ')"
            }
            else {
                Write-Warning "Found the vSphere World resource but could not find a count metric for that point in time - falling back to cache comparison."
            }
        }
        else {
            Write-Warning "Could not find the vSphere World resource - falling back to cache comparison."
        }
    }

    # 2) 메트릭으로 못 채운 항목은 로컬 캐시로 비교
    $cachePrev = $null
    if ($CompareEnabled) {
        $prevSnap = Get-ClosestSnapshot -TargetDate $Now.AddDays(-$CompareDaysAgo) -CacheDir $CacheDir
        if ($prevSnap -and $prevSnap.counts) { $cachePrev = $prevSnap.counts }
    }
    # 비교 여부와 무관하게 오늘자 스냅샷은 항상 저장 (다음에 비교할 수 있도록 이력 축적)
    Save-InventorySnapshot -Date $Now -Payload @{ counts = $curr; timestamp = $Now.ToString("o") } -CacheDir $CacheDir

    $result = @()
    foreach ($k in $curr.Keys) {
        $c = $curr[$k]
        $p = $c; $has = $false; $source = ""
        if ($metricPrev.ContainsKey($k)) {
            $p = $metricPrev[$k]; $has = $true; $source = "metric"
        }
        elseif ($cachePrev) {
            $v = $cachePrev.$k
            if ($null -ne $v) { $p = [int]$v; $has = $true; $source = "cache" }
        }
        $deltaPct = if ($has -and $p -ne 0) { [Math]::Round((($c - $p) / [double]$p) * 100, 1) } else { 0.0 }
        $result += [PSCustomObject]@{
            Label = $k; Current = $c; Previous = $p
            Delta = ($c - $p); DeltaPct = $deltaPct; HasComparison = $has; CompareSource = $source
        }
    }
    if ($CompareEnabled -and -not $cachePrev -and $metricPrev.Count -eq 0) {
        Write-Warning "Inventory counts: no comparison data from $CompareDaysAgo day(s) ago was found, so this is shown without a comparison (the snapshot cache needs to accumulate more history)."
    }
    return $result
}

function Get-ClusterMetricsFromApi {
    param($ClusterList, [hashtable]$ClusterDc, [hashtable]$HostCluster, [hashtable]$HostVmMap, [hashtable]$DcName,
          [hashtable]$StatsLookup = $null)

    $ids = @($ClusterList | ForEach-Object { $_.identifier })
    $keys = @($StatKeysCluster.Values)
    $latest = if ($StatsLookup) { $StatsLookup }
              elseif ($ids.Count -gt 0) { Get-VCFOpsStatsLatest -ResourceIds $ids -StatKeys $keys }
              else { @{} }

    $clusterHosts = @{}
    foreach ($hid in $HostCluster.Keys) {
        $cid = $HostCluster[$hid]
        if (-not $clusterHosts.ContainsKey($cid)) { $clusterHosts[$cid] = @() }
        $clusterHosts[$cid] += $hid
    }

    $result = @()
    foreach ($c in $ClusterList) {
        $cid = $c.identifier
        $name = $c.resourceKey.name
        $dcId = Get-MapValueOrDefault $ClusterDc $cid $null
        $dc = if ($dcId -and $DcName.ContainsKey($dcId)) { $DcName[$dcId] } else { "" }
        $s = if ($latest.ContainsKey($cid)) { $latest[$cid] } else { @{} }

        $cpuUsagePct = ConvertTo-SafeDouble (Get-MapValueOrDefault $s $StatKeysCluster.cpu_usage_pct)
        $cpuCapMhz = ConvertTo-SafeDouble (Get-MapValueOrDefault $s $StatKeysCluster.cpu_capacity_mhz)
        if ($cpuCapMhz -eq 0) { $cpuCapMhz = 1.0 }
        $cpuUsedGhz = [Math]::Round($cpuCapMhz * $cpuUsagePct / 100 / 1000, 1)
        $cpuTotalGhz = [Math]::Round($cpuCapMhz / 1000, 1)

        $memCapKb = ConvertTo-SafeDouble (Get-MapValueOrDefault $s $StatKeysCluster.mem_capacity_kb)
        if ($memCapKb -eq 0) { $memCapKb = 1.0 }
        $memUsagePct = ConvertTo-SafeDouble (Get-MapValueOrDefault $s $StatKeysCluster.mem_usage_pct)
        $memUsedGb = [Math]::Round($memCapKb * $memUsagePct / 100 / 1024 / 1024, 1)
        $memTotalGb = [Math]::Round($memCapKb / 1024 / 1024, 1)

        $storageUsedGb = ConvertTo-SafeDouble (Get-MapValueOrDefault $s $StatKeysCluster.storage_used_gb)
        $storageTotalGb = ConvertTo-SafeDouble (Get-MapValueOrDefault $s $StatKeysCluster.storage_total_gb)
        if ($storageTotalGb -eq 0) { $storageTotalGb = 1.0 }

        $hostIds = if ($clusterHosts.ContainsKey($cid)) { $clusterHosts[$cid] } else { @() }
        $vmCount = 0
        foreach ($hid in $hostIds) {
            if ($HostVmMap.ContainsKey($hid)) { $vmCount += $HostVmMap[$hid].Count }
        }

        $cpuPct = if ($cpuTotalGhz -gt 0) { [Math]::Round($cpuUsedGhz / $cpuTotalGhz * 100, 1) } else { 0.0 }
        $memPct = if ($memTotalGb -gt 0) { [Math]::Round($memUsedGb / $memTotalGb * 100, 1) } else { 0.0 }
        $storageUsedTb = [Math]::Round($storageUsedGb / 1024, 2)
        $storageTotalTb = [Math]::Round($storageTotalGb / 1024, 2)
        $storagePct = if ($storageTotalTb -gt 0) { [Math]::Round($storageUsedTb / $storageTotalTb * 100, 1) } else { 0.0 }
        $storageFreeTb = [Math]::Round($storageTotalTb - $storageUsedTb, 2)

        $cpuContentionPct = [Math]::Round((ConvertTo-SafeDouble (Get-MapValueOrDefault $s $StatKeysCluster.cpu_contention_pct)), 1)
        $storageLatencyMs = [Math]::Round((ConvertTo-SafeDouble (Get-MapValueOrDefault $s $StatKeysCluster.storage_latency_ms)), 1)

        $worst = [Math]::Max([Math]::Max($cpuPct, $memPct), $storagePct)
        $status = if ($worst -ge 85 -or $cpuContentionPct -ge 10) { "critical" }
                  elseif ($worst -ge 70 -or $cpuContentionPct -ge 5) { "warning" }
                  else { "normal" }

        $result += [PSCustomObject]@{
            Name = $name; Datacenter = $dc; HostCount = $hostIds.Count; VmCount = $vmCount
            CpuUsedGhz = $cpuUsedGhz; CpuTotalGhz = $cpuTotalGhz; CpuPct = $cpuPct
            MemUsedGb = $memUsedGb; MemTotalGb = $memTotalGb; MemPct = $memPct
            StorageUsedTb = $storageUsedTb; StorageTotalTb = $storageTotalTb; StoragePct = $storagePct
            StorageFreeTb = $storageFreeTb
            CpuContentionPct = $cpuContentionPct; StorageLatencyMs = $storageLatencyMs
            Status = $status
        }
    }
    return $result
}

function Merge-ClusterPrevious {
    # 현재 클러스터 목록에 과거 시점(prevClusters) 값을 같은 순서로 병합합니다.
    # 두 목록 모두 동일한 $ClusterList 에서 생성되므로 이름 기준으로 매칭합니다.
    param($Clusters, $PrevClusters, [bool]$CompareEnabled)

    $prevByName = @{}
    foreach ($pc in $PrevClusters) { $prevByName[$pc.Name] = $pc }

    foreach ($c in $Clusters) {
        $pc = if ($prevByName.ContainsKey($c.Name)) { $prevByName[$c.Name] } else { $null }
        $has = [bool]($CompareEnabled -and $pc)
        $prevCpu = if ($pc) { $pc.CpuPct } else { $c.CpuPct }
        $prevMem = if ($pc) { $pc.MemPct } else { $c.MemPct }
        $prevStorage = if ($pc) { $pc.StoragePct } else { $c.StoragePct }
        $prevCont = if ($pc) { $pc.CpuContentionPct } else { $c.CpuContentionPct }
        $c | Add-Member -MemberType NoteProperty -Name PrevCpuPct -Value $prevCpu
        $c | Add-Member -MemberType NoteProperty -Name PrevMemPct -Value $prevMem
        $c | Add-Member -MemberType NoteProperty -Name PrevStoragePct -Value $prevStorage
        $c | Add-Member -MemberType NoteProperty -Name PrevCpuContentionPct -Value $prevCont
        $c | Add-Member -MemberType NoteProperty -Name HasComparison -Value $has
    }
    return $Clusters
}

function Get-HostMetricsFromApi {
    param($HostList, [hashtable]$HostCluster, [hashtable]$ClusterName)

    $ids = @($HostList | ForEach-Object { $_.identifier })
    $keys = @($StatKeysHost.Values)
    $latest = if ($ids.Count -gt 0) { Get-VCFOpsStatsLatest -ResourceIds $ids -StatKeys $keys } else { @{} }

    $result = @()
    foreach ($h in $HostList) {
        $hid = $h.identifier
        $s = if ($latest.ContainsKey($hid)) { $latest[$hid] } else { @{} }
        $cid = Get-MapValueOrDefault $HostCluster $hid $null
        $cpuPct = [Math]::Round((ConvertTo-SafeDouble (Get-MapValueOrDefault $s $StatKeysHost.cpu_usage_pct)), 1)
        $memPct = [Math]::Round((ConvertTo-SafeDouble (Get-MapValueOrDefault $s $StatKeysHost.mem_usage_pct)), 1)
        $cpuContentionPct = [Math]::Round((ConvertTo-SafeDouble (Get-MapValueOrDefault $s $StatKeysHost.cpu_contention_pct)), 1)
        $worst = [Math]::Max($cpuPct, $memPct)
        $status = if ($worst -ge 85 -or $cpuContentionPct -ge 10) { "critical" }
                  elseif ($worst -ge 70 -or $cpuContentionPct -ge 5) { "warning" }
                  else { "normal" }

        $result += [PSCustomObject]@{
            Name = Protect-VCFOpsHostIdentifier -Value $h.resourceKey.name
            Cluster = if ($cid -and $ClusterName.ContainsKey($cid)) { $ClusterName[$cid] } else { "" }
            CpuPct = $cpuPct; MemPct = $memPct
            CpuContentionPct = $cpuContentionPct
            MemContentionPct = [Math]::Round((ConvertTo-SafeDouble (Get-MapValueOrDefault $s $StatKeysHost.mem_contention_pct)), 1)
            Status = $status
        }
    }
    return $result
}

function Get-VcpuCountMap {
    param([string[]]$Names, $VmList)
    $nameToId = @{}
    foreach ($v in $VmList) {
        if ($Names -contains $v.resourceKey.name) { $nameToId[$v.resourceKey.name] = $v.identifier }
    }
    $out = @{}
    foreach ($name in $nameToId.Keys) {
        try {
            $props = Get-VCFOpsProperties -ResourceId $nameToId[$name]
            $out[$name] = [int](ConvertTo-SafeDouble (Get-MapValueOrDefault $props $PropertyKeysVM.vcpu_num))
        }
        catch {
            Write-Warning "Failed to query vCPU properties ($name): $($_.Exception.Message)"
            $out[$name] = 0
        }
    }
    return $out
}

function Get-VmPerformanceFromApi {
    param($VmList, [hashtable]$VmHost, [hashtable]$HostName, [hashtable]$HostCluster, [hashtable]$ClusterName)

    $ids = @($VmList | ForEach-Object { $_.identifier })
    $keys = @($StatKeysVM.Values)
    $latest = if ($ids.Count -gt 0) { Get-VCFOpsStatsLatest -ResourceIds $ids -StatKeys $keys } else { @{} }

    $vmPerformance = @()
    $topCpuRaw = @()
    $topReadyRaw = @()
    $diskLatRaw = @()

    foreach ($v in $VmList) {
        $vid = $v.identifier
        $name = $v.resourceKey.name
        $s = if ($latest.ContainsKey($vid)) { $latest[$vid] } else { @{} }
        $hid = Get-MapValueOrDefault $VmHost $vid $null
        $cid = if ($hid) { Get-MapValueOrDefault $HostCluster $hid $null } else { $null }
        $cluster = if ($cid -and $ClusterName.ContainsKey($cid)) { $ClusterName[$cid] } else { "" }
        $hostNm = if ($hid -and $HostName.ContainsKey($hid)) { $HostName[$hid] } else { "" }

        $cpuPct = [Math]::Round((ConvertTo-SafeDouble (Get-MapValueOrDefault $s $StatKeysVM.cpu_usage_pct)), 1)
        $readyPct = [Math]::Round((ConvertTo-SafeDouble (Get-MapValueOrDefault $s $StatKeysVM.cpu_ready_pct)), 2)
        $memPct = [Math]::Round((ConvertTo-SafeDouble (Get-MapValueOrDefault $s $StatKeysVM.mem_usage_pct)), 1)
        $memActiveGb = [Math]::Round((ConvertTo-SafeDouble (Get-MapValueOrDefault $s $StatKeysVM.mem_active_kb)) / 1024 / 1024, 1)
        $diskLat = [Math]::Round((ConvertTo-SafeDouble (Get-MapValueOrDefault $s $StatKeysVM.disk_latency_ms)), 1)
        $readLat = [Math]::Round((ConvertTo-SafeDouble (Get-MapValueOrDefault $s $StatKeysVM.disk_read_latency_ms)), 1)
        $writeLat = [Math]::Round((ConvertTo-SafeDouble (Get-MapValueOrDefault $s $StatKeysVM.disk_write_latency_ms)), 1)
        $readIops = ConvertTo-SafeDouble (Get-MapValueOrDefault $s $StatKeysVM.disk_read_iops)
        $writeIops = ConvertTo-SafeDouble (Get-MapValueOrDefault $s $StatKeysVM.disk_write_iops)
        $iops = [int]($readIops + $writeIops)
        $netMbps = [Math]::Round((ConvertTo-SafeDouble (Get-MapValueOrDefault $s $StatKeysVM.net_throughput_kbps)) / 1024, 1)

        $vmPerformance += [PSCustomObject]@{
            Name = $name; Cluster = $cluster
            CpuUsagePct = $cpuPct; CpuReadyPct = $readyPct
            MemUsagePct = $memPct; MemActiveGb = $memActiveGb
            DiskLatencyMs = $diskLat; DiskIops = $iops; NetThroughputMbps = $netMbps
        }
        $topCpuRaw += [PSCustomObject]@{ Name = $name; Cluster = $cluster; Host = $hostNm; Value = $cpuPct }
        $topReadyRaw += [PSCustomObject]@{ Name = $name; Cluster = $cluster; Host = $hostNm; Value = $readyPct }
        if ($readLat -gt 0 -or $writeLat -gt 0) {
            $diskLatRaw += [PSCustomObject]@{ Name = $name; Cluster = $cluster; Read = $readLat; Write = $writeLat }
        }
    }

    $topCpuSorted = @($topCpuRaw | Sort-Object -Property Value -Descending | Select-Object -First 10)
    $topReadySorted = @($topReadyRaw | Sort-Object -Property Value -Descending | Select-Object -First 10)

    $namesNeeded = @($topCpuSorted | ForEach-Object { $_.Name }) + @($topReadySorted | ForEach-Object { $_.Name }) | Select-Object -Unique
    $vcpuMap = Get-VcpuCountMap -Names $namesNeeded -VmList $VmList

    $topCpuVMs = @($topCpuSorted | ForEach-Object {
        $vc = if ($vcpuMap.ContainsKey($_.Name)) { $vcpuMap[$_.Name] } else { 0 }
        [PSCustomObject]@{ Name = $_.Name; Cluster = $_.Cluster; Host = $_.Host; VcpuCount = $vc; CpuUsagePct = $_.Value }
    })
    $topReadyVMs = @($topReadySorted | ForEach-Object {
        $vc = if ($vcpuMap.ContainsKey($_.Name)) { $vcpuMap[$_.Name] } else { 0 }
        [PSCustomObject]@{ Name = $_.Name; Cluster = $_.Cluster; Host = $_.Host; VcpuCount = $vc; CpuReadyPct = $_.Value }
    })

    $diskLatencyVMs = @($diskLatRaw | Sort-Object -Property { [Math]::Max($_.Read, $_.Write) } -Descending | Select-Object -First 10 | ForEach-Object {
        [PSCustomObject]@{ Name = $_.Name; Cluster = $_.Cluster; Datastore = "N/A"; ReadLatencyMs = $_.Read; WriteLatencyMs = $_.Write }
    })

    return [PSCustomObject]@{
        VmPerformance = $vmPerformance
        TopCpuVMs = $topCpuVMs
        TopReadyVMs = $topReadyVMs
        DiskLatencyVMs = $diskLatencyVMs
    }
}

function Merge-DiskLatencyDatastore {
    # 가상디스크 레이턴시 Top10 리스트의 Datastore는 VM 레벨 통계(여러 디스크 합산값)만으로는
    # 알 수 없어 "N/A"로 비어 있었습니다. VM 인벤토리(properties)에서 이미 파싱해 둔
    # 디스크별 데이터스토어 정보를 이름 기준으로 매칭해 채워줍니다.
    param($DiskLatencyVMs, $VmInventory)

    $byName = @{}
    foreach ($v in $VmInventory) { $byName[$v.Name] = $v }

    foreach ($row in $DiskLatencyVMs) {
        if ($byName.ContainsKey($row.Name)) {
            $vm = $byName[$row.Name]
            $dsNames = @($vm.Disks | ForEach-Object { $_.Datastore } | Where-Object { $_ } | Select-Object -Unique)
            if ($dsNames.Count -gt 0) {
                $row.Datastore = ($dsNames -join ", ")
            }
        }
    }
    return $DiskLatencyVMs
}

function Get-PrevClusters {
    # N일 전 시점의 클러스터 통계를 API로 직접 조회해 현재와 동일한 구조로 재구성합니다.
    # (Get-PerfSummaryWithDelta / Merge-ClusterPrevious 양쪽에서 재사용 - API 중복호출 방지)
    param($ClusterList, [hashtable]$ClusterDc, [hashtable]$HostCluster, [hashtable]$HostVmMap,
          [hashtable]$DcName, [datetime]$Now, [int]$CompareDaysAgo, [bool]$CompareEnabled)

    if (-not $CompareEnabled) { return $null }

    Write-Verbose "Querying cluster statistics from $CompareDaysAgo day(s) ago..."
    $atMs = [DateTimeOffset]::new($Now.AddDays(-$CompareDaysAgo)).ToUnixTimeMilliseconds()
    $ids = @($ClusterList | ForEach-Object { $_.identifier })
    $keys = @($StatKeysCluster.Values)
    $prevLookup = if ($ids.Count -gt 0) {
        Get-VCFOpsStatsPointInTime -ResourceIds $ids -StatKeys $keys -AtMs $atMs -WindowMinutes 180
    } else { @{} }

    if (-not $prevLookup -or $prevLookup.Keys.Count -eq 0) {
        Write-Warning "Could not find statistics from $CompareDaysAgo day(s) ago (past the retention period, or not yet collected) - showing without a comparison."
        return $null
    }
    return Get-ClusterMetricsFromApi -ClusterList $ClusterList -ClusterDc $ClusterDc `
        -HostCluster $HostCluster -HostVmMap $HostVmMap -DcName $DcName -StatsLookup $prevLookup
}

function Get-PerfSummaryWithDelta {
    param($Clusters, $PrevClusters, [bool]$CompareEnabled)

    if (-not $Clusters -or $Clusters.Count -eq 0) {
        return @(
            [PSCustomObject]@{ Label = "평균 CPU 사용률";   Unit = "%";  Current = 0; Previous = 0; HasComparison = $false }
            [PSCustomObject]@{ Label = "평균 메모리 사용률"; Unit = "%";  Current = 0; Previous = 0; HasComparison = $false }
            [PSCustomObject]@{ Label = "스토리지 사용량";    Unit = "TB"; Current = 0; Previous = 0; HasComparison = $false }
        )
    }
    $avgCpu = [Math]::Round((($Clusters | Measure-Object -Property CpuPct -Average).Average), 1)
    $avgMem = [Math]::Round((($Clusters | Measure-Object -Property MemPct -Average).Average), 1)
    $totalStorage = [Math]::Round((($Clusters | Measure-Object -Property StorageUsedTb -Sum).Sum), 1)

    $prevCpu = $avgCpu; $prevMem = $avgMem; $prevStorage = $totalStorage
    $hasComparison = [bool]($CompareEnabled -and $PrevClusters -and $PrevClusters.Count -gt 0)
    if ($hasComparison) {
        $prevCpu = [Math]::Round((($PrevClusters | Measure-Object -Property CpuPct -Average).Average), 1)
        $prevMem = [Math]::Round((($PrevClusters | Measure-Object -Property MemPct -Average).Average), 1)
        $prevStorage = [Math]::Round((($PrevClusters | Measure-Object -Property StorageUsedTb -Sum).Sum), 1)
    }

    return @(
        [PSCustomObject]@{ Label = "평균 CPU 사용률";   Unit = "%";  Current = $avgCpu; Previous = $prevCpu; HasComparison = $hasComparison }
        [PSCustomObject]@{ Label = "평균 메모리 사용률"; Unit = "%";  Current = $avgMem; Previous = $prevMem; HasComparison = $hasComparison }
        [PSCustomObject]@{ Label = "스토리지 사용량";    Unit = "TB"; Current = $totalStorage; Previous = $prevStorage; HasComparison = $hasComparison }
    )
}

function Get-DatastoreInfoWithDelta {
    # 데이터스토어 현황: 클러스터명 + 이전/현재 용량 + 증감.
    # properties의 isLocal=true(로컬 데이터스토어)는 결과에서 제외합니다.
    param($DatastoreList, [hashtable]$DatastoreClusterNames, [datetime]$Now, [int]$CompareDaysAgo, [bool]$CompareEnabled)

    if (-not $DatastoreList -or $DatastoreList.Count -eq 0) { return @() }

    $ids = @($DatastoreList | ForEach-Object { $_.identifier })
    $keys = @($StatKeysDatastore.Values)
    $latest = Get-VCFOpsStatsLatest -ResourceIds $ids -StatKeys $keys

    $prevLookup = $null
    $hasComparison = $false
    if ($CompareEnabled) {
        $atMs = [DateTimeOffset]::new($Now.AddDays(-$CompareDaysAgo)).ToUnixTimeMilliseconds()
        try {
            $prevLookup = Get-VCFOpsStatsPointInTime -ResourceIds $ids -StatKeys $keys -AtMs $atMs -WindowMinutes 720
            if ($prevLookup -and $prevLookup.Keys.Count -gt 0) { $hasComparison = $true }
        }
        catch {
            Write-Warning "Failed to query historical datastore data: $($_.Exception.Message)"
        }
    }

    $result = @()
    $excludedLocal = 0
    $excludedDuplicate = 0
    $seenUuids = @{}
    foreach ($d in $DatastoreList) {
        $did = $d.identifier
        $name = $d.resourceKey.name

        try {
            $props = Get-VCFOpsProperties -ResourceId $did
            $isLocalRaw = "$(Get-MapValueOrDefault $props $PropertyKeysDatastore.is_local '')".ToLower()
            if ($isLocalRaw -eq "true") {
                $excludedLocal++
                continue
            }

            # 동일한 물리 데이터스토어가 UUID 기준으로 이미 한 번 표시되었으면 건너뜁니다
            # (여러 vCenter/리소스로 중복 검출되는 경우 대비).
            $uuidVal = "$(Get-MapValueOrDefault $props $PropertyKeysDatastore.uuid_url '')"
            if ($uuidVal) {
                if ($seenUuids.ContainsKey($uuidVal)) {
                    $excludedDuplicate++
                    continue
                }
                $seenUuids[$uuidVal] = $true
            }
        }
        catch {
            Write-Warning "Failed to query datastore properties ($name): $($_.Exception.Message)"
        }

        $s = if ($latest.ContainsKey($did)) { $latest[$did] } else { @{} }
        $capGb = ConvertTo-SafeDouble (Get-MapValueOrDefault $s $StatKeysDatastore.capacity_gb)
        $usedGb = ConvertTo-SafeDouble (Get-MapValueOrDefault $s $StatKeysDatastore.used_gb)
        $freeGb = ConvertTo-SafeDouble (Get-MapValueOrDefault $s $StatKeysDatastore.free_gb)

        $prevCapGb = $capGb; $prevUsedGb = $usedGb; $rowHasCmp = $false
        if ($hasComparison -and $prevLookup.ContainsKey($did)) {
            $pv = $prevLookup[$did]
            $prevCapGb = ConvertTo-SafeDouble (Get-MapValueOrDefault $pv $StatKeysDatastore.capacity_gb)
            $prevUsedGb = ConvertTo-SafeDouble (Get-MapValueOrDefault $pv $StatKeysDatastore.used_gb)
            $rowHasCmp = $true
        }

        $clusterNm = Get-MapValueOrDefault $DatastoreClusterNames $did ""

        $result += [PSCustomObject]@{
            Name = $name; Cluster = $clusterNm
            CapacityGb = [Math]::Round($capGb, 1); UsedGb = [Math]::Round($usedGb, 1)
            FreeGb = [Math]::Round($freeGb, 1)
            PrevCapacityGb = [Math]::Round($prevCapGb, 1); PrevUsedGb = [Math]::Round($prevUsedGb, 1)
            DeltaUsedGb = [Math]::Round($usedGb - $prevUsedGb, 1)
            DeltaCapacityGb = [Math]::Round($capGb - $prevCapGb, 1)
            HasComparison = $rowHasCmp
        }
    }
    if ($excludedLocal -gt 0) {
        Write-Verbose "Excluded $excludedLocal local datastore(s) from the list."
    }
    if ($excludedDuplicate -gt 0) {
        Write-Verbose "Excluded $excludedDuplicate duplicate datastore(s) with the same UUID from the list."
    }
    return ($result | Sort-Object -Property Cluster, Name)
}

function Get-VmInventoryFromApi {
    param($VmList, [hashtable]$VmHost, [hashtable]$HostName, [hashtable]$HostCluster, [hashtable]$ClusterName,
          [int]$SnapshotAgeThresholdDays = 7)

    $idName = @{}
    foreach ($v in $VmList) { $idName[$v.identifier] = $v.resourceKey.name }

    $propsMap = @{}
    foreach ($v in $VmList) {
        $vid = $v.identifier
        try {
            $propsMap[$vid] = Get-VCFOpsProperties -ResourceId $vid
        }
        catch {
            Write-Warning "Failed to query properties ($($idName[$vid])): $($_.Exception.Message)"
            $propsMap[$vid] = @{}
        }
    }

    # 스냅샷 용량은 property가 아니라 stat(시계열)이라 별도로 일괄 조회합니다 (1개 키, 전체 VM 한 번에).
    $vmIds = @($VmList | ForEach-Object { $_.identifier })
    $snapSizeLookup = if ($vmIds.Count -gt 0) {
        Get-VCFOpsStatsLatest -ResourceIds $vmIds -StatKeys @($StatKeySnapshotSizeGb)
    } else { @{} }

    $inventory = @()
    $snapshotAlerts = @()

    foreach ($v in $VmList) {
        $vid = $v.identifier
        $name = $idName[$vid]
        $props = $propsMap[$vid]
        $hid = Get-MapValueOrDefault $VmHost $vid $null
        $cid = if ($hid) { Get-MapValueOrDefault $HostCluster $hid $null } else { $null }
        $clusterNm = if ($cid -and $ClusterName.ContainsKey($cid)) { $ClusterName[$cid] } else { "" }

        $disks = ConvertTo-VDiskList -Props $props
        $diskTotalGb = [Math]::Round((($disks | Measure-Object -Property CapacityGb -Sum).Sum), 1)

        $inventory += [PSCustomObject]@{
            Name = $name
            Cluster = $clusterNm
            Host = if ($hid -and $HostName.ContainsKey($hid)) { $HostName[$hid] } else { "" }
            Vcpu = [int](ConvertTo-SafeDouble (Get-MapValueOrDefault $props $PropertyKeysVM.vcpu_num))
            VmemGb = [Math]::Round((ConvertTo-SafeDouble (Get-MapValueOrDefault $props $PropertyKeysVM.vmem_kb)) / 1024 / 1024, 1)
            GuestOs = Get-MapValueOrDefault $props $PropertyKeysVM.guest_os "Unknown"
            HwVersion = Get-MapValueOrDefault $props $PropertyKeysVM.hw_version ""
            VmToolsVersion = Get-MapValueOrDefault $props $PropertyKeysVM.vmtools_version ""
            VmToolsStatus = Get-MapValueOrDefault $props $PropertyKeysVM.vmtools_status ""
            PowerState = Get-MapValueOrDefault $props $PropertyKeysVM.power_state ""
            Disks = $disks
            HasSharedDisk = [bool]($disks | Where-Object { $_.Shared })
            DiskTotalGb = $diskTotalGb
        }

        # ---- 스냅샷 (확인된 실제 키: diskspace|snapshot|snapshotAge, -1이면 스냅샷 없음) ----
        $ageRaw = ConvertTo-SafeDouble (Get-MapValueOrDefault $props $PropertyKeysSnapshot.snapshot_age_days) -1
        $ageDays = [int][Math]::Round($ageRaw)
        if ($ageDays -ge 0 -and $ageDays -ge $SnapshotAgeThresholdDays) {
            $sizeGb = 0.0
            if ($snapSizeLookup.ContainsKey($vid)) {
                $sizeGb = ConvertTo-SafeDouble (Get-MapValueOrDefault $snapSizeLookup[$vid] $StatKeySnapshotSizeGb)
            }
            $snapshotAlerts += [PSCustomObject]@{
                Name = $name; Cluster = $clusterNm
                SnapshotCount = 1   # 정확한 개수는 property로 노출되지 않아 보존(존재) 여부만 표시
                OldestSnapshotAgeDays = $ageDays
                TotalSnapshotSizeGb = [Math]::Round($sizeGb, 1)
            }
        }
    }
    return [PSCustomObject]@{ Inventory = $inventory; SnapshotAlerts = ($snapshotAlerts | Sort-Object -Property OldestSnapshotAgeDays -Descending) }
}

function Get-VcpuBucketLabel {
    param([int]$Vcpu)
    if ($Vcpu -le 4) { return "vCPU 4개 이하" }
    elseif ($Vcpu -le 8) { return "vCPU 5~8개" }
    elseif ($Vcpu -le 16) { return "vCPU 9~16개" }
    elseif ($Vcpu -le 32) { return "vCPU 17~32개" }
    else { return "vCPU 33개 이상" }
}

function Get-VmBreakdownWithDelta {
    # Guest OS / VMware Tools 버전 / 가상 HW버전 / vCPU 구간별 VM 수량.
    # properties는 "현재 상태"만 제공되어 과거 시점을 API로 직접 조회할 수 없으므로,
    # 인벤토리 수량과 동일하게 로컬 스냅샷 캐시로 비교합니다(캐시가 누적되어야 비교 가능).
    param($VmInventory, [datetime]$Now, [int]$CompareDaysAgo, [string]$CacheDir, [bool]$CompareEnabled)

    $vcpuBucketOrder = @("vCPU 4개 이하", "vCPU 5~8개", "vCPU 9~16개", "vCPU 17~32개", "vCPU 33개 이상")

    function Build-Counts {
        param($Items)
        $osCounts = @{}; $toolsCounts = @{}; $hwCounts = @{}; $vcpuCounts = @{}
        foreach ($v in $Items) {
            $os = if ([string]::IsNullOrWhiteSpace($v.GuestOs)) { "(알수없음)" } else { $v.GuestOs }
            $tools = if ([string]::IsNullOrWhiteSpace($v.VmToolsVersion)) { "(알수없음)" } else { $v.VmToolsVersion }
            $hw = if ([string]::IsNullOrWhiteSpace($v.HwVersion)) { "(알수없음)" } else { $v.HwVersion }
            $bucket = Get-VcpuBucketLabel -Vcpu $v.Vcpu
            if (-not $osCounts.ContainsKey($os)) { $osCounts[$os] = 0 }; $osCounts[$os]++
            if (-not $toolsCounts.ContainsKey($tools)) { $toolsCounts[$tools] = 0 }; $toolsCounts[$tools]++
            if (-not $hwCounts.ContainsKey($hw)) { $hwCounts[$hw] = 0 }; $hwCounts[$hw]++
            if (-not $vcpuCounts.ContainsKey($bucket)) { $vcpuCounts[$bucket] = 0 }; $vcpuCounts[$bucket]++
        }
        return @{ os = $osCounts; tools = $toolsCounts; hw = $hwCounts; vcpu = $vcpuCounts }
    }

    $currCounts = Build-Counts -Items $VmInventory
    $currTotal = @($VmInventory).Count

    $prevCounts = $null
    $hasComparison = $false
    if ($CompareEnabled) {
        $prevSnap = Get-ClosestSnapshot -TargetDate $Now.AddDays(-$CompareDaysAgo) -CacheDir $CacheDir -ToleranceDays 3
        if ($prevSnap -and $prevSnap.vmBreakdown) {
            $prevCounts = @{
                os = @{}; tools = @{}; hw = @{}; vcpu = @{}
            }
            foreach ($cat in @("os", "tools", "hw", "vcpu")) {
                $src = $prevSnap.vmBreakdown.$cat
                if ($src) {
                    foreach ($prop in $src.PSObject.Properties) { $prevCounts[$cat][$prop.Name] = [int]$prop.Value }
                }
            }
            $hasComparison = $true
        }
        else {
            Write-Warning "VM inventory distribution: no snapshot from $CompareDaysAgo day(s) ago was found, so this is shown without a comparison (the snapshot cache needs to accumulate more history)."
        }
    }

    # 오늘자 캐시에 분포 데이터도 함께 보강 저장 (counts/perf 등 기존 내용 보존)
    $todayFile = Join-Path $CacheDir ("{0:yyyy-MM-dd}.json" -f $Now)
    $merged = @{ vmBreakdown = $currCounts }
    if (Test-Path $todayFile) {
        $existing = Get-Content $todayFile -Raw -Encoding utf8 | ConvertFrom-Json
        if ($existing.counts) { $merged["counts"] = $existing.counts }
        if ($existing.perf) { $merged["perf"] = $existing.perf }
        if ($existing.timestamp) { $merged["timestamp"] = $existing.timestamp }
    }
    Save-InventorySnapshot -Date $Now -Payload $merged -CacheDir $CacheDir

    function Build-Rows {
        param([hashtable]$Curr, [hashtable]$Prev, [int]$Total, [bool]$HasCmp, [string[]]$ForceOrder = $null, [int]$TopN = 8)
        $keys = if ($ForceOrder) { $ForceOrder } else { @($Curr.Keys | Sort-Object { -$Curr[$_] }) }
        $shown = @($keys | Select-Object -First $TopN)
        $rest = @($keys | Select-Object -Skip $TopN)
        $rows = @()
        foreach ($k in $shown) {
            $c = $Curr[$k]
            $p = if ($Prev -and $Prev.ContainsKey($k)) { $Prev[$k] } else { 0 }
            $pct = if ($Total -gt 0) { [Math]::Round($c / $Total * 100, 1) } else { 0 }
            $rows += [PSCustomObject]@{ Label = $k; Count = $c; Pct = $pct; PrevCount = $p; Delta = ($c - $p); HasComparison = $HasCmp }
        }
        if ($rest.Count -gt 0) {
            $restC = 0; $restP = 0
            foreach ($k in $rest) {
                $restC += $Curr[$k]
                if ($Prev -and $Prev.ContainsKey($k)) { $restP += $Prev[$k] }
            }
            $pct = if ($Total -gt 0) { [Math]::Round($restC / $Total * 100, 1) } else { 0 }
            $rows += [PSCustomObject]@{ Label = "기타 $($rest.Count)종"; Count = $restC; Pct = $pct; PrevCount = $restP; Delta = ($restC - $restP); HasComparison = $HasCmp }
        }
        return $rows
    }

    $osPrev = if ($prevCounts) { $prevCounts.os } else { $null }
    $toolsPrev = if ($prevCounts) { $prevCounts.tools } else { $null }
    $hwPrev = if ($prevCounts) { $prevCounts.hw } else { $null }
    $vcpuPrev = if ($prevCounts) { $prevCounts.vcpu } else { $null }

    return [PSCustomObject]@{
        Total = $currTotal
        HasComparison = $hasComparison
        OsRows = Build-Rows -Curr $currCounts.os -Prev $osPrev -Total $currTotal -HasCmp $hasComparison
        ToolsRows = Build-Rows -Curr $currCounts.tools -Prev $toolsPrev -Total $currTotal -HasCmp $hasComparison
        HwRows = Build-Rows -Curr $currCounts.hw -Prev $hwPrev -Total $currTotal -HasCmp $hasComparison
        VcpuRows = Build-Rows -Curr $currCounts.vcpu -Prev $vcpuPrev -Total $currTotal -HasCmp $hasComparison -ForceOrder $vcpuBucketOrder -TopN 5
    }
}

function Invoke-VCFOpsCollection {
    [CmdletBinding()]
    param(
        [string]$CustomerName = "Customer",
        [string]$VCenterScope = "All vCenters",
        [int]$CompareDaysAgo = 0,
        [string]$SnapshotCacheDir = "./snapshots",
        [int]$MaxVMs = 0
    )

    $now = Get-Date
    $compareEnabled = $CompareDaysAgo -gt 0
    if ($compareEnabled) {
        try { $null = $now.AddDays(-$CompareDaysAgo) }
        catch {
            Write-Warning "The comparison date is not valid (-CompareDays $CompareDaysAgo) - showing only the current value, without a comparison."
            $compareEnabled = $false
        }
    }
    $previousDate = if ($compareEnabled) { $now.AddDays(-$CompareDaysAgo) } else { $null }

    Write-VCFOpsSubStep "Querying the resource inventory... (datacenters/clusters/hosts/VMs)"
    Write-Verbose "Querying the resource inventory..."
    $dcList      = Get-VCFOpsResources -ResourceKind $ResourceKind.datacenter -AdapterKind $AdapterKindVMware
    $clusterList = Get-VCFOpsResources -ResourceKind $ResourceKind.cluster    -AdapterKind $AdapterKindVMware
    $hostList    = Get-VCFOpsResources -ResourceKind $ResourceKind.host      -AdapterKind $AdapterKindVMware
    $vmList      = Get-VCFOpsResources -ResourceKind $ResourceKind.vm        -AdapterKind $AdapterKindVMware
    $datastoreList = Get-VCFOpsResources -ResourceKind $ResourceKind.datastore -AdapterKind $AdapterKindVMware
    Write-VCFOpsSubStep "Querying the vCenter count..."
    $vCenterCount = Get-VCenterCount

    if ($MaxVMs -gt 0 -and $vmList.Count -gt $MaxVMs) {
        $vmList = $vmList[0..($MaxVMs - 1)]
    }

    $clusterName = @{}; foreach ($c in $clusterList) { $clusterName[$c.identifier] = $c.resourceKey.name }
    # ESXi 호스트명은 마스킹 처리(FQDN 도메인 -> vcf.local, IP -> 앞 3옥텟 ***)된 값으로 저장합니다.
    # 이 맵을 참조하는 모든 곳(호스트 Top10, VM 인벤토리/Top 리스트의 Host 컬럼)에 자동 반영됩니다.
    $hostName    = @{}; foreach ($h in $hostList)    { $hostName[$h.identifier]    = Protect-VCFOpsHostIdentifier -Value $h.resourceKey.name }
    $dcName      = @{}; foreach ($d in $dcList)       { $dcName[$d.identifier]      = $d.resourceKey.name }

    Write-VCFOpsSubStep "Mapping resource relationships (parent/child)..."
    Write-Verbose "Mapping resource relationships (parent/child)..."
    $clusterDc = @{}
    foreach ($d in $dcList) {
        foreach ($cid in (Get-VCFOpsChildren -ResourceId $d.identifier -ChildResourceKind $ResourceKind.cluster)) {
            $clusterDc[$cid] = $d.identifier
        }
    }
    $hostCluster = @{}
    foreach ($c in $clusterList) {
        foreach ($hid in (Get-VCFOpsChildren -ResourceId $c.identifier -ChildResourceKind $ResourceKind.host)) {
            $hostCluster[$hid] = $c.identifier
        }
    }
    $vmHost = @{}
    foreach ($h in $hostList) {
        foreach ($vid in (Get-VCFOpsChildren -ResourceId $h.identifier -ChildResourceKind $ResourceKind.vm)) {
            $vmHost[$vid] = $h.identifier
        }
    }
    $hostVmMap = @{}
    foreach ($vid in $vmHost.Keys) {
        $hid = $vmHost[$vid]
        if (-not $hostVmMap.ContainsKey($hid)) { $hostVmMap[$hid] = @() }
        $hostVmMap[$hid] += $vid
    }

    # 데이터스토어 -> 클러스터명 (한 데이터스토어가 여러 클러스터에 공유되면 쉼표로 연결)
    $datastoreClusterNames = @{}
    foreach ($c in $clusterList) {
        foreach ($did in (Get-VCFOpsChildren -ResourceId $c.identifier -ChildResourceKind $ResourceKind.datastore)) {
            $existing = Get-MapValueOrDefault $datastoreClusterNames $did ""
            $cName = $c.resourceKey.name
            $datastoreClusterNames[$did] = if ($existing) { "$existing, $cName" } else { $cName }
        }
    }

    Write-VCFOpsSubStep "Processing inventory count comparison (vSphere World/cache)..."
    $inventoryCounts = Get-InventoryCountsWithDelta -DcList $dcList -ClusterList $clusterList -HostList $hostList `
        -VmList $vmList -VCenterCount $vCenterCount -Now $now -CompareDaysAgo $CompareDaysAgo `
        -CacheDir $SnapshotCacheDir -CompareEnabled $compareEnabled

    Write-VCFOpsSubStep "Querying cluster performance statistics..."
    Write-Verbose "Querying cluster performance statistics..."
    $clusters = Get-ClusterMetricsFromApi -ClusterList $clusterList -ClusterDc $clusterDc `
        -HostCluster $hostCluster -HostVmMap $hostVmMap -DcName $dcName

    # N일 전 시점 클러스터 통계는 한 번만 조회해서 (1)클러스터 카드 비교, (2)Executive Summary
    # 비교 양쪽에 재사용합니다.
    $prevClusters = Get-PrevClusters -ClusterList $clusterList -ClusterDc $clusterDc -HostCluster $hostCluster `
        -HostVmMap $hostVmMap -DcName $dcName -Now $now -CompareDaysAgo $CompareDaysAgo -CompareEnabled $compareEnabled
    $clusters = Merge-ClusterPrevious -Clusters $clusters -PrevClusters $prevClusters -CompareEnabled $compareEnabled

    Write-VCFOpsSubStep "Querying host performance statistics..."
    Write-Verbose "Querying host performance statistics..."
    $hosts = Get-HostMetricsFromApi -HostList $hostList -HostCluster $hostCluster -ClusterName $clusterName

    Write-VCFOpsSubStep "Querying VM performance statistics... ($($vmList.Count) VM(s))"
    Write-Verbose "Querying VM performance statistics... ($($vmList.Count) VM(s))"
    $vmPerfResult = Get-VmPerformanceFromApi -VmList $vmList -VmHost $vmHost -HostName $hostName `
        -HostCluster $hostCluster -ClusterName $clusterName

    $perfSummary = Get-PerfSummaryWithDelta -Clusters $clusters -PrevClusters $prevClusters -CompareEnabled $compareEnabled

    Write-VCFOpsSubStep "Querying datastore status (capacity comparison)..."
    $datastoreInfo = Get-DatastoreInfoWithDelta -DatastoreList $datastoreList -DatastoreClusterNames $datastoreClusterNames `
        -Now $now -CompareDaysAgo $CompareDaysAgo -CompareEnabled $compareEnabled

    Write-VCFOpsSubStep "Querying detailed VM inventory (properties)... ($($vmList.Count) VM(s), this may take a while)"
    Write-Verbose "Querying detailed VM inventory (properties)... ($($vmList.Count) VM(s), this may take a while)"
    $vmInvResult = Get-VmInventoryFromApi -VmList $vmList -VmHost $vmHost -HostName $hostName `
        -HostCluster $hostCluster -ClusterName $clusterName

    # VM 인벤토리(properties)에서 얻은 디스크별 데이터스토어 정보로 디스크 레이턴시 Top10의
    # "N/A" 데이터스토어를 실제 값으로 채웁니다.
    $diskLatencyVMs = Merge-DiskLatencyDatastore -DiskLatencyVMs $vmPerfResult.DiskLatencyVMs -VmInventory $vmInvResult.Inventory

    # 리소스 현황의 "가상머신" 카드에 Power On/Off 수량을 추가로 붙입니다.
    $vmCountRow = $inventoryCounts | Where-Object { $_.Label -eq "가상머신" } | Select-Object -First 1
    if ($vmCountRow) {
        $poweredOn = @($vmInvResult.Inventory | Where-Object { $_.PowerState -eq "Powered On" }).Count
        $poweredOff = @($vmInvResult.Inventory).Count - $poweredOn
        $vmCountRow | Add-Member -MemberType NoteProperty -Name PoweredOnCount -Value $poweredOn -Force
        $vmCountRow | Add-Member -MemberType NoteProperty -Name PoweredOffCount -Value $poweredOff -Force
    }

    Write-VCFOpsSubStep "Calculating VM inventory distribution (OS/Tools/HW/vCPU)..."
    $vmBreakdown = Get-VmBreakdownWithDelta -VmInventory $vmInvResult.Inventory -Now $now `
        -CompareDaysAgo $CompareDaysAgo -CacheDir $SnapshotCacheDir -CompareEnabled $compareEnabled

    return [PSCustomObject]@{
        Meta = [PSCustomObject]@{
            CustomerName = $CustomerName; VCenterScope = $VCenterScope
            CurrentDate = $now; PreviousDate = $previousDate; CompareEnabled = $compareEnabled
            GeneratedBy = "VCF Operations Capacity & Health Report Generator (PowerShell)"
        }
        InventoryCounts     = $inventoryCounts
        PerfSummary         = $perfSummary
        DatastoreInfo       = $datastoreInfo
        Clusters            = $clusters
        Hosts               = $hosts
        TopCpuVMs           = $vmPerfResult.TopCpuVMs
        TopReadyVMs         = $vmPerfResult.TopReadyVMs
        DiskLatencyVMs      = $diskLatencyVMs
        SnapshotAlerts      = $vmInvResult.SnapshotAlerts
        VmInventory         = $vmInvResult.Inventory
        VmBreakdown         = $vmBreakdown
        VmPerformance       = $vmPerfResult.VmPerformance
    }
}


# ---- inlined from Operations/Modules/VCFOpsMockData.psm1 ----
# VCFOpsMockData.psm1
# -----------------------------------------------------------------------------
# 실제 API 연결 없이 HTML 렌더러를 검증/데모하기 위한 샘플 데이터 생성기.
# Python 버전(vcfops/mock_data.py)과 동일한 분포/구조를 사용합니다.
# -----------------------------------------------------------------------------

$Script:MockClusters = @(
    @{ Name = "CLU-PROD-01"; Dc = "DC-Seoul"; Short = "PRD1" }
    @{ Name = "CLU-PROD-02"; Dc = "DC-Seoul"; Short = "PRD2" }
    @{ Name = "CLU-DEV-01";  Dc = "DC-Busan"; Short = "DEV1" }
    @{ Name = "CLU-DR-01";   Dc = "DC-Busan"; Short = "DR01" }
)
$Script:MockGuestOsList = @(
    "Windows Server 2022", "Windows Server 2019", "RHEL 9", "RHEL 8",
    "Ubuntu 22.04", "VMware Photon OS 4.0", "SUSE Linux 15", "Oracle Linux 8"
)
$Script:MockVmRoles = @("WEB", "APP", "DB", "BATCH", "MQ", "CACHE", "FILE", "AD", "DNS", "MON")
$Script:MockDatastoreList = @("vSAN-DS01", "vSAN-DS02", "NFS-DS01", "VMFS-DS01", "VMFS-DS02")

function Get-JitterValue {
    param([double]$Base, [double]$PctRange = 0.08)
    $factor = 1 + (Get-Random -Minimum (0 - $PctRange) -Maximum $PctRange)
    return $Base * $factor
}

function Get-WeightedChoice {
    param([string[]]$Options, [int[]]$Weights)
    $total = ($Weights | Measure-Object -Sum).Sum
    $r = Get-Random -Minimum 0 -Maximum $total
    $acc = 0
    for ($i = 0; $i -lt $Options.Count; $i++) {
        $acc += $Weights[$i]
        if ($r -lt $acc) { return $Options[$i] }
    }
    return $Options[$Options.Count - 1]
}

function New-MockReportData {
    [CmdletBinding()]
    param([string]$CustomerName = "Customer")

    $now = Get-Date
    $prev = $now.AddDays(-30)
    $compareEnabled = $true
    $cmpLabel = "30일 전"

    # ---------------- 인벤토리 수량 ----------------
    $invCurr = [ordered]@{ "vCenter" = 2; "데이터센터" = 2; "클러스터" = 4; "ESXi 호스트" = 18; "가상머신" = 312 }
    $invPrev = [ordered]@{ "vCenter" = 2; "데이터센터" = 2; "클러스터" = 4; "ESXi 호스트" = 16; "가상머신" = 287 }
    $inventoryCounts = @()
    foreach ($k in $invCurr.Keys) {
        $c = $invCurr[$k]; $p = $invPrev[$k]
        $deltaPct = if ($p -ne 0) { [Math]::Round((($c - $p) / [double]$p) * 100, 1) } else { 0.0 }
        $src = if ($k -eq "가상머신" -or $k -eq "ESXi 호스트") { "metric" } else { "cache" }
        $row = [PSCustomObject]@{
            Label = $k; Current = $c; Previous = $p; Delta = ($c - $p); DeltaPct = $deltaPct
            HasComparison = $compareEnabled; CompareSource = $src
        }
        if ($k -eq "가상머신") {
            $poweredOn = [int]($c * 0.86)
            $row | Add-Member -MemberType NoteProperty -Name PoweredOnCount -Value $poweredOn
            $row | Add-Member -MemberType NoteProperty -Name PoweredOffCount -Value ($c - $poweredOn)
        }
        $inventoryCounts += $row
    }

    # ---------------- 성능 요약 ----------------
    $perfSummary = @(
        [PSCustomObject]@{ Label = "평균 CPU 사용률";   Unit = "%";  Current = 61.4;  Previous = 55.2; HasComparison = $compareEnabled }
        [PSCustomObject]@{ Label = "평균 메모리 사용률"; Unit = "%";  Current = 73.2;  Previous = 68.0; HasComparison = $compareEnabled }
        [PSCustomObject]@{ Label = "스토리지 사용량";    Unit = "TB"; Current = 184.6; Previous = 162.8; HasComparison = $compareEnabled }
    )

    # ---------------- 클러스터 / 호스트 / 데이터스토어 ----------------
    $clusters = @()
    $allHosts = @()
    $allDatastores = @()
    $hostCounter = 0
    $hostsByCluster = @{}

    foreach ($cl in $Script:MockClusters) {
        $nHosts = Get-Random -InputObject @(3, 4, 5, 6)
        $cpuTotalGhzBase = $nHosts * (Get-Random -InputObject @(76.8, 86.4, 96.0))
        $memTotalGbBase  = $nHosts * (Get-Random -InputObject @(512, 768, 1024))
        $storageTotalTb  = Get-Random -InputObject @(60, 80, 100, 120)

        $cpuTarget = Get-Random -Minimum 45.0 -Maximum 92.0
        $memTarget = Get-Random -Minimum 55.0 -Maximum 90.0
        $stoTarget = Get-Random -Minimum 50.0 -Maximum 88.0

        $cpuUsedGhz  = [Math]::Round($cpuTotalGhzBase * $cpuTarget / 100, 1)
        $cpuTotalGhz = [Math]::Round($cpuTotalGhzBase, 1)
        $memUsedGb   = [Math]::Round($memTotalGbBase * $memTarget / 100, 1)
        $memTotalGb  = [Math]::Round($memTotalGbBase, 1)
        $storageUsedTb = [Math]::Round($storageTotalTb * $stoTarget / 100, 2)

        $cpuContentionPct = [Math]::Round((Get-Random -Minimum 0.5 -Maximum 14.0), 1)
        $storageLatencyMs = [Math]::Round((Get-Random -Minimum 1.2 -Maximum 22.0), 1)

        $cpuPct = [Math]::Round($cpuUsedGhz / $cpuTotalGhz * 100, 1)
        $memPct = [Math]::Round($memUsedGb / $memTotalGb * 100, 1)
        $storagePct = [Math]::Round($storageUsedTb / $storageTotalTb * 100, 1)
        $storageFreeTb = [Math]::Round($storageTotalTb - $storageUsedTb, 2)
        $worst = [Math]::Max([Math]::Max($cpuPct, $memPct), $storagePct)
        $status = if ($worst -ge 85 -or $cpuContentionPct -ge 10) { "critical" }
                  elseif ($worst -ge 70 -or $cpuContentionPct -ge 5) { "warning" }
                  else { "normal" }

        $clusterHostNames = @()
        for ($h = 0; $h -lt $nHosts; $h++) {
            $hostCounter++
            $hcpu = [Math]::Max(5, [Math]::Min(99, $cpuTarget + (Get-Random -Minimum -12.0 -Maximum 12.0)))
            $hmem = [Math]::Max(5, [Math]::Min(99, $memTarget + (Get-Random -Minimum -10.0 -Maximum 10.0)))
            $hcont = [Math]::Max(0, $cpuContentionPct + (Get-Random -Minimum -3.0 -Maximum 5.0))
            $hname = "esx-{0}-{1:D2}" -f $cl.Short.ToLower(), $hostCounter
            $clusterHostNames += $hname

            $hWorst = [Math]::Max($hcpu, $hmem)
            $hStatus = if ($hWorst -ge 85 -or $hcont -ge 10) { "critical" }
                       elseif ($hWorst -ge 70 -or $hcont -ge 5) { "warning" }
                       else { "normal" }

            $allHosts += [PSCustomObject]@{
                Name = $hname; Cluster = $cl.Name
                CpuPct = [Math]::Round($hcpu, 1); MemPct = [Math]::Round($hmem, 1)
                CpuContentionPct = [Math]::Round($hcont, 1)
                MemContentionPct = [Math]::Round([Math]::Max(0, (Get-Random -Minimum 0.0 -Maximum 4.0)), 1)
                Status = $hStatus
            }
        }
        $hostsByCluster[$cl.Name] = $clusterHostNames

        $clusters += [PSCustomObject]@{
            Name = $cl.Name; Datacenter = $cl.Dc; HostCount = $nHosts; VmCount = 0
            CpuUsedGhz = $cpuUsedGhz; CpuTotalGhz = $cpuTotalGhz; CpuPct = $cpuPct
            MemUsedGb = $memUsedGb; MemTotalGb = $memTotalGb; MemPct = $memPct
            StorageUsedTb = $storageUsedTb; StorageTotalTb = $storageTotalTb; StoragePct = $storagePct
            StorageFreeTb = $storageFreeTb
            CpuContentionPct = $cpuContentionPct; StorageLatencyMs = $storageLatencyMs
            Status = $status
            PrevCpuPct = [Math]::Round([Math]::Max(0, $cpuPct - (Get-Random -Minimum -8.0 -Maximum 8.0)), 1)
            PrevMemPct = [Math]::Round([Math]::Max(0, $memPct - (Get-Random -Minimum -6.0 -Maximum 6.0)), 1)
            PrevStoragePct = [Math]::Round([Math]::Max(0, $storagePct - (Get-Random -Minimum -5.0 -Maximum 5.0)), 1)
            PrevCpuContentionPct = [Math]::Round([Math]::Max(0, $cpuContentionPct - (Get-Random -Minimum -2.0 -Maximum 2.0)), 1)
            HasComparison = $compareEnabled
        }

        $nDatastores = Get-Random -Minimum 2 -Maximum 4
        for ($di = 1; $di -le $nDatastores; $di++) {
            $capGb = [Math]::Round((Get-Random -Minimum 4000.0 -Maximum 30000.0), 1)
            $usedGb = [Math]::Round($capGb * (Get-Random -Minimum 0.35 -Maximum 0.85), 1)
            $prevCapGb = $capGb - [Math]::Round((Get-Random -Minimum 0.0 -Maximum 500.0), 1)   # 용량 증설을 데모하기 위해 이전이 더 작거나 같게
            $prevUsedGb = [Math]::Round([Math]::Max(0, $usedGb - (Get-Random -Minimum -300.0 -Maximum 600.0)), 1)
            $allDatastores += [PSCustomObject]@{
                Name = "$($cl.Name)-DS$('{0:D2}' -f $di)"; Cluster = $cl.Name
                CapacityGb = $capGb; UsedGb = $usedGb; FreeGb = [Math]::Round($capGb - $usedGb, 1)
                PrevCapacityGb = $prevCapGb; PrevUsedGb = $prevUsedGb
                DeltaUsedGb = [Math]::Round($usedGb - $prevUsedGb, 1)
                DeltaCapacityGb = [Math]::Round($capGb - $prevCapGb, 1)
                HasComparison = $compareEnabled
            }
        }
    }

    # ---------------- VM ----------------
    $vmInventory = @()
    $vmPerformance = @()
    $allTopCpu = @()
    $allTopReady = @()
    $allDiskLat = @()
    $allSnapshots = @()
    $vmSeq = 0
    $baseCpuMap = @{ DB = 55; BATCH = 48; APP = 40; WEB = 35; MQ = 38; CACHE = 33; FILE = 20; AD = 18; DNS = 12; MON = 22 }

    foreach ($cl in $clusters) {
        $nVms = Get-Random -Minimum 60 -Maximum 91
        $cl.VmCount = $nVms
        $clusterHostNames = $hostsByCluster[$cl.Name]
        $shortName = ($Script:MockClusters | Where-Object { $_.Name -eq $cl.Name }).Short

        for ($i = 0; $i -lt $nVms; $i++) {
            $vmSeq++
            $role = Get-Random -InputObject $Script:MockVmRoles
            $name = "{0}-{1}-{2:D3}" -f $shortName, $role, $vmSeq
            $vcpu = Get-Random -InputObject @(2, 2, 4, 4, 4, 8, 8, 16)
            $vmem = Get-Random -InputObject @(4, 8, 8, 16, 16, 32, 64)
            $osName = Get-Random -InputObject $Script:MockGuestOsList
            $hostName = Get-Random -InputObject $clusterHostNames
            $hwVer = Get-Random -InputObject @("vmx-19", "vmx-20", "vmx-21")
            $toolsVer = Get-Random -InputObject @("12389", "12416", "12451", "11365")
            $toolsStatus = Get-WeightedChoice -Options @("running, current", "running, out-of-date", "not running") -Weights @(80, 15, 5)

            $nDisks = Get-Random -InputObject @(1, 1, 2, 2, 3)
            $disks = @()
            $sharedFlag = (($role -eq "DB" -or $role -eq "MQ") -and (Get-Random -Minimum 0.0 -Maximum 1.0) -lt 0.12)
            for ($d = 0; $d -lt $nDisks; $d++) {
                $provRaw = Get-Random -InputObject @("Thin", "Thin", "Thick Eager Zeroed", "Thick Lazy Zeroed")
                $disks += [PSCustomObject]@{
                    Label = "Hard disk $($d + 1)"
                    CapacityGb = Get-Random -InputObject @(40, 60, 80, 100, 200, 500, 1024)
                    Provisioning = $provRaw
                    # 실제 API 경로(Modules/VCFOpsCollector.psm1의 ConvertTo-VDiskList)와 동일하게
                    # "Thin"/"Thick" 축약 구분값도 함께 채워야 Thick 디스크 목록 섹션이 -Mock 에서도
                    # 정상적으로 채워집니다(HTML 렌더러는 Provisioning이 아니라 ProvisioningKind로 필터링).
                    ProvisioningKind = if ($provRaw -match "(?i)thin") { "Thin" } else { "Thick" }
                    Datastore = Get-Random -InputObject $Script:MockDatastoreList
                    Shared = ($sharedFlag -and $d -eq ($nDisks - 1))
                }
            }
            $diskTotalGb = [Math]::Round((($disks | Measure-Object -Property CapacityGb -Sum).Sum), 1)
            $hasSharedDisk = [bool]($disks | Where-Object { $_.Shared })

            $vmInventory += [PSCustomObject]@{
                Name = $name; Cluster = $cl.Name; Host = $hostName; Vcpu = $vcpu; VmemGb = $vmem
                GuestOs = $osName; HwVersion = $hwVer; VmToolsVersion = $toolsVer; VmToolsStatus = $toolsStatus
                PowerState = "poweredOn"; Disks = $disks; HasSharedDisk = $hasSharedDisk; DiskTotalGb = $diskTotalGb
            }

            $baseCpu = if ($baseCpuMap.ContainsKey($role)) { $baseCpuMap[$role] } else { 30 }
            $cpuUse = [Math]::Max(2, [Math]::Min(99, (Get-JitterValue -Base $baseCpu -PctRange 0.6)))
            $ready = [Math]::Max(0, (Get-JitterValue -Base ($baseCpu * 0.12) -PctRange 1.2))
            $memUse = [Math]::Max(5, [Math]::Min(99, (Get-JitterValue -Base 60 -PctRange 0.35)))
            $memActive = [Math]::Round($vmem * $memUse / 100 * (Get-Random -Minimum 0.5 -Maximum 0.9), 1)
            $diskLatBase = if ($role -ne "DB") { 3 } else { 9 }
            $diskLat = [Math]::Max(0.3, (Get-JitterValue -Base $diskLatBase -PctRange 0.9))
            $iopsBase = if ($role -eq "DB") { 150 } else { 60 }
            $iops = [int][Math]::Max(5, (Get-JitterValue -Base $iopsBase -PctRange 0.7))
            $netBase = if ($role -eq "WEB" -or $role -eq "APP") { 12 } else { 4 }
            $netMbps = [Math]::Round([Math]::Max(0.1, (Get-JitterValue -Base $netBase -PctRange 0.8)), 1)

            $cpuUseR = [Math]::Round($cpuUse, 1)
            $readyR = [Math]::Round($ready, 2)

            $vmPerformance += [PSCustomObject]@{
                Name = $name; Cluster = $cl.Name; CpuUsagePct = $cpuUseR; CpuReadyPct = $readyR
                MemUsagePct = [Math]::Round($memUse, 1); MemActiveGb = $memActive
                DiskLatencyMs = [Math]::Round($diskLat, 1); DiskIops = $iops; NetThroughputMbps = $netMbps
            }
            $allTopCpu += [PSCustomObject]@{ Name = $name; Cluster = $cl.Name; Host = $hostName; VcpuCount = $vcpu; CpuUsagePct = $cpuUseR }
            $allTopReady += [PSCustomObject]@{ Name = $name; Cluster = $cl.Name; Host = $hostName; VcpuCount = $vcpu; CpuReadyPct = $readyR }

            if ((Get-Random -Minimum 0.0 -Maximum 1.0) -lt 0.18) {
                $rl = [Math]::Max(0.5, (Get-JitterValue -Base 8 -PctRange 1.0))
                $wl = [Math]::Max(0.5, (Get-JitterValue -Base 10 -PctRange 1.0))
                $allDiskLat += [PSCustomObject]@{
                    Name = $name; Cluster = $cl.Name; Datastore = (Get-Random -InputObject $Script:MockDatastoreList)
                    ReadLatencyMs = [Math]::Round($rl, 1); WriteLatencyMs = [Math]::Round($wl, 1)
                }
            }
            if ((Get-Random -Minimum 0.0 -Maximum 1.0) -lt 0.06) {
                $age = Get-Random -Minimum 7 -Maximum 46
                $allSnapshots += [PSCustomObject]@{
                    Name = $name; Cluster = $cl.Name
                    SnapshotCount = (Get-Random -Minimum 1 -Maximum 4)
                    OldestSnapshotAgeDays = $age
                    TotalSnapshotSizeGb = [Math]::Round((Get-Random -Minimum 5.0 -Maximum 280.0), 1)
                }
            }
        }
    }

    $topCpuVMs      = @($allTopCpu   | Sort-Object -Property CpuUsagePct -Descending | Select-Object -First 10)
    $topReadyVMs    = @($allTopReady | Sort-Object -Property CpuReadyPct -Descending | Select-Object -First 10)
    $diskLatencyVMs = @($allDiskLat  | Sort-Object -Property { [Math]::Max($_.ReadLatencyMs, $_.WriteLatencyMs) } -Descending | Select-Object -First 10)
    $snapshotAlerts = @($allSnapshots | Sort-Object -Property OldestSnapshotAgeDays -Descending)

    # ---------------- VM 인벤토리 분포 (OS/Tools/HW/vCPU 구간, 비교 데모용 가짜 과거값 포함) ----------------
    function Get-MockBucketLabel {
        param([int]$Vcpu)
        if ($Vcpu -le 4) { return "vCPU 4개 이하" }
        elseif ($Vcpu -le 8) { return "vCPU 5~8개" }
        elseif ($Vcpu -le 16) { return "vCPU 9~16개" }
        elseif ($Vcpu -le 32) { return "vCPU 17~32개" }
        else { return "vCPU 33개 이상" }
    }
    function Build-MockBreakdownRows {
        param([hashtable]$Counts, [int]$Total, [string[]]$ForceOrder = $null, [int]$TopN = 8)
        $keys = if ($ForceOrder) { $ForceOrder } else { @($Counts.Keys | Sort-Object { -$Counts[$_] }) }
        $shown = @($keys | Select-Object -First $TopN)
        $rows = @()
        foreach ($k in $shown) {
            $c = $Counts[$k]
            $p = [Math]::Max(0, $c - (Get-Random -Minimum -6 -Maximum 9))
            $pct = if ($Total -gt 0) { [Math]::Round($c / $Total * 100, 1) } else { 0 }
            $rows += [PSCustomObject]@{ Label = $k; Count = $c; Pct = $pct; PrevCount = $p; Delta = ($c - $p); HasComparison = $compareEnabled }
        }
        return $rows
    }

    $osCounts = @{}; $toolsCounts = @{}; $hwCounts = @{}; $vcpuCounts = @{}
    foreach ($v in $vmInventory) {
        if (-not $osCounts.ContainsKey($v.GuestOs)) { $osCounts[$v.GuestOs] = 0 }; $osCounts[$v.GuestOs]++
        if (-not $toolsCounts.ContainsKey($v.VmToolsVersion)) { $toolsCounts[$v.VmToolsVersion] = 0 }; $toolsCounts[$v.VmToolsVersion]++
        if (-not $hwCounts.ContainsKey($v.HwVersion)) { $hwCounts[$v.HwVersion] = 0 }; $hwCounts[$v.HwVersion]++
        $bucket = Get-MockBucketLabel -Vcpu $v.Vcpu
        if (-not $vcpuCounts.ContainsKey($bucket)) { $vcpuCounts[$bucket] = 0 }; $vcpuCounts[$bucket]++
    }
    $vmTotal = @($vmInventory).Count
    $vcpuOrder = @("vCPU 4개 이하", "vCPU 5~8개", "vCPU 9~16개", "vCPU 17~32개", "vCPU 33개 이상")
    $vmBreakdown = [PSCustomObject]@{
        Total = $vmTotal
        HasComparison = $compareEnabled
        OsRows = Build-MockBreakdownRows -Counts $osCounts -Total $vmTotal
        ToolsRows = Build-MockBreakdownRows -Counts $toolsCounts -Total $vmTotal
        HwRows = Build-MockBreakdownRows -Counts $hwCounts -Total $vmTotal
        VcpuRows = Build-MockBreakdownRows -Counts $vcpuCounts -Total $vmTotal -ForceOrder $vcpuOrder -TopN 5
    }

    return [PSCustomObject]@{
        Meta = [PSCustomObject]@{
            CustomerName = $CustomerName
            VCenterScope = "vCenter: vc-seoul01.corp.local 외 1"
            CurrentDate  = $now
            PreviousDate = $prev
            CompareEnabled = $compareEnabled
            GeneratedBy  = "VCF Operations Capacity & Health Report Generator (PowerShell)"
        }
        InventoryCounts     = $inventoryCounts
        PerfSummary         = $perfSummary
        DatastoreInfo       = ($allDatastores | Sort-Object -Property Cluster, Name)
        Clusters            = $clusters
        Hosts               = $allHosts
        TopCpuVMs           = $topCpuVMs
        TopReadyVMs         = $topReadyVMs
        DiskLatencyVMs      = $diskLatencyVMs
        SnapshotAlerts      = $snapshotAlerts
        VmInventory         = $vmInventory
        VmBreakdown         = $vmBreakdown
        VmPerformance       = $vmPerformance
    }
}


# ---- inlined from Operations/Modules/VCFOpsHtmlReport.psm1 ----
# VCFOpsHtmlReport.psm1
# -----------------------------------------------------------------------------
# HTML 리포트 렌더러 (PowerShell 버전)
# Python 버전(report/html_report.py)과 동일한 CSS 클래스/색상/구조를 사용해
# 동일한 모던+파스텔 대시보드 결과물을 생성합니다.
# -----------------------------------------------------------------------------


function Get-ArrowHtml {
    param([double]$Delta)
    if ($Delta -gt 0) { return "<span class=`"delta up`">▲ $(Format-Number ([Math]::Abs($Delta)))</span>" }
    if ($Delta -lt 0) { return "<span class=`"delta down`">▼ $(Format-Number ([Math]::Abs($Delta)))</span>" }
    return "<span class=`"delta flat`">– 0.0</span>"
}

function Get-BadgeHtml {
    param([Parameter(Mandatory)][string]$Status)
    $s = $StatusColor[$Status]
    return "<span class=`"badge`" style=`"color:#$($s.fg);background:#$($s.bg);`">$($s.label)</span>"
}

function Get-BarHtml {
    param([double]$Pct, [Parameter(Mandatory)][string]$Status)
    $s = $StatusColor[$Status]
    $clamped = [Math]::Max(0, [Math]::Min(100, $Pct))
    return "<div class=`"bar-track`"><div class=`"bar-fill`" style=`"width:$($clamped)%;background:#$($s.fg);`"></div></div>"
}

function Get-CssBlock {
    $c = $Colors
    return @"
:root {
  --bg:#$($c.bg); --surface:#$($c.surface); --surface-alt:#$($c.surface_alt);
  --border:#$($c.border);
  --text:#$($c.text_primary); --text2:#$($c.text_secondary); --muted:#$($c.text_muted);
  --primary:#$($c.primary); --primary-dark:#$($c.primary_dark); --primary-tint:#$($c.primary_tint);
  --mint:#$($c.mint); --mint-dark:#$($c.mint_dark); --mint-tint:#$($c.mint_tint);
  --peach:#$($c.peach); --peach-dark:#$($c.peach_dark); --peach-tint:#$($c.peach_tint);
  --coral:#$($c.coral); --coral-dark:#$($c.coral_dark); --coral-tint:#$($c.coral_tint);
  --sky:#$($c.sky); --sky-dark:#$($c.sky_dark); --sky-tint:#$($c.sky_tint);
  --lilac:#$($c.lilac);
}
* { box-sizing:border-box; }
html,body { margin:0; padding:0; background:var(--bg); color:var(--text);
  font-family:'Pretendard','Noto Sans KR','Segoe UI',sans-serif; font-size:15px; line-height:1.6; }
.wrap { max-width:1280px; margin:0 auto; padding:0 28px 80px; }

.hero { background:linear-gradient(135deg, var(--primary-tint) 0%, var(--sky-tint) 60%, var(--mint-tint) 100%);
  padding:40px 28px 32px; border-radius:0 0 28px 28px; margin-bottom:28px; }
.hero-inner { max-width:1280px; margin:0 auto; display:flex; justify-content:space-between; align-items:flex-end; flex-wrap:wrap; gap:16px;}
.hero-eyebrow { color:var(--primary-dark); font-weight:700; letter-spacing:.04em; font-size:13px; text-transform:uppercase; }
.hero h1 { font-size:30px; font-weight:800; margin:8px 0 6px; color:var(--text); }
.hero .sub { color:var(--text2); font-size:14.5px; }
.hero .meta-box { background:rgba(255,255,255,.7); border-radius:16px; padding:14px 20px; font-size:13.5px; color:var(--text2); min-width:260px; }
.hero .meta-box b { color:var(--text); }

.nav { position:sticky; top:0; z-index:50; background:rgba(245,246,251,.92); backdrop-filter:blur(6px);
  border-bottom:1px solid var(--border); padding:10px 28px; display:flex; gap:6px; flex-wrap:wrap; }
.nav a { color:var(--text2); text-decoration:none; font-size:13px; font-weight:600; padding:7px 13px;
  border-radius:20px; white-space:nowrap; margin-right:4px; }
.nav a:hover { background:var(--primary-tint); color:var(--primary-dark); }

section { margin:46px 0; }
.section-head { display:flex; align-items:center; gap:12px; margin-bottom:18px; }
.section-icon { width:36px; height:36px; border-radius:50%; display:flex; align-items:center; justify-content:center;
  font-size:17px; background:var(--primary-tint); color:var(--primary-dark); flex-shrink:0; }
.section-head h2 { font-size:21px; font-weight:800; margin:0; color:var(--text); }
.section-head .desc { color:var(--muted); font-size:13px; margin-top:2px; }

.grid3, .grid4, .grid2 { display:flex; flex-wrap:wrap; gap:18px; }
.grid3 > * { flex:1 1 calc(33.333% - 18px); min-width:280px; }
.grid4 > * { flex:1 1 calc(25% - 16px); min-width:230px; }
.grid2 > * { flex:1 1 calc(50% - 18px); min-width:320px; }
@media (max-width:980px) { .grid3 > *, .grid4 > * { flex:1 1 calc(50% - 18px); } }
@media (max-width:640px) { .grid3 > *, .grid4 > *, .grid2 > * { flex:1 1 100%; } }

.card { background:var(--surface); border:1px solid var(--border); border-radius:18px; padding:22px;
  box-shadow:0 2px 14px rgba(46,49,72,.05); }
.kpi-card .label { font-size:13px; color:var(--text2); font-weight:600; }
.kpi-card .value { font-size:30px; font-weight:800; margin:6px 0 4px; color:var(--text); }
.kpi-card .value .unit { font-size:15px; font-weight:600; color:var(--muted); margin-left:4px;}
.delta { font-size:12.5px; font-weight:700; padding:2px 8px; border-radius:10px; }
.delta.up { color:var(--coral-dark); background:var(--coral-tint); }
.delta.down { color:var(--mint-dark); background:var(--mint-tint); }
.delta.flat { color:var(--text2); background:var(--surface-alt); }
.kpi-card .delta-row { display:flex; align-items:center; gap:8px; font-size:12.5px; color:var(--muted); }
.kpi-card .delta-row .delta { margin-right:6px; }

.cluster-card .ch { display:flex; justify-content:space-between; align-items:center; margin-bottom:14px;}
.cluster-card .ch .name { font-weight:800; font-size:16px; }
.cluster-card .ch .dc { font-size:12px; color:var(--muted); }
.metric-row { margin-bottom:12px; }
.metric-row .mrow-top { display:flex; justify-content:space-between; font-size:13px; margin-bottom:5px; }
.metric-row .mrow-top .mlabel { color:var(--text2); font-weight:600; }
.metric-row .mrow-top .mval { font-weight:700; color:var(--text); }
.bar-track { height:8px; border-radius:6px; background:var(--surface-alt); overflow:hidden; }
.bar-fill { height:100%; border-radius:6px; }
.sub-stats { display:flex; gap:14px; margin-top:14px; padding-top:12px; border-top:1px dashed var(--border); }
.sub-stat { font-size:12px; color:var(--text2); margin-right:14px; }
.sub-stat:last-child { margin-right:0; }
.sub-stat b { display:block; font-size:14px; color:var(--text); font-weight:800; }

.table-card { background:var(--surface); border:1px solid var(--border); border-radius:18px; padding:6px 6px 14px;
  box-shadow:0 2px 14px rgba(46,49,72,.05); overflow:hidden; }
.table-toolbar { display:flex; justify-content:space-between; align-items:center; padding:14px 18px 8px; gap:10px; flex-wrap:wrap;}
.table-toolbar .count { font-size:12.5px; color:var(--muted); }
.search-box { border:1px solid var(--border); border-radius:10px; padding:7px 12px; font-size:13px;
  background:var(--surface-alt); color:var(--text); width:230px; }
.search-box:focus { outline:2px solid var(--primary-tint); }
table { width:100%; border-collapse:collapse; font-size:13.5px; }
thead th { background:var(--surface-alt); color:var(--text2); font-weight:700; text-align:left;
  padding:10px 14px; font-size:12.5px; position:sticky; top:0; }
tbody td { padding:9px 14px; border-bottom:1px solid var(--border); color:var(--text); }
tbody tr:hover { background:var(--primary-tint); }
.badge { font-size:11.5px; font-weight:700; padding:3px 10px; border-radius:10px; white-space:nowrap; }
.num { text-align:center; font-weight:600; }
.scroll-y { max-height:560px; overflow-y:auto; }
.mono { font-family:'SF Mono','Consolas',monospace; font-size:12.5px; color:var(--text2); }
.tag { display:inline-block; font-size:11px; padding:2px 8px; border-radius:8px; background:var(--surface-alt); color:var(--text2); margin-right:4px;}
.tag.thin { background:var(--mint-tint); color:var(--mint-dark); }
.tag.thick { background:var(--sky-tint); color:var(--sky-dark); }
.tag.shared { background:var(--peach-tint); color:var(--peach-dark); }

.foot { text-align:center; color:var(--muted); font-size:12px; margin-top:60px; }
.legend { display:flex; gap:16px; font-size:12px; color:var(--text2); margin-top:10px; flex-wrap:wrap;}
.legend span { display:inline-flex; align-items:center; gap:6px; margin-right:16px; }
.legend i { width:10px; height:10px; border-radius:50%; display:inline-block; margin-right:6px; }

.bd-title { font-weight:800; font-size:14.5px; color:var(--text); margin-bottom:14px; }
.bd-title .bd-total { font-weight:600; font-size:12px; color:var(--muted); margin-left:8px; }
.bd-row { display:flex; align-items:center; gap:10px; margin-bottom:10px; font-size:12.5px; }
.bd-label { width:38%; color:var(--text2); font-weight:600; overflow:hidden; text-overflow:ellipsis; white-space:nowrap; }
.bd-bar-track { flex:1; height:9px; border-radius:6px; background:var(--surface-alt); overflow:hidden; }
.bd-bar-fill { height:100%; border-radius:6px; background:var(--primary); }
.bd-count { width:88px; text-align:right; color:var(--text); font-weight:700; white-space:nowrap; }
.bd-count .bd-pct { color:var(--muted); font-weight:500; }

.stacked-bar { display:flex; height:14px; border-radius:7px; overflow:hidden; background:var(--surface-alt); margin-bottom:14px; }
.stacked-bar .seg.normal { background:var(--mint); }
.stacked-bar .seg.warning { background:var(--peach); }
.stacked-bar .seg.critical { background:var(--coral); }
.status-legend-row { display:flex; gap:16px; font-size:12.5px; color:var(--text2); flex-wrap:wrap; }
.status-legend-row .dot { width:9px; height:9px; border-radius:50%; display:inline-block; margin-right:6px; }
.status-legend-row .dot.normal { background:var(--mint-dark); }
.status-legend-row .dot.warning { background:var(--peach-dark); }
.status-legend-row .dot.critical { background:var(--coral-dark); }

@media print {
  .nav { position:static; }
  .search-box { display:none; }
  .table-toolbar .search-box { display:none; }
  .scroll-y { max-height:none !important; overflow:visible !important; }
  section { break-inside:avoid-page; }
  body { background:#fff; }
}
"@
}

function Get-JsBlock {
    return @"
function filterTable(inputId, tableId) {
  var q = document.getElementById(inputId).value.trim().toLowerCase();
  var rows = document.querySelectorAll('#' + tableId + ' tbody tr');
  var visible = 0;
  rows.forEach(function (r) {
    var hit = r.innerText.toLowerCase().indexOf(q) !== -1;
    r.style.display = hit ? '' : 'none';
    if (hit) visible++;
  });
  var counter = document.getElementById(tableId + '-count');
  if (counter) counter.innerText = visible + ' 행 표시';
}
"@
}

function Build-SectionHead {
    param([string]$Icon, [string]$Title, [string]$Desc, [string]$Anchor)
    return @"
<div class="section-head" id="$Anchor">
  <div class="section-icon">$Icon</div>
  <div><h2>$Title</h2><div class="desc">$Desc</div></div>
</div>
"@
}

function Build-HeroSection {
    param($Data)
    $m = $Data.Meta
    $cur = $m.CurrentDate.ToString("yyyy-MM-dd")
    $cmpLabel = Get-CompareDaysLabel -Meta $m
    $cmpLine = if ($m.CompareEnabled -and $m.PreviousDate) {
        "비교 기준일($cmpLabel) &nbsp;<b>$($m.PreviousDate.ToString("yyyy-MM-dd"))</b><br>"
    } else {
        "비교 기준일 &nbsp;<b>비교 없음</b><br>"
    }
    return @"
<div class="hero"><div class="hero-inner">
  <div>
    <div class="hero-eyebrow">VCF Operations · Capacity &amp; Health Report</div>
    <h1>$($m.CustomerName) 가상화 인프라 운영 현황 리포트</h1>
    <div class="sub">$($m.VCenterScope)</div>
  </div>
  <div class="meta-box">
    조회 기준일 &nbsp;<b>$cur</b><br>
    $cmpLine
    생성: $($m.GeneratedBy)
  </div>
</div></div>
"@
}

function Build-NavSection {
    $items = @(
        @{ Id = "exec"; Label = "Executive Summary" }
        @{ Id = "inventory"; Label = "리소스 현황" }
        @{ Id = "cluster"; Label = "클러스터 성능" }
        @{ Id = "datastore"; Label = "데이터스토어" }
        @{ Id = "hosts"; Label = "ESXi 호스트" }
        @{ Id = "vm-top"; Label = "VM Top 리스트" }
        @{ Id = "ops"; Label = "운영 참고사항" }
        @{ Id = "vm-inv"; Label = "VM 인벤토리" }
        @{ Id = "vm-thick"; Label = "Thick 디스크" }
        @{ Id = "vm-shared"; Label = "공유 디스크" }
        @{ Id = "vm-perf"; Label = "VM 성능정보" }
    )
    $links = ($items | ForEach-Object { "<a href=`"#$($_.Id)`">$($_.Label)</a>" }) -join ""
    return "<div class=`"nav`">$links</div>"
}

function Get-CompareDaysLabel {
    param($Meta)
    if (-not $Meta.CompareEnabled -or -not $Meta.PreviousDate) { return "비교 없음" }
    $days = [Math]::Round(($Meta.CurrentDate - $Meta.PreviousDate).TotalDays)
    # 주의: "$days일"처럼 변수 뒤에 한글을 바로 붙이면 PowerShell이 "$days일"을
    # 통째로 하나의 변수명으로 해석해버려(한글도 식별자로 허용됨) 값이 사라집니다.
    # 반드시 ${days}처럼 중괄호로 변수명을 명시적으로 구분해야 합니다.
    return "${days}일 전"
}

function Build-ExecSummarySection {
    param($Data)
    $cmpLabel = Get-CompareDaysLabel -Meta $Data.Meta
    $cards = ($Data.PerfSummary | ForEach-Object {
        $p = $_
        $deltaRow = if ($p.HasComparison) {
            "<div class=`"delta-row`">$(Get-ArrowHtml -Delta ($p.Current - $p.Previous)) <span>$cmpLabel 대비 (이전 $(Format-Number $p.Previous)$($p.Unit))</span></div>"
        } else {
            "<div class=`"delta-row`"><span style=`"color:var(--muted);`">비교 없음</span></div>"
        }
        @"
<div class="card kpi-card">
  <div class="label">$($p.Label)</div>
  <div class="value">$(Format-Number $p.Current)<span class="unit">$($p.Unit)</span></div>
  $deltaRow
</div>
"@
    }) -join ""
    $desc = if ($Data.Meta.CompareEnabled) { "최근 인프라 성능 요약 ($cmpLabel 대비)" } else { "최근 인프라 성능 요약 (비교 없음)" }
    $head = Build-SectionHead -Icon "Σ" -Title "Executive Summary" -Desc $desc -Anchor "exec"
    return "<section>$head<div class=`"grid3`">$cards</div></section>"
}

function Build-InventorySection {
    param($Data)
    $icons = @{ "vCenter" = "🌐"; "데이터센터" = "🏢"; "클러스터" = "🧩"; "ESXi 호스트" = "🖥️"; "가상머신" = "🧱" }
    $cards = ($Data.InventoryCounts | ForEach-Object {
        $inv = $_
        $icon = if ($icons.ContainsKey($inv.Label)) { $icons[$inv.Label] } else { "•" }
        $srcTag = if ($inv.PSObject.Properties.Name -contains "CompareSource" -and $inv.CompareSource -eq "metric") {
            " <span style=`"color:var(--mint-dark);font-size:10.5px;`">(실측)</span>"
        } else { "" }
        $deltaRow = if ($inv.HasComparison) {
            "<div class=`"delta-row`">$(Get-ArrowHtml -Delta $inv.Delta) <span>이전 $($inv.Previous.ToString("N0")) → 변화율 $(Format-Number $inv.DeltaPct)%$srcTag</span></div>"
        } else {
            "<div class=`"delta-row`"><span style=`"color:var(--muted);`">비교 없음</span></div>"
        }
        $powerRow = ""
        if ($inv.PSObject.Properties.Name -contains "PoweredOnCount") {
            $powerRow = "<div style=`"font-size:11.5px;color:var(--text2);margin-top:6px;`">🟢 켜짐 $($inv.PoweredOnCount.ToString("N0"))대 &nbsp;·&nbsp; ⚪ 꺼짐 $($inv.PoweredOffCount.ToString("N0"))대</div>"
        }
        @"
<div class="card kpi-card">
  <div class="label">$icon $($inv.Label)</div>
  <div class="value">$($inv.Current.ToString("N0"))<span class="unit">대</span></div>
  $deltaRow
  $powerRow
</div>
"@
    }) -join ""
    $head = Build-SectionHead -Icon "📊" -Title "리소스 현황 (수량 변화)" -Desc "vCenter / 데이터센터 / 클러스터 / 호스트 / VM 수량" -Anchor "inventory"
    return "<section>$head<div class=`"grid3`">$cards</div></section>"
}

function Build-ClusterSection {
    param($Data)
    $cmpLabel = Get-CompareDaysLabel -Meta $Data.Meta
    $cards = ($Data.Clusters | ForEach-Object {
        $cm = $_
        $cpuSt = Get-StatusFromPct -Value $cm.CpuPct -Warning $Threshold.cpu_warning -Critical $Threshold.cpu_critical
        $memSt = Get-StatusFromPct -Value $cm.MemPct -Warning $Threshold.mem_warning -Critical $Threshold.mem_critical
        $stoSt = Get-StatusFromPct -Value $cm.StoragePct -Warning $Threshold.storage_warning -Critical $Threshold.storage_critical
        $contSt = Get-StatusFromPct -Value $cm.CpuContentionPct -Warning $Threshold.cpu_contention_warning -Critical $Threshold.cpu_contention_critical

        $cpuDelta = if ($cm.HasComparison) { " $(Get-ArrowHtml -Delta ($cm.CpuPct - $cm.PrevCpuPct))" } else { "" }
        $memDelta = if ($cm.HasComparison) { " $(Get-ArrowHtml -Delta ($cm.MemPct - $cm.PrevMemPct))" } else { "" }
        $stoDelta = if ($cm.HasComparison) { " $(Get-ArrowHtml -Delta ($cm.StoragePct - $cm.PrevStoragePct))" } else { "" }
        $contDelta = if ($cm.HasComparison) { " $(Get-ArrowHtml -Delta ($cm.CpuContentionPct - $cm.PrevCpuContentionPct))" } else { "" }
        $cmpNote = if ($cm.HasComparison) { "<div style=`"font-size:11px;color:var(--muted);margin-top:8px;`">$cmpLabel 대비</div>" } else { "" }

        @"
<div class="card cluster-card">
  <div class="ch">
    <div><div class="name">$($cm.Name)</div><div class="dc">$($cm.Datacenter) · 호스트 $($cm.HostCount)대 · VM $($cm.VmCount)대</div></div>
    $(Get-BadgeHtml -Status $cm.Status)
  </div>

  <div class="metric-row">
    <div class="mrow-top"><span class="mlabel">CPU</span><span class="mval">$(Format-Number $cm.CpuUsedGhz) / $(Format-Number $cm.CpuTotalGhz) GHz &nbsp;($($cm.CpuPct)%)$cpuDelta</span></div>
    $(Get-BarHtml -Pct $cm.CpuPct -Status $cpuSt)
  </div>
  <div class="metric-row">
    <div class="mrow-top"><span class="mlabel">Memory</span><span class="mval">$(Format-Number $cm.MemUsedGb) / $(Format-Number $cm.MemTotalGb) GB &nbsp;($($cm.MemPct)%)$memDelta</span></div>
    $(Get-BarHtml -Pct $cm.MemPct -Status $memSt)
  </div>
  <div class="metric-row">
    <div class="mrow-top"><span class="mlabel">Storage</span><span class="mval">$(Format-Number $cm.StorageUsedTb 2) / $(Format-Number $cm.StorageTotalTb 2) TB &nbsp;($($cm.StoragePct)%)$stoDelta</span></div>
    $(Get-BarHtml -Pct $cm.StoragePct -Status $stoSt)
  </div>

  <div class="sub-stats">
    <div class="sub-stat">CPU 경합(Ready)<b style="color:#$($StatusColor[$contSt].fg)">$($cm.CpuContentionPct)%</b>$contDelta</div>
  </div>
  $cmpNote
</div>
"@
    }) -join ""

    $desc = if ($Data.Meta.CompareEnabled) { "CPU / Memory / Storage 실사용량·비율, CPU 경합률 ($cmpLabel 대비)" } else { "CPU / Memory / Storage 실사용량·비율, CPU 경합률" }
    $head = Build-SectionHead -Icon "🧩" -Title "클러스터별 성능 현황" -Desc $desc -Anchor "cluster"
    $legend = @"
<div class="legend">
  <span><i style="background:var(--mint-dark)"></i>정상(&lt;70%)</span>
  <span><i style="background:var(--peach-dark)"></i>주의(70~85%)</span>
  <span><i style="background:var(--coral-dark)"></i>위험(≥85% 또는 경합 ≥10%)</span>
</div>
"@
    return "<section>$head<div class=`"grid3`">$cards</div>$legend</section>"
}

function Build-DatastoreSection {
    param($Data)
    $cmpLabel = Get-CompareDaysLabel -Meta $Data.Meta
    $rows = $Data.DatastoreInfo
    $anyComparison = [bool]($rows | Where-Object { $_.HasComparison } | Select-Object -First 1)
    $desc = if ($anyComparison) { "데이터스토어 용량/사용량 — $cmpLabel 대비 증감" } else { "데이터스토어 용량/사용량" }
    $head = Build-SectionHead -Icon "💾" -Title "데이터스토어 현황" -Desc $desc -Anchor "datastore"

    $rowsHtml = ($rows | ForEach-Object {
        $d = $_
        $usedPct = if ($d.CapacityGb -gt 0) { [Math]::Round($d.UsedGb / $d.CapacityGb * 100, 1) } else { 0 }
        $freePct = if ($d.CapacityGb -gt 0) { [Math]::Round($d.FreeGb / $d.CapacityGb * 100, 1) } else { 0 }
        $prevCell = if ($d.HasComparison) { "$(Format-Number $d.PrevUsedGb) GB" } else { "<span style=`"color:var(--muted);`">비교 없음</span>" }
        $deltaCell = if ($d.HasComparison) { Get-ArrowHtml -Delta $d.DeltaUsedGb } else { "<span style=`"color:var(--muted);`">비교 없음</span>" }
        "<tr><td>$($d.Name)</td><td class=`"num`">$(Format-Number $d.CapacityGb) GB</td><td class=`"num`">$(Format-Number $d.UsedGb) GB ($usedPct%)</td><td class=`"num`">$prevCell</td><td class=`"num`">$deltaCell</td><td class=`"num`">$(Format-Number $d.FreeGb) GB ($freePct%)</td></tr>"
    }) -join ""
    if (-not $rowsHtml) {
        $rowsHtml = "<tr><td colspan=`"6`" style=`"text-align:center;color:var(--muted);padding:24px;`">데이터스토어 정보가 없습니다</td></tr>"
    }

    return @"
<section>$head
<div class="table-card">
  <div class="table-toolbar">
    <input class="search-box" id="dsSearch" placeholder="데이터스토어 검색..." onkeyup="filterTable('dsSearch','dsTable')">
    <span class="count" id="dsTable-count">$(@($rows).Count) 행 표시</span>
  </div>
  <div class="scroll-y">
  <table id="dsTable">
    <thead><tr><th>데이터스토어</th><th>총량</th><th>현재 사용량</th><th>이전 사용량</th><th>증감</th><th>잔여 용량</th></tr></thead>
    <tbody>$rowsHtml</tbody>
  </table>
  </div>
</div>
</section>
"@
}

function Build-FullWidthTableCard {
    param([string]$Title, [string]$CountLabel, [string]$TableId, [string]$HeaderHtml, [string]$RowsHtml)
    return @"
<div class="card" style="padding:0;margin-bottom:18px;">
  <div style="padding:18px 20px 4px;font-weight:800;font-size:14.5px;">$Title</div>
  <div class="table-toolbar"><span class="count">$CountLabel</span></div>
  <div class="scroll-y" style="max-height:480px;">
  <table id="$TableId"><thead><tr>$HeaderHtml</tr></thead><tbody>$RowsHtml</tbody></table>
  </div>
</div>
"@
}

function Build-HostsSection {
    param($Data)
    $head = Build-SectionHead -Icon "🖥️" -Title "ESXi 호스트 Top 리스트" `
        -Desc "IP 주소 제외 · CPU 사용률 / MEM 사용률 / CPU 경합률 각각 상위 10대" -Anchor "hosts"

    $cpuTop = @($Data.Hosts | Sort-Object -Property CpuPct -Descending | Select-Object -First 10)
    $memTop = @($Data.Hosts | Sort-Object -Property MemPct -Descending | Select-Object -First 10)
    $contTop = @($Data.Hosts | Sort-Object -Property CpuContentionPct -Descending | Select-Object -First 10)

    $cpuRows = ""; $i = 0
    foreach ($h in $cpuTop) {
        $i++
        $st = Get-StatusFromPct -Value $h.CpuPct -Warning $Threshold.cpu_warning -Critical $Threshold.cpu_critical
        $cpuRows += "<tr><td>$i</td><td>$($h.Name)</td><td>$($h.Cluster)</td><td class=`"num`">$($h.CpuPct)%</td><td>$(Get-BadgeHtml -Status $st)</td></tr>"
    }
    $memRows = ""; $i = 0
    foreach ($h in $memTop) {
        $i++
        $st = Get-StatusFromPct -Value $h.MemPct -Warning $Threshold.mem_warning -Critical $Threshold.mem_critical
        $memRows += "<tr><td>$i</td><td>$($h.Name)</td><td>$($h.Cluster)</td><td class=`"num`">$($h.MemPct)%</td><td>$(Get-BadgeHtml -Status $st)</td></tr>"
    }
    $contRows = ""; $i = 0
    foreach ($h in $contTop) {
        $i++
        $st = Get-StatusFromPct -Value $h.CpuContentionPct -Warning $Threshold.cpu_contention_warning -Critical $Threshold.cpu_contention_critical
        $contRows += "<tr><td>$i</td><td>$($h.Name)</td><td>$($h.Cluster)</td><td class=`"num`">$($h.CpuContentionPct)%</td><td>$(Get-BadgeHtml -Status $st)</td></tr>"
    }

    $cpuCard = Build-FullWidthTableCard -Title "CPU 사용률 Top10" -CountLabel "상위 $($cpuTop.Count)대" `
        -TableId "hostCpuTop" -HeaderHtml "<th>#</th><th>호스트명</th><th>클러스터</th><th>CPU 사용률</th><th>상태</th>" -RowsHtml $cpuRows
    $memCard = Build-FullWidthTableCard -Title "MEM 사용률 Top10" -CountLabel "상위 $($memTop.Count)대" `
        -TableId "hostMemTop" -HeaderHtml "<th>#</th><th>호스트명</th><th>클러스터</th><th>MEM 사용률</th><th>상태</th>" -RowsHtml $memRows
    $contCard = Build-FullWidthTableCard -Title "CPU 경합률 Top10" -CountLabel "상위 $($contTop.Count)대" `
        -TableId "hostContTop" -HeaderHtml "<th>#</th><th>호스트명</th><th>클러스터</th><th>CPU 경합률</th><th>상태</th>" -RowsHtml $contRows

    return "<section>$head$cpuCard$memCard$contCard</section>"
}

function Build-VmTopListsSection {
    param($Data)
    $head = Build-SectionHead -Icon "🔥" -Title "VM Top 리스트" `
        -Desc "vCPU 사용률 / CPU 경합(Ready) / 가상디스크 레이턴시 각각 상위 10대" -Anchor "vm-top"

    $cpuRows = ""; $i = 0
    foreach ($v in $Data.TopCpuVMs) {
        $i++
        $st = Get-StatusFromPct -Value $v.CpuUsagePct -Warning $Threshold.cpu_warning -Critical $Threshold.cpu_critical
        $cpuRows += "<tr><td>$i</td><td>$($v.Name)</td><td>$($v.Cluster)</td><td>$($v.Host)</td><td class=`"num`">$($v.VcpuCount)</td><td class=`"num`">$($v.CpuUsagePct)%</td><td>$(Get-BadgeHtml -Status $st)</td></tr>"
    }
    $readyRows = ""; $i = 0
    foreach ($v in $Data.TopReadyVMs) {
        $i++
        $st = Get-StatusFromPct -Value $v.CpuReadyPct -Warning $Threshold.cpu_contention_warning -Critical $Threshold.cpu_contention_critical
        $readyRows += "<tr><td>$i</td><td>$($v.Name)</td><td>$($v.Cluster)</td><td>$($v.Host)</td><td class=`"num`">$($v.VcpuCount)</td><td class=`"num`">$($v.CpuReadyPct)%</td><td>$(Get-BadgeHtml -Status $st)</td></tr>"
    }
    $diskRows = ""; $i = 0
    foreach ($v in $Data.DiskLatencyVMs) {
        $i++
        $maxLat = [Math]::Max($v.ReadLatencyMs, $v.WriteLatencyMs)
        $st = Get-StatusFromPct -Value $maxLat -Warning $Threshold.disk_latency_warning_ms -Critical $Threshold.disk_latency_critical_ms
        $diskRows += "<tr><td>$i</td><td>$($v.Name)</td><td>$($v.Cluster)</td><td>$($v.Datastore)</td><td class=`"num`">$($v.ReadLatencyMs) ms</td><td class=`"num`">$($v.WriteLatencyMs) ms</td><td>$(Get-BadgeHtml -Status $st)</td></tr>"
    }

    $cpuCard = Build-FullWidthTableCard -Title "vCPU 사용률 Top10" -CountLabel "상위 $($Data.TopCpuVMs.Count)건" `
        -TableId "vmCpuTop" -HeaderHtml "<th>#</th><th>VM명</th><th>클러스터</th><th>호스트</th><th>vCPU</th><th>사용률</th><th>상태</th>" -RowsHtml $cpuRows
    $readyCard = Build-FullWidthTableCard -Title "CPU 경합(Ready) Top10" -CountLabel "상위 $($Data.TopReadyVMs.Count)건" `
        -TableId "vmReadyTop" -HeaderHtml "<th>#</th><th>VM명</th><th>클러스터</th><th>호스트</th><th>vCPU</th><th>Ready %</th><th>상태</th>" -RowsHtml $readyRows
    $diskCard = Build-FullWidthTableCard -Title "가상디스크 레이턴시 Top10" -CountLabel "상위 $($Data.DiskLatencyVMs.Count)건" `
        -TableId "vmDiskTop" -HeaderHtml "<th>#</th><th>VM명</th><th>클러스터</th><th>데이터스토어</th><th>Read</th><th>Write</th><th>상태</th>" -RowsHtml $diskRows

    return "<section>$head$cpuCard$readyCard$diskCard</section>"
}

function Build-OpsNotesSection {
    param($Data)
    $head = Build-SectionHead -Icon "🛠️" -Title "운영 참고사항" -Desc "1주 이상 보존된 VM 스냅샷 — 스토리지 점유 및 성능 영향 점검 필요" -Anchor "ops"

    $rows = ($Data.SnapshotAlerts | ForEach-Object {
        $s = $_
        $st = if ($s.OldestSnapshotAgeDays -ge 30) { "critical" } else { "warning" }
        "<tr><td>$($s.Name)</td><td>$($s.Cluster)</td><td class=`"num`">$($s.SnapshotCount)</td><td class=`"num`">$($s.OldestSnapshotAgeDays)일</td><td class=`"num`">$(Format-Number $s.TotalSnapshotSizeGb) GB</td><td>$(Get-BadgeHtml -Status $st)</td></tr>"
    }) -join ""
    if (-not $rows) {
        $rows = "<tr><td colspan=`"6`" style=`"text-align:center;color:var(--muted);padding:24px;`">7일 이상 보존된 스냅샷이 없습니다</td></tr>"
    }

    return @"
<section>$head
<div class="table-card">
  <div class="table-toolbar">
    <input class="search-box" id="snapSearch" placeholder="VM/클러스터 검색..." onkeyup="filterTable('snapSearch','snapTable')">
    <span class="count" id="snapTable-count">$($Data.SnapshotAlerts.Count) 행 표시</span>
  </div>
  <div class="scroll-y">
  <table id="snapTable">
    <thead><tr><th>VM명</th><th>클러스터</th><th>스냅샷 수</th><th>최장 보존기간</th><th>총 용량</th><th>상태</th></tr></thead>
    <tbody>$rows</tbody>
  </table>
  </div>
</div>
</section>
"@
}

function Build-BreakdownCard {
    param([string]$Title, $Rows, [int]$Total)
    $rowsHtml = ($Rows | ForEach-Object {
        $barPct = [Math]::Max(2, $_.Pct)
        "<div class=`"bd-row`"><div class=`"bd-label`" title=`"$($_.Label)`">$($_.Label)</div><div class=`"bd-bar-track`"><div class=`"bd-bar-fill`" style=`"width:$($barPct)%;`"></div></div><div class=`"bd-count`">$($_.Count)대 <span class=`"bd-pct`">($($_.Pct)%)</span></div></div>"
    }) -join ""
    if (-not $rowsHtml) {
        $rowsHtml = "<div style=`"color:var(--muted);font-size:12.5px;`">데이터가 없습니다</div>"
    }
    return @"
<div class="card">
  <div class="bd-title">$Title<span class="bd-total">전체 $Total 대</span></div>
  $rowsHtml
</div>
"@
}

function Build-VmInventorySection {
    param($Data)
    $head = Build-SectionHead -Icon "🧱" -Title "VM 인벤토리 요약" `
        -Desc "Guest OS / VMware Tools 버전 / 가상 HW버전 / vCPU 구간별 VM 수량 분포" -Anchor "vm-inv"

    $total = $Data.VmBreakdown.Total
    $osCard = Build-BreakdownCard -Title "Guest OS별 VM 수량" -Rows $Data.VmBreakdown.OsRows -Total $total
    $toolsCard = Build-BreakdownCard -Title "VMware Tools 버전별 VM 수량" -Rows $Data.VmBreakdown.ToolsRows -Total $total
    $hwCard = Build-BreakdownCard -Title "Virtual Hardware 버전별 VM 수량" -Rows $Data.VmBreakdown.HwRows -Total $total
    $vcpuCard = Build-BreakdownCard -Title "vCPU 구간별 VM 수량" -Rows $Data.VmBreakdown.VcpuRows -Total $total

    return "<section>$head<div class=`"grid2`">$osCard$toolsCard$hwCard$vcpuCard</div></section>"
}

function Build-ThickDiskSection {
    param($Data)
    $head = Build-SectionHead -Icon "🟦" -Title "Thick 프로비저닝 디스크 목록" `
        -Desc "디스크 유형이 Thick(Eager/Lazy Zeroed)인 가상 디스크 목록" -Anchor "vm-thick"

    $rows = ""
    foreach ($v in $Data.VmInventory) {
        foreach ($d in $v.Disks) {
            if ($d.ProvisioningKind -eq "Thick") {
                $rows += "<tr><td>$($v.Name)</td><td>$($v.Cluster)</td><td>$($v.Host)</td><td>$($d.Label)</td><td class=`"num`">$(Format-Number $d.CapacityGb 0) GB</td><td>$($d.Datastore)</td></tr>"
            }
        }
    }
    $count = ([regex]::Matches($rows, "<tr>")).Count
    if (-not $rows) {
        $rows = "<tr><td colspan=`"6`" style=`"text-align:center;color:var(--muted);padding:24px;`">Thick 프로비저닝 디스크가 없습니다</td></tr>"
    }

    return @"
<section>$head
<div class="table-card">
  <div class="table-toolbar">
    <input class="search-box" id="thickSearch" placeholder="VM/클러스터 검색..." onkeyup="filterTable('thickSearch','thickTable')">
    <span class="count" id="thickTable-count">$count 행 표시</span>
  </div>
  <div class="scroll-y">
  <table id="thickTable">
    <thead><tr><th>VM명</th><th>클러스터</th><th>ESXi Host</th><th>디스크</th><th>용량</th><th>데이터스토어</th></tr></thead>
    <tbody>$rows</tbody>
  </table>
  </div>
</div>
</section>
"@
}

function Build-SharedDiskSection {
    param($Data)
    $head = Build-SectionHead -Icon "🟧" -Title "공유 디스크 목록" `
        -Desc "Shared(멀티라이터 등) 가상 디스크 목록" -Anchor "vm-shared"

    $rows = ""
    foreach ($v in $Data.VmInventory) {
        foreach ($d in $v.Disks) {
            if ($d.Shared) {
                $rows += "<tr><td>$($v.Name)</td><td>$($v.Cluster)</td><td>$($v.Host)</td><td>$($d.Label)</td><td class=`"num`">$(Format-Number $d.CapacityGb 0) GB</td><td>$($d.Datastore)</td></tr>"
            }
        }
    }
    $count = ([regex]::Matches($rows, "<tr>")).Count
    if (-not $rows) {
        $rows = "<tr><td colspan=`"6`" style=`"text-align:center;color:var(--muted);padding:24px;`">공유 디스크가 없습니다</td></tr>"
    }

    return @"
<section>$head
<div class="table-card">
  <div class="table-toolbar">
    <input class="search-box" id="sharedSearch" placeholder="VM/클러스터 검색..." onkeyup="filterTable('sharedSearch','sharedTable')">
    <span class="count" id="sharedTable-count">$count 행 표시</span>
  </div>
  <div class="scroll-y">
  <table id="sharedTable">
    <thead><tr><th>VM명</th><th>클러스터</th><th>ESXi Host</th><th>디스크</th><th>용량</th><th>데이터스토어</th></tr></thead>
    <tbody>$rows</tbody>
  </table>
  </div>
</div>
</section>
"@
}

function Get-StatusCounts {
    param($Values, [double]$Warning, [double]$Critical)
    $normal = 0; $warn = 0; $crit = 0
    foreach ($v in $Values) {
        $st = Get-StatusFromPct -Value $v -Warning $Warning -Critical $Critical
        if ($st -eq "critical") { $crit++ } elseif ($st -eq "warning") { $warn++ } else { $normal++ }
    }
    return [PSCustomObject]@{ Normal = $normal; Warning = $warn; Critical = $crit; Total = ($normal + $warn + $crit) }
}

function Build-StatusBreakdownCard {
    param([string]$Title, $Counts, $RangeLabel)
    $total = [Math]::Max(1, $Counts.Total)
    $nPct = [Math]::Round($Counts.Normal / $total * 100, 1)
    $wPct = [Math]::Round($Counts.Warning / $total * 100, 1)
    $cPct = [Math]::Round($Counts.Critical / $total * 100, 1)
    return @"
<div class="card">
  <div class="bd-title">$Title<span class="bd-total">전체 $($Counts.Total)대</span></div>
  <div class="stacked-bar">
    <div class="seg normal" style="width:$($nPct)%;"></div>
    <div class="seg warning" style="width:$($wPct)%;"></div>
    <div class="seg critical" style="width:$($cPct)%;"></div>
  </div>
  <div class="status-legend-row">
    <span><span class="dot normal"></span>정상 $($Counts.Normal)대 <span style="color:var(--muted);">($($RangeLabel.Normal))</span></span>
    <span><span class="dot warning"></span>주의 $($Counts.Warning)대 <span style="color:var(--muted);">($($RangeLabel.Warning))</span></span>
    <span><span class="dot critical"></span>위험 $($Counts.Critical)대 <span style="color:var(--muted);">($($RangeLabel.Critical))</span></span>
  </div>
</div>
"@
}

function Build-VmPerformanceSection {
    param($Data)
    $head = Build-SectionHead -Icon "📈" -Title "VM 성능정보 요약" `
        -Desc "CPU 사용률 / CPU 경합(Ready) / MEM 사용률 / 가상디스크 레이턴시 — 등급별 VM 수량" -Anchor "vm-perf"

    $cpuCounts = Get-StatusCounts -Values ($Data.VmPerformance | ForEach-Object { $_.CpuUsagePct }) `
        -Warning $Threshold.cpu_warning -Critical $Threshold.cpu_critical
    $readyCounts = Get-StatusCounts -Values ($Data.VmPerformance | ForEach-Object { $_.CpuReadyPct }) `
        -Warning $Threshold.cpu_contention_warning -Critical $Threshold.cpu_contention_critical
    $memCounts = Get-StatusCounts -Values ($Data.VmPerformance | ForEach-Object { $_.MemUsagePct }) `
        -Warning $Threshold.mem_warning -Critical $Threshold.mem_critical
    $diskCounts = Get-StatusCounts -Values ($Data.VmPerformance | ForEach-Object { $_.DiskLatencyMs }) `
        -Warning $Threshold.disk_latency_warning_ms -Critical $Threshold.disk_latency_critical_ms

    $cpuRange = Get-RangeLabel -Warning $Threshold.cpu_warning -Critical $Threshold.cpu_critical -Unit "%"
    $readyRange = Get-RangeLabel -Warning $Threshold.cpu_contention_warning -Critical $Threshold.cpu_contention_critical -Unit "%"
    $memRange = Get-RangeLabel -Warning $Threshold.mem_warning -Critical $Threshold.mem_critical -Unit "%"
    $diskRange = Get-RangeLabel -Warning $Threshold.disk_latency_warning_ms -Critical $Threshold.disk_latency_critical_ms -Unit "ms"

    $c1 = Build-StatusBreakdownCard -Title "CPU 사용률" -Counts $cpuCounts -RangeLabel $cpuRange
    $c2 = Build-StatusBreakdownCard -Title "CPU 경합(Ready)" -Counts $readyCounts -RangeLabel $readyRange
    $c3 = Build-StatusBreakdownCard -Title "MEM 사용률" -Counts $memCounts -RangeLabel $memRange
    $c4 = Build-StatusBreakdownCard -Title "가상디스크 레이턴시" -Counts $diskCounts -RangeLabel $diskRange

    return "<section>$head<div class=`"grid4`">$c1$c2$c3$c4</div></section>"
}

function New-VCFOpsHtmlReport {
    [CmdletBinding()]
    param([Parameter(Mandatory)]$Data)

    $bodyParts = @(
        (Build-NavSection)
        '<div class="wrap">'
        (Build-HeroSection -Data $Data)
        (Build-ExecSummarySection -Data $Data)
        (Build-InventorySection -Data $Data)
        (Build-ClusterSection -Data $Data)
        (Build-DatastoreSection -Data $Data)
        (Build-HostsSection -Data $Data)
        (Build-VmTopListsSection -Data $Data)
        (Build-OpsNotesSection -Data $Data)
        (Build-VmInventorySection -Data $Data)
        (Build-ThickDiskSection -Data $Data)
        (Build-SharedDiskSection -Data $Data)
        (Build-VmPerformanceSection -Data $Data)
        "<div class=`"foot`">$($Data.Meta.GeneratedBy) · 생성 시각 $(Get-Date -Format 'yyyy-MM-dd HH:mm')</div>"
        '</div>'
    )
    $body = $bodyParts -join ""
    $css = Get-CssBlock
    $js = Get-JsBlock
    $title = "$($Data.Meta.CustomerName) 가상화 인프라 운영 현황 리포트"

    return @"
<!DOCTYPE html>
<html lang="ko">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>$title</title>
<link rel="stylesheet" href="https://cdn.jsdelivr.net/gh/orioncactus/pretendard@v1.3.9/dist/web/static/pretendard.css">
<style>$css</style>
</head>
<body>
$body
<script>$js</script>
</body>
</html>
"@
}


# ---- inlined from Operations/Modules/VCFOpsEmailHtmlReport.psm1 ----
# VCFOpsEmailHtmlReport.psm1
# -----------------------------------------------------------------------------
# 이메일 본문 삽입/첨부용 "이메일 세이프(email-safe)" HTML 리포트 렌더러.
#
# Modules/VCFOpsHtmlReport.psm1 이 만드는 메인 HTML 리포트는 <style> 블록,
# flexbox/grid, position:sticky, 외부 폰트(<link>), <script>(검색 필터) 등을 사용해
# 웹 브라우저에서는 예쁘지만, Outlook 등 데스크톱 메일 클라이언트(Word 렌더링 엔진)
# 에서는 다수의 CSS가 무시되거나 레이아웃이 깨질 수 있습니다.
#
# 이 모듈은 동일한 $Data(리포트 데이터)를 받아, 메일 클라이언트 호환성이 검증된
# "전통적인 HTML 이메일 작성법"으로 다시 렌더링합니다:
#   - <style> 블록/외부 리소스/<script> 없음 (전부 인라인 style 속성만 사용)
#   - flexbox/grid 대신 <table>로 레이아웃 구성 (카드형 UI 대신 데이터 테이블 위주)
#   - 검색창 등 JS 상호작용 요소 제거 (정적 테이블로 전체 데이터 표시)
# -----------------------------------------------------------------------------


$Script:EmailFont = "Arial,'Malgun Gothic',Helvetica,sans-serif"

# 첨부 참고 스타일(EmailReport 예시)의 색상 팔레트를 그대로 적용합니다.
# (참고 파일은 구조/문구가 다른 별도 리포트이며, 여기서는 "색상"만 동일하게 맞춥니다.)
# 상태 배지(위험/주의/정상)는 참고 파일에 대응 요소가 없어 기존 $StatusColor를 유지합니다.
$Script:EC = @{
    page_bg        = "f1f4f9"  # 페이지(바깥) 배경
    card_bg        = "ffffff"  # 카드/컨테이너 배경
    border         = "dde1e8"  # 테두리
    text_primary   = "171923"  # 본문 텍스트
    text_muted     = "8b93a7"  # 흐린/보조 텍스트
    subsection     = "4a5062"  # 소제목(라벨) 텍스트
    accent         = "4f46e5"  # 섹션 타이틀 좌측 강조 바
    banner_bg      = "3730a3"  # 상단 배너 배경
    banner_title   = "ffffff"  # 배너 제목 텍스트
    banner_subtle  = "c7d2fe"  # 배너 부제/메타 텍스트
    th_bg          = "1c2130"  # 테이블 헤더(th) 배경
    th_text        = "ffffff"  # 테이블 헤더(th) 텍스트
    row_even       = "ffffff"  # 테이블 짝수 행 배경
    row_odd        = "f6f8fb"  # 테이블 홀수 행 배경
    stat_bg        = "fafafc"  # 통계 타일 배경
    footer_bg      = "f6f8fb"  # 푸터 배경
}

function Get-EmailArrowHtml {
    param([double]$Delta)
    if ($Delta -gt 0) { return "<span style=`"color:#$($Colors.coral_dark);font-weight:bold;`">▲$(Format-Number ([Math]::Abs($Delta)))</span>" }
    if ($Delta -lt 0) { return "<span style=`"color:#$($Colors.mint_dark);font-weight:bold;`">▼$(Format-Number ([Math]::Abs($Delta)))</span>" }
    return "<span style=`"color:#$($Script:EC.text_muted);`">–0.0</span>"
}

function Get-EmailBadgeHtml {
    param([Parameter(Mandatory)][string]$Status)
    $s = $StatusColor[$Status]
    return "<span style=`"display:inline-block;padding:2px 8px;font-size:11px;font-weight:bold;color:#$($s.fg);background-color:#$($s.bg);border-radius:8px;white-space:nowrap;`">$($s.label)</span>"
}

function Get-EmailCompareDaysLabel {
    param($Meta)
    if (-not $Meta.CompareEnabled -or -not $Meta.PreviousDate) { return "비교 없음" }
    $days = [Math]::Round(($Meta.CurrentDate - $Meta.PreviousDate).TotalDays)
    # "$days일"처럼 붙여 쓰면 PowerShell이 "days일"을 하나의 변수명으로 해석해 값이
    # 사라지므로(한글도 식별자로 허용됨) 반드시 ${days}로 변수명을 명시적으로 구분합니다.
    return "${days}일 전"
}

function Get-EmailStatusCounts {
    param($Values, [double]$Warning, [double]$Critical)
    $normal = 0; $warn = 0; $crit = 0
    foreach ($v in $Values) {
        $st = Get-StatusFromPct -Value $v -Warning $Warning -Critical $Critical
        if ($st -eq "critical") { $crit++ } elseif ($st -eq "warning") { $warn++ } else { $normal++ }
    }
    return [PSCustomObject]@{ Normal = $normal; Warning = $warn; Critical = $crit; Total = ($normal + $warn + $crit) }
}

function Build-EmailSectionHeader {
    param([string]$Icon, [string]$Title, [string]$Desc)
    return @"
<table role="presentation" width="100%" cellpadding="0" cellspacing="0" border="0" style="margin:26px 0 10px;">
  <tr><td style="font-size:14px;font-weight:bold;color:#$($Script:EC.text_primary);font-family:$Script:EmailFont;border-left:4px solid #$($Script:EC.accent);padding-left:8px;">$Icon $Title</td></tr>
  <tr><td style="font-size:11.5px;color:#$($Script:EC.text_muted);font-family:$Script:EmailFont;padding-top:2px;padding-bottom:8px;padding-left:12px;">$Desc</td></tr>
</table>
"@
}

function Build-EmailDataTable {
    # 헤더 배열 + 행(각 행은 셀 HTML 문자열의 배열) -> 인라인 style 기반 <table>
    # 첨부 참고 스타일과 동일하게: 진한 네이비 헤더(#th_bg) + 흰 글자, 짝/홀수 행 교차 배경.
    param([string[]]$Headers, $Rows, [string]$EmptyMessage = "데이터가 없습니다")

    $theadCells = ($Headers | ForEach-Object {
        "<th align=`"left`" style=`"padding:7px 10px;background-color:#$($Script:EC.th_bg);color:#$($Script:EC.th_text);font-size:10.5px;font-family:$Script:EmailFont;text-transform:uppercase;letter-spacing:.02em;border:1px solid #$($Script:EC.th_bg);white-space:nowrap;`">$_</th>"
    }) -join ""

    $rowList = @($Rows)
    if ($rowList.Count -eq 0) {
        $bodyRows = "<tr><td colspan=`"$($Headers.Count)`" align=`"center`" style=`"padding:16px;background-color:#$($Script:EC.row_even);border:1px solid #$($Script:EC.border);color:#$($Script:EC.text_muted);font-size:12px;font-family:$Script:EmailFont;`">$EmptyMessage</td></tr>"
    }
    else {
        $i = 0
        $bodyRows = ($rowList | ForEach-Object {
            $rowBg = if ($i % 2 -eq 0) { $Script:EC.row_even } else { $Script:EC.row_odd }
            $i++
            $tds = ($_ | ForEach-Object {
                "<td style=`"padding:6px 10px;background-color:#$rowBg;border:1px solid #$($Script:EC.border);font-size:12px;color:#$($Script:EC.text_primary);font-family:$Script:EmailFont;`">$_</td>"
            }) -join ""
            "<tr>$tds</tr>"
        }) -join ""
    }

    return @"
<table role="presentation" width="100%" cellpadding="0" cellspacing="0" border="0" style="border:1px solid #$($Script:EC.border);border-collapse:collapse;margin-bottom:6px;">
  <tr>$theadCells</tr>
  $bodyRows
</table>
"@
}

function Build-EmailHeaderHtml {
    param($Data)
    $m = $Data.Meta
    $cur = $m.CurrentDate.ToString("yyyy-MM-dd")
    $cmpLine = if ($m.CompareEnabled -and $m.PreviousDate) {
        "비교 기준일 ($(Get-EmailCompareDaysLabel -Meta $m)): <b>$($m.PreviousDate.ToString('yyyy-MM-dd'))</b>"
    } else { "비교 기준일: <b>비교 없음</b>" }

    return @"
<table role="presentation" width="100%" cellpadding="0" cellspacing="0" border="0" style="background-color:#$($Script:EC.banner_bg);margin-bottom:6px;">
  <tr><td style="padding:20px;font-family:$Script:EmailFont;">
    <div style="font-size:11px;font-weight:bold;letter-spacing:.04em;color:#$($Script:EC.banner_subtle);text-transform:uppercase;">VCF Operations · Capacity &amp; Health Report</div>
    <div style="font-size:19px;font-weight:bold;color:#$($Script:EC.banner_title);margin:8px 0 4px;">$($m.CustomerName) 가상화 인프라 운영 현황 리포트</div>
    <div style="font-size:12.5px;color:#$($Script:EC.banner_subtle);margin-bottom:12px;">$($m.VCenterScope)</div>
    <div style="font-size:12px;color:#$($Script:EC.banner_subtle);line-height:1.7;">
      조회 기준일: <b style="color:#$($Script:EC.banner_title);">$cur</b><br>
      $cmpLine<br>
      생성: $($m.GeneratedBy)
    </div>
  </td></tr>
</table>
"@
}

function Build-EmailExecSummarySection {
    param($Data)
    $cmpLabel = Get-EmailCompareDaysLabel -Meta $Data.Meta
    $rows = @($Data.PerfSummary | ForEach-Object {
        $p = $_
        $deltaCell = if ($p.HasComparison) { Get-EmailArrowHtml -Delta ($p.Current - $p.Previous) } else { "<span style=`"color:#$($Script:EC.text_muted);`">비교 없음</span>" }
        , @($p.Label, "$(Format-Number $p.Current) $($p.Unit)", "$(Format-Number $p.Previous) $($p.Unit)", $deltaCell)
    })
    $head = Build-EmailSectionHeader -Icon "Σ" -Title "Executive Summary" -Desc "최근 인프라 성능 요약 ($cmpLabel 대비)"
    $table = Build-EmailDataTable -Headers @("지표", "현재", "이전", "증감") -Rows $rows
    return "$head$table"
}

function Build-EmailInventorySection {
    param($Data)
    $rows = @($Data.InventoryCounts | ForEach-Object {
        $inv = $_
        $deltaCell = if ($inv.HasComparison) {
            $srcTag = if ($inv.PSObject.Properties.Name -contains "CompareSource" -and $inv.CompareSource -eq "metric") { " (실측)" } else { "" }
            "$(Get-EmailArrowHtml -Delta $inv.Delta) ($(Format-Number $inv.DeltaPct)%)$srcTag"
        } else { "<span style=`"color:#$($Script:EC.text_muted);`">비교 없음</span>" }
        $note = if ($inv.PSObject.Properties.Name -contains "PoweredOnCount") {
            "켜짐 $($inv.PoweredOnCount.ToString('N0'))대 / 꺼짐 $($inv.PoweredOffCount.ToString('N0'))대"
        } else { "" }
        , @($inv.Label, "$($inv.Current.ToString('N0'))대", "$($inv.Previous.ToString('N0'))대", $deltaCell, $note)
    })
    $head = Build-EmailSectionHeader -Icon "📊" -Title "리소스 현황 (수량 변화)" -Desc "vCenter / 데이터센터 / 클러스터 / 호스트 / VM 수량"
    $table = Build-EmailDataTable -Headers @("항목", "현재", "이전", "증감", "비고") -Rows $rows
    return "$head$table"
}

function Build-EmailClusterSection {
    param($Data)
    $cmpLabel = Get-EmailCompareDaysLabel -Meta $Data.Meta
    $rows = @($Data.Clusters | ForEach-Object {
        $cm = $_
        $contSt = Get-StatusFromPct -Value $cm.CpuContentionPct -Warning $Threshold.cpu_contention_warning -Critical $Threshold.cpu_contention_critical

        $cpuCell = "$($cm.CpuPct)%" + $(if ($cm.HasComparison) { " " + (Get-EmailArrowHtml -Delta ($cm.CpuPct - $cm.PrevCpuPct)) } else { "" })
        $memCell = "$($cm.MemPct)%" + $(if ($cm.HasComparison) { " " + (Get-EmailArrowHtml -Delta ($cm.MemPct - $cm.PrevMemPct)) } else { "" })
        $stoCell = "$($cm.StoragePct)%" + $(if ($cm.HasComparison) { " " + (Get-EmailArrowHtml -Delta ($cm.StoragePct - $cm.PrevStoragePct)) } else { "" })
        $contCell = "<span style=`"color:#$($StatusColor[$contSt].fg);font-weight:bold;`">$($cm.CpuContentionPct)%</span>"

        , @(
            "$($cm.Name)<br><span style=`"color:#$($Script:EC.text_muted);font-size:11px;`">$($cm.Datacenter)</span>",
            "$($cm.HostCount)대", "$($cm.VmCount)대",
            $cpuCell, $memCell, $stoCell, $contCell,
            (Get-EmailBadgeHtml -Status $cm.Status)
        )
    })
    $head = Build-EmailSectionHeader -Icon "🧩" -Title "클러스터별 성능 현황" -Desc "CPU / Memory / Storage 사용률, CPU 경합률 ($cmpLabel 대비)"
    $table = Build-EmailDataTable -Headers @("클러스터", "호스트", "VM", "CPU", "MEM", "Storage", "경합", "상태") -Rows $rows
    return "$head$table"
}

function Build-EmailDatastoreSection {
    param($Data)
    $cmpLabel = Get-EmailCompareDaysLabel -Meta $Data.Meta
    $rows = @($Data.DatastoreInfo | ForEach-Object {
        $d = $_
        $usedPct = if ($d.CapacityGb -gt 0) { [Math]::Round($d.UsedGb / $d.CapacityGb * 100, 1) } else { 0 }
        $deltaCell = if ($d.HasComparison) { Get-EmailArrowHtml -Delta $d.DeltaUsedGb } else { "<span style=`"color:#$($Script:EC.text_muted);`">비교 없음</span>" }
        , @($d.Name, $d.Cluster, "$(Format-Number $d.CapacityGb) GB", "$(Format-Number $d.UsedGb) GB ($usedPct%)", $deltaCell, "$(Format-Number $d.FreeGb) GB")
    })
    $anyComparison = [bool]($Data.DatastoreInfo | Where-Object { $_.HasComparison } | Select-Object -First 1)
    $desc = if ($anyComparison) { "데이터스토어 용량/사용량 — $cmpLabel 대비 증감" } else { "데이터스토어 용량/사용량" }
    $head = Build-EmailSectionHeader -Icon "💾" -Title "데이터스토어 현황" -Desc $desc
    $table = Build-EmailDataTable -Headers @("데이터스토어", "클러스터", "총량", "사용량", "증감", "잔여") -Rows $rows
    return "$head$table"
}

function Build-EmailHostsSection {
    param($Data)
    $head = Build-EmailSectionHeader -Icon "🖥️" -Title "ESXi 호스트 Top 리스트" -Desc "CPU 사용률 / MEM 사용률 / CPU 경합률 각각 상위 10대"

    $cpuTop = @($Data.Hosts | Sort-Object -Property CpuPct -Descending | Select-Object -First 10)
    $memTop = @($Data.Hosts | Sort-Object -Property MemPct -Descending | Select-Object -First 10)
    $contTop = @($Data.Hosts | Sort-Object -Property CpuContentionPct -Descending | Select-Object -First 10)

    function Get-TopRows {
        param($List, [string]$ValueProp, [double]$Warn, [double]$Crit)
        $i = 0
        @($List | ForEach-Object {
            $i++
            $val = $_.$ValueProp
            $st = Get-StatusFromPct -Value $val -Warning $Warn -Critical $Crit
            , @("$i", $_.Name, $_.Cluster, "$val%", (Get-EmailBadgeHtml -Status $st))
        })
    }

    $cpuRows = Get-TopRows -List $cpuTop -ValueProp "CpuPct" -Warn $Threshold.cpu_warning -Crit $Threshold.cpu_critical
    $memRows = Get-TopRows -List $memTop -ValueProp "MemPct" -Warn $Threshold.mem_warning -Crit $Threshold.mem_critical
    $contRows = Get-TopRows -List $contTop -ValueProp "CpuContentionPct" -Warn $Threshold.cpu_contention_warning -Crit $Threshold.cpu_contention_critical

    $sub1 = "<div style=`"font-weight:bold;font-size:13px;margin:4px 0 6px;color:#$($Script:EC.text_primary);font-family:$Script:EmailFont;`">CPU 사용률 Top10</div>"
    $sub2 = "<div style=`"font-weight:bold;font-size:13px;margin:14px 0 6px;color:#$($Script:EC.text_primary);font-family:$Script:EmailFont;`">MEM 사용률 Top10</div>"
    $sub3 = "<div style=`"font-weight:bold;font-size:13px;margin:14px 0 6px;color:#$($Script:EC.text_primary);font-family:$Script:EmailFont;`">CPU 경합률 Top10</div>"

    $cpuTable = Build-EmailDataTable -Headers @("#", "호스트명", "클러스터", "CPU 사용률", "상태") -Rows $cpuRows
    $memTable = Build-EmailDataTable -Headers @("#", "호스트명", "클러스터", "MEM 사용률", "상태") -Rows $memRows
    $contTable = Build-EmailDataTable -Headers @("#", "호스트명", "클러스터", "CPU 경합률", "상태") -Rows $contRows

    return "$head$sub1$cpuTable$sub2$memTable$sub3$contTable"
}

function Build-EmailVmTopListsSection {
    param($Data)
    $head = Build-EmailSectionHeader -Icon "🔥" -Title "VM Top 리스트" -Desc "vCPU 사용률 / CPU 경합(Ready) / 가상디스크 레이턴시 각각 상위 10대"

    $cpuRows = @(); $i = 0
    foreach ($v in $Data.TopCpuVMs) {
        $i++
        $st = Get-StatusFromPct -Value $v.CpuUsagePct -Warning $Threshold.cpu_warning -Critical $Threshold.cpu_critical
        $cpuRows += , @("$i", $v.Name, $v.Cluster, $v.Host, "$($v.VcpuCount)", "$($v.CpuUsagePct)%", (Get-EmailBadgeHtml -Status $st))
    }
    $readyRows = @(); $i = 0
    foreach ($v in $Data.TopReadyVMs) {
        $i++
        $st = Get-StatusFromPct -Value $v.CpuReadyPct -Warning $Threshold.cpu_contention_warning -Critical $Threshold.cpu_contention_critical
        $readyRows += , @("$i", $v.Name, $v.Cluster, $v.Host, "$($v.VcpuCount)", "$($v.CpuReadyPct)%", (Get-EmailBadgeHtml -Status $st))
    }
    $diskRows = @(); $i = 0
    foreach ($v in $Data.DiskLatencyVMs) {
        $i++
        $maxLat = [Math]::Max($v.ReadLatencyMs, $v.WriteLatencyMs)
        $st = Get-StatusFromPct -Value $maxLat -Warning $Threshold.disk_latency_warning_ms -Critical $Threshold.disk_latency_critical_ms
        $diskRows += , @("$i", $v.Name, $v.Cluster, $v.Datastore, "$($v.ReadLatencyMs) ms", "$($v.WriteLatencyMs) ms", (Get-EmailBadgeHtml -Status $st))
    }

    $sub1 = "<div style=`"font-weight:bold;font-size:13px;margin:4px 0 6px;color:#$($Script:EC.text_primary);font-family:$Script:EmailFont;`">vCPU 사용률 Top10</div>"
    $sub2 = "<div style=`"font-weight:bold;font-size:13px;margin:14px 0 6px;color:#$($Script:EC.text_primary);font-family:$Script:EmailFont;`">CPU 경합(Ready) Top10</div>"
    $sub3 = "<div style=`"font-weight:bold;font-size:13px;margin:14px 0 6px;color:#$($Script:EC.text_primary);font-family:$Script:EmailFont;`">가상디스크 레이턴시 Top10</div>"

    $cpuTable = Build-EmailDataTable -Headers @("#", "VM명", "클러스터", "호스트", "vCPU", "사용률", "상태") -Rows $cpuRows
    $readyTable = Build-EmailDataTable -Headers @("#", "VM명", "클러스터", "호스트", "vCPU", "Ready %", "상태") -Rows $readyRows
    $diskTable = Build-EmailDataTable -Headers @("#", "VM명", "클러스터", "데이터스토어", "Read", "Write", "상태") -Rows $diskRows

    return "$head$sub1$cpuTable$sub2$readyTable$sub3$diskTable"
}

function Build-EmailOpsNotesSection {
    param($Data)
    $head = Build-EmailSectionHeader -Icon "🛠️" -Title "운영 참고사항" -Desc "1주 이상 보존된 VM 스냅샷 — 스토리지 점유 및 성능 영향 점검 필요"
    $rows = @($Data.SnapshotAlerts | ForEach-Object {
        $s = $_
        $st = if ($s.OldestSnapshotAgeDays -ge 30) { "critical" } else { "warning" }
        , @($s.Name, $s.Cluster, "$($s.SnapshotCount)", "$($s.OldestSnapshotAgeDays)일", "$(Format-Number $s.TotalSnapshotSizeGb) GB", (Get-EmailBadgeHtml -Status $st))
    })
    $table = Build-EmailDataTable -Headers @("VM명", "클러스터", "스냅샷 수", "최장 보존기간", "총 용량", "상태") -Rows $rows -EmptyMessage "7일 이상 보존된 스냅샷이 없습니다"
    return "$head$table"
}

function Build-EmailBreakdownTable {
    param([string]$Title, $Rows, [int]$Total)
    $tblRows = @($Rows | ForEach-Object {
        $deltaCell = if ($_.HasComparison) { Get-EmailArrowHtml -Delta $_.Delta } else { "<span style=`"color:#$($Script:EC.text_muted);`">비교 없음</span>" }
        , @($_.Label, "$($_.Count)대", "$($_.Pct)%", $deltaCell)
    })
    $sub = "<div style=`"font-weight:bold;font-size:13px;margin:14px 0 6px;color:#$($Script:EC.text_primary);font-family:$Script:EmailFont;`">$Title <span style=`"font-weight:normal;color:#$($Script:EC.text_muted);font-size:11px;`">(전체 $Total 대)</span></div>"
    $table = Build-EmailDataTable -Headers @("구분", "수량", "비중", "증감") -Rows $tblRows
    return "$sub$table"
}

function Build-EmailVmInventorySection {
    param($Data)
    $head = Build-EmailSectionHeader -Icon "🧱" -Title "VM 인벤토리 요약" -Desc "Guest OS / VMware Tools 버전 / 가상 HW버전 / vCPU 구간별 VM 수량 분포"
    $total = $Data.VmBreakdown.Total
    $os = Build-EmailBreakdownTable -Title "Guest OS별 VM 수량" -Rows $Data.VmBreakdown.OsRows -Total $total
    $tools = Build-EmailBreakdownTable -Title "VMware Tools 버전별 VM 수량" -Rows $Data.VmBreakdown.ToolsRows -Total $total
    $hw = Build-EmailBreakdownTable -Title "Virtual Hardware 버전별 VM 수량" -Rows $Data.VmBreakdown.HwRows -Total $total
    $vcpu = Build-EmailBreakdownTable -Title "vCPU 구간별 VM 수량" -Rows $Data.VmBreakdown.VcpuRows -Total $total
    return "$head$os$tools$hw$vcpu"
}

function Build-EmailThickDiskSection {
    param($Data)
    $head = Build-EmailSectionHeader -Icon "🟦" -Title "Thick 프로비저닝 디스크 목록" -Desc "디스크 유형이 Thick(Eager/Lazy Zeroed)인 가상 디스크 목록"
    $rows = @()
    foreach ($v in $Data.VmInventory) {
        foreach ($d in $v.Disks) {
            if ($d.ProvisioningKind -eq "Thick") {
                $rows += , @($v.Name, $v.Cluster, $v.Host, $d.Label, "$(Format-Number $d.CapacityGb 0) GB", $d.Datastore)
            }
        }
    }
    $table = Build-EmailDataTable -Headers @("VM명", "클러스터", "ESXi Host", "디스크", "용량", "데이터스토어") -Rows $rows -EmptyMessage "Thick 프로비저닝 디스크가 없습니다"
    return "$head$table"
}

function Build-EmailSharedDiskSection {
    param($Data)
    $head = Build-EmailSectionHeader -Icon "🟧" -Title "공유 디스크 목록" -Desc "Shared(멀티라이터 등) 가상 디스크 목록"
    $rows = @()
    foreach ($v in $Data.VmInventory) {
        foreach ($d in $v.Disks) {
            if ($d.Shared) {
                $rows += , @($v.Name, $v.Cluster, $v.Host, $d.Label, "$(Format-Number $d.CapacityGb 0) GB", $d.Datastore)
            }
        }
    }
    $table = Build-EmailDataTable -Headers @("VM명", "클러스터", "ESXi Host", "디스크", "용량", "데이터스토어") -Rows $rows -EmptyMessage "공유 디스크가 없습니다"
    return "$head$table"
}

function Build-EmailVmPerformanceSection {
    param($Data)
    $head = Build-EmailSectionHeader -Icon "📈" -Title "VM 성능정보 요약" -Desc "CPU 사용률 / CPU 경합(Ready) / MEM 사용률 / 가상디스크 레이턴시 — 등급별 VM 수량"

    $cpuCounts = Get-EmailStatusCounts -Values ($Data.VmPerformance | ForEach-Object { $_.CpuUsagePct }) -Warning $Threshold.cpu_warning -Critical $Threshold.cpu_critical
    $readyCounts = Get-EmailStatusCounts -Values ($Data.VmPerformance | ForEach-Object { $_.CpuReadyPct }) -Warning $Threshold.cpu_contention_warning -Critical $Threshold.cpu_contention_critical
    $memCounts = Get-EmailStatusCounts -Values ($Data.VmPerformance | ForEach-Object { $_.MemUsagePct }) -Warning $Threshold.mem_warning -Critical $Threshold.mem_critical
    $diskCounts = Get-EmailStatusCounts -Values ($Data.VmPerformance | ForEach-Object { $_.DiskLatencyMs }) -Warning $Threshold.disk_latency_warning_ms -Critical $Threshold.disk_latency_critical_ms

    $rows = @(
        , @("CPU 사용률", "$($cpuCounts.Normal)대", "$($cpuCounts.Warning)대", "$($cpuCounts.Critical)대", "$($cpuCounts.Total)대")
        , @("CPU 경합(Ready)", "$($readyCounts.Normal)대", "$($readyCounts.Warning)대", "$($readyCounts.Critical)대", "$($readyCounts.Total)대")
        , @("MEM 사용률", "$($memCounts.Normal)대", "$($memCounts.Warning)대", "$($memCounts.Critical)대", "$($memCounts.Total)대")
        , @("디스크 레이턴시", "$($diskCounts.Normal)대", "$($diskCounts.Warning)대", "$($diskCounts.Critical)대", "$($diskCounts.Total)대")
    )
    $table = Build-EmailDataTable -Headers @("지표", "정상", "주의", "위험", "전체") -Rows $rows
    return "$head$table"
}

function New-VCFOpsEmailHtmlReport {
    # 이메일 발송(본문 삽입/첨부)용 - <style>/<script>/외부 리소스 없이 <table> +
    # 인라인 style 속성만으로 구성된 정적 HTML을 생성합니다.
    [CmdletBinding()]
    param([Parameter(Mandatory)]$Data)

    $bodyParts = @(
        (Build-EmailHeaderHtml -Data $Data)
        (Build-EmailExecSummarySection -Data $Data)
        (Build-EmailInventorySection -Data $Data)
        (Build-EmailClusterSection -Data $Data)
        (Build-EmailDatastoreSection -Data $Data)
        (Build-EmailHostsSection -Data $Data)
        (Build-EmailVmTopListsSection -Data $Data)
        (Build-EmailOpsNotesSection -Data $Data)
        (Build-EmailVmInventorySection -Data $Data)
        (Build-EmailThickDiskSection -Data $Data)
        (Build-EmailSharedDiskSection -Data $Data)
        (Build-EmailVmPerformanceSection -Data $Data)
    )
    $body = $bodyParts -join ""
    $title = "$($Data.Meta.CustomerName) 가상화 인프라 운영 현황 리포트 (이메일용)"

    return @"
<!DOCTYPE html>
<html lang="ko">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<meta name="x-apple-disable-message-reformatting">
<title>$title</title>
</head>
<body style="margin:0;padding:0;background-color:#$($Script:EC.page_bg);">
<table role="presentation" width="100%" cellpadding="0" cellspacing="0" border="0" style="background-color:#$($Script:EC.page_bg);">
<tr><td align="center" style="padding:20px 12px;">
<table role="presentation" width="680" cellpadding="0" cellspacing="0" border="0" style="max-width:680px;width:100%;background-color:#$($Script:EC.card_bg);border:1px solid #$($Script:EC.border);">
<tr><td style="padding:20px;">
$body
</td></tr>
<tr><td style="padding:12px 20px;background-color:#$($Script:EC.footer_bg);border-top:1px solid #$($Script:EC.border);text-align:center;">
<div style="color:#$($Script:EC.text_muted);font-size:11px;font-family:$Script:EmailFont;">$($Data.Meta.GeneratedBy) &middot; 생성 시각 $(Get-Date -Format 'yyyy-MM-dd HH:mm')</div>
</td></tr>
</table>
</td></tr>
</table>
</body>
</html>
"@
}


# ---- inlined from Operations/Modules/VCFOpsCsvExport.psm1 ----
# VCFOpsCsvExport.psm1
# -----------------------------------------------------------------------------
# 리포트 데이터를 데이터셋별 CSV 파일로 출력합니다 (Excel 등 후속 분석용).
# HTML은 요약/분포 위주로 보여주지만, CSV는 원본 상세 데이터(VM별 1행 등)를
# 그대로 내보냅니다.
# -----------------------------------------------------------------------------

function Write-VCFOpsCsvDataset {
    param([string]$OutputDir, [string]$Name, $Rows)
    $path = Join-Path $OutputDir "$Name.csv"
    $items = @($Rows)
    if ($items.Count -eq 0) {
        # 빈 데이터셋도 헤더 없이 빈 파일로라도 남겨 "데이터 없음"을 구분되게 함
        "" | Set-Content -Path $path -Encoding utf8
    }
    else {
        $items | Export-Csv -Path $path -NoTypeInformation -Encoding utf8
    }
    return $path
}

function Export-VCFOpsCsv {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]$Data,
        [Parameter(Mandatory)][string]$OutputDir
    )

    if (-not (Test-Path -Path $OutputDir)) {
        New-Item -ItemType Directory -Path $OutputDir -Force | Out-Null
    }

    $written = @()

    # ---- 인벤토리 수량 ----
    $written += Write-VCFOpsCsvDataset -OutputDir $OutputDir -Name "inventory_counts" -Rows `
        ($Data.InventoryCounts | Select-Object Label, Current, Previous, Delta, DeltaPct, HasComparison, CompareSource, PoweredOnCount, PoweredOffCount)

    # ---- Executive Summary(성능 요약) ----
    $written += Write-VCFOpsCsvDataset -OutputDir $OutputDir -Name "perf_summary" -Rows `
        ($Data.PerfSummary | Select-Object Label, Unit, Current, Previous, HasComparison)

    # ---- 데이터스토어 현황 ----
    $written += Write-VCFOpsCsvDataset -OutputDir $OutputDir -Name "datastores" -Rows ($Data.DatastoreInfo | Select-Object `
        Cluster, Name, CapacityGb, PrevCapacityGb, DeltaCapacityGb, UsedGb, PrevUsedGb, DeltaUsedGb, FreeGb, HasComparison)

    # ---- 클러스터 ----
    $written += Write-VCFOpsCsvDataset -OutputDir $OutputDir -Name "clusters" -Rows ($Data.Clusters | Select-Object `
        Name, Datacenter, HostCount, VmCount, CpuUsedGhz, CpuTotalGhz, CpuPct, MemUsedGb, MemTotalGb, MemPct, `
        StorageUsedTb, StorageTotalTb, StoragePct, StorageFreeTb, CpuContentionPct, StorageLatencyMs, Status, `
        PrevCpuPct, PrevMemPct, PrevStoragePct, PrevCpuContentionPct, HasComparison)

    # ---- ESXi 호스트 ----
    $written += Write-VCFOpsCsvDataset -OutputDir $OutputDir -Name "hosts" -Rows `
        ($Data.Hosts | Select-Object Name, Cluster, CpuPct, MemPct, CpuContentionPct, MemContentionPct, Status)

    # ---- VM Top 리스트 ----
    $written += Write-VCFOpsCsvDataset -OutputDir $OutputDir -Name "vm_top_cpu_usage" -Rows `
        ($Data.TopCpuVMs | Select-Object Name, Cluster, Host, VcpuCount, CpuUsagePct)
    $written += Write-VCFOpsCsvDataset -OutputDir $OutputDir -Name "vm_top_cpu_ready" -Rows `
        ($Data.TopReadyVMs | Select-Object Name, Cluster, Host, VcpuCount, CpuReadyPct)
    $written += Write-VCFOpsCsvDataset -OutputDir $OutputDir -Name "vm_top_disk_latency" -Rows `
        ($Data.DiskLatencyVMs | Select-Object Name, Cluster, Datastore, ReadLatencyMs, WriteLatencyMs)

    # ---- 운영 참고사항 (스냅샷) ----
    $written += Write-VCFOpsCsvDataset -OutputDir $OutputDir -Name "snapshot_alerts" -Rows `
        ($Data.SnapshotAlerts | Select-Object Name, Cluster, SnapshotCount, OldestSnapshotAgeDays, TotalSnapshotSizeGb)

    # ---- VM 인벤토리 상세 (VM 1행 = 1대, Disks는 별도 파일로 분리) ----
    $vmInvRows = $Data.VmInventory | ForEach-Object {
        [PSCustomObject]@{
            Name = $_.Name; Cluster = $_.Cluster; Host = $_.Host
            Vcpu = $_.Vcpu; VmemGb = $_.VmemGb; GuestOs = $_.GuestOs
            HwVersion = $_.HwVersion; VmToolsVersion = $_.VmToolsVersion; VmToolsStatus = $_.VmToolsStatus
            PowerState = $_.PowerState; DiskTotalGb = $_.DiskTotalGb; HasSharedDisk = $_.HasSharedDisk
        }
    }
    $written += Write-VCFOpsCsvDataset -OutputDir $OutputDir -Name "vm_inventory" -Rows $vmInvRows

    # ---- VM 가상 디스크 상세 (VM 1대당 디스크 N개 = N행) ----
    $diskRows = @()
    foreach ($v in $Data.VmInventory) {
        foreach ($d in $v.Disks) {
            $diskRows += [PSCustomObject]@{
                VmName = $v.Name; Cluster = $v.Cluster; Host = $v.Host
                DiskLabel = $d.Label; CapacityGb = $d.CapacityGb; Provisioning = $d.Provisioning
                Datastore = $d.Datastore; Shared = $d.Shared
            }
        }
    }
    $written += Write-VCFOpsCsvDataset -OutputDir $OutputDir -Name "vm_disks" -Rows $diskRows

    # ---- VM 성능정보 ----
    $written += Write-VCFOpsCsvDataset -OutputDir $OutputDir -Name "vm_performance" -Rows ($Data.VmPerformance | Select-Object `
        Name, Cluster, CpuUsagePct, CpuReadyPct, MemUsagePct, MemActiveGb, DiskLatencyMs, DiskIops, NetThroughputMbps)

    # ---- VM 인벤토리 분포 (OS/Tools/HW/vCPU 구간) ----
    if ($Data.VmBreakdown) {
        $written += Write-VCFOpsCsvDataset -OutputDir $OutputDir -Name "vm_breakdown_guest_os" -Rows `
            ($Data.VmBreakdown.OsRows | Select-Object Label, Count, Pct, PrevCount, Delta, HasComparison)
        $written += Write-VCFOpsCsvDataset -OutputDir $OutputDir -Name "vm_breakdown_vmtools" -Rows `
            ($Data.VmBreakdown.ToolsRows | Select-Object Label, Count, Pct, PrevCount, Delta, HasComparison)
        $written += Write-VCFOpsCsvDataset -OutputDir $OutputDir -Name "vm_breakdown_hw_version" -Rows `
            ($Data.VmBreakdown.HwRows | Select-Object Label, Count, Pct, PrevCount, Delta, HasComparison)
        $written += Write-VCFOpsCsvDataset -OutputDir $OutputDir -Name "vm_breakdown_vcpu_range" -Rows `
            ($Data.VmBreakdown.VcpuRows | Select-Object Label, Count, Pct, PrevCount, Delta, HasComparison)
    }

    return $written
}


# ---- inlined from Operations/Modules/VCFOpsExcelExport.psm1 ----
# VCFOpsExcelExport.psm1
# -----------------------------------------------------------------------------
# 데이터셋별 CSV 여러 개 대신, 시트가 여러 개인 엑셀 파일 하나로 출력합니다.
# PowerShell Gallery의 ImportExcel 모듈(Doug Finke 작성, EPPlus 기반)을 사용합니다.
# 이 모듈은 Excel 설치 없이도 .xlsx를 직접 만들 수 있고, 네이티브 차트도 지원합니다.
#
# 설치:  Install-Module ImportExcel -Scope CurrentUser
#
# 동작:
#   - ImportExcel 모듈이 없으면 $null 을 반환 -> 호출부(New-VCFOpsReport.ps1)가
#     자동으로 기존 다중 CSV 출력으로 폴백합니다.
#   - 시트 작성은 항목별로 개별 try/catch 처리: 한 시트가 실패해도 나머지는 계속 작성됩니다.
#   - 차트는 데이터 작성과 같은 Export-Excel 호출에서 -AutoNameRange 와 함께 컬럼명으로
#     참조하는 방식을 사용합니다(셀 범위를 직접 계산하는 것보다 훨씬 안전). 차트 포함 호출이
#     실패하면 차트 없이 데이터만 다시 써서, 데이터 자체는 항상 보존되도록 했습니다.
# -----------------------------------------------------------------------------

function Test-VCFOpsImportExcelAvailable {
    [CmdletBinding()]
    param()
    return [bool](Get-Module -ListAvailable -Name ImportExcel | Select-Object -First 1)
}

function Add-VCFOpsExcelSheet {
    # $ChartDefinition 을 주면 데이터 작성과 같은 호출에서 차트를 함께 시도하고,
    # 그 호출이 실패하면(버전별 파라미터 차이 등) 차트 없이 데이터만 다시 써서 보존합니다.
    param([string]$Path, [string]$SheetName, $Rows, $ChartDefinition = $null)

    $items = @($Rows)
    if ($items.Count -eq 0) {
        $items = @([PSCustomObject]@{ 안내 = "데이터가 없습니다" })
        $ChartDefinition = $null
    }

    if ($ChartDefinition) {
        try {
            $items | Export-Excel -Path $Path -WorksheetName $SheetName `
                -AutoSize -BoldTopRow -FreezeTopRow -TableStyle Medium2 -AutoNameRange `
                -ExcelChartDefinition $ChartDefinition -ErrorAction Stop
            return $true
        }
        catch {
            Write-Warning "Failed to write Excel sheet '$SheetName' with charts - rewriting the data only, without charts: $($_.Exception.Message)"
        }
    }

    try {
        $items | Export-Excel -Path $Path -WorksheetName $SheetName `
            -AutoSize -BoldTopRow -FreezeTopRow -TableStyle Medium2 -ErrorAction Stop
        return $true
    }
    catch {
        Write-Warning "Failed to write Excel sheet '$SheetName': $($_.Exception.Message)"
        return $false
    }
}

function Export-VCFOpsExcel {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]$Data,
        [Parameter(Mandatory)][string]$Path
    )

    if (-not (Test-VCFOpsImportExcelAvailable)) {
        Write-Warning "The ImportExcel module is not installed, so Excel output is being skipped."
        Write-Warning "  -> To install: Install-Module ImportExcel -Scope CurrentUser  (re-run afterward to get Excel output)"
        Write-Warning "  -> Writing per-dataset CSV files instead."
        return $null
    }

    try {
        Import-Module ImportExcel -ErrorAction Stop
    }
    catch {
        Write-Warning "Failed to load the ImportExcel module: $($_.Exception.Message) - falling back to CSV."
        return $null
    }

    if (Test-Path -LiteralPath $Path) { Remove-Item -LiteralPath $Path -Force -ErrorAction SilentlyContinue }

    $vmInvRows = $Data.VmInventory | ForEach-Object {
        [PSCustomObject]@{
            Name = $_.Name; Cluster = $_.Cluster; Host = $_.Host
            Vcpu = $_.Vcpu; VmemGb = $_.VmemGb; GuestOs = $_.GuestOs
            HwVersion = $_.HwVersion; VmToolsVersion = $_.VmToolsVersion; VmToolsStatus = $_.VmToolsStatus
            PowerState = $_.PowerState; DiskTotalGb = $_.DiskTotalGb; HasSharedDisk = $_.HasSharedDisk
        }
    }
    $diskRows = @()
    foreach ($v in $Data.VmInventory) {
        foreach ($d in $v.Disks) {
            $diskRows += [PSCustomObject]@{
                VmName = $v.Name; Cluster = $v.Cluster; Host = $v.Host
                DiskLabel = $d.Label; CapacityGb = $d.CapacityGb; Provisioning = $d.Provisioning
                Datastore = $d.Datastore; Shared = $d.Shared
            }
        }
    }
    $dsRows = @($Data.DatastoreInfo | Select-Object Cluster, Name, CapacityGb, PrevCapacityGb, DeltaCapacityGb, UsedGb, PrevUsedGb, DeltaUsedGb, FreeGb, HasComparison)
    $osRows = if ($Data.VmBreakdown) { @($Data.VmBreakdown.OsRows | Select-Object Label, Count, Pct, PrevCount, Delta, HasComparison) } else { @() }
    $toolsRows = if ($Data.VmBreakdown) { @($Data.VmBreakdown.ToolsRows | Select-Object Label, Count, Pct, PrevCount, Delta, HasComparison) } else { @() }
    $hwRows = if ($Data.VmBreakdown) { @($Data.VmBreakdown.HwRows | Select-Object Label, Count, Pct, PrevCount, Delta, HasComparison) } else { @() }
    $vcpuRows = if ($Data.VmBreakdown) { @($Data.VmBreakdown.VcpuRows | Select-Object Label, Count, Pct, PrevCount, Delta, HasComparison) } else { @() }

    # 차트는 데이터(컬럼명) 기준으로 정의 - 셀 범위를 직접 계산하지 않아 행 수가 달라져도 안전합니다.
    $clusterChart = $null
    if ($Data.Clusters -and $Data.Clusters.Count -gt 0) {
        try {
            $clusterChart = New-ExcelChartDefinition -Title "클러스터별 CPU/MEM/Storage 사용률(%)" `
                -ChartType ColumnClustered -XRange "Name" -YRange @("CpuPct", "MemPct", "StoragePct") `
                -Width 700 -Height 350 -ErrorAction Stop
        }
        catch { Write-Warning "Failed to build the cluster chart definition (continuing without a chart): $($_.Exception.Message)"; $clusterChart = $null }
    }
    $osChart = $null
    if ($osRows.Count -gt 0) {
        try {
            $osChart = New-ExcelChartDefinition -Title "Guest OS별 VM 수량" -ChartType Pie `
                -XRange "Label" -YRange "Count" -Width 500 -Height 350 -ErrorAction Stop
        }
        catch { Write-Warning "Failed to build the Guest OS chart definition (continuing without a chart): $($_.Exception.Message)"; $osChart = $null }
    }
    $dsChart = $null
    if ($dsRows.Count -gt 0) {
        try {
            $dsChart = New-ExcelChartDefinition -Title "데이터스토어별 용량(GB) - 현재/이전" -ChartType ColumnClustered `
                -XRange "Name" -YRange @("CapacityGb", "PrevCapacityGb") -Width 700 -Height 350 -ErrorAction Stop
        }
        catch { Write-Warning "Failed to build the datastore chart definition (continuing without a chart): $($_.Exception.Message)"; $dsChart = $null }
    }

    $sheetDefs = [ordered]@{
        "인벤토리수량"    = @{ Rows = ($Data.InventoryCounts | Select-Object Label, Current, Previous, Delta, DeltaPct, HasComparison, CompareSource, PoweredOnCount, PoweredOffCount) }
        "성능요약"        = @{ Rows = ($Data.PerfSummary | Select-Object Label, Unit, Current, Previous, HasComparison) }
        "데이터스토어"    = @{ Rows = $dsRows; Chart = $dsChart }
        "클러스터"        = @{ Rows = ($Data.Clusters | Select-Object Name, Datacenter, HostCount, VmCount, CpuUsedGhz, CpuTotalGhz, `
                              CpuPct, MemUsedGb, MemTotalGb, MemPct, StorageUsedTb, StorageTotalTb, StoragePct, StorageFreeTb, `
                              CpuContentionPct, StorageLatencyMs, Status, PrevCpuPct, PrevMemPct, PrevStoragePct, `
                              PrevCpuContentionPct, HasComparison); Chart = $clusterChart }
        "ESXi호스트"      = @{ Rows = ($Data.Hosts | Select-Object Name, Cluster, CpuPct, MemPct, CpuContentionPct, MemContentionPct, Status) }
        "VM_Top_사용률"   = @{ Rows = ($Data.TopCpuVMs | Select-Object Name, Cluster, Host, VcpuCount, CpuUsagePct) }
        "VM_Top_경합"     = @{ Rows = ($Data.TopReadyVMs | Select-Object Name, Cluster, Host, VcpuCount, CpuReadyPct) }
        "VM_Top_레이턴시" = @{ Rows = ($Data.DiskLatencyVMs | Select-Object Name, Cluster, Datastore, ReadLatencyMs, WriteLatencyMs) }
        "스냅샷"          = @{ Rows = ($Data.SnapshotAlerts | Select-Object Name, Cluster, SnapshotCount, OldestSnapshotAgeDays, TotalSnapshotSizeGb) }
        "VM인벤토리"      = @{ Rows = $vmInvRows }
        "VM디스크"        = @{ Rows = $diskRows }
        "VM성능"          = @{ Rows = ($Data.VmPerformance | Select-Object Name, Cluster, CpuUsagePct, CpuReadyPct, MemUsagePct, `
                              MemActiveGb, DiskLatencyMs, DiskIops, NetThroughputMbps) }
        "VM분포_GuestOS"  = @{ Rows = $osRows; Chart = $osChart }
        "VM분포_Tools"    = @{ Rows = $toolsRows }
        "VM분포_HW버전"   = @{ Rows = $hwRows }
        "VM분포_vCPU구간" = @{ Rows = $vcpuRows }
    }

    $okCount = 0
    foreach ($name in $sheetDefs.Keys) {
        $def = $sheetDefs[$name]
        $chartDef = if ($def.ContainsKey("Chart")) { $def.Chart } else { $null }
        if (Add-VCFOpsExcelSheet -Path $Path -SheetName $name -Rows $def.Rows -ChartDefinition $chartDef) { $okCount++ }
    }

    if ($okCount -eq 0) {
        Write-Warning "Could not create any Excel sheet - falling back to CSV."
        return $null
    }
    return $Path
}


# ---- inlined from Operations/Modules/VCFOpsPdfExport.psm1 ----
# VCFOpsPdfExport.psm1
# -----------------------------------------------------------------------------
# 생성된 HTML 리포트를 PDF로 변환합니다. 별도 모듈/도구 설치 없이도 동작하도록
# Windows 10/11에 기본 내장된 Microsoft Edge의 headless 모드(--print-to-pdf)를
# 1차로 사용하고, Edge가 없으면 Chrome headless를 시도합니다. 둘 다 없으면
# PDF 생성을 건너뛰고 HTML/Excel/CSV는 정상적으로 유지합니다.
# -----------------------------------------------------------------------------

function Find-VCFOpsPdfBrowser {
    [CmdletBinding()]
    param()
    $candidates = @(
        "$env:ProgramFiles\Microsoft\Edge\Application\msedge.exe",
        "${env:ProgramFiles(x86)}\Microsoft\Edge\Application\msedge.exe",
        "$env:LOCALAPPDATA\Microsoft\Edge\Application\msedge.exe",
        "$env:ProgramFiles\Google\Chrome\Application\chrome.exe",
        "${env:ProgramFiles(x86)}\Google\Chrome\Application\chrome.exe",
        "$env:LOCALAPPDATA\Google\Chrome\Application\chrome.exe"
    )
    foreach ($c in $candidates) {
        if ($c -and (Test-Path -LiteralPath $c)) { return $c }
    }
    # PATH 상에 있는 경우도 시도 (Linux/Mac의 pwsh 등)
    foreach ($name in @("msedge", "google-chrome", "chromium", "chromium-browser")) {
        $cmd = Get-Command -Name $name -ErrorAction SilentlyContinue
        if ($cmd) { return $cmd.Source }
    }
    return $null
}

function Resolve-VCFOpsFullPath {
    # 파일이 아직 존재하지 않아도(생성 전이라도) 절대경로로 바꿔줍니다.
    # PowerShell의 $PWD와 .NET의 Environment.CurrentDirectory가 서로 어긋나는 경우가 있어
    # (cd/Set-Location 후에도 .NET 쪽이 갱신 안 되는 경우) $PWD.Path를 명시적으로 사용합니다.
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$Path)
    if ([System.IO.Path]::IsPathRooted($Path)) { return $Path }
    return [System.IO.Path]::GetFullPath((Join-Path $PWD.Path $Path))
}

function Convert-VCFOpsHtmlToPdf {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$HtmlPath,
        [Parameter(Mandatory)][string]$PdfPath,
        [int]$TimeoutSec = 60
    )

    $browser = Find-VCFOpsPdfBrowser
    if (-not $browser) {
        Write-Warning "Could not find an Edge/Chrome executable, so PDF conversion is being skipped. (HTML/Excel/CSV were still generated normally)"
        return $null
    }

    $absHtml = (Resolve-Path -LiteralPath $HtmlPath).Path
    $uri = "file:///" + ($absHtml -replace '\\', '/')

    # --print-to-pdf 인자는 브라우저 프로세스 자체의 작업 디렉터리 기준으로 해석되어
    # PowerShell의 현재 위치와 다를 수 있습니다(상대경로 그대로 넘기면 "경로를 찾을 수
    # 없습니다" 오류가 발생). 항상 절대경로로 변환해서 넘깁니다.
    $absPdf = Resolve-VCFOpsFullPath -Path $PdfPath
    $pdfDir = Split-Path -Path $absPdf -Parent
    if ($pdfDir -and -not (Test-Path -LiteralPath $pdfDir)) {
        New-Item -ItemType Directory -Path $pdfDir -Force | Out-Null
    }
    if (Test-Path -LiteralPath $absPdf) { Remove-Item -LiteralPath $absPdf -Force -ErrorAction SilentlyContinue }

    $tempProfile = Join-Path ([System.IO.Path]::GetTempPath()) ("vcfops_pdf_" + [guid]::NewGuid().ToString("N"))
    $pdfArgs = @(
        "--headless",
        "--disable-gpu",
        "--no-sandbox",
        "--disable-extensions",
        "--user-data-dir=$tempProfile",     # 기존 브라우저 프로필/세션과 충돌 방지
        "--print-to-pdf=$absPdf",
        "--print-to-pdf-no-header",
        $uri
    )

    try {
        $proc = Start-Process -FilePath $browser -ArgumentList $pdfArgs -PassThru -WindowStyle Hidden
        if (-not $proc.WaitForExit($TimeoutSec * 1000)) {
            Write-Warning "PDF conversion did not finish within $TimeoutSec seconds, so it is being aborted."
            try { $proc.Kill() } catch { }
            return $null
        }
    }
    catch {
        Write-Warning "Failed to run PDF conversion: $($_.Exception.Message)"
        return $null
    }
    finally {
        Remove-Item -LiteralPath $tempProfile -Recurse -Force -ErrorAction SilentlyContinue
    }

    if (Test-Path -LiteralPath $absPdf) { return $absPdf }
    Write-Warning "The PDF file was not created (the browser ran, but produced no output file)."
    return $null
}


# ---- inlined from Operations/Modules/VCFOpsEmailExport.psm1 ----
# VCFOpsEmailExport.psm1
# -----------------------------------------------------------------------------
# 생성된 리포트(HTML/Excel/CSV/PDF)를 SMTP로 이메일 발송합니다.
# Send-MailMessage는 마이크로소프트가 더 이상 사용을 권장하지 않는(향후 제거 예정)
# cmdlet이라, .NET의 System.Net.Mail.SmtpClient/MailMessage를 직접 사용합니다.
# -----------------------------------------------------------------------------

function Send-VCFOpsReportEmail {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$SmtpServer,
        [int]$SmtpPort = 587,
        [Parameter(Mandatory)][string]$From,
        [Parameter(Mandatory)][string[]]$To,
        [string[]]$Cc = @(),
        [Parameter(Mandatory)][string]$Subject,
        [string]$Body = "",
        [bool]$IsBodyHtml = $false,
        [string[]]$AttachmentPaths = @(),
        [string]$Username = "",
        [string]$Password = "",
        [bool]$UseSsl = $true,
        [int]$TimeoutSec = 60
    )

    $mail = $null
    $smtp = $null
    $attachments = @()
    try {
        $mail = New-Object System.Net.Mail.MailMessage
        $mail.From = $From
        foreach ($t in $To) { if ($t) { $mail.To.Add($t) } }
        foreach ($c in $Cc) { if ($c) { $mail.CC.Add($c) } }
        if ($mail.To.Count -eq 0) {
            Write-Warning "No recipient (-SmtpTo) was given, so no email is being sent."
            return $false
        }
        $mail.Subject = $Subject
        $mail.Body = $Body
        $mail.IsBodyHtml = $IsBodyHtml

        foreach ($path in $AttachmentPaths) {
            if ($path -and (Test-Path -LiteralPath $path)) {
                $att = New-Object System.Net.Mail.Attachment($path)
                $attachments += $att
                $mail.Attachments.Add($att)
            }
            elseif ($path) {
                Write-Warning "Could not find the attachment, skipping it: $path"
            }
        }

        $smtp = New-Object System.Net.Mail.SmtpClient($SmtpServer, $SmtpPort)
        $smtp.EnableSsl = $UseSsl
        $smtp.Timeout = $TimeoutSec * 1000
        if ($Username) {
            $smtp.Credentials = New-Object System.Net.NetworkCredential($Username, $Password)
        }

        $smtp.Send($mail)
        return $true
    }
    catch {
        Write-Warning "Failed to send the email: $($_.Exception.Message)"
        return $false
    }
    finally {
        foreach ($att in $attachments) { try { $att.Dispose() } catch { } }
        if ($mail) { try { $mail.Dispose() } catch { } }
        if ($smtp) { try { $smtp.Dispose() } catch { } }
    }
}

function Send-VCFOpsReportEmailWithHtmlBody {
    # Send-VCFOpsReportEmail과 달리, 생성된 HTML 리포트를 "첨부파일"이 아니라
    # 이메일 "본문 자체"로 삽입해서 발송합니다 (수신자가 메일을 열자마자 바로
    # 리포트를 볼 수 있음 - 첨부파일을 별도로 열 필요 없음).
    # Excel/PDF/CSV(zip) 등 나머지 산출물은 기존과 동일하게 첨부로 보낼 수 있습니다.
    #
    # ⚠️ 참고: Outlook 데스크톱 앱은 자체 렌더링 엔진(Word 기반)을 사용해 CSS
    #    flexbox/grid/position:sticky, 외부 폰트(<link>), <script>(검색창 필터 등)
    #    일부가 그대로 보이지 않을 수 있습니다(표/카드/색상/기본 레이아웃은 정상
    #    표시됩니다). 완전히 동일한 모습이 꼭 필요하면 기존 Send-VCFOpsReportEmail
    #    (HTML 첨부 방식)을 함께 사용하는 것을 권장합니다.
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$SmtpServer,
        [int]$SmtpPort = 587,
        [Parameter(Mandatory)][string]$From,
        [Parameter(Mandatory)][string[]]$To,
        [string[]]$Cc = @(),
        [Parameter(Mandatory)][string]$Subject,
        [Parameter(Mandatory)][string]$HtmlPath,      # New-VCFOpsHtmlReport 로 생성된 HTML 파일 경로
        [string[]]$AttachmentPaths = @(),              # HTML은 본문에 들어가므로 보통 제외하고, Excel/PDF/CSV(zip)만 지정
        [string]$Username = "",
        [string]$Password = "",
        [bool]$UseSsl = $true,
        [int]$TimeoutSec = 60
    )

    if (-not (Test-Path -LiteralPath $HtmlPath)) {
        Write-Warning "Could not find the HTML file, so it can't be inserted into the email body: $HtmlPath"
        return $false
    }
    try {
        $htmlBody = Get-Content -LiteralPath $HtmlPath -Raw -Encoding utf8
    }
    catch {
        Write-Warning "Failed to read the HTML file: $($_.Exception.Message)"
        return $false
    }

    $mail = $null
    $smtp = $null
    $attachments = @()
    try {
        $mail = New-Object System.Net.Mail.MailMessage
        $mail.From = $From
        foreach ($t in $To) { if ($t) { $mail.To.Add($t) } }
        foreach ($c in $Cc) { if ($c) { $mail.CC.Add($c) } }
        if ($mail.To.Count -eq 0) {
            Write-Warning "No recipient (-SmtpTo) was given, so no email is being sent."
            return $false
        }
        $mail.Subject = $Subject
        $mail.Body = $htmlBody
        $mail.IsBodyHtml = $true
        $mail.BodyEncoding = [System.Text.Encoding]::UTF8
        $mail.SubjectEncoding = [System.Text.Encoding]::UTF8

        foreach ($path in $AttachmentPaths) {
            if ($path -and (Test-Path -LiteralPath $path)) {
                $att = New-Object System.Net.Mail.Attachment($path)
                $attachments += $att
                $mail.Attachments.Add($att)
            }
            elseif ($path) {
                Write-Warning "Could not find the attachment, skipping it: $path"
            }
        }

        $smtp = New-Object System.Net.Mail.SmtpClient($SmtpServer, $SmtpPort)
        $smtp.EnableSsl = $UseSsl
        $smtp.Timeout = $TimeoutSec * 1000
        if ($Username) {
            $smtp.Credentials = New-Object System.Net.NetworkCredential($Username, $Password)
        }

        $smtp.Send($mail)
        return $true
    }
    catch {
        Write-Warning "Failed to send the email (HTML body): $($_.Exception.Message)"
        return $false
    }
    finally {
        foreach ($att in $attachments) { try { $att.Dispose() } catch { } }
        if ($mail) { try { $mail.Dispose() } catch { } }
        if ($smtp) { try { $smtp.Dispose() } catch { } }
    }
}




$ErrorActionPreference = "Stop"
if ($PSBoundParameters.ContainsKey('Verbose')) {
    # 모듈 함수(Write-Verbose)까지 전파되도록 전역 스코프로 설정
    $Global:VerbosePreference = 'Continue'
}

# 같은 PowerShell 세션에서 스크립트를 여러 번 실행할 경우, 모듈 내부에서 중첩 임포트되는
# 의존 모듈(StatKeys/Theme 등)이 "이미 로드됨"으로 판단되어 디스크의 최신 수정사항을
# 반영하지 못하는 문제가 있어, 매번 완전히 제거 후 새로 불러옵니다.


if (-not (Test-Path -Path $OutputDir)) {
    New-Item -ItemType Directory -Path $OutputDir -Force | Out-Null
}

if ($SendEmail) {
    if (-not $SmtpServer -or -not $SmtpFrom -or -not $SmtpTo -or $SmtpTo.Count -eq 0) {
        Write-Error "-SmtpServer, -SmtpFrom, and -SmtpTo (recipient) are required when using -SendEmail."
        return
    }
    if ($SmtpUsername -and -not $SmtpPassword) {
        $secureSmtpPw = Read-Host "SMTP password ($SmtpUsername)" -AsSecureString
        $SmtpPassword = [System.Net.NetworkCredential]::new("", $secureSmtpPw).Password
    }
}

$totalSteps = 4
if (-not $SkipData) { $totalSteps++ }
if (-not $SkipPdf) { $totalSteps++ }
if ($SendEmail) { $totalSteps++ }
Initialize-VCFOpsProgress -Total $totalSteps

Write-Host ""
Write-Host "=== Starting VCF Operations report generation ===" -ForegroundColor Magenta
Write-Host ""

# ------------------------------------------------------------------
# 1) 데이터 수집
# ------------------------------------------------------------------
if ($Mock) {
    Write-VCFOpsStep "Generating mock data... (-Mock)"
    $data = New-MockReportData -CustomerName $CustomerName
    Write-VCFOpsStepDone
}
else {

    if (-not $HostUrl) { $HostUrl = Read-Host "VCF Operations URL (e.g. https://vcfops.corp.local)" }
    if (-not $Username) { $Username = Read-Host "VCF Operations username" }
    if (-not $Password) {
        $securePw = Read-Host "VCF Operations password" -AsSecureString
        $Password = [System.Net.NetworkCredential]::new("", $securePw).Password
    }

    Write-VCFOpsStep "Logging in to VCF Operations... ($HostUrl)"
    try {
        Connect-VCFOps -HostUrl $HostUrl -Username $Username -Password $Password `
            -AuthSource $AuthSource -SkipCertCheck:$SkipCertCheck | Out-Null
        Write-VCFOpsStepDone
    }
    catch {
        Write-Error "Login failed: $($_.Exception.Message)"
        return
    }

    Write-VCFOpsStep "Collecting data... (resources/statistics/properties - may take a while depending on environment size)"
    try {
        $data = Invoke-VCFOpsCollection -CustomerName $CustomerName -VCenterScope $ScopeLabel `
            -CompareDaysAgo $CompareDays -SnapshotCacheDir $SnapshotCacheDir -MaxVMs $MaxVMs
        Write-VCFOpsStepDone
    }
    catch {
        Write-Error "Failed to collect the report: $($_.Exception.Message)"
        return
    }
    finally {
        Disconnect-VCFOps
    }
}

# ------------------------------------------------------------------
# 2) HTML 출력 생성 (웹용 1개 + 이메일용 1개, 총 2개 파일)
# ------------------------------------------------------------------
Write-VCFOpsStep "Generating the HTML report..."
$timestamp = Get-Date -Format "yyyyMMdd_HHmm"
$htmlPath = Join-Path $OutputDir "vcfops_report_$timestamp.html"
$emailHtmlPath = Join-Path $OutputDir "vcfops_report_${timestamp}_email.html"

$html = New-VCFOpsHtmlReport -Data $data
Set-Content -Path $htmlPath -Value $html -Encoding utf8
Write-VCFOpsStepDone $htmlPath

# 이메일 본문 삽입/첨부에 최적화된 버전 - <style>/<script>/외부 리소스 없이
# <table> + 인라인 style만 사용해 Outlook 등 데스크톱 메일 클라이언트에서도 깨지지 않습니다.
$emailHtml = New-VCFOpsEmailHtmlReport -Data $data
Set-Content -Path $emailHtmlPath -Value $emailHtml -Encoding utf8
Write-VCFOpsStepDone "$emailHtmlPath  (for email, table-based without CSS)"

# ------------------------------------------------------------------
# 3) 데이터 출력 생성 (Excel 우선, 안 되면 CSV 다중 파일로 폴백)
# ------------------------------------------------------------------
if (-not $SkipData) {
    Write-VCFOpsStep "Generating data files... (tries Excel -> falls back to CSV automatically)"
    $xlsxPath = Join-Path $OutputDir "vcfops_report_$timestamp.xlsx"
    $excelResult = Export-VCFOpsExcel -Data $data -Path $xlsxPath
    if ($excelResult) {
        Write-VCFOpsStepDone $excelResult
    }
    else {
        $csvDir = Join-Path $OutputDir "csv_$timestamp"
        $csvFiles = Export-VCFOpsCsv -Data $data -OutputDir $csvDir
        Write-VCFOpsStepDone "$csvDir  ($($csvFiles.Count) CSV file(s))"
    }
}

# ------------------------------------------------------------------
# 4) PDF 변환 (Edge/Chrome headless, 둘 다 없으면 건너뜀)
# ------------------------------------------------------------------
if (-not $SkipPdf) {
    Write-VCFOpsStep "Converting to PDF... (Edge/Chrome headless)"
    $pdfPath = Join-Path $OutputDir "vcfops_report_$timestamp.pdf"
    $pdfResult = Convert-VCFOpsHtmlToPdf -HtmlPath $htmlPath -PdfPath $pdfPath
    if ($pdfResult) {
        Write-VCFOpsStepDone $pdfResult
    }
    else {
        Write-Host "    (PDF conversion was skipped - HTML/Excel/CSV were still generated normally)" -ForegroundColor DarkYellow
    }
}

# ------------------------------------------------------------------
# 5) 이메일(SMTP) 발송 - 생성된 파일들을 첨부
#    (-EmailHtmlInBody 지정 시: HTML은 첨부 대신 메일 본문에 직접 삽입)
# ------------------------------------------------------------------
if ($SendEmail) {
    Write-VCFOpsStep "Sending email... (${SmtpServer}:$SmtpPort)"

    # Excel/PDF/CSV(zip) - HTML을 본문에 넣을지 첨부할지와 무관하게 공통으로 준비
    $otherAttachments = @()
    if ($pdfResult) { $otherAttachments += $pdfResult }
    if ($excelResult) {
        $otherAttachments += $excelResult
    }
    elseif ($csvDir -and (Test-Path -LiteralPath $csvDir)) {
        # CSV 폴백 시 파일이 여러 개라 첨부가 너무 많아지지 않도록 zip으로 한 번에 묶습니다.
        $csvZipPath = Join-Path $OutputDir "vcfops_report_${timestamp}_csv.zip"
        try {
            Compress-Archive -Path (Join-Path $csvDir "*") -DestinationPath $csvZipPath -Force
            $otherAttachments += $csvZipPath
        }
        catch {
            Write-Warning "Failed to compress the CSV files, so CSV will not be attached: $($_.Exception.Message)"
        }
    }

    $subject = if ($EmailSubject) { $EmailSubject } else { "[$CustomerName] VCF Operations 운영 현황 리포트 ($timestamp)" }

    if ($EmailHtmlInBody) {
        # HTML 리포트를 첨부가 아니라 메일 본문 자체로 삽입 (Excel/PDF/CSV는 그대로 첨부)
        # 웹용 HTML($htmlPath)이 아니라 CSS/JS 없이 테이블로만 구성된 이메일용 HTML을 사용해야
        # Outlook 등에서 레이아웃이 깨지지 않습니다.
        $emailOk = Send-VCFOpsReportEmailWithHtmlBody -SmtpServer $SmtpServer -SmtpPort $SmtpPort -From $SmtpFrom `
            -To $SmtpTo -Cc $SmtpCc -Subject $subject -HtmlPath $emailHtmlPath -AttachmentPaths $otherAttachments `
            -Username $SmtpUsername -Password $SmtpPassword -UseSsl (-not $SmtpNoSsl)
    }
    else {
        $attachments = @($htmlPath) + $otherAttachments
        $bodyText = @"
$CustomerName 가상화 인프라 운영 현황 리포트입니다.

생성 시각: $(Get-Date -Format 'yyyy-MM-dd HH:mm')
대상: $ScopeLabel

첨부파일을 확인해주세요. 이 메일은 자동 생성되었습니다.
"@

        $emailOk = Send-VCFOpsReportEmail -SmtpServer $SmtpServer -SmtpPort $SmtpPort -From $SmtpFrom `
            -To $SmtpTo -Cc $SmtpCc -Subject $subject -Body $bodyText -AttachmentPaths $attachments `
            -Username $SmtpUsername -Password $SmtpPassword -UseSsl (-not $SmtpNoSsl)
    }

    if ($emailOk) {
        Write-VCFOpsStepDone "Sent -> $($SmtpTo -join ', ')"
    }
    else {
        Write-Host "    (Email sending failed - see the warning above. The files were still generated normally)" -ForegroundColor DarkYellow
    }
}

Write-Host ""
Write-Host "=== Done ===" -ForegroundColor Magenta
}

function Invoke-AuditVm8Tool {
Param (
    # Virtual Machine Name
    [Parameter(Mandatory=$true)]
    [ValidateNotNullOrEmpty()]
    [string]$Name,
    # Output File Name
    [Parameter(Mandatory=$false)]
    [ValidateNotNullOrEmpty()]
    [string]$OutputFileName,
    # Accept-EULA
    [Parameter(Mandatory=$false)]
    [switch]$AcceptEULA,
    # Skip safety checks
    [Parameter(Mandatory=$false)]
    [switch]$NoSafetyChecks,
    # Skip safety checks except for appliances
    [Parameter(Mandatory=$false)]
    [switch]$NoSafetyChecksExceptAppliances = $false
)

function ConvertTo-MaskedAuditName {
    param([string]$HostName, [switch]$ForFileName)
    if ([string]::IsNullOrWhiteSpace($HostName)) { return $HostName }
    $mask = if ($ForFileName) { "xxx" } else { "***" }
    if ($HostName -match '^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$') {
        $octets = $HostName.Split('.')
        return "$mask.$mask.$mask.$($octets[3])"
    }
    if ($HostName -match '\.') {
        $shortName = $HostName.Split('.')[0]
        return "$shortName.$mask.$mask"
    }
    return $HostName
}
$DisplayName = ConvertTo-MaskedAuditName $name


# Import common functions
# ---- inlined from security-hardening/vmware-tools/scg-common.psm1 ----
<#
    Module Name: scg-common
    Description: Common functions for VMware vSphere Security Configuration Guide 8.0 scripts
    Copyright (C) 2026 Broadcom, Inc. All rights reserved.
#>

#####################
# Log to both screen and file
function Write-Log {
    param (
        [Parameter(Mandatory=$false)]
        [AllowEmptyString()]
        [AllowNull()]
        [string]$Message = "",

        [Parameter(Mandatory=$false)]
        [ValidateSet("INFO", "WARNING", "ERROR", "EULA", "PASS", "FAIL", "UPDATE")]
        [string]$Level = "INFO",

        [Parameter(Mandatory=$false)]
        [string]$OutputFileName
    )

    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $logEntry = "[$timestamp] [$Level] $Message"

    # Output to screen
    switch ($Level) {
        "INFO"    { Write-Host $logEntry -ForegroundColor White }
        "WARNING" { Write-Host $logEntry -ForegroundColor Yellow }
        "ERROR"   { Write-Host $logEntry -ForegroundColor Red }
        "EULA"    { Write-Host $logEntry -ForegroundColor Cyan }
        "PASS"    { Write-Host $logEntry -ForegroundColor Gray }
        "FAIL"    { Write-Host $logEntry -ForegroundColor Yellow }
        "UPDATE"  { Write-Host $logEntry -ForegroundColor Green }
    }

    # Append to file
    if ($OutputFileName) {
        $logEntry | Out-File -FilePath $OutputFileName -Append
    }
}

#####################
# Accept EULA and terms to continue
Function Show-EULA {
    param (
        [Parameter(Mandatory=$false)]
        [string]$OutputFileName
    )

    Write-Log "This software is provided as is and any express or implied warranties, including," -Level "EULA" -OutputFileName $OutputFileName
    Write-Log "but not limited to, the implied warranties of merchantability and fitness for a particular" -Level "EULA" -OutputFileName $OutputFileName
    Write-Log "purpose are disclaimed. In no event shall the copyright holder or contributors be liable" -Level "EULA" -OutputFileName $OutputFileName
    Write-Log "for any direct, indirect, incidental, special, exemplary, or consequential damages (including," -Level "EULA" -OutputFileName $OutputFileName
    Write-Log "but not limited to, procurement of substitute goods or services; loss of use, data, or" -Level "EULA" -OutputFileName $OutputFileName
    Write-Log "profits; or business interruption) however caused and on any theory of liability, whether" -Level "EULA" -OutputFileName $OutputFileName
    Write-Log "in contract, strict liability, or tort (including negligence or otherwise) arising in any" -Level "EULA" -OutputFileName $OutputFileName
    Write-Log "way out of the use of this software, even if advised of the possibility of such damage." -Level "EULA" -OutputFileName $OutputFileName
    Write-Log "The provider makes no claims, promises, or guarantees about the accuracy, completeness, or" -Level "EULA" -OutputFileName $OutputFileName
    Write-Log "adequacy of this sample. Organizations should engage appropriate legal, business, technical," -Level "EULA" -OutputFileName $OutputFileName
    Write-Log "and audit expertise within their specific organization for review of requirements and" -Level "EULA" -OutputFileName $OutputFileName
    Write-Log "effectiveness of implementations. You acknowledge that there may be performance or other" -Level "EULA" -OutputFileName $OutputFileName
    Write-Log "considerations, and that this example may make assumptions which may not be valid in your" -Level "EULA" -OutputFileName $OutputFileName
    Write-Log "environment or organization." -Level "EULA" -OutputFileName $OutputFileName
    Write-Log "" -Level "EULA" -OutputFileName $OutputFileName
    Write-Log "Press any character key to accept all terms and risk. Use CTRL+C to return." -Level "EULA" -OutputFileName $OutputFileName

    $null = $host.UI.RawUI.FlushInputBuffer()
    do {
        $key = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
    } while ($key.Character -eq [char]0)
}

#####################
# Pause for user input
Function Wait-UserInput {
    param (
        [Parameter(Mandatory=$false)]
        [string]$OutputFileName
    )

    Write-Log "Check the vSphere Client to make sure all tasks have completed, then press any character key." -Level "INFO" -OutputFileName $OutputFileName
    $null = $host.UI.RawUI.FlushInputBuffer()
    do {
        $key = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
    } while ($key.Character -eq [char]0)
}

#####################
# Check to see if we are attached to a vCenter Server
Function Test-vCenterConnection {
    param (
        [Parameter(Mandatory=$false)]
        [string]$OutputFileName
    )

    if ($global:DefaultVIServers.Count -lt 1) {
        Write-Log "Please connect to a vCenter Server (use Connect-VIServer) prior to running this script. Thank you." -Level "ERROR" -OutputFileName $OutputFileName
        return $false
    }

    if ($global:DefaultVIServers.Count -gt 1) {
        Write-Log "Connect to a single vCenter Server (use Connect-VIServer) prior to running this script." -Level "ERROR" -OutputFileName $OutputFileName
        return $false
    }

    return $true
}

#####################
# Check to see if we have hosts attached
Function Test-HostsExist {
    param (
        [Parameter(Mandatory=$false)]
        [string]$OutputFileName
    )

    $ESX = Get-VMHost
    if ($ESX.Count -lt 1) {
        Write-Log "No ESX hosts found. Please ensure hosts are connected to vCenter." -Level "ERROR" -OutputFileName $OutputFileName
        return $false
    }

    return $true
}

# Export functions

# Wrapper functions for backward compatibility
function Log-Message {
    param (
        [Parameter(Mandatory=$false)][AllowEmptyString()][AllowNull()][string]$Message = "",
        [Parameter(Mandatory=$false)][ValidateSet("INFO", "WARNING", "ERROR", "EULA", "PASS", "FAIL", "UPDATE")][string]$Level = "INFO"
    )
    Write-Log -Message $Message -Level $Level -OutputFileName $OutputFileName
}

Function Accept-EULA() { Show-EULA -OutputFileName $OutputFileName }
Function Do-Pause() { Wait-UserInput -OutputFileName $OutputFileName }
Function Check-vCenter() { if (-not (Test-vCenterConnection -OutputFileName $OutputFileName)) { return } }
Function Check-Hosts() { if (-not (Test-HostsExist -OutputFileName $OutputFileName)) { return } }

#######################################################################################################

$currentDateTime = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
Log-Message "VMware Virtual Machine Security Settings Audit Utility 8.0.3" -Level "INFO"
Log-Message "Audit of $DisplayName started at $currentDateTime from $env:COMPUTERNAME by $env:USERNAME" -Level "INFO"

# Accept EULA and terms to continue
if ($false -eq $AcceptEULA) {
    Accept-EULA
    Log-Message "EULA accepted." -Level "INFO"
} else {
    Log-Message "EULA accepted." -Level "INFO"
}

# Safety checks
if ($false -eq $NoSafetyChecks) {
    Check-vCenter
    Check-Hosts
} else {
    Log-Message "Safety checks skipped." -Level "INFO"
}

#####################
# Read the VM into objects and views once to save time & resources
$obj = Get-VM $name -ErrorAction Stop
$view = Get-View -VIObject $obj

# Broadcom/VMware support policy does not permit changes to VMware virtual appliances
if (($NoSafetyChecks -eq $false) -or ($NoSafetyChecksExceptAppliances -eq $true)) {
    #####################
    # Is this a VMware appliance or vCLS container (CRX)?
    $flag = $false
    if ($obj | Select-Object -ExpandProperty Notes | Select-String -Pattern "VMware" -AllMatches) { $flag = $true}
    if ($obj | Select-Object -ExpandProperty Notes | Select-String -Pattern "vSphere Cluster Service" -AllMatches) { $flag = $true}
    if ($obj | Select-Object -ExpandProperty Name | Select-String -Pattern "vCLS-" -AllMatches) { $flag = $true}

    if ($flag) {
        Log-Message "$DisplayName`: The specified object may be a VMware virtual appliance or vCLS container." -Level "ERROR"
        Log-Message "$DisplayName`: Altering these types of objects is not supported and may result in operational issues." -Level "ERROR"
        Log-Message "$DisplayName`: vCLS Containers are managed by the vSphere Cluster Service and cannot be altered." -Level "ERROR"
        Log-Message "$DisplayName`: If you wish to audit this component anyhow consider the -NoSafetyChecks" -Level "ERROR"
        Log-Message "$DisplayName`: or the -NoSafetyChecksExceptAppliances flag." -Level "ERROR"
        return
    }
}

#####################
# Test for Secure Boot
$value = $obj.ExtensionData.Config.BootOptions.EfiSecureBootEnabled
if ($value -eq $true) {
    Log-Message "$DisplayName`: Secure Boot configured ($value)" -Level "PASS"
} else {
    Log-Message "$DisplayName`: VM does not have Secure Boot configured ($value)" -Level "FAIL"
}

#####################
# Test for VM Hardware version
$value = $view.Config.Version
switch ($value) {
    'vmx-19' { Log-Message "$DisplayName`: VM is VM Hardware 19 (vSphere 7) ($value)" -Level "PASS"  }
    'vmx-20' { Log-Message "$DisplayName`: VM is VM Hardware 20 (vSphere 8) ($value)" -Level "PASS"  }
    'vmx-21' { Log-Message "$DisplayName`: VM is VM Hardware 21 (vSphere 8) ($value)" -Level "PASS"  }
    Default { Log-Message "$DisplayName`: VM Hardware version should be version 19 or later ($value)" -Level "FAIL"  }
} 

#####################
# Tests for advanced parameters
#
# Parameter guidelines for configurations requiring boolean values:
#
# T-OR-NP = The setting should be configured as TRUE or not present, where the default of TRUE will take over.
# F-OR-NP = The setting should be configured as FALSE or not present, where the default of FALSE will take over.
# TRUE = The setting should be configured as TRUE.
# FALSE = The setting should be configured as FALSE.
# NP = The setting should not be configured at all.
#
$scg_bool = @{
    
    'isolation.tools.copy.disable' = 'T-OR-NP'
    'isolation.tools.paste.disable' = 'T-OR-NP'
    'isolation.tools.diskShrink.disable' = 'T-OR-NP'
    'isolation.tools.diskWiper.disable' = 'T-OR-NP'
    'mks.enable3d' = 'F-OR-NP'
    'tools.guestlib.enableHostInfo' = 'F-OR-NP'
    'tools.guest.desktop.autolock' = 'T-OR-NP'
    'isolation.device.connectable.disable' = 'T-OR-NP'
    'isolation.tools.dnd.disable' = 'T-OR-NP'
    'sched.mem.pshare.salt' = 'NP'
    
}    

$scg_num = @{
    'RemoteDisplay.maxConnections' = @{ Expected = 1; Comparator = 'eq'; Default = $false }
    'tools.setInfo.sizeLimit' = @{ Expected = 1048576; Comparator = 'le'; Default = $true }
    'log.keepOld' = @{ Expected = 10; Comparator = 'eq'; Default = $true }
    'log.rotateSize' = @{ Expected = 2048000; Comparator = 'eq'; Default = $true }
}

foreach ($param in $scg_bool.GetEnumerator() )
{
    $vmval = (Get-AdvancedSetting -Entity $obj "$($param.Name)").Value

    switch ($($param.Value)) {
        'T-OR-NP' { 
            switch ($vmval) {
                'TRUE' {  Log-Message "$DisplayName`: $($param.Name) configured correctly ($vmval)" -Level "PASS"  }
                'FALSE' { Log-Message "$DisplayName`: $($param.Name) configured incorrectly ($vmval)" -Level "FAIL"  }
                '' {      Log-Message "$DisplayName`: $($param.Name) not configured and is using secure defaults ($vmval)" -Level "PASS"  }
                Default { Log-Message "$DisplayName`: $($param.Name) configured to something unexpected ($vmval)" -Level "FAIL"  }
            }
        }
        'F-OR-NP' { 
            switch ($vmval) {
                'TRUE' {  Log-Message "$DisplayName`: $($param.Name) configured incorrectly ($vmval)" -Level "FAIL"  }
                'FALSE' { Log-Message "$DisplayName`: $($param.Name) configured correctly ($vmval)" -Level "PASS"  }
                '' {      Log-Message "$DisplayName`: $($param.Name) not configured and is using secure defaults ($vmval)" -Level "PASS"  }
                Default { Log-Message "$DisplayName`: $($param.Name) configured to something unexpected ($vmval)" -Level "FAIL"  }
            }
        }
        'TRUE' { 
            switch ($vmval) {
                'TRUE' {  Log-Message "$DisplayName`: $($param.Name) configured correctly ($vmval)" -Level "PASS"  }
                'FALSE' { Log-Message "$DisplayName`: $($param.Name) configured incorrectly ($vmval)" -Level "FAIL"  }
                '' {      Log-Message "$DisplayName`: $($param.Name) not configured ($vmval)" -Level "FAIL"  }
                Default { Log-Message "$DisplayName`: $($param.Name) configured to something unexpected ($vmval)" -Level "FAIL"  }
            }
        }
        'FALSE' { 
            switch ($vmval) {
                'TRUE' {  Log-Message "$DisplayName`: $($param.Name) configured incorrectly ($vmval)" -Level "FAIL"  }
                'FALSE' { Log-Message "$DisplayName`: $($param.Name) configured correctly ($vmval)" -Level "PASS"  }
                '' {      Log-Message "$DisplayName`: $($param.Name) not configured ($vmval)" -Level "FAIL"  }
                Default { Log-Message "$DisplayName`: $($param.Name) configured to something unexpected ($vmval)" -Level "FAIL"  }
            }
        }
        'NP' { 
            if ($vmval) {
                Log-Message "$DisplayName`: $($param.Name) configured incorrectly ($vmval)." -Level "FAIL"
            } else {
                Log-Message "$DisplayName`: $($param.Name) not configured ($vmval)." -Level "PASS"
            }
            }
        Default { Log-Message "$DisplayName`: $($param.Name) configured to something unexpected ($vmval)" -Level "FAIL"  }
    }
}

foreach ($param in $scg_num.GetEnumerator()) {
    $vmval = (Get-AdvancedSetting -Entity $obj "$($param.Name)").Value
    $expected = $param.Value.Expected
    $comparator = $param.Value.Comparator
    $isDefault = $param.Value.Default

    if ([string]::IsNullOrEmpty($vmval)) {
        if ($isDefault) {
            Log-Message "$DisplayName`: $($param.Name) not configured and is using secure defaults" -Level "PASS"
        } else {
            Log-Message "$DisplayName`: $($param.Name) not configured" -Level "FAIL"
        }
    } else {
        $pass = switch ($comparator) {
            'eq' { $vmval -eq $expected }
            'ge' { $vmval -ge $expected }
            'le' { $vmval -le $expected }
        }

        if ($pass) {
            Log-Message "$DisplayName`: $($param.Name) configured correctly ($vmval)" -Level "PASS"
        } else {
            Log-Message "$DisplayName`: $($param.Name) configured incorrectly ($vmval, expected $comparator $expected)" -Level "FAIL"
        }
    }
}

#####################
# Test for vMotion encryption
$value = $obj.ExtensionData.Config.MigrateEncryption
switch($value) {
    'required' { Log-Message "$DisplayName`: Encrypted vMotion configured correctly ($value)" -Level "PASS"  }
    'opportunistic' { Log-Message "$DisplayName`: Encrypted vMotion defaults configured ($value)." -Level "FAIL"  }
    Default { Log-Message "$DisplayName`: Encrypted vMotion not configured ($value)" -Level "FAIL"  }
}

#####################
# Test for Fault Tolerance encryption
$value = $obj.ExtensionData.Config.FtEncryptionMode
switch($value) {
    'ftEncryptionRequired' { Log-Message "$DisplayName`: Encrypted Fault Tolerance configured correctly ($value)" -Level "PASS"  }
    'ftEncryptionOpportunistic' { Log-Message "$DisplayName`: Encrypted Fault Tolerance defaults configured ($value)" -Level "FAIL"  }
    Default { Log-Message "$DisplayName`: Encrypted Fault Tolerance not configured ($value)" -Level "FAIL"  }
}

#####################
# Test for VM logging
$value = $obj.ExtensionData.Config.Flags.EnableLogging
switch($value) {
    'True' { Log-Message "$DisplayName`: Diagnostic logging configured correctly ($value)" -Level "PASS"  }
    Default { Log-Message "$DisplayName`: Diagnostic logging not configured ($value)" -Level "FAIL"  }
}

#####################
# Test for dvFilters
$value = Get-AdvancedSetting -Entity $obj 'ethernet*.filter*.name*'
if ($NULL -eq $value) {
    Log-Message "$DisplayName`: dvFilters not configured ($value)" -Level "PASS"
} else {
    Log-Message "$DisplayName`: dvFilters configured, verify they are legitimate ($value)" -Level "FAIL"
}

#####################
# Test for passthrough devices
$value = $obj | Get-PassthroughDevice
if ($NULL -eq $value) {
    Log-Message "$DisplayName`: Passthrough hardware devices not configured" -Level "PASS"
} else {
    Log-Message "$DisplayName`: Passthrough hardware configured. Evaluate and remove if not necessary." -Level "FAIL"
}

#####################
# Test for unnecessary devices
$UnnecessaryHardware = "VirtualUSBController|VirtualUSBXHCIController|VirtualParallelPort|VirtualFloppy|VirtualSerialPort|VirtualHdAudioCard|VirtualAHCIController|VirtualEnsoniq1371|VirtualCdrom"

$view.Config.Hardware.Device | Where-Object {$_.GetType().Name -match $UnnecessaryHardware} | Foreach-Object {
    $devname = $_.GetType().Name
    Log-Message "$DisplayName`: $devname device present. Evaluate and remove if not necessary." -Level "FAIL"
}

#####################
# Test for BIOS boot classes
$value = (Get-AdvancedSetting -Entity $obj "bios.bootDeviceClasses").Value
if ($value -eq "allow:hd") {
    Log-Message "$DisplayName`: VM only permitted to boot from virtual HDD. ($value)" -Level "PASS"
} else {
    Log-Message "$DisplayName`: VM permitted to boot from all possible sources. ($value)" -Level "FAIL"
}

Log-Message "$DisplayName`: Audit of $DisplayName completed at $(Get-Date -Format "yyyy-MM-dd HH:mm:ss")" -Level "INFO"
}

function Invoke-AuditEsxi8Tool {
Param (
    # ESX Host Name
    [Parameter(Mandatory=$true)]
    [ValidateNotNullOrEmpty()]
    [string]$Name,
    # Output File Name
    [Parameter(Mandatory=$false)]
    [ValidateNotNullOrEmpty()]
    [string]$OutputFileName,
    # Accept-EULA
    [Parameter(Mandatory=$false)]
    [switch]$AcceptEULA,
    # Skip safety checks
    [Parameter(Mandatory=$false)]
    [switch]$NoSafetyChecks
)

function ConvertTo-MaskedAuditName {
    param([string]$HostName, [switch]$ForFileName)
    if ([string]::IsNullOrWhiteSpace($HostName)) { return $HostName }
    $mask = if ($ForFileName) { "xxx" } else { "***" }
    if ($HostName -match '^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$') {
        $octets = $HostName.Split('.')
        return "$mask.$mask.$mask.$($octets[3])"
    }
    if ($HostName -match '\.') {
        $shortName = $HostName.Split('.')[0]
        return "$shortName.$mask.$mask"
    }
    return $HostName
}
$DisplayName = ConvertTo-MaskedAuditName $name


# Import common functions
# ---- inlined from security-hardening/vmware-tools/scg-common.psm1 ----
<#
    Module Name: scg-common
    Description: Common functions for VMware vSphere Security Configuration Guide 8.0 scripts
    Copyright (C) 2026 Broadcom, Inc. All rights reserved.
#>

#####################
# Log to both screen and file
function Write-Log {
    param (
        [Parameter(Mandatory=$false)]
        [AllowEmptyString()]
        [AllowNull()]
        [string]$Message = "",

        [Parameter(Mandatory=$false)]
        [ValidateSet("INFO", "WARNING", "ERROR", "EULA", "PASS", "FAIL", "UPDATE")]
        [string]$Level = "INFO",

        [Parameter(Mandatory=$false)]
        [string]$OutputFileName
    )

    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $logEntry = "[$timestamp] [$Level] $Message"

    # Output to screen
    switch ($Level) {
        "INFO"    { Write-Host $logEntry -ForegroundColor White }
        "WARNING" { Write-Host $logEntry -ForegroundColor Yellow }
        "ERROR"   { Write-Host $logEntry -ForegroundColor Red }
        "EULA"    { Write-Host $logEntry -ForegroundColor Cyan }
        "PASS"    { Write-Host $logEntry -ForegroundColor Gray }
        "FAIL"    { Write-Host $logEntry -ForegroundColor Yellow }
        "UPDATE"  { Write-Host $logEntry -ForegroundColor Green }
    }

    # Append to file
    if ($OutputFileName) {
        $logEntry | Out-File -FilePath $OutputFileName -Append
    }
}

#####################
# Accept EULA and terms to continue
Function Show-EULA {
    param (
        [Parameter(Mandatory=$false)]
        [string]$OutputFileName
    )

    Write-Log "This software is provided as is and any express or implied warranties, including," -Level "EULA" -OutputFileName $OutputFileName
    Write-Log "but not limited to, the implied warranties of merchantability and fitness for a particular" -Level "EULA" -OutputFileName $OutputFileName
    Write-Log "purpose are disclaimed. In no event shall the copyright holder or contributors be liable" -Level "EULA" -OutputFileName $OutputFileName
    Write-Log "for any direct, indirect, incidental, special, exemplary, or consequential damages (including," -Level "EULA" -OutputFileName $OutputFileName
    Write-Log "but not limited to, procurement of substitute goods or services; loss of use, data, or" -Level "EULA" -OutputFileName $OutputFileName
    Write-Log "profits; or business interruption) however caused and on any theory of liability, whether" -Level "EULA" -OutputFileName $OutputFileName
    Write-Log "in contract, strict liability, or tort (including negligence or otherwise) arising in any" -Level "EULA" -OutputFileName $OutputFileName
    Write-Log "way out of the use of this software, even if advised of the possibility of such damage." -Level "EULA" -OutputFileName $OutputFileName
    Write-Log "The provider makes no claims, promises, or guarantees about the accuracy, completeness, or" -Level "EULA" -OutputFileName $OutputFileName
    Write-Log "adequacy of this sample. Organizations should engage appropriate legal, business, technical," -Level "EULA" -OutputFileName $OutputFileName
    Write-Log "and audit expertise within their specific organization for review of requirements and" -Level "EULA" -OutputFileName $OutputFileName
    Write-Log "effectiveness of implementations. You acknowledge that there may be performance or other" -Level "EULA" -OutputFileName $OutputFileName
    Write-Log "considerations, and that this example may make assumptions which may not be valid in your" -Level "EULA" -OutputFileName $OutputFileName
    Write-Log "environment or organization." -Level "EULA" -OutputFileName $OutputFileName
    Write-Log "" -Level "EULA" -OutputFileName $OutputFileName
    Write-Log "Press any character key to accept all terms and risk. Use CTRL+C to return." -Level "EULA" -OutputFileName $OutputFileName

    $null = $host.UI.RawUI.FlushInputBuffer()
    do {
        $key = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
    } while ($key.Character -eq [char]0)
}

#####################
# Pause for user input
Function Wait-UserInput {
    param (
        [Parameter(Mandatory=$false)]
        [string]$OutputFileName
    )

    Write-Log "Check the vSphere Client to make sure all tasks have completed, then press any character key." -Level "INFO" -OutputFileName $OutputFileName
    $null = $host.UI.RawUI.FlushInputBuffer()
    do {
        $key = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
    } while ($key.Character -eq [char]0)
}

#####################
# Check to see if we are attached to a vCenter Server
Function Test-vCenterConnection {
    param (
        [Parameter(Mandatory=$false)]
        [string]$OutputFileName
    )

    if ($global:DefaultVIServers.Count -lt 1) {
        Write-Log "Please connect to a vCenter Server (use Connect-VIServer) prior to running this script. Thank you." -Level "ERROR" -OutputFileName $OutputFileName
        return $false
    }

    if ($global:DefaultVIServers.Count -gt 1) {
        Write-Log "Connect to a single vCenter Server (use Connect-VIServer) prior to running this script." -Level "ERROR" -OutputFileName $OutputFileName
        return $false
    }

    return $true
}

#####################
# Check to see if we have hosts attached
Function Test-HostsExist {
    param (
        [Parameter(Mandatory=$false)]
        [string]$OutputFileName
    )

    $ESX = Get-VMHost
    if ($ESX.Count -lt 1) {
        Write-Log "No ESX hosts found. Please ensure hosts are connected to vCenter." -Level "ERROR" -OutputFileName $OutputFileName
        return $false
    }

    return $true
}

# Export functions

# Wrapper functions for backward compatibility
function Log-Message {
    param (
        [Parameter(Mandatory=$false)][AllowEmptyString()][AllowNull()][string]$Message = "",
        [Parameter(Mandatory=$false)][ValidateSet("INFO", "WARNING", "ERROR", "EULA", "PASS", "FAIL", "UPDATE")][string]$Level = "INFO"
    )
    Write-Log -Message $Message -Level $Level -OutputFileName $OutputFileName
}

Function Accept-EULA() { Show-EULA -OutputFileName $OutputFileName }
Function Do-Pause() { Wait-UserInput -OutputFileName $OutputFileName }
Function Check-vCenter() { if (-not (Test-vCenterConnection -OutputFileName $OutputFileName)) { return } }
Function Check-Hosts() { if (-not (Test-HostsExist -OutputFileName $OutputFileName)) { return } }

#######################################################################################################

$currentDateTime = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
Log-Message "VMware ESX Host Security Settings Audit Utility 8.0.3" -Level "INFO"
Log-Message "Audit of $DisplayName started at $currentDateTime from $env:COMPUTERNAME by $env:USERNAME" -Level "INFO"

# Accept EULA and terms to continue
if ($false -eq $AcceptEULA) {
    Accept-EULA
    Log-Message "EULA accepted." -Level "INFO"
} else {
    Log-Message "EULA accepted." -Level "INFO"
}

# Safety checks
if ($false -eq $NoSafetyChecks) {
    Check-vCenter
    Check-Hosts
} else {
    Log-Message "Safety checks skipped." -Level "INFO"
}

#####################
# Read the ESX host into objects and views once to save time & resources
$obj = Get-VMHost $name -ErrorAction Stop
$view = Get-View -VIObject $obj
$ESXcli = Get-EsxCli -VMHost $obj -V2


#####################
# Tests for advanced parameters
# Comparators: eq = equal, ge = greater or equal (more secure), le = less or equal (more secure)
$scg_adv = @{
    'Security.AccountUnlockTime' = @{ Expected = 900; Comparator = 'ge' }
    'Security.AccountLockFailures' = @{ Expected = 5; Comparator = 'le' }
    'Security.PasswordQualityControl' = @{ Expected = 'similar=deny retry=3 min=disabled,disabled,disabled,disabled,15 max=64'; Comparator = 'eq' }
    'Security.PasswordHistory' = @{ Expected = 5; Comparator = 'ge' }
    'Security.PasswordMaxDays' = @{ Expected = 9999; Comparator = 'eq' }
    'Config.HostAgent.vmacore.soap.sessionTimeout' = @{ Expected = 10; Comparator = 'le' }
    'Config.HostAgent.plugins.solo.enableMob' = @{ Expected = $false; Comparator = 'eq' }
    'UserVars.DcuiTimeOut' = @{ Expected = 600; Comparator = 'le' }
    'UserVars.SuppressHyperthreadWarning' = @{ Expected = 0; Comparator = 'eq' }
    'UserVars.SuppressShellWarning' = @{ Expected = 0; Comparator = 'eq' }
    'UserVars.HostClientSessionTimeout' = @{ Expected = 900; Comparator = 'le' }
    'Net.BMCNetworkEnable' = @{ Expected = 0; Comparator = 'eq' }
    'DCUI.Access' = @{ Expected = 'root'; Comparator = 'eq' }
    'Syslog.global.auditRecord.storageEnable' = @{ Expected = $true; Comparator = 'eq' }
    'Syslog.global.auditRecord.storageCapacity' = @{ Expected = 100; Comparator = 'ge' }
    'Syslog.global.auditRecord.remoteEnable' = @{ Expected = $true; Comparator = 'eq' }
    'Config.HostAgent.log.level' = @{ Expected = 'info'; Comparator = 'eq' }
    'Syslog.global.logLevel' = @{ Expected = 'error'; Comparator = 'eq' }
    'Syslog.global.certificate.checkSSLCerts' = @{ Expected = $true; Comparator = 'eq' }
    'Syslog.global.certificate.strictX509Compliance' = @{ Expected = $true; Comparator = 'eq' }
    'Net.BlockGuestBPDU' = @{ Expected = 1; Comparator = 'eq' }
    'Net.DVFilterBindIpAddress' = @{ Expected = ''; Comparator = 'eq' }
    'UserVars.ESXiShellInteractiveTimeOut' = @{ Expected = 900; Comparator = 'le' }
    'UserVars.ESXiShellTimeOut' = @{ Expected = 600; Comparator = 'le' }
    'UserVars.ESXiVPsDisabledProtocols' = @{ Expected = "sslv3,tlsv1,tlsv1.1"; Comparator = 'eq' }
    'Mem.ShareForceSalting' = @{ Expected = 2; Comparator = 'eq' }
    'VMkernel.Boot.execInstalledOnly' = @{ Expected = $true; Comparator = 'eq' }
    'Mem.MemEagerZero' = @{ Expected = 1; Comparator = 'eq' }
}

foreach ($param in $scg_adv.GetEnumerator()) {
    $vmval = (Get-AdvancedSetting -Entity $obj "$($param.Name)").Value
    $expected = $param.Value.Expected
    $comparator = $param.Value.Comparator

    $pass = switch ($comparator) {
        'eq' { $vmval -eq $expected }
        'ge' { $vmval -ge $expected }
        'le' { $vmval -le $expected }
    }

    if ($pass) {
        Log-Message "$DisplayName`: $($param.Name) configured correctly ($vmval)" -Level "PASS"
    } else {
        Log-Message "$DisplayName`: $($param.Name) not configured correctly ($vmval)" -Level "FAIL"
    }
}

#####################
# Tests for things that should not be set a certain way
$scg_not = @{

    'Annotations.WelcomeMessage' = ''
    'Config.Etc.Issue' = ''
    'Syslog.global.logHost' = ''

}

foreach ($param in $scg_not.GetEnumerator() )
{
    $vmval = (Get-AdvancedSetting -Entity $obj "$($param.Name)").Value

    if ($vmval -eq $($param.Value)) {
        Log-Message "$DisplayName`: $($param.Name) not configured correctly ($vmval)" -Level "FAIL"
    } else {
        Log-Message "$DisplayName`: $($param.Name) configured correctly ($vmval)" -Level "PASS"
    }
}

#####################
# Test local log output locations for persistence
$persistent = $ESXcli.system.syslog.config.get.Invoke() | Select-Object -ExpandProperty LocalLogOutputIsPersistent
$localsyslog = $ESXcli.system.syslog.config.get.Invoke() | Select-Object -ExpandProperty LocalLogOutput
$localauditlog = $obj | Get-AdvancedSetting Syslog.global.auditRecord.storageDirectory | Select-Object -ExpandProperty Value

if ($persistent) {
    Log-Message "$DisplayName`: Local log location is persistent ($localsyslog)" -Level "PASS"
} else {
    Log-Message "$DisplayName`: Local log location is not persistent ($localsyslog)" -Level "FAIL"
}

if (($localsyslog -like "/scratch*") -and ($localauditlog -like "*scratch*") -and ($persistent)) {
    Log-Message "$DisplayName`: Local audit log location is persistent ($localsyslog, $localauditlog)" -Level "PASS"
} else {
    Log-Message "$DisplayName`: Local audit log location is not persistent ($localsyslog, $localauditlog)" -Level "FAIL"
}

#####################
# Test Log Filters
$value = $ESXcli.system.syslog.config.logfilter.get.invoke() | Select -ExpandProperty LogFilteringEnabled 
if ($value -eq 'false') {
    Log-Message "$DisplayName`: Log filtering is deactivated ($value)" -Level "PASS"
} else {
    Log-Message "$DisplayName`: Log filtering is enabled ($value)" -Level "FAIL"
}

#####################
# Test DCUI user
$value = $ESXcli.system.account.list.Invoke() | Where-Object { $_.UserID -eq 'dcui' } | Select-Object -ExpandProperty Shellaccess
if ($value -eq 'false') {
    Log-Message "$DisplayName`: DCUI user has shell access deactivated ($value)" -Level "PASS"
} else {
    Log-Message "$DisplayName`: DCUI user has shell access enabled ($value)" -Level "FAIL"
}

#####################
# Test Entropy Sources
$value1 = $ESXcli.system.settings.kernel.list.Invoke() | Where-Object {$_.Name -eq "disableHwrng"} | Select-Object -ExpandProperty Configured
$value2 = $ESXcli.system.settings.kernel.list.Invoke() | Where-Object {$_.Name -eq "entropySources"} | Select-Object -ExpandProperty Configured

if ($value1 -eq 'FALSE' -and $value2 -eq '0') {
    Log-Message "$DisplayName`: Entropy sources configured correctly ($value1, $value2)" -Level "PASS"
} else {
    Log-Message "$DisplayName`: Entropy sources not configured correctly ($value1, $value2)" -Level "FAIL"
}

#####################
# Test Host Secure Boot capability
$value = $view.Capability.UefiSecureBoot
if ($value -eq 'true') {
    Log-Message "$DisplayName`: Secure Boot is enabled on the host ($value)" -Level "PASS"
} else {
    Log-Message "$DisplayName`: Secure Boot is not enabled on the host ($value)" -Level "FAIL"
}

#####################
# Test Host Secure Boot Enforcement
$value = $ESXcli.system.settings.encryption.get.Invoke() | Select-Object -ExpandProperty RequireSecureBoot
if ($value -eq 'true') {
    Log-Message "$DisplayName`: Secure Boot TPM-based enforcement is enabled ($value)" -Level "PASS"
} else {
    Log-Message "$DisplayName`: Secure Boot TPM-based enforcement is not enabled ($value)" -Level "FAIL"
}

#####################
# Test for TPM Configuration Encryption 
$value = $ESXcli.system.settings.encryption.get.Invoke() | Select-Object -ExpandProperty Mode
if ($value -eq 'TPM') {
    Log-Message "$DisplayName`: TPM configuration encryption is enabled ($value)" -Level "PASS"
} else {
    Log-Message "$DisplayName`: TPM configuration encryption is not enabled ($value)" -Level "FAIL"
}

#####################
# Test for Key Persistence
$value = $ESXcli.system.security.keypersistence.get.invoke() | Select-Object -ExpandProperty Enabled
if ($value -eq 'false') {
    Log-Message "$DisplayName`: Key persistence is not enabled ($value)" -Level "PASS"
} else {
    Log-Message "$DisplayName`: Key persistence is enabled ($value)" -Level "FAIL"
}

#####################
# Test the TLS Profile
$value = $ESXcli.system.tls.server.get.invoke() | Select-Object -ExpandProperty Profile
if ($value -eq 'NIST_2024') {
    Log-Message "$DisplayName`: TLS profile is configured correctly ($value)" -Level "PASS"
} else {
    Log-Message "$DisplayName`: TLS profile is not configured correctly ($value)" -Level "FAIL"
}

#####################
# Test Software Acceptance Level (VMwareCertified, VMwareAccepted, PartnerSupported, CommunitySupported)
$value = $ESXcli.software.acceptance.get.Invoke()
if (($value -eq 'PartnerSupported') -or ($value -eq 'VMwareCertified') -or ($value -eq 'VMwareAccepted')) {
    Log-Message "$DisplayName`: Host Image Profile Acceptance Level is configured correctly ($value)" -Level "PASS"
} else {
    Log-Message "$DisplayName`: Host Image Profile Acceptance Level is not configured correctly ($value)" -Level "FAIL"
}

#####################
# Test authentication configuration
$value = $obj | Get-VMHostAuthentication | Select-Object -ExpandProperty Domain
if ($null -eq $value) {
    Log-Message "$DisplayName`: Active Directory integration is configured correctly ($value)" -Level "PASS"
} else {
    Log-Message "$DisplayName`: Active Directory integration is not configured correctly ($value)" -Level "FAIL"
}

#####################
# Test the menagerie of SSH configuration settings
$value = $ESXcli.system.security.fips140.ssh.get.Invoke() | Select-Object -ExpandProperty Enabled
if ($value -eq 'true') {
    Log-Message "$DisplayName`: SSH has FIPS mode enabled ($value)" -Level "PASS"
} else {
    Log-Message "$DisplayName`: SSH does not have FIPS mode enabled ($value)" -Level "FAIL"
}

$value = $ESXcli.system.ssh.server.config.list.invoke() | Where-Object {$_.Key -eq 'ciphers'} | Select-Object -ExpandProperty Value
if ($value -eq 'aes256-gcm@openssh.com,aes128-gcm@openssh.com,aes256-ctr,aes192-ctr,aes128-ctr') {
    Log-Message "$DisplayName`: SSH ciphers configured correctly ($value)" -Level "PASS"
} else {
    Log-Message "$DisplayName`: SSH ciphers not configured correctly ($value)" -Level "FAIL"
}

$value = $ESXcli.system.ssh.server.config.list.invoke() | Where-Object {$_.Key -eq 'gatewayports'} | Select-Object -ExpandProperty Value
if ($value -eq 'no') {
    Log-Message "$DisplayName`: SSH gatewayports configured correctly ($value)" -Level "PASS"
} else {
    Log-Message "$DisplayName`: SSH gatewayports not configured correctly ($value)" -Level "FAIL"
}

$value = $ESXcli.system.ssh.server.config.list.invoke() | Where-Object {$_.Key -eq 'hostbasedauthentication'} | Select-Object -ExpandProperty Value
if ($value -eq 'no') {
    Log-Message "$DisplayName`: SSH hostbasedauthentication configured correctly ($value)" -Level "PASS"
} else {
    Log-Message "$DisplayName`: SSH hostbasedauthentication not configured correctly ($value)" -Level "FAIL"
}

$value = $ESXcli.system.ssh.server.config.list.invoke() | Where-Object {$_.Key -eq 'clientalivecountmax'} | Select-Object -ExpandProperty Value
if ($value -eq '3') {
    Log-Message "$DisplayName`: SSH clientalivecountmax configured correctly ($value)" -Level "PASS"
} else {
    Log-Message "$DisplayName`: SSH clientalivecountmax not configured correctly ($value)" -Level "FAIL"
}

$value = $ESXcli.system.ssh.server.config.list.invoke() | Where-Object {$_.Key -eq 'clientaliveinterval'} | Select-Object -ExpandProperty Value
if ($value -eq '200') {
    Log-Message "$DisplayName`: SSH clientaliveinterval configured correctly ($value)" -Level "PASS"
} else {
    Log-Message "$DisplayName`: SSH clientaliveinterval not configured correctly ($value)" -Level "FAIL"
}

$value = $ESXcli.system.ssh.server.config.list.invoke() | Where-Object {$_.Key -eq 'banner'} | Select-Object -ExpandProperty Value
if ($value -eq '/etc/issue') {
    Log-Message "$DisplayName`: SSH banner configured correctly ($value)" -Level "PASS"
} else {
    Log-Message "$DisplayName`: SSH banner not configured correctly ($value)" -Level "FAIL"
}

$value = $ESXcli.system.ssh.server.config.list.invoke() | Where-Object {$_.Key -eq 'ignorerhosts'} | Select-Object -ExpandProperty Value
if ($value -eq 'yes') {
    Log-Message "$DisplayName`: SSH ignorerhosts configured correctly ($value)" -Level "PASS"
} else {
    Log-Message "$DisplayName`: SSH ignorerhosts not configured correctly ($value)" -Level "FAIL"
}

$value = $ESXcli.system.ssh.server.config.list.invoke() | Where-Object {$_.Key -eq 'allowstreamlocalforwarding'} | Select-Object -ExpandProperty Value
if ($value -eq 'no') {
    Log-Message "$DisplayName`: SSH allowstreamlocalforwarding configured correctly ($value)" -Level "PASS"
} else {
    Log-Message "$DisplayName`: SSH allowstreamlocalforwarding not configured correctly ($value)" -Level "FAIL"
}

$value = $ESXcli.system.ssh.server.config.list.invoke() | Where-Object {$_.Key -eq 'allowtcpforwarding'} | Select-Object -ExpandProperty Value
if ($value -eq 'no') {
    Log-Message "$DisplayName`: SSH allowtcpforwarding configured correctly ($value)" -Level "PASS"
} else {
    Log-Message "$DisplayName`: SSH allowtcpforwarding not configured correctly ($value)" -Level "FAIL"
}

$value = $ESXcli.system.ssh.server.config.list.invoke() | Where-Object {$_.Key -eq 'permittunnel'} | Select-Object -ExpandProperty Value
if ($value -eq 'no') {
    Log-Message "$DisplayName`: SSH permittunnel configured correctly ($value)" -Level "PASS"
} else {
    Log-Message "$DisplayName`: SSH permittunnel not configured correctly ($value)" -Level "FAIL"
}

$value = $ESXcli.system.ssh.server.config.list.invoke() | Where-Object {$_.Key -eq 'permituserenvironment'} | Select-Object -ExpandProperty Value
if ($value -eq 'no') {
    Log-Message "$DisplayName`: SSH permituserenvironment configured correctly ($value)" -Level "PASS"
} else {
    Log-Message "$DisplayName`: SSH permituserenvironment not configured correctly ($value)" -Level "FAIL"
}

#####################
# Test ESX services
$services_should_be_false = "sfcbd-watchdog", "TSM", "slpd", "snmpd", "TSM-SSH"

foreach ($service in $services_should_be_false) {
    $value = $obj | Get-VMHostService | Where-Object {$_.Key -eq $service} | Select-Object -ExpandProperty Running
    if ($value -eq $false) {
        Log-Message "$DisplayName`: $service is not running ($value)" -Level "PASS"
    } else {
        Log-Message "$DisplayName`: $service is running ($value)" -Level "FAIL"
    }

    $value = $obj | Get-VMHostService | Where-Object {$_.Key -eq $service} | Select-Object -ExpandProperty Policy
    if ($value -eq 'off') {
        Log-Message "$DisplayName`: $service is not configured to start ($value)" -Level "PASS"
    } else {
        Log-Message "$DisplayName`: $service is configured to start ($value)" -Level "FAIL"
    }
}

#####################
# Test NTP services
# You might also have PTP, in which case this may fail but your environment is alright.
$services_should_be_true = "ntpd"

foreach ($service in $services_should_be_true) {
    $value = $obj | Get-VMHostService | Where-Object {$_.Key -eq $service} | Select-Object -ExpandProperty Running
    if ($value -eq $true) {
        Log-Message "$DisplayName`: $service is running ($value)" -Level "PASS"
    } else {
        Log-Message "$DisplayName`: $service is not running ($value)" -Level "FAIL"
    }

    $value = $obj | Get-VMHostService | Where-Object {$_.Key -eq $service} | Select-Object -ExpandProperty Policy
    if ($value -eq 'on') {
        Log-Message "$DisplayName`: $service is configured to start ($value)" -Level "PASS"
    } else {
        Log-Message "$DisplayName`: $service is not configured to start ($value)" -Level "FAIL"
    }
}

#####################
# Test NTP configurations
$value = $obj | Get-VMHostNtpServer
if ($null -eq $value) {
    Log-Message "$DisplayName`: NTP client not configured ($value)" -Level "FAIL"
} else {
    Log-Message "$DisplayName`: NTP client configured ($value)" -Level "PASS"
}

#####################
# Test lockdown mode
$value = ((Get-View($view).ConfigManager.HostAccessManager)).QueryLockdownExceptions()
if ([string]::IsNullOrEmpty($value)) {
    Log-Message "$DisplayName`: Lockdown Mode exception users configured correctly ($value)" -Level "PASS"
} else {
    Log-Message "$DisplayName`: Lockdown Mode exception users not configured correctly ($value)" -Level "FAIL"
}

$value = (Get-View ($view).ConfigManager.HostAccessManager).LockdownMode
if ($value -eq 'lockdownDisabled') {
    Log-Message "$DisplayName`: Lockdown Mode is not configured correctly ($value)" -Level "FAIL"
} else {
    Log-Message "$DisplayName`: Lockdown Mode is configured correctly ($value)" -Level "PASS"
}

#####################
# Test Standard Switches
$switches = Get-VirtualSwitch -VMHost $obj -Standard

foreach ($switch in $switches) {
    $value = $switch | Get-SecurityPolicy | Select-Object -ExpandProperty AllowPromiscuous
    if ($value -eq $false) {
        Log-Message "$DisplayName`: Standard switch `'$switch`' is not configured to allow promiscuous mode ($value)" -Level "PASS"
    } else {
        Log-Message "$DisplayName`: Standard switch `'$switch`' is configured to allow promiscuous mode ($value)" -Level "FAIL"
    }

    $value = $switch | Get-SecurityPolicy | Select-Object -ExpandProperty MacChanges
    if ($value -eq $false) {
        Log-Message "$DisplayName`: Standard switch `'$switch`' is not configured to allow MAC address changes ($value)" -Level "PASS"
    } else {
        Log-Message "$DisplayName`: Standard switch `'$switch`' is configured to allow MAC address changes ($value)" -Level "FAIL"
    }

    $value = $switch | Get-SecurityPolicy | Select-Object -ExpandProperty ForgedTransmits
    if ($value -eq $false) {
        Log-Message "$DisplayName`: Standard switch `'$switch`' is not configured to allow forged transmits ($value)" -Level "PASS"
    } else {
        Log-Message "$DisplayName`: Standard switch `'$switch`' is configured to allow forged transmits ($value)" -Level "FAIL"
    }

    $portgroups = Get-VirtualPortGroup -VirtualSwitch $switch
    foreach ($portgroup in $portgroups) {
        $value = $portgroup | Get-SecurityPolicy | Select-Object -ExpandProperty AllowPromiscuous
        if ($value -eq $false) {
            Log-Message "$DisplayName`: Standard portgroup `'$portgroup`' is not configured to allow promiscuous mode ($value)" -Level "PASS"
        } else {
            Log-Message "$DisplayName`: Standard portgroup `'$portgroup`' is configured to allow promiscuous mode ($value)" -Level "FAIL"
        }
    
        $value = $portgroup | Get-SecurityPolicy | Select-Object -ExpandProperty MacChanges
        if ($value -eq $false) {
            Log-Message "$DisplayName`: Standard portgroup `'$portgroup`' is not configured to allow MAC address changes ($value)" -Level "PASS"
        } else {
            Log-Message "$DisplayName`: Standard portgroup `'$portgroup`' is configured to allow MAC address changes ($value)" -Level "FAIL"
        }
    
        $value = $portgroup | Get-SecurityPolicy | Select-Object -ExpandProperty ForgedTransmits
        if ($value -eq $false) {
            Log-Message "$DisplayName`: Standard portgroup `'$portgroup`' is not configured to allow forged transmits ($value)" -Level "PASS"
        } else {
            Log-Message "$DisplayName`: Standard portgroup `'$portgroup`' is configured to allow forged transmits ($value)" -Level "FAIL"
        }

        $value = $portgroup | Select-Object -ExpandProperty VLanID
        if ($value -eq 4095) {
            Log-Message "$DisplayName`: Standard portgroup `'$portgroup`' is configured to allow VLAN 4095 ($value)" -Level "FAIL"
        } else {
            Log-Message "$DisplayName`: Standard portgroup `'$portgroup`' is not configured to allow VLAN 4095 ($value)" -Level "PASS"
        }
       
        if (($value -eq 1) -or ($null -eq $value)) {
            Log-Message "$DisplayName`: Standard portgroup `'$portgroup`' may be configured to use a default VLAN and should be assessed ($value)" -Level "FAIL"
        } else {
            Log-Message "$DisplayName`: Standard portgroup `'$portgroup`' does not appear to be configured to use a default VLAN ($value)" -Level "PASS"
        }
    }

}

$vmks = $obj | Get-VMHostNetworkAdapter -VMKernel
foreach ($vmk in $vmks) {
    $valueObj = $vmk | Select-Object ManagementTrafficEnabled,VMotionEnabled,FaultToleranceLoggingEnabled,
                                    VsanTrafficEnabled,ProvisioningEnabled,VSphereReplicationEnabled,
                                    VSphereReplicationNFCEnabled,VSphereBackupNFCEnabled
    $valueStr = ($valueObj.PSObject.Properties | ForEach-Object { "$($_.Name): $($_.Value)" }) -join ', '

    if ($vmk.ManagementTrafficEnabled) {
        if ($vmk.VMotionEnabled -or
            $vmk.FaultToleranceLoggingEnabled -or
            $vmk.VsanTrafficEnabled -or
            $vmk.ProvisioningEnabled -or
            $vmk.VSphereReplicationEnabled -or
            $vmk.VSphereReplicationNFCEnabled -or
            $vmk.VSphereBackupNFCEnabled) {
                Log-Message "$DisplayName`: VMkernel NIC `'$vmk`' has management configured alongside other services and should be assessed ($valueStr)" -Level "FAIL"
        } else {
            Log-Message "$DisplayName`: VMkernel NIC `'$vmk`' has only management configured ($valueStr)" -Level "PASS"
        }
    } else {
        Log-Message "$DisplayName`: VMkernel NIC `'$vmk`' is not configured for management ($valueStr)" -Level "PASS"
    }
}

Log-Message "$DisplayName`: Audit of $DisplayName completed at $(Get-Date -Format "yyyy-MM-dd HH:mm:ss")" -Level "INFO"
}

function Invoke-AuditVcenter8Tool {
Param (
    # vCenter Name
    [Parameter(Mandatory=$true)]
    [ValidateNotNullOrEmpty()]
    [string]$Name,
    # Output File Name
    [Parameter(Mandatory=$false)]
    [ValidateNotNullOrEmpty()]
    [string]$OutputFileName,
    # Accept-EULA
    [Parameter(Mandatory=$false)]
    [switch]$AcceptEULA,
    # Skip safety checks
    [Parameter(Mandatory=$false)]
    [switch]$NoSafetyChecks = $false
)

function ConvertTo-MaskedAuditName {
    param([string]$HostName, [switch]$ForFileName)
    if ([string]::IsNullOrWhiteSpace($HostName)) { return $HostName }
    $mask = if ($ForFileName) { "xxx" } else { "***" }
    if ($HostName -match '^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$') {
        $octets = $HostName.Split('.')
        return "$mask.$mask.$mask.$($octets[3])"
    }
    if ($HostName -match '\.') {
        $shortName = $HostName.Split('.')[0]
        return "$shortName.$mask.$mask"
    }
    return $HostName
}
$DisplayName = ConvertTo-MaskedAuditName $name


# Import common functions
# ---- inlined from security-hardening/vmware-tools/scg-common.psm1 ----
<#
    Module Name: scg-common
    Description: Common functions for VMware vSphere Security Configuration Guide 8.0 scripts
    Copyright (C) 2026 Broadcom, Inc. All rights reserved.
#>

#####################
# Log to both screen and file
function Write-Log {
    param (
        [Parameter(Mandatory=$false)]
        [AllowEmptyString()]
        [AllowNull()]
        [string]$Message = "",

        [Parameter(Mandatory=$false)]
        [ValidateSet("INFO", "WARNING", "ERROR", "EULA", "PASS", "FAIL", "UPDATE")]
        [string]$Level = "INFO",

        [Parameter(Mandatory=$false)]
        [string]$OutputFileName
    )

    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $logEntry = "[$timestamp] [$Level] $Message"

    # Output to screen
    switch ($Level) {
        "INFO"    { Write-Host $logEntry -ForegroundColor White }
        "WARNING" { Write-Host $logEntry -ForegroundColor Yellow }
        "ERROR"   { Write-Host $logEntry -ForegroundColor Red }
        "EULA"    { Write-Host $logEntry -ForegroundColor Cyan }
        "PASS"    { Write-Host $logEntry -ForegroundColor Gray }
        "FAIL"    { Write-Host $logEntry -ForegroundColor Yellow }
        "UPDATE"  { Write-Host $logEntry -ForegroundColor Green }
    }

    # Append to file
    if ($OutputFileName) {
        $logEntry | Out-File -FilePath $OutputFileName -Append
    }
}

#####################
# Accept EULA and terms to continue
Function Show-EULA {
    param (
        [Parameter(Mandatory=$false)]
        [string]$OutputFileName
    )

    Write-Log "This software is provided as is and any express or implied warranties, including," -Level "EULA" -OutputFileName $OutputFileName
    Write-Log "but not limited to, the implied warranties of merchantability and fitness for a particular" -Level "EULA" -OutputFileName $OutputFileName
    Write-Log "purpose are disclaimed. In no event shall the copyright holder or contributors be liable" -Level "EULA" -OutputFileName $OutputFileName
    Write-Log "for any direct, indirect, incidental, special, exemplary, or consequential damages (including," -Level "EULA" -OutputFileName $OutputFileName
    Write-Log "but not limited to, procurement of substitute goods or services; loss of use, data, or" -Level "EULA" -OutputFileName $OutputFileName
    Write-Log "profits; or business interruption) however caused and on any theory of liability, whether" -Level "EULA" -OutputFileName $OutputFileName
    Write-Log "in contract, strict liability, or tort (including negligence or otherwise) arising in any" -Level "EULA" -OutputFileName $OutputFileName
    Write-Log "way out of the use of this software, even if advised of the possibility of such damage." -Level "EULA" -OutputFileName $OutputFileName
    Write-Log "The provider makes no claims, promises, or guarantees about the accuracy, completeness, or" -Level "EULA" -OutputFileName $OutputFileName
    Write-Log "adequacy of this sample. Organizations should engage appropriate legal, business, technical," -Level "EULA" -OutputFileName $OutputFileName
    Write-Log "and audit expertise within their specific organization for review of requirements and" -Level "EULA" -OutputFileName $OutputFileName
    Write-Log "effectiveness of implementations. You acknowledge that there may be performance or other" -Level "EULA" -OutputFileName $OutputFileName
    Write-Log "considerations, and that this example may make assumptions which may not be valid in your" -Level "EULA" -OutputFileName $OutputFileName
    Write-Log "environment or organization." -Level "EULA" -OutputFileName $OutputFileName
    Write-Log "" -Level "EULA" -OutputFileName $OutputFileName
    Write-Log "Press any character key to accept all terms and risk. Use CTRL+C to return." -Level "EULA" -OutputFileName $OutputFileName

    $null = $host.UI.RawUI.FlushInputBuffer()
    do {
        $key = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
    } while ($key.Character -eq [char]0)
}

#####################
# Pause for user input
Function Wait-UserInput {
    param (
        [Parameter(Mandatory=$false)]
        [string]$OutputFileName
    )

    Write-Log "Check the vSphere Client to make sure all tasks have completed, then press any character key." -Level "INFO" -OutputFileName $OutputFileName
    $null = $host.UI.RawUI.FlushInputBuffer()
    do {
        $key = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
    } while ($key.Character -eq [char]0)
}

#####################
# Check to see if we are attached to a vCenter Server
Function Test-vCenterConnection {
    param (
        [Parameter(Mandatory=$false)]
        [string]$OutputFileName
    )

    if ($global:DefaultVIServers.Count -lt 1) {
        Write-Log "Please connect to a vCenter Server (use Connect-VIServer) prior to running this script. Thank you." -Level "ERROR" -OutputFileName $OutputFileName
        return $false
    }

    if ($global:DefaultVIServers.Count -gt 1) {
        Write-Log "Connect to a single vCenter Server (use Connect-VIServer) prior to running this script." -Level "ERROR" -OutputFileName $OutputFileName
        return $false
    }

    return $true
}

#####################
# Check to see if we have hosts attached
Function Test-HostsExist {
    param (
        [Parameter(Mandatory=$false)]
        [string]$OutputFileName
    )

    $ESX = Get-VMHost
    if ($ESX.Count -lt 1) {
        Write-Log "No ESX hosts found. Please ensure hosts are connected to vCenter." -Level "ERROR" -OutputFileName $OutputFileName
        return $false
    }

    return $true
}

# Export functions

# Wrapper functions for backward compatibility
function Log-Message {
    param (
        [Parameter(Mandatory=$false)][AllowEmptyString()][AllowNull()][string]$Message = "",
        [Parameter(Mandatory=$false)][ValidateSet("INFO", "WARNING", "ERROR", "EULA", "PASS", "FAIL", "UPDATE")][string]$Level = "INFO"
    )
    Write-Log -Message $Message -Level $Level -OutputFileName $OutputFileName
}

Function Accept-EULA() { Show-EULA -OutputFileName $OutputFileName }
Function Do-Pause() { Wait-UserInput -OutputFileName $OutputFileName }
Function Check-vCenter() { if (-not (Test-vCenterConnection -OutputFileName $OutputFileName)) { return } }
Function Check-Hosts() { if (-not (Test-HostsExist -OutputFileName $OutputFileName)) { return } }

#######################################################################################################

$currentDateTime = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
Log-Message "VMware vCenter Security Settings Audit Utility 8.0.3" -Level "INFO"
Log-Message "Audit of $DisplayName started at $currentDateTime from $env:COMPUTERNAME by $env:USERNAME" -Level "INFO"

# Accept EULA and terms to continue
if ($false -eq $AcceptEULA) {
    Accept-EULA
    Log-Message "EULA accepted." -Level "INFO"
} else {
    Log-Message "EULA accepted." -Level "INFO"
}

# Safety checks
if ($false -eq $NoSafetyChecks) {
    Check-vCenter
    Check-Hosts
} else {
    Log-Message "Safety checks skipped." -Level "INFO"
}

#####################
# Tests for SSO 
$scg_adv = @{
    
    'vpxd.event.syslog.enabled' = $true
    'config.log.level' = 'info'
    'VirtualCenter.VimPasswordExpirationInDays' = 30

}

foreach ($param in $scg_adv.GetEnumerator() )
{
    $value = (Get-AdvancedSetting -Entity $global:DefaultVIServers.Name "$($param.Name)").Value

    if ($value -eq $($param.Value)) {
        Log-Message "$($param.Name) configured correctly ($value)" -Level "PASS"
    } else {
        Log-Message "$($param.Name) not configured correctly ($value)" -Level "FAIL"
    }
}

#####################
# Tests for things that should not be set a certain way
$scg_not = @{

    'etc.issue' = 'Platform Services Controller' # Just test to see if the stock message is there.

}

foreach ($param in $scg_not.GetEnumerator() )
{
    $value = (Get-AdvancedSetting -Entity $global:DefaultVIServers.Name -Name "$($param.Name)" | Select-Object -ExpandProperty Value)

    $singleline = $value -replace '\r?\n', ' '
    if ($value -match $($param.Value)) {
        Log-Message "$($param.Name) contains the default message ($singleline)" -Level "FAIL"
    } else {
        Log-Message "$($param.Name) does not contain the default message ($singleline)" -Level "PASS"
    }
}

#####################
# Test SSO Lockout Configurations
try {
    $lockoutPolicy = Get-SsoLockoutPolicy

    $ssoLockoutChecks = @{
        'AutoUnlockIntervalSec' = @{ Expected = 0; Comparator = 'eq' }
        'FailedAttemptIntervalSec' = @{ Expected = 900; Comparator = 'ge' }
        'MaxFailedAttempts' = @{ Expected = 5; Comparator = 'le' }
    }

    foreach ($check in $ssoLockoutChecks.GetEnumerator()) {
        $actual = $lockoutPolicy.$($check.Name)
        $pass = switch ($check.Value.Comparator) {
            'eq' { $actual -eq $check.Value.Expected }
            'ge' { $actual -ge $check.Value.Expected }
            'le' { $actual -le $check.Value.Expected }
        }
        if ($pass) {
            Log-Message "SSO $($check.Name) configured correctly ($actual)" -Level "PASS"
        } else {
            Log-Message "SSO $($check.Name) not configured correctly ($actual)" -Level "FAIL"
        }
    }
} catch {
    Log-Message "Failed to check SSO Lockout Policy: $_" -Level "ERROR"
}

#####################
# Test SSO Password Policy
try {
    $passwordPolicy = Get-SsoPasswordPolicy

    $ssoPasswordChecks = @{
        'PasswordLifetimeDays' = @{ Expected = 9999; Comparator = 'eq' }
        'ProhibitedPreviousPasswordsCount' = @{ Expected = 5; Comparator = 'ge' }
        'MinLength' = @{ Expected = 15; Comparator = 'ge' }
        'MaxLength' = @{ Expected = 64; Comparator = 'ge' }
        'MinNumericCount' = @{ Expected = 1; Comparator = 'ge' }
        'MinSpecialCharCount' = @{ Expected = 1; Comparator = 'ge' }
        'MaxIdenticalAdjacentCharacters' = @{ Expected = 3; Comparator = 'le' }
        'MinAlphabeticCount' = @{ Expected = 2; Comparator = 'ge' }
        'MinUppercaseCount' = @{ Expected = 1; Comparator = 'ge' }
        'MinLowercaseCount' = @{ Expected = 1; Comparator = 'ge' }
    }

    foreach ($check in $ssoPasswordChecks.GetEnumerator()) {
        $actual = $passwordPolicy.$($check.Name)
        $pass = switch ($check.Value.Comparator) {
            'eq' { $actual -eq $check.Value.Expected }
            'ge' { $actual -ge $check.Value.Expected }
            'le' { $actual -le $check.Value.Expected }
        }
        if ($pass) {
            Log-Message "SSO $($check.Name) configured correctly ($actual)" -Level "PASS"
        } else {
            Log-Message "SSO $($check.Name) not configured correctly ($actual)" -Level "FAIL"
        }
    }
} catch {
    Log-Message "Failed to check SSO Password Policy: $_" -Level "ERROR"
}

#####################
# Test Distributed Switches
try {
    $switches = Get-VDSwitch
} catch {
    Log-Message "Failed to retrieve distributed switches: $_" -Level "ERROR"
    $switches = @()
}

foreach ($switch in $switches) {
    $value = $switch | Get-VDSecurityPolicy | Select-Object -ExpandProperty AllowPromiscuous
    if ($value -eq $false) {
        Log-Message "Distributed switch `'$switch`' is not configured to allow promiscuous mode ($value)" -Level "PASS"
    } else {
        Log-Message "Distributed switch `'$switch`' is configured to allow promiscuous mode ($value)" -Level "FAIL"
    }

    $value = $switch | Get-VDSecurityPolicy | Select-Object -ExpandProperty MacChanges
    if ($value -eq $false) {
        Log-Message "Distributed switch `'$switch`' is not configured to allow MAC address changes ($value)" -Level "PASS"
    } else {
        Log-Message "Distributed switch `'$switch`' is configured to allow MAC address changes ($value)" -Level "FAIL"
    }

    $value = $switch | Get-VDSecurityPolicy | Select-Object -ExpandProperty ForgedTransmits
    if ($value -eq $false) {
        Log-Message "Distributed switch `'$switch`' is not configured to allow forged transmits ($value)" -Level "PASS"
    } else {
        Log-Message "Distributed switch `'$switch`' is configured to allow forged transmits ($value)" -Level "FAIL"
    }

    $value = $switch.ExtensionData.Config.LinkDiscoveryProtocolConfig | Select-Object -ExpandProperty Operation
    if ($value -eq "none") {
        Log-Message "Distributed switch `'$switch`' link discovery is configured correctly ($value)" -Level "PASS"
    } else {
        Log-Message "Distributed switch `'$switch`' link discovery is not configured correctly ($value)" -Level "FAIL"
    }

    $value = $switch.ExtensionData.Config.IpfixConfig | Select-Object -ExpandProperty CollectorIpAddress
    if (($value -eq "") -or ($null -eq $value)) {
        Log-Message "Distributed switch `'$switch`' NetFlow is configured correctly ($value)" -Level "PASS"
    } else {
        Log-Message "Distributed switch `'$switch`' NetFlow is configured with a collector ($value)" -Level "FAIL"
    }

    $value = $switch.ExtensionData.Config | Select-Object -ExpandProperty VspanSession
    if ($null -eq $value) {
        Log-Message "Distributed switch `'$switch`' port mirroring is inactive ($value)" -Level "PASS"
    } else {
        Log-Message "Distributed switch `'$switch`' port mirroring is active ($value)" -Level "FAIL"
    }

    $portgroups = Get-VDPortgroup -VDSwitch $switch | Where-Object {$_.ExtensionData.Config.Uplink -ne "True"}
    foreach ($portgroup in $portgroups) {
        $value = $portgroup | Get-VDSecurityPolicy | Select-Object -ExpandProperty AllowPromiscuous
        if ($value -eq $false) {
            Log-Message "Distributed portgroup `'$portgroup`' is not configured to allow promiscuous mode ($value)" -Level "PASS"
        } else {
            Log-Message "Distributed portgroup `'$portgroup`' is configured to allow promiscuous mode ($value)" -Level "FAIL"
        }
    
        $value = $portgroup | Get-VDSecurityPolicy | Select-Object -ExpandProperty MacChanges
        if ($value -eq $false) {
            Log-Message "Distributed portgroup `'$portgroup`' is not configured to allow MAC address changes ($value)" -Level "PASS"
        } else {
            Log-Message "Distributed portgroup `'$portgroup`' is configured to allow MAC address changes ($value)" -Level "FAIL"
        }
    
        $value = $portgroup | Get-VDSecurityPolicy | Select-Object -ExpandProperty ForgedTransmits
        if ($value -eq $false) {
            Log-Message "Distributed portgroup `'$portgroup`' is not configured to allow forged transmits ($value)" -Level "PASS"
        } else {
            Log-Message "Distributed portgroup `'$portgroup`' is configured to allow forged transmits ($value)" -Level "FAIL"
        }

        $value = $portgroup | Select-Object -ExpandProperty VlanConfiguration
        if ($value -eq 4095) {
            Log-Message "Distributed portgroup `'$portgroup`' is configured to allow VLAN 4095 ($value)" -Level "FAIL"
        } else {
            Log-Message "Distributed portgroup `'$portgroup`' is not configured to allow VLAN 4095 ($value)" -Level "PASS"
        }
       
        if (($value -eq 1) -or ($null -eq $value)) {
            Log-Message "Distributed portgroup `'$portgroup`' may be configured to use a default VLAN and should be assessed ($value)" -Level "FAIL"
        } else {
            Log-Message "Distributed portgroup `'$portgroup`' does not appear to be configured to use a default VLAN ($value)" -Level "PASS"
        }

        $value = $portgroup.ExtensionData.Config.Policy | Select-Object -ExpandProperty PortConfigResetAtDisconnect
        if ($value -eq $true) {
            Log-Message "Distributed portgroup `'$portgroup`' is configured to reset port configuration on disconnect ($value)" -Level "PASS"
        } else {
            Log-Message "Distributed portgroup `'$portgroup`' is not configured to reset port configuration on disconnect ($value)" -Level "FAIL"
        }

        $value = $portgroup.ExtensionData.Config.DefaultPortConfig.IpfixEnabled | Select-Object -ExpandProperty Value
        if ($value -eq $false) {
            Log-Message "Distributed portgroup `'$portgroup`' NetFlow is configured correctly ($value)" -Level "PASS"
        } else {
            Log-Message "Distributed portgroup `'$portgroup`' NetFlow is not configured correctly ($value)" -Level "FAIL"
        }

        # Test port group policies
        $valueObj = $portgroup.ExtensionData.Config.Policy | Select-Object VlanOverrideAllowed, UplinkTeamingOverrideAllowed, 
                    SecurityPolicyOverrideAllowed, MacManagementOverrideAllowed, BlockOverrideAllowed, ShapingOverrideAllowed, IpfixOverrideAllowed,
                    VendorConfigOverrideAllowed, LivePortMovingAllowed, NetworkResourcePoolOverrideAllowed, TrafficFilterOverrideAllowed
        $valueStr = ($valueObj.PSObject.Properties | ForEach-Object { "$($_.Name): $($_.Value)" }) -join ', '

        if (
            $valueObj.VlanOverrideAllowed -eq $false -and
            $valueObj.UplinkTeamingOverrideAllowed -eq $false -and
            $valueObj.SecurityPolicyOverrideAllowed -eq $false -and
            $valueObj.MacManagementOverrideAllowed -eq $false -and
            $valueObj.BlockOverrideAllowed -eq $true -and
            $valueObj.ShapingOverrideAllowed -eq $false -and
            $valueObj.IpfixOverrideAllowed -eq $false -and
            $valueObj.VendorConfigOverrideAllowed -eq $false -and
            $valueObj.LivePortMovingAllowed -eq $false -and
            $valueObj.NetworkResourcePoolOverrideAllowed -eq $false -and
            $valueObj.TrafficFilterOverrideAllowed -eq $false
        ) {
            Log-Message "Distributed portgroup `'$portgroup`' policies are configured correctly ($valueStr)" -Level "PASS"
        } else {
            Log-Message "Distributed portgroup `'$portgroup`' policies are not configured correctly ($valueStr)" -Level "FAIL"
        }

        # Test MAC learning policy
        $value = $portgroup.ExtensionData.Config.DefaultPortConfig.MacManagementPolicy.MacLearningPolicy | Select-Object -ExpandProperty Enabled
        if ($value -eq $false) {
            Log-Message "Distributed portgroup `'$portgroup`' MAC learning is not enabled ($value)" -Level "PASS"
        } else {
            Log-Message "Distributed portgroup `'$portgroup`' MAC learning is enabled ($value)" -Level "FAIL"
        }
    }
}

#####################
# Test VCSA Settings for SSH
try {
    $value = (Get-CisService -Name "com.vmware.appliance.access.ssh").get()
    if ($value -eq $true) {
        Log-Message "vCenter Server Appliance has SSH enabled ($value)" -Level "FAIL"
    } else {
        Log-Message "vCenter Server Appliance does not have SSH enabled ($value)" -Level "PASS"
    }
} catch {
    Log-Message "Failed to check vCenter Server Appliance SSH status: $_" -Level "ERROR"
}

#####################
# Test VCSA Settings for password policies
try {
    $value = (Get-CisService -Name "com.vmware.appliance.local_accounts.policy").get() | Select-Object -ExpandProperty max_days
    if ($value -ne 9999) {
        Log-Message "vCenter Server Appliance local accounts max_days not configured correctly ($value)" -Level "FAIL"
    } else {
        Log-Message "vCenter Server Appliance local accounts max_days configured correctly ($value)" -Level "PASS"
    }
} catch {
    Log-Message "Failed to check vCenter Server Appliance local accounts policy: $_" -Level "ERROR"
}

#####################
# Test VCSA Settings for log forwarding
try {
    $value = (Get-CisService -Name "com.vmware.appliance.logging.forwarding").get()
    if ($value.Count -eq 0) {
        Log-Message "vCenter Server Appliance not configured to forward logs ($($value.Hostname))" -Level "FAIL"
    } else {
        Log-Message "vCenter Server Appliance configured to forward logs ($($value.Hostname))" -Level "PASS"
    }
} catch {
    Log-Message "Failed to check vCenter Server Appliance log forwarding: $_" -Level "ERROR"
}

#####################
# Test VCSA Settings for NTP
try {
    $value = (Get-CisService -Name "com.vmware.appliance.timesync").get()
    if ($value -ne "NTP") {
        Log-Message "vCenter Server Appliance NTP not configured ($value)" -Level "FAIL"
    } else {
        Log-Message "vCenter Server Appliance NTP is configured ($value)" -Level "PASS"
    }

    $value = (Get-CisService -Name "com.vmware.appliance.ntp").get()
    if ($null -eq $value) {
        Log-Message "vCenter Server Appliance NTP does not have servers defined ($value)" -Level "FAIL"
    } else {
        Log-Message "vCenter Server Appliance NTP has servers defined ($value)" -Level "PASS"
    }
} catch {
    Log-Message "Failed to check vCenter Server Appliance NTP settings: $_" -Level "ERROR"
}

#####################
Log-Message "Audit of $DisplayName completed at $(Get-Date -Format "yyyy-MM-dd HH:mm:ss")" -Level "INFO"
}

function Invoke-AuditAllTool {
Param (
    # Output File Name
    [Parameter(Mandatory=$false)]
    [ValidateNotNullOrEmpty()]
    [string]$OutputDirName,
    # Accept-EULA
    [Parameter(Mandatory=$false)]
    [switch]$AcceptEULA,
    # Skip safety checks
    [Parameter(Mandatory=$false)]
    [switch]$NoSafetyChecks
)

function ConvertTo-MaskedAuditName {
    param([string]$HostName, [switch]$ForFileName)
    if ([string]::IsNullOrWhiteSpace($HostName)) { return $HostName }
    $mask = if ($ForFileName) { "xxx" } else { "***" }
    if ($HostName -match '^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$') {
        $octets = $HostName.Split('.')
        return "$mask.$mask.$mask.$($octets[3])"
    }
    if ($HostName -match '\.') {
        $shortName = $HostName.Split('.')[0]
        return "$shortName.$mask.$mask"
    }
    return $HostName
}


# Import common functions
# ---- inlined from security-hardening/vmware-tools/scg-common.psm1 ----
<#
    Module Name: scg-common
    Description: Common functions for VMware vSphere Security Configuration Guide 8.0 scripts
    Copyright (C) 2026 Broadcom, Inc. All rights reserved.
#>

#####################
# Log to both screen and file
function Write-Log {
    param (
        [Parameter(Mandatory=$false)]
        [AllowEmptyString()]
        [AllowNull()]
        [string]$Message = "",

        [Parameter(Mandatory=$false)]
        [ValidateSet("INFO", "WARNING", "ERROR", "EULA", "PASS", "FAIL", "UPDATE")]
        [string]$Level = "INFO",

        [Parameter(Mandatory=$false)]
        [string]$OutputFileName
    )

    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $logEntry = "[$timestamp] [$Level] $Message"

    # Output to screen
    switch ($Level) {
        "INFO"    { Write-Host $logEntry -ForegroundColor White }
        "WARNING" { Write-Host $logEntry -ForegroundColor Yellow }
        "ERROR"   { Write-Host $logEntry -ForegroundColor Red }
        "EULA"    { Write-Host $logEntry -ForegroundColor Cyan }
        "PASS"    { Write-Host $logEntry -ForegroundColor Gray }
        "FAIL"    { Write-Host $logEntry -ForegroundColor Yellow }
        "UPDATE"  { Write-Host $logEntry -ForegroundColor Green }
    }

    # Append to file
    if ($OutputFileName) {
        $logEntry | Out-File -FilePath $OutputFileName -Append
    }
}

#####################
# Accept EULA and terms to continue
Function Show-EULA {
    param (
        [Parameter(Mandatory=$false)]
        [string]$OutputFileName
    )

    Write-Log "This software is provided as is and any express or implied warranties, including," -Level "EULA" -OutputFileName $OutputFileName
    Write-Log "but not limited to, the implied warranties of merchantability and fitness for a particular" -Level "EULA" -OutputFileName $OutputFileName
    Write-Log "purpose are disclaimed. In no event shall the copyright holder or contributors be liable" -Level "EULA" -OutputFileName $OutputFileName
    Write-Log "for any direct, indirect, incidental, special, exemplary, or consequential damages (including," -Level "EULA" -OutputFileName $OutputFileName
    Write-Log "but not limited to, procurement of substitute goods or services; loss of use, data, or" -Level "EULA" -OutputFileName $OutputFileName
    Write-Log "profits; or business interruption) however caused and on any theory of liability, whether" -Level "EULA" -OutputFileName $OutputFileName
    Write-Log "in contract, strict liability, or tort (including negligence or otherwise) arising in any" -Level "EULA" -OutputFileName $OutputFileName
    Write-Log "way out of the use of this software, even if advised of the possibility of such damage." -Level "EULA" -OutputFileName $OutputFileName
    Write-Log "The provider makes no claims, promises, or guarantees about the accuracy, completeness, or" -Level "EULA" -OutputFileName $OutputFileName
    Write-Log "adequacy of this sample. Organizations should engage appropriate legal, business, technical," -Level "EULA" -OutputFileName $OutputFileName
    Write-Log "and audit expertise within their specific organization for review of requirements and" -Level "EULA" -OutputFileName $OutputFileName
    Write-Log "effectiveness of implementations. You acknowledge that there may be performance or other" -Level "EULA" -OutputFileName $OutputFileName
    Write-Log "considerations, and that this example may make assumptions which may not be valid in your" -Level "EULA" -OutputFileName $OutputFileName
    Write-Log "environment or organization." -Level "EULA" -OutputFileName $OutputFileName
    Write-Log "" -Level "EULA" -OutputFileName $OutputFileName
    Write-Log "Press any character key to accept all terms and risk. Use CTRL+C to return." -Level "EULA" -OutputFileName $OutputFileName

    $null = $host.UI.RawUI.FlushInputBuffer()
    do {
        $key = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
    } while ($key.Character -eq [char]0)
}

#####################
# Pause for user input
Function Wait-UserInput {
    param (
        [Parameter(Mandatory=$false)]
        [string]$OutputFileName
    )

    Write-Log "Check the vSphere Client to make sure all tasks have completed, then press any character key." -Level "INFO" -OutputFileName $OutputFileName
    $null = $host.UI.RawUI.FlushInputBuffer()
    do {
        $key = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
    } while ($key.Character -eq [char]0)
}

#####################
# Check to see if we are attached to a vCenter Server
Function Test-vCenterConnection {
    param (
        [Parameter(Mandatory=$false)]
        [string]$OutputFileName
    )

    if ($global:DefaultVIServers.Count -lt 1) {
        Write-Log "Please connect to a vCenter Server (use Connect-VIServer) prior to running this script. Thank you." -Level "ERROR" -OutputFileName $OutputFileName
        return $false
    }

    if ($global:DefaultVIServers.Count -gt 1) {
        Write-Log "Connect to a single vCenter Server (use Connect-VIServer) prior to running this script." -Level "ERROR" -OutputFileName $OutputFileName
        return $false
    }

    return $true
}

#####################
# Check to see if we have hosts attached
Function Test-HostsExist {
    param (
        [Parameter(Mandatory=$false)]
        [string]$OutputFileName
    )

    $ESX = Get-VMHost
    if ($ESX.Count -lt 1) {
        Write-Log "No ESX hosts found. Please ensure hosts are connected to vCenter." -Level "ERROR" -OutputFileName $OutputFileName
        return $false
    }

    return $true
}

# Export functions

# Wrapper functions for backward compatibility
function Log-Message {
    param (
        [Parameter(Mandatory=$false)][AllowEmptyString()][AllowNull()][string]$Message = "",
        [Parameter(Mandatory=$false)][ValidateSet("INFO", "WARNING", "ERROR", "EULA", "PASS", "FAIL", "UPDATE")][string]$Level = "INFO"
    )
    Write-Log -Message $Message -Level $Level -OutputFileName $OutputFileName
}

Function Accept-EULA() { Show-EULA -OutputFileName $OutputFileName }
Function Do-Pause() { Wait-UserInput -OutputFileName $OutputFileName }
Function Check-vCenter() { if (-not (Test-vCenterConnection -OutputFileName $OutputFileName)) { return } }
Function Check-Hosts() { if (-not (Test-HostsExist -OutputFileName $OutputFileName)) { return } }

#######################################################################################################

$currentDateTime = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
Log-Message "VMware vSphere Security Settings Audit Utility 8.0.3" -Level "INFO"
Log-Message "Audit started at $currentDateTime from $env:COMPUTERNAME by $env:USERNAME" -Level "INFO"

# Accept EULA and terms to continue
if ($false -eq $AcceptEULA) {
    Accept-EULA
    Log-Message "EULA accepted." -Level "INFO"
} else {
    Log-Message "EULA accepted." -Level "INFO"
}

# Safety checks
if ($false -eq $NoSafetyChecks) {
    Check-vCenter
    Check-Hosts
} else {
    Log-Message "Safety checks skipped." -Level "INFO"
}

#####################
# Test to see if the output directory exists
if (!(Test-Path -Path $OutputDirName -PathType Container)) {
    Log-Message "The directory '$OutputDirName' does not exist. Please create it and try again." -Level "ERROR"
    return
}

#####################
# Test to see if the output directory is empty
if ((Get-ChildItem -Path $OutputDirName -Force | Measure-Object).Count -ne 0) {
    Log-Message "The directory '$OutputDirName' is not empty. Please empty it and try again." -Level "ERROR"
    return
}

#####################
# Read the VMs and ESX hosts
try {
    $vms = Get-VM -ErrorAction Stop | Sort-Object -Property Name
    Log-Message "Found $($vms.Count) virtual machines to audit." -Level "INFO"
}
catch {
    Log-Message "Failed to retrieve virtual machines: $_" -Level "ERROR"
    return
}

try {
    $hosts = Get-VMHost -ErrorAction Stop | Sort-Object -Property Name
    Log-Message "Found $($hosts.Count) ESX hosts to audit." -Level "INFO"
}
catch {
    Log-Message "Failed to retrieve ESX hosts: $_" -Level "ERROR"
    return
}

#####################
# Run the audits
foreach ($vm in $vms) {
    try {
        Invoke-AuditVm8Tool -name $vm -AcceptEULA -NoSafetyChecksExceptAppliances -OutputFileName "$OutputDirName\$(ConvertTo-MaskedAuditName -HostName "$vm" -ForFileName).txt" -ErrorAction Stop
    }
    catch {
        Log-Message "Failed to audit VM '$vm': $_" -Level "ERROR"
    }
}

foreach ($esxi in $hosts) {
    try {
        Invoke-AuditEsxi8Tool -name $esxi -AcceptEULA -NoSafetyChecks -OutputFileName "$OutputDirName\$(ConvertTo-MaskedAuditName -HostName "$esxi" -ForFileName).txt" -ErrorAction Stop
    }
    catch {
        Log-Message "Failed to audit ESX host '$esxi': $_" -Level "ERROR"
    }
}

$name = $global:DefaultVIServers.Name
try {
    Invoke-AuditVcenter8Tool -Name $name -AcceptEULA -NoSafetyChecks -OutputFileName "$OutputDirName\$(ConvertTo-MaskedAuditName -HostName $name -ForFileName).txt" -ErrorAction Stop
}
catch {
    Log-Message "Failed to audit vCenter '$name': $_" -Level "ERROR"
}
}

function Invoke-AuditRunnerTool {
param(
    [string]$SharedVcAddress,
    [System.Management.Automation.PSCredential]$SharedCredential
)

function ConvertTo-MaskedAuditName {
    param([string]$HostName, [switch]$ForFileName)
    if ([string]::IsNullOrWhiteSpace($HostName)) { return $HostName }
    $mask = if ($ForFileName) { "xxx" } else { "***" }
    if ($HostName -match '^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$') {
        $octets = $HostName.Split('.')
        return "$mask.$mask.$mask.$($octets[3])"
    }
    if ($HostName -match '\.') {
        $shortName = $HostName.Split('.')[0]
        return "$shortName.$mask.$mask"
    }
    return $HostName
}

<#
    Script Name: vSphere Audit Orchestrator (Main Launcher)
    Description: 모듈 확인, 인증 관리, 감사 스크립트 실행을 통합 관리하는 스크립트
    Author: Gemini
#>

# ---------------------------------------------------------------------------
# 1. 모듈 설치 확인 및 설치
# ---------------------------------------------------------------------------
Write-Host "Checking required PowerShell modules..." -ForegroundColor Cyan

$requiredModules = @(
    @{ Name = "VCF.PowerCLI"; Version = "9.0.0" }
    @{ Name = "VMware.vSphere.SsoAdmin"; Version = "1.4.0" }
)

foreach ($mod in $requiredModules) {
    $installed = Get-Module -ListAvailable -Name $mod.Name | Where-Object { $_.Version -ge [version]$mod.Version }
    
    if (-not $installed) {
        Write-Host "Module '$($mod.Name)' is missing or outdated. Installing..." -ForegroundColor Yellow
        
        # PSGallery 신뢰 정책 설정 (필요 시)
        $repo = Get-PSRepository -Name PSGallery -ErrorAction SilentlyContinue
        if ($repo.InstallationPolicy -ne 'Trusted') {
            Set-PSRepository -Name PSGallery -InstallationPolicy Trusted -ErrorAction SilentlyContinue
        }

        try {
            # Scope AllUsers는 관리자 권한 필요
            Install-Module -Name $mod.Name -MinimumVersion $mod.Version -Scope AllUsers -Force -AllowClobber -ErrorAction Stop
            Write-Host "Successfully installed '$($mod.Name)'." -ForegroundColor Green
        }
        catch {
            Write-Host "Failed to install module '$($mod.Name)'. Ensure you are running as Administrator." -ForegroundColor Red
            Write-Host "Error details: $_" -ForegroundColor Red
            return
        }
    } else {
        Write-Host "Module '$($mod.Name)' is already installed." -ForegroundColor Green
    }
}

# ---------------------------------------------------------------------------
# 2. vCenter 연결 및 자격 증명 관리 (Credential Management)
# ---------------------------------------------------------------------------
$credFilePath = Join-Path $OutputRoot "security-hardening\cached_credential.xml"
if ($SharedVcAddress -and $SharedCredential) {
    $vcAddress = $SharedVcAddress
    $credential = $SharedCredential
    $useCached = $false
} else {
    $vcAddress = Read-Host "Enter vCenter Server IP or FQDN"

    $credential = $null
    $useCached = $false

    # A. Check for a saved credential
    if (Test-Path $credFilePath) {
        $response = Read-Host "Saved credential found. Do you want to use it? (Y/N)"
        if ($response -eq "Y" -or $response -eq "y") {
            try {
                $credential = Import-Clixml -Path $credFilePath
                $useCached = $true
            }
            catch {
                Write-Host "Failed to load saved credential. Proceeding to manual input." -ForegroundColor Yellow
            }
        }
    }

    # B. No credential yet, or a fresh one is required
    if ($null -eq $credential) {
        Write-Host "Please enter your vCenter credentials:" -ForegroundColor Cyan
        $credential = Get-Credential

        # Ask whether to save it
        $saveResponse = Read-Host "Do you want to save this credential for future use? (Y/N)"
        if ($saveResponse -eq "Y" -or $saveResponse -eq "y") {
            $credential | Export-Clixml -Path $credFilePath
            Write-Host "Credential saved to '$credFilePath'." -ForegroundColor Green
        }
    }
}

# C. 연결 시도 (connect.ps1 로직 통합)
Write-Host "Connecting to vCenter Server ($(ConvertTo-MaskedAuditName -HostName $vcAddress))..." -ForegroundColor Cyan

try {
    # 에러 메시지를 숨기기 위해 ErrorAction Stop 사용 후 catch 블록으로 이동
    Connect-VIServer -Server $vcAddress -Credential $credential -ErrorAction Stop | Out-Null
    Write-Host "Successfully connected to vCenter Server." -ForegroundColor Green
}
catch {
    Write-Host "==========================================" -ForegroundColor Red
    Write-Host "Connection Failed!" -ForegroundColor Red
    Write-Host "Please check your vCenter IP, Username, and Password." -ForegroundColor Red
    Write-Host "==========================================" -ForegroundColor Red
    # PowerShell 기본 에러 스택은 출력하지 않고 종료
    return
}

# 추가 서비스 연결 (CIS, SSO) - 실패해도 메인 감사는 진행 가능하므로 Warning 처리
try {
    Connect-CisServer -Server $vcAddress -Credential $credential -ErrorAction Stop | Out-Null
    Write-Host "Connected to CIS Server." -ForegroundColor Green
} catch { Write-Host "Warning: Failed to connect to CIS Server." -ForegroundColor Yellow }

try {
    Connect-SsoAdminServer -Server $vcAddress -Credential $credential -SkipCertificateCheck -ErrorAction Stop | Out-Null
    Write-Host "Connected to SSO Admin Server." -ForegroundColor Green
} catch { Write-Host "Warning: Failed to connect to SSO Admin Server." -ForegroundColor Yellow }


# ---------------------------------------------------------------------------
# 3. Audit 실행 (audit-all.ps1 호출)
# ---------------------------------------------------------------------------
$timestamp = Get-Date -Format "yyyyMMdd-HHmm"
$reportDir = Join-Path $OutputRoot "security-hardening\Audit_Report_$timestamp"

# 결과 폴더 생성
New-Item -ItemType Directory -Force -Path $reportDir | Out-Null

Write-Host "`nStarting Security Audit..." -ForegroundColor Cyan
Write-Host "Output Directory: $reportDir" -ForegroundColor Cyan

# Call audit-all (direct inlined-function call)
Invoke-AuditAllTool -OutputDirName $reportDir -AcceptEULA

Write-Host "`nAudit Completed. Check the report folder." -ForegroundColor Green

return $reportDir
}

function Invoke-AuditReporterTool {
param(
    [string]$TargetDirOverride
)

<#
    Script Name: vSphere Audit Reporter (Standalone)
    Description: Generates an HTML report (plus CSV, and Excel when possible) from existing
                 audit logs without running new audits or connecting to vCenter. Log type
                 (vCenter/ESXi/VM) is auto-detected from each log file's own banner text.
                 Excel export requires the ImportExcel PowerShell module; if it isn't
                 installed, Excel export is skipped automatically and HTML/CSV are still
                 produced.
                 If a VMware vSphere Security Configuration Guide "controls" CSV (the
                 official SCG spreadsheet, identified by its "SCG ID" / "Configuration
                 Parameter" columns) is placed next to this script, each PASS/FAIL/INFO
                 line is matched against it and enriched with SCG ID, priority, baseline
                 value, DISA STIG / PCI DSS 4.0 mapping and a remediation command - in the
                 CSV, Excel and HTML outputs. This is optional; if no such CSV is found,
                 everything else still runs exactly as before.
    Author: Gemini
#>

# ---------------------------------------------------------------------------
# 1. Select Audit Folder (Interactive)
# ---------------------------------------------------------------------------
function Select-Audit-Folder {
    Write-Host "`n[1/3] Select Audit Log Folder..." -ForegroundColor Cyan

    # Get subdirectories
    $subFolders = Get-ChildItem -Path (Join-Path $OutputRoot "security-hardening") -Directory -Filter "Audit_Report_*" | Sort-Object LastWriteTime -Descending

    if ($subFolders.Count -eq 0) {
        Write-Host "  ! No subfolders found in current directory." -ForegroundColor Red
        return
    }

    # List folders
    Write-Host "  Available Folders:" -ForegroundColor Yellow
    for ($i = 0; $i -lt $subFolders.Count; $i++) {
        Write-Host "    [$($i+1)] $($subFolders[$i].Name)  (Last Modified: $($subFolders[$i].LastWriteTime))"
    }

    # User Input
    while ($true) {
        $selection = Read-Host "  > Enter the number of the folder to process"
        if ($selection -match "^\d+$" -and [int]$selection -gt 0 -and [int]$selection -le $subFolders.Count) {
            $selectedFolder = $subFolders[[int]$selection - 1]
            Write-Host "  - Selected: $($selectedFolder.FullName)" -ForegroundColor Green
            return $selectedFolder.FullName
        } else {
            Write-Host "  ! Invalid selection. Please try again." -ForegroundColor Red
        }
    }
}

# ---------------------------------------------------------------------------
# 2. Discover & Classify Log Files (No vCenter connection required)
# ---------------------------------------------------------------------------
# Each audit log's first lines carry a banner identifying what kind of
# object it audited, e.g.:
#   "VMware vCenter ... Security Settings Audit Utility ..."       -> vCenter
#   "VMware ESX Host Security Settings Audit Utility ..."          -> ESXi
#   "VMware Virtual Machine Security Settings Audit Utility ..."   -> VM
# We read that banner directly instead of querying vCenter for inventory.
function Discover-LogFiles {
    param ($TargetDir)
    Write-Host "`n[2/3] Discovering and classifying log files..." -ForegroundColor Cyan

    $files = Get-ChildItem -Path $TargetDir -Filter "*.txt" -File | Sort-Object Name
    if ($files.Count -eq 0) {
        Write-Host "  ! No .txt log files found in the selected folder." -ForegroundColor Red
        return
    }

    $classified = @{ vCenter = @(); ESXi = @(); VM = @() }

    foreach ($file in $files) {
        # Only need the first few lines to find the banner / "Audit of X started" line
        $headLines = Get-Content -Path $file.FullName -TotalCount 5
        $headerText = $headLines -join " "

        $type = $null
        if ($headerText -match "VMware vCenter") { $type = "vCenter" }
        elseif ($headerText -match "ESX Host") { $type = "ESXi" }
        elseif ($headerText -match "Virtual Machine") { $type = "VM" }

        if (-not $type) {
            Write-Host "  ! Skipped (unrecognized audit type): $($file.Name)" -ForegroundColor Yellow
            continue
        }

        # Prefer the object name reported inside the log ("Audit of <name> started"),
        # fall back to the file name if that line isn't found.
        $objName = [System.IO.Path]::GetFileNameWithoutExtension($file.Name)
        $nameMatch = $headLines | Select-String -Pattern "Audit of (\S+) started"
        if ($nameMatch) {
            $objName = $nameMatch.Matches[0].Groups[1].Value
        }

        $classified[$type] += [PSCustomObject]@{ Name = $objName; Path = $file.FullName }
    }

    Write-Host "  - Classified: $($classified.vCenter.Count) vCenter, $($classified.ESXi.Count) ESXi, $($classified.VM.Count) VM log(s)." -ForegroundColor Gray
    return $classified
}

# ---------------------------------------------------------------------------
# 2.5 Load VMware Security Configuration Guide (SCG) controls (optional)
# ---------------------------------------------------------------------------
# If a copy of the official "vSphere Security Configuration Guide - controls" CSV is
# placed next to this script, we use it to enrich every PASS/FAIL/INFO line with the
# matching official control: SCG ID, implementation priority, baseline value, DISA STIG
# and PCI DSS 4.0 mapping, and a PowerCLI remediation command. Detected purely by content
# (the header row must contain both "SCG ID" and "Configuration Parameter") so the file
# can keep whatever name it was downloaded with. Entirely optional - if it's missing, the
# rest of the report still generates exactly as before.
function Import-ScgControls {
    Write-Host "`nLooking for a VMware Security Configuration Guide (SCG) controls CSV next to the script..." -ForegroundColor Cyan

    $candidates = Get-ChildItem -Path $PSScriptRoot -Filter "*.csv" -File -ErrorAction SilentlyContinue
    $scgFile = $candidates | Where-Object {
        try {
            $firstLine = Get-Content -Path $_.FullName -TotalCount 1 -ErrorAction Stop
            $firstLine -match "SCG ID" -and $firstLine -match "Configuration Parameter"
        } catch { $false }
    } | Select-Object -First 1

    if (-not $scgFile) {
        Write-Host "  - No SCG controls CSV found next to the script. Skipping SCG enrichment." -ForegroundColor Gray
        return $null
    }

    try {
        $rows = Import-Csv -Path $scgFile.FullName -Encoding UTF8

        $byParam = @{}
        $byId = @{}
        foreach ($row in $rows) {
            $id = $row.'SCG ID'
            if ($id) { $byId[$id] = $row }

            $param = $row.'Configuration Parameter'
            if ($param -and $param.Trim() -and $param.Trim() -ne 'N/A') {
                $key = $param.Trim().ToLower()
                if (-not $byParam.ContainsKey($key)) { $byParam[$key] = $row }
            }
        }

        Write-Host "  - Loaded SCG controls: $($scgFile.Name) ($($rows.Count) rows, $($byParam.Count) config-parameter keys)" -ForegroundColor Green
        return [PSCustomObject]@{ ByParam = $byParam; ById = $byId; FileName = $scgFile.Name; Count = $rows.Count }
    } catch {
        Write-Host "  ! Failed to read SCG controls CSV ($($scgFile.Name)): $($_.Exception.Message)" -ForegroundColor Yellow
        Write-Host "    Skipping SCG enrichment." -ForegroundColor Yellow
        return $null
    }
}

# Supplemental hand-built crosswalk: the audit tool's advanced-setting/config keys as they
# literally appear in the logs, mapped to the SCG ID of the control that covers them, for
# cases where the SCG's own "Configuration Parameter" column is "N/A" (sshd_config options,
# vSwitch/portgroup security policies, service enable/disable checks) or describes several
# settings in one combined prose field (vCenter SSO password/lockout policy). Verified by
# hand against the official controls CSV - see the review notes for how each was chosen.
$script:ScgCrosswalk = @{
    # SSO password / lockout policy (vCenter) - SCG describes these as combined prose
    # fields, not per-setting keys.
    'sso failedattemptintervalsec'         = 'vcenter-8.administration-sso-lockout-policy-max-attempts'
    'sso autounlockintervalsec'            = 'vcenter-8.administration-sso-lockout-policy-unlock-time'
    'sso maxfailedattempts'                = 'vcenter-8.administration-sso-lockout-policy-max-attempts'
    'sso maxidenticaladjacentcharacters'   = 'vcenter-8.administration-sso-password-policy'
    'sso minalphabeticcount'               = 'vcenter-8.administration-sso-password-policy'
    'sso minnumericcount'                  = 'vcenter-8.administration-sso-password-policy'
    'sso minuppercasecount'                = 'vcenter-8.administration-sso-password-policy'
    'sso minlowercasecount'                = 'vcenter-8.administration-sso-password-policy'
    'sso minspecialcharcount'              = 'vcenter-8.administration-sso-password-policy'
    'sso minlength'                        = 'vcenter-8.administration-sso-password-policy'
    'sso maxlength'                        = 'vcenter-8.administration-sso-password-policy'
    'sso passwordlifetimedays'             = 'vcenter-8.administration-sso-password-lifetime'
    'sso prohibitedpreviouspasswordscount' = 'vcenter-8.administration-sso-password-reuse'

    # SSH daemon settings (ESXi) - SCG lists these as "N/A" because they are sshd_config
    # options, not vSphere advanced settings.
    'ssh allowstreamlocalforwarding' = 'esxi-8.ssh-stream-local-forwarding'
    'ssh allowtcpforwarding'         = 'esxi-8.ssh-tcp-forwarding'
    'ssh hostbasedauthentication'    = 'esxi-8.ssh-host-based-auth'
    'ssh clientalivecountmax'        = 'esxi-8.ssh-idle-timeout-count'
    'ssh clientaliveinterval'        = 'esxi-8.ssh-idle-timeout-interval'
    'ssh banner'                     = 'esxi-8.ssh-login-banner'
    'ssh ignorerhosts'               = 'esxi-8.ssh-rhosts'
    'ssh gatewayports'               = 'esxi-8.ssh-gateway-ports'
    'ssh permittunnel'               = 'esxi-8.ssh-tunnels'
    'ssh permituserenvironment'      = 'esxi-8.ssh-user-environment'
    'ssh ciphers'                    = 'esxi-8.ssh-fips-ciphers'

    # Misc single-setting concepts, also "N/A" or differently-named in Configuration Parameter.
    'dvfilters'                           = 'vm-8.dvfilter'
    'diagnostic logging'                  = 'vm-8.log-enable'
    'passthrough hardware devices'        = 'vm-8.pci-passthrough'
    'active directory integration'        = 'esxi-8.ad-auth-proxy'
    'entropy sources'                     = 'esxi-8.entropy'
    'lockdown mode'                       = 'esxi-8.lockdown-mode'
    'lockdown mode exception users'       = 'esxi-8.lockdown-mode'
    'host image profile acceptance level' = 'esxi-8.vib-acceptance-level-supported'
}

# "TLS profile" is a distinct control for both ESXi and vCenter with identical wording, so
# it needs the object Type to disambiguate.
$script:ScgCrosswalkByType = @{
    'ESXi|tls profile'    = 'esxi-8.tls-profile'
    'vCenter|tls profile' = 'vcenter-8.tls-profile'
}

# ESXi service enable/disable checks ("<svc> is running (...)" / "is configured to start (...)").
$script:ScgServiceCrosswalk = @{
    'tsm'            = 'esxi-8.deactivate-shell'
    'tsm-ssh'        = 'esxi-8.deactivate-ssh'
    'sfcbd-watchdog' = 'esxi-8.deactivate-cim'
    'slpd'           = 'esxi-8.deactivate-slp'
    'snmpd'          = 'esxi-8.deactivate-snmp'
}

# Whole-message fixed phrases that don't follow the "<key> configured..." shape.
$script:ScgFixedPhraseCrosswalk = [ordered]@{
    'Local audit log location is persistent'           = 'esxi-8.logs-audit-persistent'
    'Local log location is persistent'                 = 'esxi-8.logs-persistent'
    'Log filtering is deactivated'                      = 'esxi-8.logs-filter'
    'DCUI user has shell access enabled'                = 'esxi-8.account-dcui'
    'Secure Boot TPM-based enforcement is not enabled'  = 'esxi-8.secureboot-enforcement'
    'Secure Boot is not enabled on the host'            = 'esxi-8.secureboot'
    'TPM configuration encryption is not enabled'       = 'esxi-8.tpm-configuration'
    'Key persistence is not enabled'                    = 'esxi-8.key-persistence'
    'SSH has FIPS mode enabled'                         = 'esxi-8.ssh-fips'
    'VM does not have Secure Boot configured'           = 'guest-8.secure-boot'
    'Encrypted vMotion defaults configured'             = 'vm-8.vmotion-encrypted'
    'Encrypted Fault Tolerance defaults configured'     = 'vm-8.ft-encrypted'
}

# Distributed vs. Standard portgroup/switch network-policy checks. SCG splits these into a
# separate ESXi (standard switch) control and a separate vCenter (distributed switch)
# control for the same policy, both listed as "N/A" in Configuration Parameter.
$script:ScgNetworkCrosswalk = @{
    'promiscuous|Standard'        = 'esxi-8.network-reject-promiscuous-mode-standardswitch'
    'promiscuous|Distributed'     = 'vcenter-8.network-reject-promiscuous-mode-dvportgroup'
    'forgedtransmits|Standard'    = 'esxi-8.network-reject-forged-transmit-standardswitch'
    'forgedtransmits|Distributed' = 'vcenter-8.network-reject-forged-transmit-dvportgroup'
    'macchanges|Standard'         = 'esxi-8.network-reject-mac-changes-standardswitch'
    'macchanges|Distributed'      = 'vcenter-8.network-reject-mac-changes-dvportgroup'
    'netflow|Distributed'         = 'vcenter-8.network-restrict-netflow-usage'
    'portmirroring|Distributed'   = 'vcenter-8.network-restrict-port-mirroring'
    'maclearning|Distributed'     = 'vcenter-8.network-mac-learning'
    'resetport|Distributed'       = 'vcenter-8.network-reset-port'
    'linkdiscovery|Distributed'   = 'vcenter-8.network-restrict-discovery-protocol'
}

# Matches one audit-log message against the loaded SCG data (direct Configuration Parameter
# lookup first, then the supplemental crosswalks above). Returns $null when nothing matches -
# most INFO/banner lines and a handful of check types with no SCG equivalent (VLAN defaults,
# VM hardware version, NTP) are expected to come back empty.
function Get-ScgMatch {
    param ($ScgData, [string]$Type, [string]$Message)

    if (-not $ScgData) { return $null }
    $row = $null

    # 1) Network policy concepts on Distributed/Standard portgroup or switch
    $lblMatch = [regex]::Match($Message, "(?<label>Distributed portgroup|Standard portgroup|Distributed switch|Standard switch) '(?<name>[^']*)'\s+(?<tail>.+)$")
    if ($lblMatch.Success) {
        $labelType = if ($lblMatch.Groups['label'].Value -like 'Distributed*') { 'Distributed' } else { 'Standard' }
        $tail = $lblMatch.Groups['tail'].Value

        $concept = $null
        if ($tail -match 'configured to allow promiscuous mode') { $concept = 'promiscuous' }
        elseif ($tail -match 'allow MAC address changes') { $concept = 'macchanges' }
        elseif ($tail -match 'allow forged transmits') { $concept = 'forgedtransmits' }
        elseif ($tail -match 'NetFlow') { $concept = 'netflow' }
        elseif ($tail -match 'port mirroring') { $concept = 'portmirroring' }
        elseif ($tail -match 'MAC learning') { $concept = 'maclearning' }
        elseif ($tail -match 'reset port configuration on disconnect') { $concept = 'resetport' }
        elseif ($tail -match 'link discovery') { $concept = 'linkdiscovery' }

        if ($concept) {
            $ck = "$concept|$labelType"
            if ($script:ScgNetworkCrosswalk.ContainsKey($ck)) {
                $scgId = $script:ScgNetworkCrosswalk[$ck]
                if ($ScgData.ById.ContainsKey($scgId)) { $row = $ScgData.ById[$scgId] }
            }
        }
    }

    # 2) Generic "<key> configured / not configured ..." pattern
    if (-not $row) {
        $m = [regex]::Match($Message, '([\w][\w.\- ]*?)\s+(?:is\s+)?(?:not configured correctly|configured incorrectly|configured correctly|not configured and is using secure defaults|not configured)\b')
        if ($m.Success) {
            $key = $m.Groups[1].Value.Trim().ToLower()
            $typeKey = "$Type|$key"
            if ($script:ScgCrosswalkByType.ContainsKey($typeKey)) {
                $scgId = $script:ScgCrosswalkByType[$typeKey]
                if ($ScgData.ById.ContainsKey($scgId)) { $row = $ScgData.ById[$scgId] }
            } elseif ($ScgData.ByParam.ContainsKey($key)) {
                $row = $ScgData.ByParam[$key]
            } elseif ($script:ScgCrosswalk.ContainsKey($key)) {
                $scgId = $script:ScgCrosswalk[$key]
                if ($ScgData.ById.ContainsKey($scgId)) { $row = $ScgData.ById[$scgId] }
            }
        }
    }

    # 3) ESXi service-state messages
    if (-not $row) {
        $m = [regex]::Match($Message, '([A-Za-z][\w-]*) is (?:not )?(?:running|configured to start)\s*\(')
        if ($m.Success) {
            $svc = $m.Groups[1].Value.Trim().ToLower()
            if ($script:ScgServiceCrosswalk.ContainsKey($svc)) {
                $scgId = $script:ScgServiceCrosswalk[$svc]
                if ($ScgData.ById.ContainsKey($scgId)) { $row = $ScgData.ById[$scgId] }
            }
        }
    }

    # 4) Fixed whole-message phrases
    if (-not $row) {
        foreach ($fk in $script:ScgFixedPhraseCrosswalk.Keys) {
            if ($Message.Contains($fk)) {
                $scgId = $script:ScgFixedPhraseCrosswalk[$fk]
                if ($ScgData.ById.ContainsKey($scgId)) { $row = $ScgData.ById[$scgId] }
                break
            }
        }
    }

    if (-not $row) { return $null }

    return [PSCustomObject]@{
        ScgId       = $row.'SCG ID'
        Priority    = ($row.'Implementation Priority' -replace "`r?`n", ' ')
        Title       = $row.'Description/Title'
        Baseline    = $row.'Baseline Suggested Value'
        Stig        = $row.'DISA STIG Mapping'
        Pci         = $row.'PCI DSS 4.0 Mapping'
        Remediation = ($row.'PowerCLI Command Remediation Example' -replace "`r?`n", ' ')
    }
}

# ---------------------------------------------------------------------------
# 3. Parse Logs
# ---------------------------------------------------------------------------
function Parse-Logs {
    param ($LogFiles, $ScgData)
    Write-Host "`n[3/3] Analyzing logs and creating report..." -ForegroundColor Cyan

    $results = @{
        Summary = @{ TotalPass = 0; TotalFail = 0; TotalInfo = 0 }
        Data = @{ vCenter = @(); ESXi = @(); VM = @() }
    }
    $scgMatchedCount = 0

    foreach ($type in $LogFiles.Keys) {
        foreach ($fileEntry in $LogFiles[$type]) {
            $objData = @{ Name = $fileEntry.Name; Type = $type; Pass = 0; Fail = 0; Info = 0; Details = @() }

            $content = Get-Content $fileEntry.Path
            foreach ($line in $content) {
                if ($line -match "\[(PASS|FAIL|INFO|WARNING|ERROR)\]") {
                    $match = $matches[1]
                    switch ($match) {
                        "PASS" { $objData.Pass++; $results.Summary.TotalPass++ }
                        "FAIL" { $objData.Fail++; $results.Summary.TotalFail++ }
                        "INFO"    { $objData.Info++; $results.Summary.TotalInfo++ }
                        "WARNING" { $objData.Info++; $results.Summary.TotalInfo++ }
                        "ERROR"   { $objData.Fail++; $results.Summary.TotalFail++ }
                    }

                    $cssClass = switch ($match) { "PASS"{"status-pass"} "FAIL"{"status-fail"} default{"status-info"} }
                    $message = ($line -replace "\[.*?\]\s*", "")
                    $detailEntry = @{ Status = $match; Message = $message; CssClass = $cssClass }

                    $scgMatch = Get-ScgMatch -ScgData $ScgData -Type $type -Message $message
                    if ($scgMatch) {
                        $scgMatchedCount++
                        $detailEntry.ScgId = $scgMatch.ScgId
                        $detailEntry.ScgPriority = $scgMatch.Priority
                        $detailEntry.ScgTitle = $scgMatch.Title
                        $detailEntry.ScgBaseline = $scgMatch.Baseline
                        $detailEntry.ScgStig = $scgMatch.Stig
                        $detailEntry.ScgPci = $scgMatch.Pci
                        $detailEntry.ScgRemediation = $scgMatch.Remediation
                    }

                    $objData.Details += $detailEntry
                }
            }
            $results.Data[$type] += $objData
        }
    }

    $results.ScgInfo = @{
        Loaded  = [bool]$ScgData
        FileName = if ($ScgData) { $ScgData.FileName } else { $null }
        ControlCount = if ($ScgData) { $ScgData.Count } else { 0 }
        MatchedCount = $scgMatchedCount
    }
    if ($ScgData) {
        Write-Host "  - SCG enrichment: matched $scgMatchedCount check(s) to an official control." -ForegroundColor Gray
    }

    return $results
}

# ---------------------------------------------------------------------------
# 4. Generate HTML
# ---------------------------------------------------------------------------
function Generate-Html {
    param ($Results, $FilePath)
    $jsonData = $Results | ConvertTo-Json -Depth 10 -Compress
    $date = Get-Date -Format "yyyy-MM-dd HH:mm:ss"

    $html = @"
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<title>vSphere Security Audit Report</title>
<style>
:root {
  --bg:#f1f5f9; --bg-alt:#e2e8f0; --card:#ffffff; --border:#e2e8f0;
  --text:#1e293b; --text-muted:#64748b;
  --pass:#16a34a; --pass-bg:#dcfce7;
  --fail:#dc2626; --fail-bg:#fee2e2;
  --info:#0891b2; --info-bg:#cffafe;
  --accent:#2563eb; --radius:10px;
  --shadow:0 1px 3px rgba(0,0,0,0.08), 0 1px 2px rgba(0,0,0,0.06);
}
* { box-sizing: border-box; }
body { margin:0; font-family:'Segoe UI',Roboto,-apple-system,sans-serif; background:var(--bg); color:var(--text); }
.container { max-width:1280px; margin:0 auto; padding:24px 20px 60px; }
.report-header { background:linear-gradient(135deg,#1e293b,#334155); color:#fff; padding:32px 28px; border-radius:var(--radius); margin-bottom:24px; box-shadow:var(--shadow); }
.report-header h1 { margin:0 0 8px; font-size:1.7em; }
.header-meta { color:#cbd5e1; font-size:0.9em; margin-top:4px; }

.dashboard { display:grid; grid-template-columns:repeat(5,1fr); gap:16px; margin-bottom:24px; }
.stat-card { background:var(--card); border-radius:var(--radius); box-shadow:var(--shadow); padding:18px 16px; text-align:center; border-top:4px solid var(--border); }
.stat-card.total{ border-top-color:#64748b; }
.stat-card.pass{ border-top-color:var(--pass); }
.stat-card.fail{ border-top-color:var(--fail); }
.stat-card.info{ border-top-color:var(--info); }
.stat-card.rate{ border-top-color:var(--accent); }
.stat-label { font-size:0.8em; color:var(--text-muted); text-transform:uppercase; letter-spacing:.05em; margin-bottom:6px; }
.stat-value { font-size:2em; font-weight:700; }
.stat-card.pass .stat-value{ color:var(--pass); }
.stat-card.fail .stat-value{ color:var(--fail); }
.stat-card.info .stat-value{ color:var(--info); }
.stat-card.rate .stat-value{ color:var(--accent); }

.toolbar{ display:flex; gap:12px; align-items:center; margin-bottom:20px; flex-wrap:wrap; }
#searchBox{ flex:1; min-width:220px; padding:10px 14px; border:1px solid var(--border); border-radius:8px; font-size:0.95em; }
.type-filters{ display:flex; gap:8px; flex-wrap:wrap; }
.filter-btn{ padding:8px 16px; border:1px solid var(--border); background:var(--card); border-radius:20px; cursor:pointer; font-size:0.85em; color:var(--text-muted); }
.filter-btn.active{ background:var(--accent); color:#fff; border-color:var(--accent); }

.section{ margin-bottom:28px; }
.section-header{ display:flex; align-items:center; justify-content:space-between; margin-bottom:12px; }
.section-title{ font-size:1.2em; font-weight:600; display:flex; align-items:center; gap:8px; }
.type-badge{ background:var(--accent); color:#fff; font-size:0.7em; padding:2px 10px; border-radius:12px; }

table{ width:100%; border-collapse:collapse; background:var(--card); border-radius:var(--radius); overflow:hidden; box-shadow:var(--shadow); }
thead th{ background:var(--bg-alt); padding:12px 14px; text-align:left; font-size:0.8em; text-transform:uppercase; letter-spacing:.03em; color:var(--text-muted); }
tbody td{ padding:12px 14px; border-top:1px solid var(--border); font-size:0.92em; vertical-align:middle; }
tr.obj-row{ cursor:pointer; }
tr.obj-row:hover{ background:#f8fafc; }
.obj-name{ font-weight:600; }
.count-pill{ display:inline-flex; align-items:center; justify-content:center; min-width:34px; padding:3px 8px; border-radius:6px; font-size:0.8em; font-weight:600; margin-right:4px; }
.count-pill.pass{ background:var(--pass-bg); color:var(--pass); }
.count-pill.fail{ background:var(--fail-bg); color:var(--fail); }
.count-pill.info{ background:var(--info-bg); color:var(--info); }
.bar{ width:100px; height:8px; border-radius:4px; overflow:hidden; display:flex; background:var(--border); }
.bar span{ height:100%; }
.b-pass{ background:var(--pass); }
.b-fail{ background:var(--fail); }
.b-info{ background:var(--info); }
.detail-btn{ border:1px solid var(--border); background:var(--card); color:var(--accent); font-weight:600; cursor:pointer; padding:6px 14px; border-radius:6px; font-size:0.85em; }
.detail-row{ display:none; }
.detail-row.open{ display:table-row; }
.detail-wrap{ background:#f8fafc; padding:16px; }
.tabs{ display:flex; gap:8px; margin-bottom:10px; border-bottom:1px solid var(--border); padding-bottom:10px; flex-wrap:wrap; }
.tab-btn{ padding:6px 14px; border-radius:6px; border:1px solid var(--border); background:#fff; cursor:pointer; font-size:0.85em; font-weight:600; color:var(--text-muted); }
.tab-btn.active[data-status="pass"]{ background:var(--pass); border-color:var(--pass); color:#fff; }
.tab-btn.active[data-status="fail"]{ background:var(--fail); border-color:var(--fail); color:#fff; }
.tab-btn.active[data-status="info"]{ background:var(--info); border-color:var(--info); color:#fff; }
.tab-panel{ display:none; max-height:360px; overflow-y:auto; }
.tab-panel.active{ display:block; }
.log-line{ display:flex; gap:10px; padding:7px 4px; border-bottom:1px dashed var(--border); font-family:Consolas,monospace; font-size:0.85em; align-items:flex-start; }
.log-line:last-child{ border-bottom:none; }
.badge{ flex-shrink:0; padding:2px 8px; border-radius:4px; color:#fff; font-size:0.75em; font-weight:700; width:44px; text-align:center; }
.badge.status-pass{ background:var(--pass); }
.badge.status-fail{ background:var(--fail); }
.badge.status-info{ background:var(--info); }
.log-msg{ flex:1; }
.scg-pill{ flex-shrink:0; margin-left:auto; background:#eef2ff; color:#4338ca; border:1px solid #c7d2fe; padding:2px 8px; border-radius:6px; font-size:0.72em; font-weight:700; font-family:'Segoe UI',Roboto,-apple-system,sans-serif; white-space:nowrap; cursor:help; }
.empty-panel{ color:var(--text-muted); font-size:0.85em; padding:12px 4px; }
.no-results{ text-align:center; color:var(--text-muted); padding:40px; }
@media (max-width:900px){ .dashboard{ grid-template-columns:repeat(2,1fr); } }
</style>
</head>
<body>
<div class="container">
  <header class="report-header">
    <h1>vSphere Security Hardening Audit Report</h1>
    <div class="header-meta">Generated: $date</div>
    <div class="header-meta" id="objCountMeta"></div>
    <div class="header-meta" id="scgMeta"></div>
  </header>

  <section class="dashboard">
    <div class="stat-card total"><div class="stat-label">Total Checks</div><div class="stat-value" id="t-total">0</div></div>
    <div class="stat-card pass"><div class="stat-label">PASS</div><div class="stat-value" id="t-pass">0</div></div>
    <div class="stat-card fail"><div class="stat-label">FAIL</div><div class="stat-value" id="t-fail">0</div></div>
    <div class="stat-card info"><div class="stat-label">INFO</div><div class="stat-value" id="t-info">0</div></div>
    <div class="stat-card rate"><div class="stat-label">Pass Rate</div><div class="stat-value" id="t-rate">0%</div></div>
  </section>

  <section class="toolbar">
    <input type="text" id="searchBox" placeholder="Search object name...">
    <div class="type-filters" id="typeFilters"></div>
  </section>

  <div id="content"></div>
</div>

<script>
var data = $jsonData;

var totalPass = data.Summary.TotalPass;
var totalFail = data.Summary.TotalFail;
var totalInfo = data.Summary.TotalInfo;
var totalAll = totalPass + totalFail + totalInfo;
var rate = (totalPass + totalFail) > 0 ? Math.round((totalPass / (totalPass + totalFail)) * 1000) / 10 : 0;

document.getElementById('t-total').textContent = totalAll;
document.getElementById('t-pass').textContent = totalPass;
document.getElementById('t-fail').textContent = totalFail;
document.getElementById('t-info').textContent = totalInfo;
document.getElementById('t-rate').textContent = rate + '%';

var typeOrder = ['vCenter', 'ESXi', 'VM'];
var availableTypes = typeOrder.filter(function (t) {
    return data.Data[t] && data.Data[t].length > 0;
});

var countsText = availableTypes.map(function (t) {
    return t + ': ' + data.Data[t].length;
}).join('   |   ');
document.getElementById('objCountMeta').textContent = 'Objects Audited: ' + countsText;

var scgInfo = data.ScgInfo || { Loaded: false };
var scgMetaEl = document.getElementById('scgMeta');
if (scgInfo.Loaded) {
    scgMetaEl.textContent = 'SCG Controls: ' + scgInfo.FileName + ' (' + scgInfo.ControlCount + ' controls) — ' +
        scgInfo.MatchedCount + ' check(s) matched to an official control';
} else {
    scgMetaEl.textContent = 'SCG Controls: not found next to the script (enrichment skipped)';
}

var currentFilter = 'All';
var currentSearch = '';
var idCounter = 0;

var filtersEl = document.getElementById('typeFilters');

function setFilter(type, btnEl) {
    currentFilter = type;
    var all = filtersEl.querySelectorAll('.filter-btn');
    for (var i = 0; i < all.length; i++) { all[i].classList.remove('active'); }
    btnEl.classList.add('active');
    render();
}

function buildFilters() {
    var allBtn = document.createElement('button');
    allBtn.className = 'filter-btn active';
    allBtn.textContent = 'All';
    allBtn.onclick = function () { setFilter('All', allBtn); };
    filtersEl.appendChild(allBtn);
    availableTypes.forEach(function (t) {
        var btn = document.createElement('button');
        btn.className = 'filter-btn';
        btn.textContent = t;
        btn.onclick = function () { setFilter(t, btn); };
        filtersEl.appendChild(btn);
    });
}

document.getElementById('searchBox').addEventListener('input', function (e) {
    currentSearch = e.target.value.trim().toLowerCase();
    render();
});

function statusLabel(cssClass) {
    if (cssClass === 'status-pass') return 'pass';
    if (cssClass === 'status-fail') return 'fail';
    return 'info';
}

function activateTab(uid, key) {
    var root = document.getElementById('detail-' + uid);
    var btns = root.querySelectorAll('.tab-btn');
    for (var i = 0; i < btns.length; i++) { btns[i].classList.remove('active'); }
    var panels = root.querySelectorAll('.tab-panel');
    for (var j = 0; j < panels.length; j++) { panels[j].classList.remove('active'); }
    var activeBtn = root.querySelector('[data-status="' + key + '"]');
    if (activeBtn) { activeBtn.classList.add('active'); }
    var activePanel = document.getElementById('panel-' + uid + '-' + key);
    if (activePanel) { activePanel.classList.add('active'); }
}

function toggleDetail(uid) {
    var row = document.getElementById('detail-' + uid);
    row.classList.toggle('open');
}

function buildDetailBlock(obj, uid) {
    var groups = { fail: [], pass: [], info: [] };
    obj.Details.forEach(function (d) {
        groups[statusLabel(d.CssClass)].push(d);
    });

    var tabsWrap = document.createElement('div');
    tabsWrap.className = 'tabs';
    var panelWrap = document.createElement('div');
    panelWrap.className = 'panels';

    var order = ['fail', 'pass', 'info'];
    var firstSet = false;
    order.forEach(function (key) {
        var items = groups[key];
        var btn = document.createElement('button');
        btn.className = 'tab-btn';
        btn.setAttribute('data-status', key);
        btn.textContent = key.toUpperCase() + ' (' + items.length + ')';
        btn.onclick = function () { activateTab(uid, key); };
        tabsWrap.appendChild(btn);

        var panel = document.createElement('div');
        panel.className = 'tab-panel';
        panel.id = 'panel-' + uid + '-' + key;

        if (items.length === 0) {
            var empty = document.createElement('div');
            empty.className = 'empty-panel';
            empty.textContent = 'No ' + key.toUpperCase() + ' items.';
            panel.appendChild(empty);
        } else {
            items.forEach(function (d) {
                var line = document.createElement('div');
                line.className = 'log-line';
                var badge = document.createElement('span');
                badge.className = 'badge ' + d.CssClass;
                badge.textContent = d.Status;
                var msg = document.createElement('span');
                msg.className = 'log-msg';
                msg.textContent = d.Message;
                line.appendChild(badge);
                line.appendChild(msg);
                if (d.ScgId) {
                    var pill = document.createElement('span');
                    pill.className = 'scg-pill';
                    pill.textContent = d.ScgId + (d.ScgPriority ? ' · ' + d.ScgPriority : '');
                    var tipParts = [];
                    if (d.ScgTitle) tipParts.push(d.ScgTitle);
                    if (d.ScgBaseline) tipParts.push('Baseline: ' + d.ScgBaseline);
                    if (d.ScgStig) tipParts.push('DISA STIG: ' + d.ScgStig);
                    if (d.ScgPci) tipParts.push('PCI DSS 4.0: ' + d.ScgPci);
                    if (d.ScgRemediation) tipParts.push('Remediation: ' + d.ScgRemediation);
                    pill.title = tipParts.join('\n');
                    line.appendChild(pill);
                }
                panel.appendChild(line);
            });
        }
        panelWrap.appendChild(panel);

        if (!firstSet && items.length > 0) {
            btn.classList.add('active');
            panel.classList.add('active');
            firstSet = true;
        }
    });

    if (!firstSet) {
        var firstBtn = tabsWrap.querySelector('.tab-btn');
        var firstPanel = panelWrap.querySelector('.tab-panel');
        if (firstBtn) { firstBtn.classList.add('active'); }
        if (firstPanel) { firstPanel.classList.add('active'); }
    }

    var container = document.createElement('div');
    container.className = 'detail-wrap';
    container.appendChild(tabsWrap);
    container.appendChild(panelWrap);
    return container;
}

function buildObjectRow(obj, type) {
    idCounter++;
    var uid = type + '-' + idCounter;
    var tr = document.createElement('tr');
    tr.className = 'obj-row';
    tr.onclick = function () { toggleDetail(uid); };

    var tdName = document.createElement('td');
    tdName.className = 'obj-name';
    tdName.textContent = obj.Name;

    var tdCounts = document.createElement('td');
    var pillPass = document.createElement('span');
    pillPass.className = 'count-pill pass';
    pillPass.textContent = 'PASS ' + obj.Pass;
    var pillFail = document.createElement('span');
    pillFail.className = 'count-pill fail';
    pillFail.textContent = 'FAIL ' + obj.Fail;
    var pillInfo = document.createElement('span');
    pillInfo.className = 'count-pill info';
    pillInfo.textContent = 'INFO ' + obj.Info;
    tdCounts.appendChild(pillPass);
    tdCounts.appendChild(pillFail);
    tdCounts.appendChild(pillInfo);

    var tdBar = document.createElement('td');
    var total = obj.Pass + obj.Fail + obj.Info;
    var bar = document.createElement('div');
    bar.className = 'bar';
    if (total > 0) {
        var segPass = document.createElement('span');
        segPass.className = 'b-pass';
        segPass.style.width = (obj.Pass / total * 100) + '%';
        var segFail = document.createElement('span');
        segFail.className = 'b-fail';
        segFail.style.width = (obj.Fail / total * 100) + '%';
        var segInfo = document.createElement('span');
        segInfo.className = 'b-info';
        segInfo.style.width = (obj.Info / total * 100) + '%';
        bar.appendChild(segPass);
        bar.appendChild(segFail);
        bar.appendChild(segInfo);
    }
    tdBar.appendChild(bar);

    var tdBtn = document.createElement('td');
    tdBtn.style.width = '90px';
    tdBtn.style.textAlign = 'right';
    var btn = document.createElement('button');
    btn.className = 'detail-btn';
    btn.textContent = 'Details';
    btn.onclick = function (e) { e.stopPropagation(); toggleDetail(uid); };
    tdBtn.appendChild(btn);

    tr.appendChild(tdName);
    tr.appendChild(tdCounts);
    tr.appendChild(tdBar);
    tr.appendChild(tdBtn);

    var detailTr = document.createElement('tr');
    detailTr.className = 'detail-row';
    detailTr.id = 'detail-' + uid;
    var detailTd = document.createElement('td');
    detailTd.colSpan = 4;
    detailTd.appendChild(buildDetailBlock(obj, uid));
    detailTr.appendChild(detailTd);

    return [tr, detailTr];
}

function render() {
    idCounter = 0;
    var content = document.getElementById('content');
    content.innerHTML = '';
    var anyRendered = false;

    var typesToRender = currentFilter === 'All' ? availableTypes : [currentFilter];

    typesToRender.forEach(function (type) {
        var objs = (data.Data[type] || []).filter(function (o) {
            return !currentSearch || o.Name.toLowerCase().indexOf(currentSearch) !== -1;
        });
        if (objs.length === 0) { return; }
        anyRendered = true;

        var section = document.createElement('div');
        section.className = 'section';

        var header = document.createElement('div');
        header.className = 'section-header';
        var title = document.createElement('div');
        title.className = 'section-title';
        var titleText = document.createElement('span');
        titleText.textContent = type + ' Objects';
        var badge = document.createElement('span');
        badge.className = 'type-badge';
        badge.textContent = objs.length;
        title.appendChild(titleText);
        title.appendChild(badge);
        header.appendChild(title);
        section.appendChild(header);

        var table = document.createElement('table');
        var thead = document.createElement('thead');
        var headRow = document.createElement('tr');
        ['Object', 'Status', 'Distribution', ''].forEach(function (h) {
            var th = document.createElement('th');
            th.textContent = h;
            headRow.appendChild(th);
        });
        thead.appendChild(headRow);
        table.appendChild(thead);

        var tbody = document.createElement('tbody');
        objs.forEach(function (obj) {
            var rows = buildObjectRow(obj, type);
            tbody.appendChild(rows[0]);
            tbody.appendChild(rows[1]);
        });
        table.appendChild(tbody);
        section.appendChild(table);

        content.appendChild(section);
    });

    if (!anyRendered) {
        var empty = document.createElement('div');
        empty.className = 'no-results';
        empty.textContent = 'No objects match the current filter/search.';
        content.appendChild(empty);
    }
}

buildFilters();
render();
</script>
</body>
</html>
"@
    $html | Out-File -FilePath $FilePath -Encoding UTF8
    Write-Host "  - HTML Report generated: $FilePath" -ForegroundColor Green
}

# ---------------------------------------------------------------------------
# 5. Generate CSV (Summary + Details)
# ---------------------------------------------------------------------------
function Generate-Csv {
    param ($Results, $OutputDir)
    Write-Host "`nGenerating CSV report..." -ForegroundColor Cyan

    $scgLoaded = [bool]($Results.ScgInfo -and $Results.ScgInfo.Loaded)
    $typeOrder = @('vCenter', 'ESXi', 'VM')
    $summaryRows = @()
    $detailRows = @()

    foreach ($type in $typeOrder) {
        if (-not $Results.Data.ContainsKey($type)) { continue }

        foreach ($obj in $Results.Data[$type]) {
            $total = $obj.Pass + $obj.Fail + $obj.Info
            $passRate = if (($obj.Pass + $obj.Fail) -gt 0) {
                [math]::Round(($obj.Pass / ($obj.Pass + $obj.Fail)) * 100, 1)
            } else { 0 }

            $summaryRows += [PSCustomObject]@{
                Type     = $type
                Object   = $obj.Name
                Pass     = $obj.Pass
                Fail     = $obj.Fail
                Info     = $obj.Info
                Total    = $total
                PassRate = "$passRate%"
            }

            foreach ($d in $obj.Details) {
                $row = [ordered]@{
                    Type    = $type
                    Object  = $obj.Name
                    Status  = $d.Status
                    Message = $d.Message
                }
                if ($scgLoaded) {
                    $row['SCG ID']      = $d.ScgId
                    $row['Priority']    = $d.ScgPriority
                    $row['SCG Title']   = $d.ScgTitle
                    $row['Baseline']    = $d.ScgBaseline
                    $row['DISA STIG']   = $d.ScgStig
                    $row['PCI DSS 4.0'] = $d.ScgPci
                    $row['Remediation'] = $d.ScgRemediation
                }
                $detailRows += [PSCustomObject]$row
            }
        }
    }

    $summaryPath = Join-Path $OutputDir "audit_report_summary.csv"
    $detailPath  = Join-Path $OutputDir "audit_report_details.csv"

    $summaryRows | Export-Csv -Path $summaryPath -NoTypeInformation -Encoding UTF8
    $detailRows  | Export-Csv -Path $detailPath -NoTypeInformation -Encoding UTF8

    Write-Host "  - CSV summary generated: $summaryPath" -ForegroundColor Green
    Write-Host "  - CSV details generated: $detailPath" -ForegroundColor Green

    return [PSCustomObject]@{ Summary = $summaryRows; Details = $detailRows }
}

# ---------------------------------------------------------------------------
# 6. Generate Excel (optional - requires the ImportExcel module)
# ---------------------------------------------------------------------------
function Generate-Excel {
    param ($SummaryRows, $DetailRows, $OutputDir)
    Write-Host "`nGenerating Excel report..." -ForegroundColor Cyan

    if (-not (Get-Module -ListAvailable -Name ImportExcel)) {
        Write-Host "  ! ImportExcel module not found. Skipping Excel export." -ForegroundColor Yellow
        Write-Host "    (Install it with: Install-Module ImportExcel -Scope CurrentUser)" -ForegroundColor Yellow
        return
    }

    try {
        Import-Module ImportExcel -ErrorAction Stop

        $excelPath = Join-Path $OutputDir "audit_report.xlsx"
        if (Test-Path $excelPath) { Remove-Item $excelPath -Force }

        $SummaryRows | Export-Excel -Path $excelPath -WorksheetName "Summary" -TableName "Summary" -AutoSize -FreezeTopRow -BoldTopRow
        $DetailRows  | Export-Excel -Path $excelPath -WorksheetName "Details" -TableName "Details" -AutoSize -FreezeTopRow -BoldTopRow -AutoFilter

        Write-Host "  - Excel report generated: $excelPath" -ForegroundColor Green
    } catch {
        Write-Host "  ! Failed to generate Excel report: $($_.Exception.Message)" -ForegroundColor Yellow
        Write-Host "    Skipping Excel export." -ForegroundColor Yellow
    }
}

# ---------------------------------------------------------------------------
# MAIN EXECUTION
# ---------------------------------------------------------------------------
Write-Host "vSphere Audit Reporter (Standalone - no vCenter connection required)" -ForegroundColor Cyan

# Select Folder
$targetDir = if ($TargetDirOverride) { $TargetDirOverride } else { Select-Audit-Folder }

# Discover and classify the log files directly from their content
$logFiles = Discover-LogFiles -TargetDir $targetDir

# Load the SCG controls CSV if one is sitting next to the script (optional)
$scgData = Import-ScgControls

# Process
$data = Parse-Logs -LogFiles $logFiles -ScgData $scgData

# Create an output folder next to this script (not inside the log folder)
$reportFolderName = "Output_" + (Get-Date -Format "yyyyMMdd_HHmmss")
$outputDir = Join-Path (Join-Path $OutputRoot "security-hardening") $reportFolderName
New-Item -ItemType Directory -Path $outputDir -Force | Out-Null
Write-Host "  - Output folder created: $outputDir" -ForegroundColor Gray

# Save HTML
$htmlPath = Join-Path $outputDir "audit_report.html"
Generate-Html -Results $data -FilePath $htmlPath

# Save CSV (summary + details)
$csvExport = Generate-Csv -Results $data -OutputDir $outputDir

# Save Excel (skipped automatically if the ImportExcel module isn't installed)
Generate-Excel -SummaryRows $csvExport.Summary -DetailRows $csvExport.Details -OutputDir $outputDir

Write-Host "`n★ Reporting Completed!" -ForegroundColor Green
Invoke-Item $outputDir
}

function Invoke-SecurityHardeningAuditAndReport {
param(
    [string]$SharedVcAddress,
    [System.Management.Automation.PSCredential]$SharedCredential
)

$reportDir = Invoke-AuditRunnerTool -SharedVcAddress $SharedVcAddress -SharedCredential $SharedCredential

if ($reportDir -and (Test-Path -LiteralPath $reportDir)) {
    Write-Host ""
    Write-Host "[AUTO] Continuing automatically into report generation for '$reportDir'..." -ForegroundColor Cyan
    Invoke-AuditReporterTool -TargetDirOverride $reportDir
}
else {
    Write-Host "[ERROR] The audit run did not produce a usable report folder; skipping automatic report generation." -ForegroundColor Red
}
}

function Invoke-VCenterDailyReportTool {
[CmdletBinding()]
param(
    [Parameter(Mandatory = $false)]
    [string[]]$VCenterServer,

    [Parameter(Mandatory = $false)]
    [System.Management.Automation.PSCredential]$VCenterCredential,

    [Parameter(Mandatory = $false)]
    [int]$DaysBack = 1,

    [Parameter(Mandatory = $false)]
    [int]$SnapshotAgeDays = 7,

    [Parameter(Mandatory = $false)]
    [string]$OutputFolder = (Join-Path $OutputRoot "vcenter\DailyReport_$(Get-Date -Format 'yyyyMMdd_HHmm')")
)


$ErrorActionPreference = "Stop"

# ---------------------------------------------------------------------------
# 0. Config: thresholds
# ---------------------------------------------------------------------------
$Script:Threshold = @{
    CpuUsageWarnPct   = 70
    CpuUsageCritPct   = 90
    CpuReadyWarnPct   = 5
    CpuReadyCritPct   = 10
    MemUsageWarnPct   = 70
    MemUsageCritPct   = 90
    DiskLatencyWarnMs = 5
    DiskLatencyCritMs = 10
}

$Script:ReadyIntervalSeconds = 20   # adjust to match your environment's historical rollup interval

# ---------------------------------------------------------------------------
# [Shared] Safe CSV export helper
# ---------------------------------------------------------------------------
function Export-CsvSafe {
    param($Data, [string]$Path)
    # PowerShell unrolls a zero-item collection to $null when captured by a variable,
    # so Export-Csv can receive $null and throw "InputObject...null" even though the
    # underlying source was just an empty result set (no issues found, no VMs, etc.).
    # Note: @($null) has Count = 1 (one null element), NOT 0 - so nulls must be
    # filtered out before checking for emptiness, or a single-null array still
    # reaches Export-Csv and throws.
    $arr = @($Data | Where-Object { $null -ne $_ })
    if ($arr.Count -eq 0) {
        Write-Warning "No data for '$Path' - skipping CSV export (empty result set)."
        return
    }
    $arr | Export-Csv -Path $Path -NoTypeInformation -Encoding UTF8
}

# ---------------------------------------------------------------------------
# [Mode 2] Helpers
# ---------------------------------------------------------------------------
function ConvertTo-Pct {
    param([double]$ReadySummationMs, [int]$IntervalSeconds = $Script:ReadyIntervalSeconds)
    if (-not $ReadySummationMs) { return 0 }
    return [math]::Round(($ReadySummationMs / ($IntervalSeconds * 1000)) * 100, 2)
}

function Get-AvgStat {
    param($StatResults, $EntityId, [string]$MetricId)
    $vals = $StatResults | Where-Object { $_.Entity.Id -eq $EntityId -and $_.MetricId -eq $MetricId } | Select-Object -ExpandProperty Value
    if (-not $vals) { return $null }
    return [math]::Round((($vals | Measure-Object -Average).Average), 2)
}

# ---------------------------------------------------------------------------
# [Mode 2] 1. Inventory summary
# ---------------------------------------------------------------------------
function Get-InventorySummaryReport {
    param($Datacenters, $Clusters, $VMHosts, $VMs)

    $poweredOn  = @($VMs | Where-Object { $_.PowerState -eq "PoweredOn" })
    $poweredOff = @($VMs | Where-Object { $_.PowerState -eq "PoweredOff" })

    $totalCores = ($VMHosts | ForEach-Object { $_.ExtensionData.Hardware.CpuInfo.NumCpuCores } | Measure-Object -Sum).Sum
    $totalMemGB = [math]::Round((($VMHosts | Measure-Object -Property MemoryTotalGB -Sum).Sum), 1)

    $overall = [PSCustomObject]@{
        DatacenterCount = $Datacenters.Count
        ClusterCount    = $Clusters.Count
        HostCount       = $VMHosts.Count
        VmPoweredOn     = $poweredOn.Count
        VmPoweredOff    = $poweredOff.Count
        TotalCores      = $totalCores
        TotalMemoryGB   = $totalMemGB
    }

    $perCluster = foreach ($cl in $Clusters) {
        $hostsInCluster = @($VMHosts | Where-Object { $_.Parent.Id -eq $cl.Id })
        [PSCustomObject]@{
            ClusterName = $cl.Name
            HostCount   = $hostsInCluster.Count
            TotalCores  = ($hostsInCluster | ForEach-Object { $_.ExtensionData.Hardware.CpuInfo.NumCpuCores } | Measure-Object -Sum).Sum
            TotalMemGB  = [math]::Round((($hostsInCluster | Measure-Object -Property MemoryTotalGB -Sum).Sum), 1)
        }
    }

    return @{ Overall = $overall; PerCluster = @($perCluster) }
}

# ---------------------------------------------------------------------------
# [Mode 2] 2. Performance summary (overall + per cluster + Top3 hosts)
# ---------------------------------------------------------------------------
function Get-PerformanceSummaryReport {
    param($Clusters, $VMHosts, $StartTime, $FinishTime)

    Write-Host "[Perf] Querying host CPU/Mem/ready stats ($StartTime to $FinishTime, 1 batch call)..."
    $hostStats = Get-Stat -Entity $VMHosts -Stat @("cpu.usage.average","cpu.usagemhz.average","mem.usage.average","mem.consumed.average","cpu.ready.summation") `
        -Start $StartTime -Finish $FinishTime -ErrorAction SilentlyContinue

    $hostRows = foreach ($h in $VMHosts) {
        $capacityGHz = [math]::Round((($h.ExtensionData.Hardware.CpuInfo.NumCpuCores * $h.ExtensionData.Hardware.CpuInfo.Hz) / 1e9), 2)
        # cpu.latency.average is often empty/unpopulated in many environments, so host-level
        # CPU contention is derived from cpu.ready.summation instead (same approach as the
        # VM-level CPU Ready % calculation) - this is the aggregate ready time across all
        # VMs on the host, converted to a percentage.
        $hostReadySum = ($hostStats | Where-Object { $_.Entity.Id -eq $h.Id -and $_.MetricId -eq "cpu.ready.summation" } | Select-Object -ExpandProperty Value | Measure-Object -Average).Average
        [PSCustomObject]@{
            HostName       = (ConvertTo-MaskedHostName -HostName $h.Name)
            ClusterName    = $h.Parent.Name
            CpuUsagePct    = Get-AvgStat -StatResults $hostStats -EntityId $h.Id -MetricId "cpu.usage.average"
            CpuUsageGHz    = [math]::Round(((Get-AvgStat -StatResults $hostStats -EntityId $h.Id -MetricId "cpu.usagemhz.average")) / 1000, 2)
            CpuCapacityGHz = $capacityGHz
            MemUsagePct    = Get-AvgStat -StatResults $hostStats -EntityId $h.Id -MetricId "mem.usage.average"
            MemUsageGB     = [math]::Round(((Get-AvgStat -StatResults $hostStats -EntityId $h.Id -MetricId "mem.consumed.average")) / 1MB, 2)
            CpuContentionPct = ConvertTo-Pct -ReadySummationMs $hostReadySum
        }
    }
    $hostRows = @($hostRows)

    $overallAvgCpuPct = [math]::Round((($hostRows.CpuUsagePct | Measure-Object -Average).Average), 2)
    $overallAvgMemPct = [math]::Round((($hostRows.MemUsagePct | Measure-Object -Average).Average), 2)

    $perCluster = foreach ($cl in $Clusters) {
        $rowsInCluster = @($hostRows | Where-Object { $_.ClusterName -eq $cl.Name })
        $usedGHz = [math]::Round((($rowsInCluster.CpuUsageGHz | Measure-Object -Sum).Sum), 2)
        $capGHz  = [math]::Round((($rowsInCluster.CpuCapacityGHz | Measure-Object -Sum).Sum), 2)
        $usedMemGB = [math]::Round((($rowsInCluster.MemUsageGB | Measure-Object -Sum).Sum), 2)
        $capMemGB  = [math]::Round((($VMHosts | Where-Object { $_.Parent.Name -eq $cl.Name } | Measure-Object -Property MemoryTotalGB -Sum).Sum), 2)

        [PSCustomObject]@{
            ClusterName     = $cl.Name
            CpuUsageGHz     = $usedGHz
            CpuCapacityGHz  = $capGHz
            CpuUsagePct     = if ($capGHz -gt 0) { [math]::Round(($usedGHz / $capGHz) * 100, 1) } else { $null }
            MemUsageGB      = $usedMemGB
            MemCapacityGB   = $capMemGB
            MemUsagePct     = if ($capMemGB -gt 0) { [math]::Round(($usedMemGB / $capMemGB) * 100, 1) } else { $null }
        }
    }

    $top3CpuHosts    = $hostRows | Sort-Object CpuUsagePct -Descending | Select-Object -First 3
    $top3MemHosts    = $hostRows | Sort-Object MemUsagePct -Descending | Select-Object -First 3
    $top3ReadyHosts  = $hostRows | Sort-Object CpuContentionPct -Descending | Select-Object -First 3

    return @{
        OverallAvgCpuPct = $overallAvgCpuPct
        OverallAvgMemPct = $overallAvgMemPct
        PerCluster       = @($perCluster)
        HostRows         = $hostRows
        Top3CpuHosts     = @($top3CpuHosts)
        Top3MemHosts     = @($top3MemHosts)
        Top3ReadyHosts   = @($top3ReadyHosts)
    }
}

# ---------------------------------------------------------------------------
# [Mode 2] 3. Storage summary (shared datastores)
# ---------------------------------------------------------------------------
function Get-StorageSummaryReport {
    param($Datastores)

    $sharedDs = @($Datastores | Where-Object { $_.ExtensionData.Host.Count -gt 1 })

    $rows = foreach ($ds in $sharedDs) {
        [PSCustomObject]@{
            DatastoreName = $ds.Name
            CapacityGB    = [math]::Round($ds.CapacityGB, 1)
            UsedGB        = [math]::Round(($ds.CapacityGB - $ds.FreeSpaceGB), 1)
            FreeGB        = [math]::Round($ds.FreeSpaceGB, 1)
        }
    }

    return @($rows)
}

# ---------------------------------------------------------------------------
# [Mode 2] 4. VM performance Top5 lists
# ---------------------------------------------------------------------------
function Get-VmPerformanceTopLists {
    param($VMs, $StartTime, $FinishTime)

    Write-Host "[VM Perf] Querying VM CPU/Mem stats (historical, 1 batch call)..."
    $vmStats = Get-Stat -Entity $VMs -Stat @("cpu.usage.average","cpu.ready.summation","mem.usage.average") `
        -Start $StartTime -Finish $FinishTime -ErrorAction SilentlyContinue

    # virtualDisk.* latency counters are realtime-only under the default statistics
    # collection level - a historical (-Start/-Finish) query silently returns nothing
    # for them. They also report per virtual disk instance (e.g. "scsi0:0"), not a
    # single per-VM value, so a VM with multiple disks yields multiple rows per metric.
    $poweredOnVMs = @($VMs | Where-Object { $_.PowerState -eq "PoweredOn" })
    Write-Host "[VM Perf] Querying VM virtual disk latency (realtime, 1 batch call, $($poweredOnVMs.Count) powered-on VMs - latency has no data for powered-off VMs)..."
    $vmDiskStatsRt = if ($poweredOnVMs.Count -gt 0) {
        Get-Stat -Entity $poweredOnVMs -Stat @("virtualDisk.totalReadLatency.average","virtualDisk.totalWriteLatency.average") `
            -Realtime -MaxSamples 1 -ErrorAction SilentlyContinue
    } else { @() }

    $vmRows = foreach ($vm in $VMs) {
        $readySum = ($vmStats | Where-Object { $_.Entity.Id -eq $vm.Id -and $_.MetricId -eq "cpu.ready.summation" } | Select-Object -ExpandProperty Value | Measure-Object -Average).Average

        # Multiple values here = multiple virtual disks on this VM (per-instance metric).
        # Take the worst-case (max) latency across the VM's disks as its representative value.
        $readLatVals  = @($vmDiskStatsRt | Where-Object { $_.Entity.Id -eq $vm.Id -and $_.MetricId -eq "virtualDisk.totalReadLatency.average" } | Select-Object -ExpandProperty Value)
        $writeLatVals = @($vmDiskStatsRt | Where-Object { $_.Entity.Id -eq $vm.Id -and $_.MetricId -eq "virtualDisk.totalWriteLatency.average" } | Select-Object -ExpandProperty Value)
        $maxReadLat  = if ($readLatVals.Count  -gt 0) { [math]::Round((($readLatVals  | Measure-Object -Maximum).Maximum), 2) } else { $null }
        $maxWriteLat = if ($writeLatVals.Count -gt 0) { [math]::Round((($writeLatVals | Measure-Object -Maximum).Maximum), 2) } else { $null }

        [PSCustomObject]@{
            ClusterName    = $vm.VMHost.Parent.Name
            HostName       = (ConvertTo-MaskedHostName -HostName $vm.VMHost.Name)
            VmName         = $vm.Name
            NumCpu         = $vm.NumCpu
            MemoryGB       = $vm.MemoryGB
            CpuUsagePct    = Get-AvgStat -StatResults $vmStats -EntityId $vm.Id -MetricId "cpu.usage.average"
            CpuReadyPct    = ConvertTo-Pct -ReadySummationMs $readySum
            MemUsagePct    = Get-AvgStat -StatResults $vmStats -EntityId $vm.Id -MetricId "mem.usage.average"
            ReadLatencyMs  = $maxReadLat
            WriteLatencyMs = $maxWriteLat
            Datastore      = ($vm | Get-Datastore | Select-Object -First 1 -ExpandProperty Name)
        }
    }
    $vmRows = @($vmRows)

    return @{
        AllRows        = $vmRows
        Top5CpuUsage   = @($vmRows | Sort-Object CpuUsagePct -Descending | Select-Object -First 5 ClusterName,HostName,VmName,NumCpu,CpuUsagePct)
        Top5CpuReady   = @($vmRows | Sort-Object CpuReadyPct -Descending | Select-Object -First 5 ClusterName,HostName,VmName,NumCpu,CpuReadyPct)
        Top5MemUsage   = @($vmRows | Sort-Object MemUsagePct -Descending | Select-Object -First 5 ClusterName,HostName,VmName,MemoryGB,MemUsagePct)
        Top5WriteLatency = @($vmRows | Sort-Object WriteLatencyMs -Descending | Select-Object -First 5 ClusterName,HostName,VmName,Datastore,WriteLatencyMs)
        Top5ReadLatency  = @($vmRows | Sort-Object ReadLatencyMs -Descending | Select-Object -First 5 ClusterName,HostName,VmName,Datastore,ReadLatencyMs)
    }
}

# ---------------------------------------------------------------------------
# [Mode 2] 5. Snapshots older than N days
# ---------------------------------------------------------------------------
function Get-OldSnapshotReport {
    param($VMs, [int]$AgeDays)

    $cutoff = (Get-Date).AddDays(-$AgeDays)
    $rows = foreach ($vm in $VMs) {
        $snaps = @(Get-Snapshot -VM $vm -ErrorAction SilentlyContinue | Where-Object { $_.Created -lt $cutoff })
        if ($snaps.Count -eq 0) { continue }
        [PSCustomObject]@{
            ClusterName    = $vm.VMHost.Parent.Name
            HostName       = (ConvertTo-MaskedHostName -HostName $vm.VMHost.Name)
            VmName         = $vm.Name
            SnapshotCount  = $snaps.Count
            OldestAgeDays  = [math]::Round(((Get-Date) - ($snaps | Sort-Object Created | Select-Object -First 1).Created).TotalDays, 1)
            TotalSizeGB    = [math]::Round((($snaps | Measure-Object -Property SizeGB -Sum).Sum), 2)
        }
    }
    return @($rows)
}

# ---------------------------------------------------------------------------
# [Mode 2] 6. VMs with a connected virtual device (e.g. mounted ISO)
# ---------------------------------------------------------------------------
function Get-ConnectedDeviceReport {
    param($VMs)

    $rows = foreach ($vm in $VMs) {
        $cd = @(Get-CDDrive -VM $vm -ErrorAction SilentlyContinue | Where-Object { $_.ConnectionState.Connected })
        foreach ($drive in $cd) {
            [PSCustomObject]@{
                ClusterName = $vm.VMHost.Parent.Name
                HostName    = (ConvertTo-MaskedHostName -HostName $vm.VMHost.Name)
                VmName      = $vm.Name
                DeviceType  = "CD/DVD"
                MediaPath   = $drive.IsoPath
            }
        }
    }
    return @($rows)
}

# ---------------------------------------------------------------------------
# [Mode 2] 7. Full VM inventory (one row per virtual disk)
# ---------------------------------------------------------------------------
function Get-VmInventoryReport {
    param($VMs)

    $rows = foreach ($vm in $VMs) {
        $disks = @(Get-HardDisk -VM $vm -ErrorAction SilentlyContinue)
        $coresPerSocket = $vm.ExtensionData.Config.Hardware.NumCoresPerSocket
        $sockets = if ($coresPerSocket -gt 0) { $vm.NumCpu / $coresPerSocket } else { $vm.NumCpu }

        if ($disks.Count -eq 0) {
            [PSCustomObject]@{
                VmName        = $vm.Name
                HostName      = (ConvertTo-MaskedHostName -HostName $vm.VMHost.Name)
                ClusterName   = $vm.VMHost.Parent.Name
                NumCpu        = $vm.NumCpu
                CpuTopology   = "$sockets socket(s) x $coresPerSocket core(s)"
                MemoryGB      = $vm.MemoryGB
                DiskLabel     = $null
                DiskCapacityGB= $null
                DiskFormat    = $null
                Datastore     = $null
            }
        } else {
            foreach ($d in $disks) {
                [PSCustomObject]@{
                    VmName        = $vm.Name
                    HostName      = (ConvertTo-MaskedHostName -HostName $vm.VMHost.Name)
                    ClusterName   = $vm.VMHost.Parent.Name
                    NumCpu        = $vm.NumCpu
                    CpuTopology   = "$sockets socket(s) x $coresPerSocket core(s)"
                    MemoryGB      = $vm.MemoryGB
                    DiskLabel     = $d.Name
                    DiskCapacityGB= [math]::Round($d.CapacityGB, 1)
                    DiskFormat    = $d.StorageFormat
                    Datastore     = ($d.FileName -split "\]")[0].TrimStart("[")
                }
            }
        }
    }
    return @($rows)
}

# ---------------------------------------------------------------------------
# [Mode 2] 8. VM distribution
# ---------------------------------------------------------------------------
function Get-VmDistributionReport {
    param($VMs)

    $total = [math]::Max($VMs.Count, 1)

    $byGuestOs = $VMs | Group-Object { $_.Guest.OSFullName } | ForEach-Object {
        [PSCustomObject]@{ GuestOS = if ($_.Name) { $_.Name } else { "Unknown" }; Count = $_.Count; Pct = [math]::Round(($_.Count / $total) * 100, 1) }
    }

    $byTools = $VMs | Group-Object { "$($_.Guest.ToolsStatus) / $($_.Guest.ToolsVersion)" } | ForEach-Object {
        [PSCustomObject]@{ ToolsStatusVersion = $_.Name; Count = $_.Count; Pct = [math]::Round(($_.Count / $total) * 100, 1) }
    }

    $byHwVersion = $VMs | Group-Object Version | ForEach-Object {
        [PSCustomObject]@{ HardwareVersion = $_.Name; Count = $_.Count; Pct = [math]::Round(($_.Count / $total) * 100, 1) }
    }

    $byVCpuBucket = $VMs | Group-Object { [math]::Ceiling($_.NumCpu / 4) } | Sort-Object { [int]$_.Name } | ForEach-Object {
        $lo = (([int]$_.Name - 1) * 4) + 1
        $hi = [int]$_.Name * 4
        [PSCustomObject]@{ VCpuRange = "$lo-$hi vCPU"; Count = $_.Count; Pct = [math]::Round(($_.Count / $total) * 100, 1) }
    }

    $byVMemBucket = $VMs | Group-Object { [math]::Ceiling($_.MemoryGB / 8) } | Sort-Object { [int]$_.Name } | ForEach-Object {
        $lo = (([int]$_.Name - 1) * 8) + 1
        $hi = [int]$_.Name * 8
        [PSCustomObject]@{ VMemRangeGB = "$lo-$hi GB"; Count = $_.Count; Pct = [math]::Round(($_.Count / $total) * 100, 1) }
    }

    $allDisks = @($VMs | Get-HardDisk -ErrorAction SilentlyContinue)
    $byDiskFormat = $allDisks | Group-Object StorageFormat | ForEach-Object {
        [PSCustomObject]@{ DiskFormat = $_.Name; Count = $_.Count }
    }

    return @{
        ByGuestOS     = @($byGuestOs)
        ByTools       = @($byTools)
        ByHwVersion   = @($byHwVersion)
        ByVCpuBucket  = @($byVCpuBucket)
        ByVMemBucket  = @($byVMemBucket)
        ByDiskFormat  = @($byDiskFormat)
    }
}

# ---------------------------------------------------------------------------
# [Mode 2] 9. Shared (multi-writer) virtual disks
# ---------------------------------------------------------------------------
function Get-SharedDiskReport {
    param($VMs)

    $rows = foreach ($vm in $VMs) {
        $sharedDisks = @(Get-HardDisk -VM $vm -ErrorAction SilentlyContinue | Where-Object { $_.ExtensionData.Backing.Sharing -eq "sharingMultiWriter" })
        foreach ($d in $sharedDisks) {
            [PSCustomObject]@{
                ClusterName = $vm.VMHost.Parent.Name
                HostName    = (ConvertTo-MaskedHostName -HostName $vm.VMHost.Name)
                VmName      = $vm.Name
                DiskLabel   = $d.Name
                CapacityGB  = [math]::Round($d.CapacityGB, 1)
                Datastore   = ($d.FileName -split "\]")[0].TrimStart("[")
            }
        }
    }
    return @($rows)
}

# ---------------------------------------------------------------------------
# [Mode 2] 10. RDM (Raw Device Mapping) disks
# ---------------------------------------------------------------------------
function Get-RdmDiskReport {
    param($VMs)

    $rows = foreach ($vm in $VMs) {
        $rdmDisks = @(Get-HardDisk -VM $vm -DiskType "RawPhysical","RawVirtual" -ErrorAction SilentlyContinue)
        foreach ($d in $rdmDisks) {
            [PSCustomObject]@{
                ClusterName = $vm.VMHost.Parent.Name
                HostName    = (ConvertTo-MaskedHostName -HostName $vm.VMHost.Name)
                VmName      = $vm.Name
                DiskLabel   = $d.Name
                DiskType    = $d.DiskType
                CapacityGB  = [math]::Round($d.CapacityGB, 1)
                ScsiCanonicalName = $d.ScsiCanonicalName
            }
        }
    }
    return @($rows)
}

# ---------------------------------------------------------------------------
# [Mode 2] 11. VM performance distribution summary
# ---------------------------------------------------------------------------
function Get-VmPerfDistributionSummary {
    param($VmPerfRows)

    function Get-Bucket {
        param($Value, $WarnAt, $CritAt)
        if ($null -eq $Value) { return "Unknown" }
        if ($Value -gt $CritAt) { return "Critical" }
        if ($Value -gt $WarnAt) { return "Warning" }
        return "Normal"
    }

    $cpuBuckets   = $VmPerfRows | Group-Object { Get-Bucket -Value $_.CpuUsagePct -WarnAt $Script:Threshold.CpuUsageWarnPct -CritAt $Script:Threshold.CpuUsageCritPct }
    $readyBuckets = $VmPerfRows | Group-Object { Get-Bucket -Value $_.CpuReadyPct -WarnAt $Script:Threshold.CpuReadyWarnPct -CritAt $Script:Threshold.CpuReadyCritPct }
    $memBuckets   = $VmPerfRows | Group-Object { Get-Bucket -Value $_.MemUsagePct -WarnAt $Script:Threshold.MemUsageWarnPct -CritAt $Script:Threshold.MemUsageCritPct }
    $diskLatVals  = $VmPerfRows | ForEach-Object { [math]::Max( ($_.ReadLatencyMs), ($_.WriteLatencyMs) ) }
    $diskBuckets  = $diskLatVals | Group-Object { Get-Bucket -Value $_ -WarnAt $Script:Threshold.DiskLatencyWarnMs -CritAt $Script:Threshold.DiskLatencyCritMs }

    function ToSummaryRow {
        param($Groups, [string]$Category)
        foreach ($g in $Groups) {
            [PSCustomObject]@{ Category = $Category; Bucket = $g.Name; Count = $g.Count }
        }
    }

    $rows  = @(ToSummaryRow -Groups $cpuBuckets   -Category "CPU Usage")
    $rows += @(ToSummaryRow -Groups $readyBuckets -Category "CPU Ready")
    $rows += @(ToSummaryRow -Groups $memBuckets   -Category "Memory Usage")
    $rows += @(ToSummaryRow -Groups $diskBuckets  -Category "Disk Latency")

    return @($rows)
}

# ---------------------------------------------------------------------------
# [Extra] License key collection (CSV output only - not included in the HTML report)
# ---------------------------------------------------------------------------

# Masks a host name for the license CSV:
#   - IPv4 address: first three octets replaced with "*", last octet kept
#     e.g. 192.168.10.101 -> *.*.*.101
#   - FQDN whose domain suffix is not "vcf.local": short name kept, domain
#     replaced with vcf.local  e.g. esxi01.corp.local -> esxi01.vcf.local
#   - FQDN already ending in vcf.local, or a bare short name with no domain:
#     left unchanged
function ConvertTo-MaskedHostName {
    param([string]$HostName)

    if ([string]::IsNullOrWhiteSpace($HostName)) { return $HostName }

    if ($HostName -match '^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$') {
        # Mask everything up through the 3rd octet (before the 3rd dot) unconditionally -
        # each of the first 3 octets becomes a single "*" regardless of its digit count;
        # only the 4th octet stays visible.
        $octets = $HostName.Split('.')
        return "*.*.*.$($octets[3])"
    }

    if ($HostName -match '\.') {
        if ($HostName -notmatch '\.vcf\.local$') {
            $shortName = $HostName.Split('.')[0]
            return "$shortName.***.***"
        }
    }

    return $HostName
}

function Get-LicenseInventoryReport {
    param($VMHosts)

    # Bulk-query every entity's assigned license key in one call (QueryAssignedLicenses($null)
    # returns assignments for all entities - hosts and vCenter itself - avoiding a per-host
    # API call). No -Server is passed anywhere here: PowerCLI uses the current connection
    # context automatically, and passing a bare hostname string to -Server is what caused
    # the earlier "System.ArgumentException" (it expects a connection object, not a string).
    $licenseLookup = @{}
    try {
        $si = Get-View ServiceInstance -ErrorAction Stop
        $licManager = Get-View $si.Content.LicenseManager -ErrorAction Stop
        if ($licManager.LicenseAssignmentManager) {
            $licAssignMgr = Get-View $licManager.LicenseAssignmentManager -ErrorAction Stop
            $allAssignments = $licAssignMgr.QueryAssignedLicenses($null)
            foreach ($a in $allAssignments) {
                $licenseLookup[$a.EntityId] = $a.AssignedLicense
            }
            Write-Host "[License] Bulk assignment query complete ($($licenseLookup.Count) entries)."
        }
    } catch {
        Write-Warning "Failed to retrieve license assignment info, license keys will show as N/A: $($_.Exception.Message)"
    }

    # Any assignment entry whose EntityId doesn't match a host's MoRef is the vCenter's own
    # license (or another non-host entity) - report those as separate "vCenter" rows.
    $hostMorefs = @{}
    foreach ($h in $VMHosts) { $hostMorefs[$h.ExtensionData.MoRef.Value] = $true }

    $vcRows = foreach ($entityId in $licenseLookup.Keys) {
        if ($hostMorefs.ContainsKey($entityId)) { continue }
        try {
            $lic = $licenseLookup[$entityId]
            [PSCustomObject]@{
                Source     = "vCenter"
                Type       = "vCenter"
                Name       = $lic.Name
                EditionKey = $lic.EditionKey
                LicenseKey = $lic.LicenseKey
            }
        } catch {
            Write-Warning "License row build failed for entity '$entityId': $($_.Exception.GetType().FullName) - $($_.Exception.Message)"
        }
    }

    $hostRows = foreach ($h in $VMHosts) {
        try {
            $moref = $h.ExtensionData.MoRef.Value
            $assigned = if ($licenseLookup.ContainsKey($moref)) { $licenseLookup[$moref] } else { $null }
            [PSCustomObject]@{
                Source     = $h.Parent.Name
                Type       = "ESXi Host"
                Name       = ConvertTo-MaskedHostName -HostName $h.Name
                EditionKey = if ($assigned) { $assigned.EditionKey } else { $null }
                LicenseKey = if ($assigned) { $assigned.LicenseKey } else { $h.LicenseKey }
            }
        } catch {
            Write-Warning "License lookup failed for host '$($h.Name)': $($_.Exception.GetType().FullName) - $($_.Exception.Message)"
        }
    }

    return (@($vcRows) + @($hostRows))
}

# ---------------------------------------------------------------------------
# [Mode 2] HTML rendering helpers
# ---------------------------------------------------------------------------
function Get-StatusBadgeClass {
    param([string]$Text)
    switch ($Text) {
        "Normal"   { return "badge-good" }
        "Warning"  { return "badge-warn" }
        "Critical" { return "badge-crit" }
        "Unknown"  { return "badge-neutral" }
        "Thin"     { return "badge-info" }
        "Thick"    { return "badge-neutral" }
        default    { return "" }
    }
}

function ConvertTo-HtmlTable {
    param($Data, [string[]]$Columns)

    $arr = @($Data | Where-Object { $null -ne $_ })
    if ($arr.Count -eq 0) { return "<p><em>No data.</em></p>" }
    if (-not $Columns) { $Columns = $arr[0].PSObject.Properties.Name }

    $header = ($Columns | ForEach-Object { "<th>$_</th>" }) -join ""
    $rows = foreach ($item in $arr) {
        $cells = ($Columns | ForEach-Object {
            $val = $item.$_
            $badgeClass = Get-StatusBadgeClass -Text ([string]$val)
            if ($badgeClass) { "<td><span class=`"$badgeClass`">$val</span></td>" } else { "<td>$val</td>" }
        }) -join ""
        "<tr>$cells</tr>"
    }
    return "<table><tr>$header</tr>$($rows -join "`n")</table>"
}

function ConvertTo-TableCard {
    param([string]$InnerHtml, [string]$Note)
    $noteHtml = if ($Note) { "<div class=`"note`" style=`"padding:0 4px 8px;`">$Note</div>" } else { "" }
    return "<div class=`"table-card`">$noteHtml$InnerHtml</div>"
}

function ConvertTo-SectionHead {
    param([string]$Id, [string]$Title, [string]$Desc)
    $num = if ($Title -match '^(\d+)\.') { $Matches[1] } else { '' }
    $titleText = $Title -replace '^\d+\.\s*', ''
    return "<div class=`"section-head`" id=`"$Id`"><span class=`"sh-num`">$num</span><div><h2>$titleText</h2><div class=`"desc`">$Desc</div></div></div>"
}

function ConvertTo-KpiCard {
    param([string]$Label, $Value, [string]$Unit = "", [string]$SubNote = "")
    $subHtml = if ($SubNote) { "<div class=`"kpi-sub`">$SubNote</div>" } else { "" }
    return "<div class=`"card kpi-card`"><div class=`"label`">$Label</div><div class=`"value`">$Value<span class=`"unit`">$Unit</span></div>$subHtml</div>"
}

function ConvertTo-ClusterPerfCard {
    param(
        [string]$ClusterName, [int]$HostCount, [int]$VmCount,
        $CpuUsageGHz, $CpuCapacityGHz, $CpuUsagePct,
        $MemUsageGB, $MemCapacityGB, $MemUsagePct,
        $CpuContentionPct
    )

    $status = "Normal"
    if ($CpuUsagePct -gt $Script:Threshold.CpuUsageCritPct -or $MemUsagePct -gt $Script:Threshold.MemUsageCritPct) { $status = "Critical" }
    elseif ($CpuUsagePct -gt $Script:Threshold.CpuUsageWarnPct -or $MemUsagePct -gt $Script:Threshold.MemUsageWarnPct) { $status = "Warning" }
    $statusClass = Get-StatusBadgeClass -Text $status

    $cpuBarColor = if ($CpuUsagePct -gt $Script:Threshold.CpuUsageCritPct) { "var(--coral-dark)" } elseif ($CpuUsagePct -gt $Script:Threshold.CpuUsageWarnPct) { "var(--peach-dark)" } else { "var(--mint-dark)" }
    $memBarColor = if ($MemUsagePct -gt $Script:Threshold.MemUsageCritPct) { "var(--coral-dark)" } elseif ($MemUsagePct -gt $Script:Threshold.MemUsageWarnPct) { "var(--peach-dark)" } else { "var(--mint-dark)" }
    $cpuWidth = [math]::Min(100, [math]::Max(0, [double]$CpuUsagePct))
    $memWidth = [math]::Min(100, [math]::Max(0, [double]$MemUsagePct))

    return @"
<div class="card cluster-card">
  <div class="ch">
    <div><div class="name">$ClusterName</div><div class="dc">Host $HostCount &middot; VM $VmCount</div></div>
    <span class="$statusClass">$status</span>
  </div>
  <div class="metric-row">
    <div class="mrow-top"><span class="mlabel">CPU</span><span class="mval">$CpuUsageGHz / $CpuCapacityGHz GHz &nbsp;($CpuUsagePct%)</span></div>
    <div class="bar-track"><div class="bar-fill" style="width:$cpuWidth%;background:$cpuBarColor;"></div></div>
  </div>
  <div class="metric-row">
    <div class="mrow-top"><span class="mlabel">Memory</span><span class="mval">$MemUsageGB / $MemCapacityGB GB &nbsp;($MemUsagePct%)</span></div>
    <div class="bar-track"><div class="bar-fill" style="width:$memWidth%;background:$memBarColor;"></div></div>
  </div>
  <div class="sub-stats"><div class="sub-stat">CPU Ready <b>$CpuContentionPct%</b></div></div>
</div>
"@
}

function ConvertTo-BreakdownBars {
    param($Rows, [string]$LabelProp, [string]$CountProp = "Count", [string]$PctProp = "Pct")

    $arr = @($Rows | Where-Object { $null -ne $_ })
    if ($arr.Count -eq 0) { return "<p><em>No data.</em></p>" }

    $maxPct = ($arr.$PctProp | Measure-Object -Maximum).Maximum
    if (-not $maxPct -or $maxPct -le 0) { $maxPct = 100 }

    $rowsHtml = foreach ($r in $arr) {
        $label = $r.$LabelProp
        $count = $r.$CountProp
        $pct   = $r.$PctProp
        $barWidth = if ($pct) { [math]::Round(($pct / $maxPct) * 100, 1) } else { 0 }
        $pctText = if ($null -ne $pct) { "<span class=`"bd-pct`">($pct%)</span>" } else { "" }
        "<div class=`"bd-row`"><div class=`"bd-label`" title=`"$label`">$label</div><div class=`"bd-bar-track`"><div class=`"bd-bar-fill`" style=`"width:$barWidth%;`"></div></div><div class=`"bd-count`">$count $pctText</div></div>"
    }
    return ($rowsHtml -join "`n")
}

function ConvertTo-StackedBarSummary {
    param($PerfDistributionRows)

    $categories = $PerfDistributionRows | Group-Object Category
    $blocks = foreach ($cat in $categories) {
        $total = ($cat.Group.Count | Measure-Object -Sum).Sum
        $normal   = ($cat.Group | Where-Object { $_.Bucket -eq "Normal" }   | Select-Object -ExpandProperty Count | Measure-Object -Sum).Sum
        $warning  = ($cat.Group | Where-Object { $_.Bucket -eq "Warning" }  | Select-Object -ExpandProperty Count | Measure-Object -Sum).Sum
        $critical = ($cat.Group | Where-Object { $_.Bucket -eq "Critical" } | Select-Object -ExpandProperty Count | Measure-Object -Sum).Sum
        $unknown  = ($cat.Group | Where-Object { $_.Bucket -eq "Unknown" }  | Select-Object -ExpandProperty Count | Measure-Object -Sum).Sum
        $sum = [math]::Max(($normal + $warning + $critical + $unknown), 1)

        $normalW   = [math]::Round(($normal   / $sum) * 100, 1)
        $warningW  = [math]::Round(($warning  / $sum) * 100, 1)
        $criticalW = [math]::Round(($critical / $sum) * 100, 1)
        $unknownW  = [math]::Round(($unknown  / $sum) * 100, 1)

        @"
<div class="bd-title">$($cat.Name) <span class="bd-total">($sum VMs)</span></div>
<div class="stacked-bar">
  <div class="seg normal" style="width:$normalW%;" title="Normal: $normal"></div>
  <div class="seg warning" style="width:$warningW%;" title="Warning: $warning"></div>
  <div class="seg critical" style="width:$criticalW%;" title="Critical: $critical"></div>
</div>
<div class="status-legend-row">
  <span><i class="dot normal"></i>Normal $normal</span>
  <span><i class="dot warning"></i>Warning $warning</span>
  <span><i class="dot critical"></i>Critical $critical</span>
</div>
"@
    }
    return ($blocks -join "`n<br>`n")
}

# ---------------------------------------------------------------------------
# [Extra] Email-safe HTML report (table-based layout, inline styles only -
# no CSS variables, flexbox, or gradients, since most email clients -
# especially Outlook's Word-based rendering engine - don't support those).
# Saved as its own file; paste its content into an email body or use it as
# the -Body for Send-MailMessage -BodyAsHtml.
# ---------------------------------------------------------------------------
function ConvertTo-EmailTable {
    param($Data, [string[]]$Columns, [string]$Title)

    $titleHtml = if ($Title) {
        "<div style=`"font-size:11px;font-weight:bold;color:#4a5062;text-transform:uppercase;letter-spacing:.03em;margin:14px 0 6px;font-family:Arial,Helvetica,sans-serif;`">$Title</div>"
    } else { "" }

    $arr = @($Data | Where-Object { $null -ne $_ })
    if ($arr.Count -eq 0) {
        return "$titleHtml<div style=`"font-size:12px;color:#8b93a7;padding:4px 0 10px;font-family:Arial,Helvetica,sans-serif;`">No data.</div>"
    }
    if (-not $Columns) { $Columns = $arr[0].PSObject.Properties.Name }

    $headerCells = ($Columns | ForEach-Object {
        "<th style=`"background-color:#1c2130;color:#ffffff;font-size:10.5px;text-transform:uppercase;letter-spacing:.02em;padding:7px 10px;text-align:left;border:1px solid #1c2130;font-family:Arial,Helvetica,sans-serif;`">$_</th>"
    }) -join ""

    $rowIndex = 0
    $rows = foreach ($item in $arr) {
        $bg = if ($rowIndex % 2 -eq 0) { "#ffffff" } else { "#f6f8fb" }
        $rowIndex++
        $cells = ($Columns | ForEach-Object {
            "<td style=`"padding:6px 10px;font-size:12px;color:#171923;border:1px solid #dde1e8;background-color:$bg;font-family:Arial,Helvetica,sans-serif;`">$($item.$_)</td>"
        }) -join ""
        "<tr>$cells</tr>"
    }

    return "$titleHtml<table role=`"presentation`" width=`"100%`" cellpadding=`"0`" cellspacing=`"0`" style=`"border-collapse:collapse;margin-bottom:6px;`"><tr>$headerCells</tr>$($rows -join "`n")</table>"
}

function ConvertTo-EmailKpiCell {
    param([string]$Label, $Value, [string]$Unit = "")
    return "<td width=`"33%`" align=`"center`" style=`"padding:10px 6px;border:1px solid #dde1e8;background-color:#fafafc;font-family:Arial,Helvetica,sans-serif;`"><div style=`"font-size:10.5px;color:#8b93a7;text-transform:uppercase;letter-spacing:.03em;`">$Label</div><div style=`"font-size:19px;font-weight:bold;color:#171923;margin-top:4px;`">$Value<span style=`"font-size:11px;font-weight:normal;color:#8b93a7;`"> $Unit</span></div></td>"
}

function ConvertTo-EmailSectionHead {
    param([string]$Title)
    return "<div style=`"font-size:14px;font-weight:bold;color:#171923;margin:4px 0 10px;font-family:Arial,Helvetica,sans-serif;border-left:4px solid #4f46e5;padding-left:8px;`">$Title</div>"
}

function Get-EmailHtmlReport {
    param($VCenterServer, $DaysBack, $DateStr, $Inventory, $Perf, $Storage, $VmPerf, $OldSnapshots, $ConnectedDevices, $Distribution, $SharedDisks, $RdmDisks, $PerfDistribution)

    $vcenterLabel = $VCenterServer -join ', '

    $body = @"
<!DOCTYPE html>
<html>
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
</head>
<body style="margin:0;padding:0;background-color:#f1f4f9;font-family:Arial,Helvetica,sans-serif;">
<table role="presentation" width="100%" cellpadding="0" cellspacing="0" style="background-color:#f1f4f9;">
<tr><td align="center" style="padding:20px 10px;">
<table role="presentation" width="640" cellpadding="0" cellspacing="0" style="background-color:#ffffff;border:1px solid #dde1e8;">

<tr><td style="background-color:#3730a3;padding:20px 22px;">
  <div style="color:#ffffff;font-size:19px;font-weight:bold;font-family:Arial,Helvetica,sans-serif;">vCenter Comprehensive Report</div>
  <div style="color:#c7d2fe;font-size:12px;margin-top:4px;font-family:Arial,Helvetica,sans-serif;">$vcenterLabel</div>
  <div style="color:#c7d2fe;font-size:11px;margin-top:8px;font-family:Arial,Helvetica,sans-serif;">Generated $DateStr &nbsp;|&nbsp; Window: last $DaysBack day(s)</div>
</td></tr>

<tr><td style="padding:18px 22px 6px;">
$(ConvertTo-EmailSectionHead -Title "1. Inventory Summary")
<table role="presentation" width="100%" cellpadding="0" cellspacing="0" style="border-collapse:collapse;">
<tr>
$(ConvertTo-EmailKpiCell -Label "Datacenters" -Value $Inventory.Overall.DatacenterCount)
$(ConvertTo-EmailKpiCell -Label "Clusters" -Value $Inventory.Overall.ClusterCount)
$(ConvertTo-EmailKpiCell -Label "ESXi Hosts" -Value $Inventory.Overall.HostCount)
</tr>
<tr>
$(ConvertTo-EmailKpiCell -Label "VMs (On/Off)" -Value "$($Inventory.Overall.VmPoweredOn)/$($Inventory.Overall.VmPoweredOff)")
$(ConvertTo-EmailKpiCell -Label "Total Cores" -Value $Inventory.Overall.TotalCores)
$(ConvertTo-EmailKpiCell -Label "Total Memory" -Value $Inventory.Overall.TotalMemoryGB -Unit "GB")
</tr>
</table>
$(ConvertTo-EmailTable -Data $Inventory.PerCluster -Title "Per-Cluster")
</td></tr>

<tr><td style="padding:14px 22px 6px;">
$(ConvertTo-EmailSectionHead -Title "2. Performance Summary")
<div style="font-size:12px;color:#4a5062;margin-bottom:8px;font-family:Arial,Helvetica,sans-serif;">Overall Avg CPU: <b>$($Perf.OverallAvgCpuPct)%</b> &nbsp;|&nbsp; Overall Avg Mem: <b>$($Perf.OverallAvgMemPct)%</b></div>
$(ConvertTo-EmailTable -Data $Perf.PerCluster -Title "Per-Cluster CPU/Memory")
$(ConvertTo-EmailTable -Data $Perf.Top3CpuHosts -Columns @('HostName','ClusterName','CpuUsagePct') -Title "Top 3 Hosts by CPU")
$(ConvertTo-EmailTable -Data $Perf.Top3MemHosts -Columns @('HostName','ClusterName','MemUsagePct') -Title "Top 3 Hosts by Memory")
$(ConvertTo-EmailTable -Data $Perf.Top3ReadyHosts -Columns @('HostName','ClusterName','CpuContentionPct') -Title "Top 3 Hosts by CPU Ready %")
</td></tr>

<tr><td style="padding:14px 22px 6px;">
$(ConvertTo-EmailSectionHead -Title "3. Storage Summary")
$(ConvertTo-EmailTable -Data $Storage -Title "Shared Datastore Capacity")
</td></tr>

<tr><td style="padding:14px 22px 6px;">
$(ConvertTo-EmailSectionHead -Title "4. VM Performance Top 5 Lists")
$(ConvertTo-EmailTable -Data $VmPerf.Top5CpuUsage -Title "Top 5 by vCPU Usage %")
$(ConvertTo-EmailTable -Data $VmPerf.Top5CpuReady -Title "Top 5 by vCPU Ready %")
$(ConvertTo-EmailTable -Data $VmPerf.Top5MemUsage -Title "Top 5 by vMEM Usage %")
$(ConvertTo-EmailTable -Data $VmPerf.Top5WriteLatency -Title "Top 5 by Virtual Disk Write Latency")
$(ConvertTo-EmailTable -Data $VmPerf.Top5ReadLatency -Title "Top 5 by Virtual Disk Read Latency")
</td></tr>

<tr><td style="padding:14px 22px 6px;">
$(ConvertTo-EmailSectionHead -Title "5. Old Snapshots")
$(ConvertTo-EmailTable -Data $OldSnapshots)
</td></tr>

<tr><td style="padding:14px 22px 6px;">
$(ConvertTo-EmailSectionHead -Title "6. VMs With a Connected Virtual Device")
$(ConvertTo-EmailTable -Data $ConnectedDevices)
</td></tr>

<tr><td style="padding:14px 22px 6px;">
$(ConvertTo-EmailSectionHead -Title "7. VM Inventory")
<div style="font-size:12px;color:#8b93a7;font-family:Arial,Helvetica,sans-serif;">See the 07_VmInventory CSV file for the complete list.</div>
</td></tr>

<tr><td style="padding:14px 22px 6px;">
$(ConvertTo-EmailSectionHead -Title "8. VM Distribution")
$(ConvertTo-EmailTable -Data $Distribution.ByGuestOS -Title "Guest OS")
$(ConvertTo-EmailTable -Data $Distribution.ByTools -Title "VMware Tools Status / Version")
$(ConvertTo-EmailTable -Data $Distribution.ByHwVersion -Title "Virtual Hardware Version")
$(ConvertTo-EmailTable -Data $Distribution.ByVCpuBucket -Title "vCPU Buckets")
$(ConvertTo-EmailTable -Data $Distribution.ByVMemBucket -Title "vMEM Buckets")
$(ConvertTo-EmailTable -Data $Distribution.ByDiskFormat -Title "Thin / Thick Disk Count")
</td></tr>

<tr><td style="padding:14px 22px 6px;">
$(ConvertTo-EmailSectionHead -Title "9. Shared (Multi-Writer) Virtual Disks")
$(ConvertTo-EmailTable -Data $SharedDisks)
</td></tr>

<tr><td style="padding:14px 22px 6px;">
$(ConvertTo-EmailSectionHead -Title "10. RDM Disks")
$(ConvertTo-EmailTable -Data $RdmDisks)
</td></tr>

<tr><td style="padding:14px 22px 18px;">
$(ConvertTo-EmailSectionHead -Title "11. VM Performance Distribution Summary")
$(ConvertTo-EmailTable -Data $PerfDistribution)
</td></tr>

<tr><td style="background-color:#f6f8fb;padding:14px 22px;text-align:center;border-top:1px solid #dde1e8;">
  <div style="font-size:11px;color:#8b93a7;font-family:Arial,Helvetica,sans-serif;">Full detail (VM inventory, distribution breakdowns, etc.) is available in the CSV files and the full HTML report.</div>
</td></tr>

</table>
</td></tr>
</table>
</body>
</html>
"@

    return $body
}

# ---------------------------------------------------------------------------
# [Mode 2] Full comprehensive report pipeline
# ---------------------------------------------------------------------------
function Invoke-ComprehensiveVCenterReport {
    param([string[]]$VCenterServer, [int]$DaysBack, [int]$SnapshotAgeDays, [string]$OutputFolder)

    $start  = (Get-Date).AddDays(-$DaysBack)
    $finish = Get-Date

    Write-Host "`n[Inventory] Retrieving base inventory (Datacenter/Cluster/Host/VM/Datastore - 5 calls total)..."
    $datacenters = @(Get-Datacenter)
    $clusters    = @(Get-Cluster)
    $vmhosts     = @(Get-VMHost)
    $vms         = @(Get-VM)
    $datastores  = @(Get-Datastore)

    if (-not (Test-Path $OutputFolder)) { New-Item -ItemType Directory -Path $OutputFolder | Out-Null }
    $dateStr = (Get-Date).ToString("yyyyMMdd")

    # Display-only masked vCenter name(s) - same FQDN-domain rule as ESXi hosts (short name
    # kept, domain replaced with vcf.local). The real $VCenterServer is still used for the
    # actual connection; this masked version is only for what appears in generated reports.
    $maskedVCenterServer = @($VCenterServer | ForEach-Object { ConvertTo-MaskedHostName -HostName $_ })

    Write-Host "`n[1/11] Inventory summary..."
    $inventory = Get-InventorySummaryReport -Datacenters $datacenters -Clusters $clusters -VMHosts $vmhosts -VMs $vms
    Export-CsvSafe -Data @($inventory.Overall)    -Path "$OutputFolder\01_InventoryOverall_$dateStr.csv"
    Export-CsvSafe -Data $inventory.PerCluster    -Path "$OutputFolder\01_InventoryPerCluster_$dateStr.csv"

    Write-Host "[2/11] Performance summary..."
    $perf = Get-PerformanceSummaryReport -Clusters $clusters -VMHosts $vmhosts -StartTime $start -FinishTime $finish
    Export-CsvSafe -Data $perf.PerCluster       -Path "$OutputFolder\02_PerfPerCluster_$dateStr.csv"
    Export-CsvSafe -Data $perf.Top3CpuHosts     -Path "$OutputFolder\02_Top3CpuHosts_$dateStr.csv"
    Export-CsvSafe -Data $perf.Top3MemHosts     -Path "$OutputFolder\02_Top3MemHosts_$dateStr.csv"
    Export-CsvSafe -Data $perf.Top3ReadyHosts   -Path "$OutputFolder\02_Top3ReadyHosts_$dateStr.csv"

    Write-Host "[3/11] Storage summary..."
    $storage = Get-StorageSummaryReport -Datastores $datastores
    Export-CsvSafe -Data $storage -Path "$OutputFolder\03_SharedDatastores_$dateStr.csv"

    Write-Host "[4/11] VM performance Top5 lists..."
    $vmPerf = Get-VmPerformanceTopLists -VMs $vms -StartTime $start -FinishTime $finish
    Export-CsvSafe -Data $vmPerf.Top5CpuUsage     -Path "$OutputFolder\04_Top5VmCpuUsage_$dateStr.csv"
    Export-CsvSafe -Data $vmPerf.Top5CpuReady     -Path "$OutputFolder\04_Top5VmCpuReady_$dateStr.csv"
    Export-CsvSafe -Data $vmPerf.Top5MemUsage     -Path "$OutputFolder\04_Top5VmMemUsage_$dateStr.csv"
    Export-CsvSafe -Data $vmPerf.Top5WriteLatency -Path "$OutputFolder\04_Top5VmWriteLatency_$dateStr.csv"
    Export-CsvSafe -Data $vmPerf.Top5ReadLatency  -Path "$OutputFolder\04_Top5VmReadLatency_$dateStr.csv"

    Write-Host "[5/11] Old snapshots (older than $SnapshotAgeDays days)..."
    $oldSnapshots = Get-OldSnapshotReport -VMs $vms -AgeDays $SnapshotAgeDays
    Export-CsvSafe -Data $oldSnapshots -Path "$OutputFolder\05_OldSnapshots_$dateStr.csv"

    Write-Host "[6/11] Connected virtual devices (mounted ISO, etc.)..."
    $connectedDevices = Get-ConnectedDeviceReport -VMs $vms
    Export-CsvSafe -Data $connectedDevices -Path "$OutputFolder\06_ConnectedDevices_$dateStr.csv"

    Write-Host "[7/11] Full VM inventory..."
    $vmInventory = Get-VmInventoryReport -VMs $vms
    Export-CsvSafe -Data $vmInventory -Path "$OutputFolder\07_VmInventory_$dateStr.csv"

    Write-Host "[8/11] VM distribution..."
    $distribution = Get-VmDistributionReport -VMs $vms
    Export-CsvSafe -Data $distribution.ByGuestOS    -Path "$OutputFolder\08_DistByGuestOS_$dateStr.csv"
    Export-CsvSafe -Data $distribution.ByTools      -Path "$OutputFolder\08_DistByTools_$dateStr.csv"
    Export-CsvSafe -Data $distribution.ByHwVersion  -Path "$OutputFolder\08_DistByHwVersion_$dateStr.csv"
    Export-CsvSafe -Data $distribution.ByVCpuBucket -Path "$OutputFolder\08_DistByVCpuBucket_$dateStr.csv"
    Export-CsvSafe -Data $distribution.ByVMemBucket -Path "$OutputFolder\08_DistByVMemBucket_$dateStr.csv"
    Export-CsvSafe -Data $distribution.ByDiskFormat -Path "$OutputFolder\08_DistByDiskFormat_$dateStr.csv"

    Write-Host "[9/11] Shared virtual disks..."
    $sharedDisks = Get-SharedDiskReport -VMs $vms
    Export-CsvSafe -Data $sharedDisks -Path "$OutputFolder\09_SharedDisks_$dateStr.csv"

    Write-Host "[10/11] RDM disks..."
    $rdmDisks = Get-RdmDiskReport -VMs $vms
    Export-CsvSafe -Data $rdmDisks -Path "$OutputFolder\10_RdmDisks_$dateStr.csv"

    Write-Host "[11/11] VM performance distribution summary..."
    $perfDistribution = Get-VmPerfDistributionSummary -VmPerfRows $vmPerf.AllRows
    Export-CsvSafe -Data $perfDistribution -Path "$OutputFolder\11_PerfDistribution_$dateStr.csv"

    Write-Host "`n[License] Collecting vCenter and ESXi host license keys (CSV only, not included in HTML)..."
    try {
        $licenseInfo = Get-LicenseInventoryReport -VMHosts $vmhosts
        Export-CsvSafe -Data $licenseInfo -Path "$OutputFolder\LicenseKeys_$dateStr.csv"
    } catch {
        Write-Warning "License key collection failed - skipping LicenseKeys CSV."
        Write-Warning "  Exception type : $($_.Exception.GetType().FullName)"
        Write-Warning "  Message        : $($_.Exception.Message)"
        if ($_.Exception.InnerException) {
            Write-Warning "  Inner type     : $($_.Exception.InnerException.GetType().FullName)"
            Write-Warning "  Inner message  : $($_.Exception.InnerException.Message)"
        }
        Write-Warning "  Position       : $($_.InvocationInfo.PositionMessage)"
        if ($_.ScriptStackTrace) {
            Write-Warning "  Stack trace    : $($_.ScriptStackTrace)"
        }
    }

    Write-Host "`n[Export] Generating HTML summary..."
    $htmlPath = "$OutputFolder\VCenterReport_$dateStr.html"

    # Build cluster performance cards (join PerCluster perf stats with host/VM counts)
    $clusterCardsHtml = ($perf.PerCluster | ForEach-Object {
        $clName = $_.ClusterName
        $hostCount = ($inventory.PerCluster | Where-Object { $_.ClusterName -eq $clName } | Select-Object -First 1 -ExpandProperty HostCount)
        $vmCount   = @($vms | Where-Object { $_.VMHost.Parent.Name -eq $clName }).Count
        $avgReady  = ($perf.HostRows | Where-Object { $_.ClusterName -eq $clName } | Measure-Object -Property CpuContentionPct -Average).Average
        $avgReady  = if ($avgReady) { [math]::Round($avgReady, 2) } else { 0 }

        ConvertTo-ClusterPerfCard -ClusterName $clName -HostCount $hostCount -VmCount $vmCount `
            -CpuUsageGHz $_.CpuUsageGHz -CpuCapacityGHz $_.CpuCapacityGHz -CpuUsagePct $_.CpuUsagePct `
            -MemUsageGB $_.MemUsageGB -MemCapacityGB $_.MemCapacityGB -MemUsagePct $_.MemUsagePct `
            -CpuContentionPct $avgReady
    }) -join "`n"

    $html = @"
<html>
<head><meta charset="utf-8"><title>vCenter Comprehensive Report $dateStr</title>
<style>
:root{
  --bg:#f3f4f7; --surface:#ffffff; --surface-alt:#fafafc; --border:#dde1e8; --border-strong:#c7cdda;
  --text:#171923; --text2:#4a5062; --muted:#8b93a7;
  --accent:#4f46e5; --accent-tint:#eef0fe;
  --head-bg:#1c2130; --head-text:#e7e9f1;
  --good:#0e9f6e; --good-tint:#e7f9f1; --good-text:#04693f;
  --warn:#e08e0b; --warn-tint:#fef3e0; --warn-text:#8a5406;
  --crit:#e0393e; --crit-tint:#fdeaea; --crit-text:#a11c20;
  --info:#0e8fd8; --info-tint:#e6f4fc; --info-text:#0a5c8a;
  --neutral-tint:#eef0f3; --neutral-text:#4d5361;
}
*{box-sizing:border-box;}
html,body{margin:0; padding:0; background:var(--bg); color:var(--text);
  font-family:"Segoe UI",Arial,sans-serif; font-size:14px; line-height:1.55;}

/* --- Top navbar --- */
.topnav{position:sticky; top:0; z-index:100; background:rgba(255,255,255,.92); backdrop-filter:blur(8px);
  border-bottom:1px solid var(--border); padding:0 26px; display:flex; align-items:center; height:52px; gap:6px;
  overflow-x:auto; white-space:nowrap;}
.topnav .brand{font-weight:800; font-size:14px; margin-right:18px; flex:0 0 auto; color:var(--text);}
.topnav a{display:inline-flex; align-items:center; gap:7px; padding:0 11px; height:52px; color:var(--text2);
  text-decoration:none; font-size:12px; font-weight:700; border-bottom:2px solid transparent; flex:0 0 auto;}
.topnav a:hover{color:var(--text); border-bottom-color:var(--border-strong);}
.topnav a .dot{width:7px; height:7px; border-radius:50%; flex:0 0 auto;}

/* --- Hero --- */
.hero{background:linear-gradient(115deg,#3730a3 0%,#5b21b6 42%,#1d4ed8 100%); color:#fff; padding:30px 30px 26px;}
.hero-inner{max-width:1400px; margin:0 auto; display:flex; justify-content:space-between; align-items:flex-end; flex-wrap:wrap; gap:16px;}
.hero h1{font-size:23px; font-weight:800; margin:0 0 5px;}
.hero .sub{opacity:.82; font-size:12.5px;}
.hero .chips{display:flex; gap:8px; flex-wrap:wrap;}
.hero .chip{background:rgba(255,255,255,.14); border:1px solid rgba(255,255,255,.28); border-radius:7px;
  padding:6px 13px; font-size:11.5px; font-weight:600;}
.hero .chip b{font-weight:800; margin-left:5px;}

/* --- Main --- */
.main{max-width:1400px; margin:0 auto; padding:26px 30px 90px;}

section{margin:34px 0; padding-left:14px; border-left:3px solid var(--accent);}
.section-head{margin-bottom:14px; display:flex; align-items:flex-start; gap:12px;}
.section-head .sh-num{
  flex:0 0 auto; width:26px; height:26px; border-radius:7px; background:var(--accent); color:#fff;
  display:flex; align-items:center; justify-content:center; font-size:12px; font-weight:800;
}
.section-head h2{font-size:15.5px; font-weight:800; margin:2px 0 0; color:var(--text);}
.section-head .desc{color:var(--muted); font-size:11.5px; margin-top:3px;}

.grid2,.grid3,.grid4{display:flex; flex-wrap:wrap; gap:14px;}
.grid2>*{flex:1 1 calc(50% - 14px); min-width:260px;}
.grid3>*{flex:1 1 calc(33.333% - 14px); min-width:250px;}
.grid4>*{flex:1 1 calc(25% - 11px); min-width:180px;}

.card{background:var(--surface); border:1px solid var(--border); border-top:3px solid var(--accent);
  border-radius:8px; padding:16px 18px; box-shadow:0 1px 3px rgba(20,20,40,.06);}

.kpi-card .label{font-size:11px; color:var(--text2); font-weight:700; text-transform:uppercase; letter-spacing:.04em;}
.kpi-card .value{font-size:25px; font-weight:800; margin:7px 0 2px; color:var(--text); font-variant-numeric:tabular-nums;}
.kpi-card .value .unit{font-size:12px; font-weight:600; color:var(--muted); margin-left:4px;}
.kpi-card .kpi-sub{font-size:11px; color:var(--text2); margin-top:4px;}

.cluster-card .ch{display:flex; justify-content:space-between; align-items:center; margin-bottom:10px;}
.cluster-card .ch .name{font-weight:800; font-size:13.5px;}
.cluster-card .ch .dc{font-size:11px; color:var(--muted);}
.metric-row{margin-bottom:9px;}
.metric-row .mrow-top{display:flex; justify-content:space-between; font-size:11.5px; margin-bottom:4px;}
.metric-row .mrow-top .mlabel{color:var(--text2); font-weight:700; text-transform:uppercase; letter-spacing:.03em; font-size:10.5px;}
.metric-row .mrow-top .mval{font-weight:700; color:var(--text); font-variant-numeric:tabular-nums;}
.bar-track{height:6px; border-radius:4px; background:var(--surface-alt); overflow:hidden; border:1px solid var(--border);}
.bar-fill{height:100%; border-radius:4px;}
.sub-stats{display:flex; gap:14px; margin-top:10px; padding-top:9px; border-top:1px solid var(--border);}
.sub-stat{font-size:11px; color:var(--text2);}
.sub-stat b{color:var(--text); font-weight:800; margin-left:4px;}

.table-card{background:var(--surface); border:1px solid var(--border); border-top:3px solid var(--accent);
  border-radius:8px; padding:0; box-shadow:0 1px 3px rgba(20,20,40,.06); overflow:hidden; margin-bottom:6px;}
table{width:100%; border-collapse:collapse; font-size:12.5px;}
thead th{background:var(--head-bg); color:var(--head-text); font-weight:700; text-align:left; padding:9px 12px;
  font-size:10.5px; text-transform:uppercase; letter-spacing:.03em; border-right:1px solid rgba(255,255,255,.10);}
thead th:last-child{border-right:none;}
tbody td{padding:8px 12px; border-bottom:1px solid var(--border); border-right:1px solid var(--border);
  color:var(--text); font-variant-numeric:tabular-nums;}
tbody td:last-child{border-right:none;}
tbody tr:last-child td{border-bottom:none;}
tbody tr:nth-child(even) td{background:var(--surface-alt);}
tbody tr:hover td{background:var(--accent-tint);}

.badge{display:inline-block; padding:3px 11px; border-radius:6px; background:var(--info-tint); color:var(--info-text); font-weight:700; font-size:11px; margin-right:6px;}
.badge-good{display:inline-block; padding:2px 9px; border-radius:6px; background:var(--good-tint); color:var(--good-text); font-weight:700; font-size:11px;}
.badge-warn{display:inline-block; padding:2px 9px; border-radius:6px; background:var(--warn-tint); color:var(--warn-text); font-weight:700; font-size:11px;}
.badge-crit{display:inline-block; padding:2px 9px; border-radius:6px; background:var(--crit-tint); color:var(--crit-text); font-weight:700; font-size:11px;}
.badge-info{display:inline-block; padding:2px 9px; border-radius:6px; background:var(--info-tint); color:var(--info-text); font-weight:700; font-size:11px;}
.badge-neutral{display:inline-block; padding:2px 9px; border-radius:6px; background:var(--neutral-tint); color:var(--neutral-text); font-weight:700; font-size:11px;}

.subhead{font-size:11px; color:var(--muted); margin:14px 4px 6px; font-weight:700; text-transform:uppercase; letter-spacing:.04em;}
.note{color:var(--muted); font-size:11.5px;}

.bd-title{font-weight:800; font-size:12.5px; color:var(--text); margin:14px 4px 9px;}
.bd-title .bd-total{font-weight:600; font-size:11px; color:var(--muted); margin-left:6px;}
.bd-row{display:flex; align-items:center; gap:10px; margin:0 4px 7px; font-size:11.5px;}
.bd-label{width:34%; color:var(--text2); font-weight:600; overflow:hidden; text-overflow:ellipsis; white-space:nowrap;}
.bd-bar-track{flex:1; height:8px; border-radius:4px; background:var(--surface-alt); overflow:hidden; border:1px solid var(--border);}
.bd-bar-fill{height:100%; border-radius:4px; background:var(--accent);}
.bd-count{width:90px; text-align:right; color:var(--text); font-weight:700; white-space:nowrap; font-variant-numeric:tabular-nums;}
.bd-count .bd-pct{color:var(--muted); font-weight:500;}

.stacked-bar{display:flex; height:12px; border-radius:6px; overflow:hidden; background:var(--surface-alt); margin:0 4px 9px; border:1px solid var(--border);}
.stacked-bar .seg.normal{background:var(--good);}
.stacked-bar .seg.warning{background:var(--warn);}
.stacked-bar .seg.critical{background:var(--crit);}
.status-legend-row{display:flex; gap:16px; font-size:11.5px; color:var(--text2); flex-wrap:wrap; margin:0 4px 4px;}
.status-legend-row .dot{width:8px; height:8px; border-radius:50%; display:inline-block; margin-right:6px;}
.status-legend-row .dot.normal{background:var(--good);}
.status-legend-row .dot.warning{background:var(--warn);}
.status-legend-row .dot.critical{background:var(--crit);}

.foot{text-align:center; color:var(--muted); font-size:11.5px; margin-top:46px;}
</style>
</head>
<body>

<div class="topnav">
  <span class="brand">vCenter Ops</span>
  <a href="#inventory"><span class="dot" style="background:#4f46e5"></span>Inventory</a>
  <a href="#perf"><span class="dot" style="background:#7c3aed"></span>Performance</a>
  <a href="#storage"><span class="dot" style="background:#0d9488"></span>Storage</a>
  <a href="#vmperf"><span class="dot" style="background:#2563eb"></span>VM Perf</a>
  <a href="#snapshot"><span class="dot" style="background:#d97706"></span>Snapshots</a>
  <a href="#device"><span class="dot" style="background:#0891b2"></span>Devices</a>
  <a href="#vminv"><span class="dot" style="background:#475569"></span>VM Inventory</a>
  <a href="#dist"><span class="dot" style="background:#db2777"></span>Distribution</a>
  <a href="#shared"><span class="dot" style="background:#059669"></span>Shared Disks</a>
  <a href="#rdm"><span class="dot" style="background:#ea580c"></span>RDM</a>
  <a href="#summary"><span class="dot" style="background:#e11d48"></span>Perf Summary</a>
</div>

<div class="hero"><div class="hero-inner">
  <div>
    <h1>vCenter Comprehensive Report</h1>
    <div class="sub">$($maskedVCenterServer -join ', ')</div>
  </div>
  <div class="chips">
    <span class="chip">Generated<b>$dateStr</b></span>
    <span class="chip">Window<b>last $DaysBack day(s)</b></span>
  </div>
</div></div>

<div class="main">

<section style="--accent:#4f46e5">
$(ConvertTo-SectionHead -Id "inventory" -Title "1. Inventory Summary" -Desc "Datacenter / Cluster / Host / VM counts, Total Core &amp; Memory")
<div class="grid4">
$(ConvertTo-KpiCard -Label "Datacenters" -Value $inventory.Overall.DatacenterCount)
$(ConvertTo-KpiCard -Label "Clusters" -Value $inventory.Overall.ClusterCount)
$(ConvertTo-KpiCard -Label "ESXi Hosts" -Value $inventory.Overall.HostCount)
$(ConvertTo-KpiCard -Label "Virtual Machines" -Value ($inventory.Overall.VmPoweredOn + $inventory.Overall.VmPoweredOff) -SubNote "On $($inventory.Overall.VmPoweredOn) &middot; Off $($inventory.Overall.VmPoweredOff)")
$(ConvertTo-KpiCard -Label "Total Cores" -Value $inventory.Overall.TotalCores)
$(ConvertTo-KpiCard -Label "Total Memory" -Value $inventory.Overall.TotalMemoryGB -Unit "GB")
</div>
$(ConvertTo-TableCard -InnerHtml (ConvertTo-HtmlTable -Data $inventory.PerCluster) -Note "Per-cluster host count and total core/memory")
</section>

<section style="--accent:#7c3aed">
$(ConvertTo-SectionHead -Id "perf" -Title "2. Performance Summary" -Desc "Overall + per-cluster CPU/Memory, Top 3 hosts")
<p><span class="badge">Overall Avg CPU: $($perf.OverallAvgCpuPct)%</span><span class="badge">Overall Avg Mem: $($perf.OverallAvgMemPct)%</span></p>
<div class="grid3">
$clusterCardsHtml
</div>
<div class="subhead">Top 3 Hosts by CPU</div>
$(ConvertTo-TableCard -InnerHtml (ConvertTo-HtmlTable -Data $perf.Top3CpuHosts -Columns @('HostName','ClusterName','CpuUsagePct')))
<div class="subhead">Top 3 Hosts by Memory</div>
$(ConvertTo-TableCard -InnerHtml (ConvertTo-HtmlTable -Data $perf.Top3MemHosts -Columns @('HostName','ClusterName','MemUsagePct')))
<div class="subhead">Top 3 Hosts by CPU Ready %</div>
$(ConvertTo-TableCard -InnerHtml (ConvertTo-HtmlTable -Data $perf.Top3ReadyHosts -Columns @('HostName','ClusterName','CpuContentionPct')))
</section>

<section style="--accent:#0d9488">
$(ConvertTo-SectionHead -Id "storage" -Title "3. Storage Summary" -Desc "Shared datastores only - capacity")
$(ConvertTo-TableCard -InnerHtml (ConvertTo-HtmlTable -Data $storage))
</section>

<section style="--accent:#2563eb">
$(ConvertTo-SectionHead -Id "vmperf" -Title "4. VM Performance Top 5 Lists" -Desc "vCPU usage/ready, vMEM usage, virtual disk latency")
<div class="subhead">Top 5 by vCPU Usage %</div>
$(ConvertTo-TableCard -InnerHtml (ConvertTo-HtmlTable -Data $vmPerf.Top5CpuUsage))
<div class="subhead">Top 5 by vCPU Ready %</div>
$(ConvertTo-TableCard -InnerHtml (ConvertTo-HtmlTable -Data $vmPerf.Top5CpuReady))
<div class="subhead">Top 5 by vMEM Usage %</div>
$(ConvertTo-TableCard -InnerHtml (ConvertTo-HtmlTable -Data $vmPerf.Top5MemUsage))
<div class="subhead">Top 5 by Virtual Disk Write Latency</div>
$(ConvertTo-TableCard -InnerHtml (ConvertTo-HtmlTable -Data $vmPerf.Top5WriteLatency))
<div class="subhead">Top 5 by Virtual Disk Read Latency</div>
$(ConvertTo-TableCard -InnerHtml (ConvertTo-HtmlTable -Data $vmPerf.Top5ReadLatency))
</section>

<section style="--accent:#d97706">
$(ConvertTo-SectionHead -Id "snapshot" -Title "5. Snapshots Older Than $SnapshotAgeDays Days" -Desc "Count, oldest age, total size per VM")
$(ConvertTo-TableCard -InnerHtml (ConvertTo-HtmlTable -Data $oldSnapshots))
</section>

<section style="--accent:#0891b2">
$(ConvertTo-SectionHead -Id "device" -Title "6. VMs With a Connected Virtual Device" -Desc "Mounted ISO / CD-DVD, etc.")
$(ConvertTo-TableCard -InnerHtml (ConvertTo-HtmlTable -Data $connectedDevices))
</section>

<section style="--accent:#475569">
$(ConvertTo-SectionHead -Id "vminv" -Title "7. Full VM Inventory" -Desc "Compute, memory, virtual disk and datastore detail")
<p class="note">See 07_VmInventory_$dateStr.csv for the complete list (one row per virtual disk).</p>
</section>

<section style="--accent:#db2777">
$(ConvertTo-SectionHead -Id "dist" -Title "8. VM Distribution" -Desc "Guest OS, VMware Tools, HW version, vCPU/vMEM buckets, thin/thick")
<div class="card">
<div class="bd-title">Guest OS</div>
$(ConvertTo-BreakdownBars -Rows $distribution.ByGuestOS -LabelProp "GuestOS")
<div class="bd-title">VMware Tools Status / Version</div>
$(ConvertTo-BreakdownBars -Rows $distribution.ByTools -LabelProp "ToolsStatusVersion")
<div class="bd-title">Virtual Hardware Version</div>
$(ConvertTo-BreakdownBars -Rows $distribution.ByHwVersion -LabelProp "HardwareVersion")
<div class="bd-title">vCPU Buckets (4-wide)</div>
$(ConvertTo-BreakdownBars -Rows $distribution.ByVCpuBucket -LabelProp "VCpuRange")
<div class="bd-title">vMEM Buckets (8GB-wide)</div>
$(ConvertTo-BreakdownBars -Rows $distribution.ByVMemBucket -LabelProp "VMemRangeGB")
</div>
<div class="subhead">Thin / Thick Disk Count</div>
$(ConvertTo-TableCard -InnerHtml (ConvertTo-HtmlTable -Data $distribution.ByDiskFormat))
</section>

<section style="--accent:#059669">
$(ConvertTo-SectionHead -Id "shared" -Title "9. Shared (Multi-Writer) Virtual Disks" -Desc "VMDKs configured with multi-writer sharing")
$(ConvertTo-TableCard -InnerHtml (ConvertTo-HtmlTable -Data $sharedDisks))
</section>

<section style="--accent:#ea580c">
$(ConvertTo-SectionHead -Id "rdm" -Title "10. RDM (Raw Device Mapping) Disks" -Desc "Physical and virtual RDM-mapped disks")
$(ConvertTo-TableCard -InnerHtml (ConvertTo-HtmlTable -Data $rdmDisks))
</section>

<section style="--accent:#e11d48">
$(ConvertTo-SectionHead -Id "summary" -Title "11. VM Performance Distribution Summary" -Desc "Normal / Warning / Critical share by category")
<div class="card">
$(ConvertTo-StackedBarSummary -PerfDistributionRows $perfDistribution)
</div>
</section>

<div class="foot">Full detail for every section is available in the CSV files in this folder.</div>
</div>
</body>
</html>
"@

    $html | Out-File -FilePath $htmlPath -Encoding UTF8
    Write-Host "Report generated: $htmlPath"

    Write-Host "`n[Export] Generating email-safe HTML (table-based, inline styles)..."
    $emailHtmlPath = "$OutputFolder\EmailReport_$dateStr.html"
    $emailHtml = Get-EmailHtmlReport -VCenterServer $maskedVCenterServer -DaysBack $DaysBack -DateStr $dateStr `
        -Inventory $inventory -Perf $perf -Storage $storage -VmPerf $vmPerf `
        -OldSnapshots $oldSnapshots -ConnectedDevices $connectedDevices -Distribution $distribution `
        -SharedDisks $sharedDisks -RdmDisks $rdmDisks -PerfDistribution $perfDistribution
    $emailHtml | Out-File -FilePath $emailHtmlPath -Encoding UTF8
    Write-Host "Email-safe report generated: $emailHtmlPath"
}

# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

try {

    Write-Host "`n=== Starting vCenter Comprehensive Report collection ===" -ForegroundColor Cyan

    Write-Host "`n--- Login: vCenter ---"
    if (-not $VCenterServer) {
        $VCenterServer = (Read-Host "vCenter server address(es) - comma-separated for multiple") -split "," | ForEach-Object { $_.Trim() } | Where-Object { $_ }
    }
    if (-not $VCenterServer -or $VCenterServer.Count -eq 0) {
        Write-Error "No vCenter server address was entered. Re-run the script and provide at least one address (or pass -VCenterServer)."
        return
    }
    if (-not $VCenterCredential) { $VCenterCredential = Get-Credential -Message "vCenter credentials" }
    if (-not $VCenterCredential) {
        # Get-Credential returns $null if the prompt is cancelled (Esc/Cancel) - passing that
        # straight into Connect-VIServer's -Credential (typed as PSCredential) produces a
        # generic, unhelpful .NET ArgumentException instead of a clear message.
        Write-Error "No credentials were provided (the credential prompt may have been cancelled). Re-run the script and complete the credential prompt, or pass -VCenterCredential."
        return
    }

    Write-Host "`n[Connect] Connecting to vCenter: $($VCenterServer -join ', ')..."
    Connect-VIServer -Server $VCenterServer -Credential $VCenterCredential -Force | Out-Null

    Invoke-ComprehensiveVCenterReport -VCenterServer $VCenterServer -DaysBack $DaysBack `
        -SnapshotAgeDays $SnapshotAgeDays -OutputFolder $OutputFolder

    Write-Host "`n=== Done ===" -ForegroundColor Green
}
catch {
    Write-Host ""
    Write-Host "=== FAILED ===" -ForegroundColor Red
    Write-Host "Exception type : $($_.Exception.GetType().FullName)" -ForegroundColor Red
    Write-Host "Message        : $($_.Exception.Message)" -ForegroundColor Red
    Write-Host "Position       : $($_.InvocationInfo.PositionMessage)" -ForegroundColor Red
    if ($_.ScriptStackTrace) {
        Write-Host "Script stack trace:" -ForegroundColor Red
        Write-Host $_.ScriptStackTrace -ForegroundColor Red
    }
    return
}
finally {
    if ($VCenterServer) {
        Disconnect-VIServer -Server $VCenterServer -Confirm:$false -ErrorAction SilentlyContinue
    }
}
}

function Invoke-VmsaDownloaderTool {
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
    return
}

$ErrorActionPreference = "Stop"
$CurrentDir = Join-Path $OutputRoot "vmsa"
if (-not (Test-Path $CurrentDir)) { New-Item -ItemType Directory -Force -Path $CurrentDir | Out-Null }

$Timestamp      = Get-Date -Format "yyyyMMdd-HHmm"
$CsvAllPath     = Join-Path $CurrentDir "VMSA_All_Advisories_$Timestamp.csv"
$CsvCveListPath = Join-Path $CurrentDir "VMSA_CVE_List_$Timestamp.csv"
$JsonPath       = Join-Path $RepoRoot "VMSA_FullList_Data.json"   # fixed name, kept at the repo root (not output\vmsa) - incremental cache, merged/re-saved in place on every run

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
    return
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

function splitCols(row) {
  return row.split("|").map(function (c) { return c.trim(); });
}

// A handful of older advisories carry stray non-matrix fragments in their
// FixedInfo text alongside the real rows - a leftover metadata label
// ("Advisory ID: | VMSA-2025-0012.1"), the column header itself echoed back
// as if it were a data row ("VMware Product | Version | Running On | ..."),
// or a broken HTML/CSS remnant ("#000000;">Workarounds:None."). None of
// these are an actual Response Matrix row, so splitMatrixRows filters them
// out below rather than letting a bogus "product" reach mapRow().
function isJunkMatrixRow(cols) {
  if (cols.length < 2) return true;
  const first = (cols[0] || "").trim();
  if (!first) return true;
  if (/:\s*$/.test(first)) return true;
  if (/^(VMware\s*Product|Product|Version|CVE\(s\))$/i.test(first)) return true;
  if (/^#[0-9A-Fa-f]/.test(first)) return true;
  return false;
}

function splitMatrixRows(fixedInfo) {
  if (!fixedInfo || fixedInfo === "Check Link for details") return [];
  return fixedInfo.split(/<br\s*\/?>/i)
    .map(function (r) { return r.trim(); })
    .filter(Boolean)
    .filter(function (r) { return !isJunkMatrixRow(splitCols(r)); });
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
// Column 2 can itself legitimately be the literal text "N/A" for a
// standalone (non-bundled) product row - that still counts as "Component
// present" here (it is NOT itself version-like), so the real Version is
// still correctly read from column 3 rather than column 2's "N/A" landing
// in the version slot and shifting every later column (Running On, CVE,
// ...) by one.
function extractProductVersion(cols) {
  const product = cols[0] || "";
  const col1 = cols.length > 1 ? cols[1] : "";
  const col2 = cols.length > 2 ? cols[2] : "";
  const looksLikeVersion = function (v) { return /^\d/.test(v || ""); };
  const isEmptyish = function (v) { return !v || /^(n\/a|-)$/i.test(v); };

  let component = null, version = "", dataStartIdx = 2;
  if (cols.length >= 3 && !looksLikeVersion(col1) && looksLikeVersion(col2)) {
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

  // Only treat Component as real when it actually carries a value - an
  // explicit "N/A"/blank Component is just "no component", same as a row
  // that never had the column at all, so mapRow()'s "Product (Component)"
  // suffix stays off ("VMware ESX", not "VMware ESX (N/A)").
  if (component !== null && isEmptyish(component)) {
    component = null;
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

# A handful of older advisories carry stray non-matrix fragments in their
# FixedInfo text alongside the real rows - a leftover metadata label
# ("Advisory ID: | VMSA-2025-0012.1"), the column header itself echoed back
# as if it were a data row ("VMware Product | Version | Running On | ..."),
# or a broken HTML/CSS remnant ("#000000;">Workarounds:None."). None of
# these are an actual Response Matrix row, so both row-splitting functions
# below (Get-ProductVersionPairsFromFixedInfo and Get-MatrixTableRows) skip
# them via this check rather than risking a bogus "product" leaking through.
function Test-IsJunkMatrixRow {
    param([string[]]$Cols)
    if ($Cols.Count -lt 2) { return $true }
    $first = $Cols[0].Trim()
    if ([string]::IsNullOrWhiteSpace($first)) { return $true }
    if ($first -match ":\s*$") { return $true }
    if ($first -match "(?i)^(VMware\s*Product|Product|Version|CVE\(s\))$") { return $true }
    if ($first -match "^#[0-9A-Fa-f]") { return $true }
    return $false
}

# Pulls every (Product, Version) pair out of a Response Matrix - one pair per
# row, straight from columns 1 and 2.
function Get-ProductVersionPairsFromFixedInfo {
    param([string]$FixedInfo)

    $Pairs = New-Object System.Collections.Generic.List[Object]
    if ([string]::IsNullOrWhiteSpace($FixedInfo) -or $FixedInfo -eq "Check Link for details") { return $Pairs }

    foreach ($row in ($FixedInfo -split "<br>")) {
        $Cols = @($row -split "\s*\|\s*" | ForEach-Object { $_.Trim() })
        if (Test-IsJunkMatrixRow -Cols $Cols) { continue }
        $product = $Cols[0]
        if ([string]::IsNullOrWhiteSpace($product) -or $product -match "^(N/A|-)$") { continue }

        # Most rows are "Product | Version | ...". Some (VMware Cloud
        # Foundation / vSphere Foundation bundle advisories) are instead
        # "Product | Component | Version | ..." - column 2 names the actual
        # affected component (e.g. "vCenter Server", "ESXi", "NSX") rather
        # than a version. Detect that shape by checking whether column 2
        # itself looks like a version (starts with a digit); if it doesn't,
        # treat it as a Component and read the Version from column 3 instead.
        # Column 2 can itself legitimately be the literal text "N/A" for a
        # standalone (non-bundled) product row - that still counts as
        # "Component present" here (it is NOT itself version-like), so the
        # real Version is still correctly read from column 3 rather than
        # column 2's "N/A" landing in the version slot and getting the whole
        # row dropped below.
        $component = $null
        $version   = $null
        if ($Cols.Count -ge 3 -and $Cols[1] -notmatch "^\d" -and $Cols[2] -match "^\d") {
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
        # any, and only when it carries a real value - a literal "N/A"
        # Component contributes nothing to the match text), so e.g. a VCF
        # row whose Component is "vCenter Server" still lands in the vCenter
        # category/CSV, using ITS OWN version.
        $matchText = if ($component -and $component -notmatch "^(?i)(N/A|-)$") { "$product $component" } else { $product }

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

# =============================================================================
# 8. Write per-category Excel workbooks - same 8 categories as the CSV split
#    above (reusing $CategoryMap / $CategoryDefs already built in Step 7), but
#    as .xlsx workbooks with ONE WORKSHEET PER VMSA ADVISORY, each sheet
#    rendering that advisory's Response Matrix as a real Excel table. An
#    advisory with no usable Response Matrix is skipped (no sheet); a
#    category with zero qualifying advisories gets no workbook file at all.
#    Requires the "ImportExcel" PowerShell module (installed automatically
#    for the current user if missing) - no Microsoft Excel installation is
#    needed, it writes .xlsx files directly.
# =============================================================================
Write-Host "[8] Writing per-category Excel workbooks (one worksheet per VMSA with a Response Matrix)..." -ForegroundColor Cyan

$ExcelModuleOk = $true
if (-not (Get-Module -ListAvailable -Name ImportExcel)) {
    try {
        Write-Host "    ImportExcel module not found - installing for current user..." -ForegroundColor Yellow
        Install-Module -Name ImportExcel -Scope CurrentUser -Force -AllowClobber -ErrorAction Stop
    } catch {
        Write-Warning "    Could not install the ImportExcel module ($($_.Exception.Message)) - skipping Excel workbook generation. CSV/JSON/HTML outputs above are unaffected."
        $ExcelModuleOk = $false
    }
}
if ($ExcelModuleOk) {
    try {
        Import-Module ImportExcel -ErrorAction Stop
    } catch {
        Write-Warning "    Could not load the ImportExcel module ($($_.Exception.Message)) - skipping Excel workbook generation."
        $ExcelModuleOk = $false
    }
}

if ($ExcelModuleOk) {

# Same 9 columns as the HTML report's matrix table (MATRIX_HEADERS), so the
# Excel output and the HTML report always agree on layout.
$MatrixHeaders = @("VMware Product","Version","Running On","CVE","CVSSv3","Severity","Fixed Version","Workarounds","Additional Documentation")

# Splits one "Product | Version | ..." (or "Product | Component | Version |
# ...") Response Matrix row into the same 9 mapped columns as the HTML
# report's client-side mapRow()/extractProductVersion() functions, so the
# Excel table and the HTML table always show the same thing for the same row.
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

# Turns one advisory's FixedInfo string into an array of mapped 9-column
# row objects (empty array = "no usable Response Matrix" -> caller skips it).
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

# Converts a 1-based column number to its Excel letter (1->A, 26->Z, 27->AA).
function Get-ExcelColumnLetter {
    param([int]$ColumnNumber)
    $letter = ""
    $n = $ColumnNumber
    while ($n -gt 0) {
        $rem = ($n - 1) % 26
        $letter = [char](65 + $rem) + $letter
        $n = [int](($n - $rem - 1) / 26)
    }
    return $letter
}

# Writes one cell by (row, column) using a string address ("B5") rather than
# the worksheet's [row, col] numeric indexer - on some ImportExcel/EPPlus
# version combinations that numeric two-argument indexer does not bind the
# way PowerShell expects and .Cells[$row,$col] comes back as an object with
# no .Value property ("PropertyAssignmentException"). Addressing by string
# ("A1" style) is the indexer overload that reliably works everywhere.
function Set-CellValue {
    param($Worksheet, [int]$Row, [int]$Col, $Value, [switch]$Bold)
    $addr = "$(Get-ExcelColumnLetter -ColumnNumber $Col)$Row"
    $Worksheet.Cells[$addr].Value = $Value
    if ($Bold) { $Worksheet.Cells[$addr].Style.Font.Bold = $true }
}

# Builds an "A1:I20"-style range address string from two (row,col) corners.
function Get-ExcelRangeAddress {
    param([int]$StartRow, [int]$StartCol, [int]$EndRow, [int]$EndCol)
    $startAddr = "$(Get-ExcelColumnLetter -ColumnNumber $StartCol)$StartRow"
    $endAddr   = "$(Get-ExcelColumnLetter -ColumnNumber $EndCol)$EndRow"
    return "$startAddr`:$endAddr"
}

# Excel worksheet names: max 31 chars, and \ / ? * [ ] : are illegal - also
# de-duplicates in the (normally impossible) case two AdvisoryIDs collide
# after sanitizing.
function ConvertTo-SafeSheetName {
    param([string]$Name, [System.Collections.Generic.List[string]]$UsedNames)

    $safe = ($Name -replace '[\\/\?\*\[\]:]', '_').Trim()
    if ([string]::IsNullOrWhiteSpace($safe)) { $safe = "Sheet" }
    if ($safe.Length -gt 31) { $safe = $safe.Substring(0, 31) }

    $base = $safe
    $n = 1
    while ($UsedNames.Contains($safe)) {
        $suffix  = "_$n"
        $maxBase = [Math]::Max(1, 31 - $suffix.Length)
        $safe    = $base.Substring(0, [Math]::Min($base.Length, $maxBase)) + $suffix
        $n++
    }
    return $safe
}

$ExcelDir = Join-Path $CurrentDir "VMSA_Excel_$Timestamp"
New-Item -ItemType Directory -Path $ExcelDir -Force | Out-Null

$ExcelSummary = New-Object System.Collections.Generic.List[Object]

foreach ($catName in $CategoryDefs.Keys) {
    $SafeName  = ConvertTo-SafeFileName -Name $catName
    $ExcelPath = Join-Path $ExcelDir "VMSA_$SafeName.xlsx"
    if (Test-Path $ExcelPath) { Remove-Item $ExcelPath -Force }

    $Entries = @($CategoryMap[$catName].Values | Sort-Object { $_.Record.Published } -Descending)

    # Pre-filter to advisories that actually have usable Response Matrix rows -
    # an advisory whose FixedInfo is blank/"Check Link for details", or whose
    # every row fails to yield even a Product name, never gets a block below
    # (nothing left over to clean up afterwards).
    $Qualifying = New-Object System.Collections.Generic.List[Object]
    foreach ($entry in $Entries) {
        $MatrixRows = Get-MatrixTableRows -FixedInfo $entry.Record.FixedInfo
        if ($MatrixRows.Count -gt 0) {
            $Qualifying.Add([PSCustomObject]@{ Record = $entry.Record; Rows = $MatrixRows })
        }
    }

    if ($Qualifying.Count -eq 0) {
        $ExcelSummary.Add([PSCustomObject]@{ Category = $catName; Advisories = 0; File = "(skipped - no Response Matrix data)" })
        continue
    }

    $pkg       = Open-ExcelPackage -Path $ExcelPath -Create
    $SheetName = ConvertTo-SafeSheetName -Name $catName -UsedNames (New-Object System.Collections.Generic.List[string])
    $ws        = Add-Worksheet -ExcelPackage $pkg -WorksheetName $SheetName

    # Single worksheet: every qualifying advisory's meta info + its Response
    # Matrix table, stacked one block after another going down the sheet,
    # newest advisory first (same order as the category CSV).
    $r = 1
    $BlockIndex = 0
    foreach ($q in $Qualifying) {
        $rec = $q.Record
        $BlockIndex++

        # --- Advisory meta block (Field/Value pair rows) ---
        $MetaPairs = @(
            @("Advisory ID", $rec.AdvisoryID),
            @("Title",       $rec.Title),
            @("Severity",    $rec.Severity),
            @("CVSS",        $rec.CVSS),
            @("Published",   $rec.Published),
            @("Link",        $rec.Link)
        )
        foreach ($pair in $MetaPairs) {
            Set-CellValue -Worksheet $ws -Row $r -Col 1 -Value $pair[0] -Bold
            Set-CellValue -Worksheet $ws -Row $r -Col 2 -Value $pair[1]
            $r++
        }
        $r++   # blank row before this advisory's Response Matrix table

        # --- Response Matrix table (header row + one row per matrix entry) ---
        $TableStartRow = $r
        for ($c = 0; $c -lt $MatrixHeaders.Count; $c++) {
            Set-CellValue -Worksheet $ws -Row $TableStartRow -Col ($c + 1) -Value $MatrixHeaders[$c] -Bold
        }
        $rr = $TableStartRow + 1
        foreach ($row in $q.Rows) {
            Set-CellValue -Worksheet $ws -Row $rr -Col 1 -Value $row.'VMware Product'
            Set-CellValue -Worksheet $ws -Row $rr -Col 2 -Value $row.'Version'
            Set-CellValue -Worksheet $ws -Row $rr -Col 3 -Value $row.'Running On'
            Set-CellValue -Worksheet $ws -Row $rr -Col 4 -Value $row.'CVE'
            Set-CellValue -Worksheet $ws -Row $rr -Col 5 -Value $row.'CVSSv3'
            Set-CellValue -Worksheet $ws -Row $rr -Col 6 -Value $row.'Severity'
            Set-CellValue -Worksheet $ws -Row $rr -Col 7 -Value $row.'Fixed Version'
            Set-CellValue -Worksheet $ws -Row $rr -Col 8 -Value $row.'Workarounds'
            Set-CellValue -Worksheet $ws -Row $rr -Col 9 -Value $row.'Additional Documentation'
            $rr++
        }
        $TableEndRow = $rr - 1

        $RangeAddr  = Get-ExcelRangeAddress -StartRow $TableStartRow -StartCol 1 -EndRow $TableEndRow -EndCol $MatrixHeaders.Count
        $TableRange = $ws.Cells[$RangeAddr]
        $TableName  = "Matrix_$BlockIndex`_" + ($rec.AdvisoryID -replace '[^A-Za-z0-9_]', '_')
        Add-ExcelTable -Range $TableRange -TableName $TableName -TableStyle Medium9

        $r = $TableEndRow + 3   # two blank rows before the next advisory's block
    }

    if ($ws.Dimension) { $ws.Cells[$ws.Dimension.Address].AutoFitColumns() }
    Close-ExcelPackage -ExcelPackage $pkg
    $ExcelSummary.Add([PSCustomObject]@{ Category = $catName; Advisories = $Qualifying.Count; File = $ExcelPath })
}

Write-Host "    -> Excel workbooks written to $ExcelDir" -ForegroundColor Gray
$ExcelSummary | ForEach-Object {
    $fileLabel = if ($_.Advisories -gt 0) { Split-Path $_.File -Leaf } else { $_.File }
    Write-Host ("       {0,-28} {1,4} advisory(ies) -> {2}" -f $_.Category, $_.Advisories, $fileLabel) -ForegroundColor Gray
}

} # end if $ExcelModuleOk

Write-Host "`n[DONE] Total: $($AllRecords.Count) | New this run: $($NewRecords.Count) | Reused: $KnownCount | Unique CVEs: $($CveIndex.Count) | Category CSVs: $CategoryCsvDir | Category Excel: $ExcelDir" -ForegroundColor Green
}

function Invoke-VmsaCveLookupTool {
param(
    [Parameter(Mandatory = $true)]
    [string]$CveListCsv,          # path to a CSV with a "CVE" column (AdvisoryIDs/AdvisoryCount optional)
    [string]$NvdApiKey = "",      # optional NVD API key - raises the allowed request rate
    [int]$DelayMs = 0,            # 0 = auto (6200ms without a key, 650ms with one)
    [switch]$ForceRefreshAll      # ignore CVE_Lookup_Cache.json and re-fetch every CVE
)


$ErrorActionPreference = "Stop"
$CurrentDir = Join-Path $OutputRoot "vmsa"
if (-not (Test-Path $CurrentDir)) { New-Item -ItemType Directory -Force -Path $CurrentDir | Out-Null }

if (-not (Test-Path -LiteralPath $CveListCsv)) {
    Write-Error "Input CSV not found: $CveListCsv"
    return
}

if ($DelayMs -le 0) {
    $DelayMs = if ([string]::IsNullOrWhiteSpace($NvdApiKey)) { 6200 } else { 650 }
}

$Timestamp     = Get-Date -Format "yyyyMMdd-HHmm"
# Cache JSON stays right next to the script (fixed name, no timestamp, no
# subfolder) so every run - regardless of output folder - finds and reuses
# it. The CSV/HTML results for THIS run go into their own timestamped output
# folder instead of being dropped loose next to the script.
$CachePath     = Join-Path $RepoRoot "CVE_Lookup_Cache.json"   # kept at the repo root (not output\vmsa) - incremental cache, merged/re-saved in place on every run
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
    return
}
if (-not ($InputRows[0].PSObject.Properties.Name -contains "CVE")) {
    Write-Error "$CveListCsv has no 'CVE' column. Expected a CSV like VMSA_CVE_List_<timestamp>.csv."
    return
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
}

function Invoke-VmsaEnvironmentReportTool {
param(
    [string]$JsonFileName       = "VMSA_FullList_Data.json",
    [string]$DownloaderScriptName = "vmsa_fulllist_downloader.ps1",
    [string]$OutputFolderName  = "vmsa_environment",  # fixed subfolder (created next to this script) that the CSV/HTML outputs are saved into
    [bool]$IgnoreInvalidCertificate = $true,   # most internal vCenters use a self-signed/internal-CA certificate
    [switch]$SkipCveLookup                     # force-skip the CVE_Lookup_<date-time> folder even if one is present
    ,[string]$SharedVcAddress
    ,[System.Management.Automation.PSCredential]$SharedCredential
)


$ErrorActionPreference = "Stop"
$ScriptDir = Join-Path $OutputRoot "vmsa"
if (-not (Test-Path $ScriptDir)) { New-Item -ItemType Directory -Force -Path $ScriptDir | Out-Null }

# The dataset (and the downloader that can generate it) are looked up next
# to the script itself, same as always - only the CSV/HTML OUTPUTS below go
# into their own fixed subfolder so repeated runs don't clutter the script's
# own folder.
$OutputDir = Join-Path $ScriptDir $OutputFolderName
New-Item -ItemType Directory -Path $OutputDir -Force | Out-Null

$Timestamp = Get-Date -Format "yyyyMMdd-HHmm"
$JsonPath  = Join-Path $RepoRoot $JsonFileName   # repo root - matches where Invoke-VmsaDownloaderTool writes/maintains it, not $ScriptDir/output\vmsa
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
    Write-Host "    -> $JsonFileName not found next to this script - running the VMSA downloader tool to generate it" -ForegroundColor Yellow
    Write-Host "       (this calls the internet-facing Broadcom API - make sure this machine has that access) ..." -ForegroundColor Yellow
    Invoke-VmsaDownloaderTool
    if (-not (Test-Path $JsonPath)) {
        Write-Error "VMSA downloader ran but $JsonFileName still was not created. Aborting."
        return
    }
}

try {
    $VmsaData = Get-Content -Path $JsonPath -Raw -Encoding UTF8 | ConvertFrom-Json
} catch {
    Write-Error "Failed to read/parse $JsonPath : $($_.Exception.Message)"
    return
}
$AllAdvisories = @($VmsaData.Advisories)
Write-Host "    -> Loaded $($AllAdvisories.Count) advisories (dataset generated $($VmsaData.Metadata.GeneratedAt), last updated $($VmsaData.Metadata.LastUpdatedAt))." -ForegroundColor Green

# =============================================================================
# 1. Prompt for vCenter connection details
# =============================================================================
Write-Host "`n[1] vCenter connection" -ForegroundColor Cyan
if ($SharedVcAddress -and $SharedCredential) {
    $VcServer = $SharedVcAddress
    $VcCredential = $SharedCredential
    Write-Host "    Using the vCenter login already entered above." -ForegroundColor Gray
}
else {
    $VcServer = Read-Host "    vCenter host/IP (FQDN or IP address)"
    if ([string]::IsNullOrWhiteSpace($VcServer)) {
        Write-Error "No vCenter host/IP entered. Aborting."
        return
    }
    $VcUser = Read-Host "    Username (e.g. administrator@vsphere.local)"
    if ([string]::IsNullOrWhiteSpace($VcUser)) {
        Write-Error "No username entered. Aborting."
        return
    }
    $VcSecurePassword = Read-Host "    Password" -AsSecureString
    $VcCredential = New-Object System.Management.Automation.PSCredential($VcUser, $VcSecurePassword)
}

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
        return
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
    return
} finally {
    # Runs even after the return above (finally always executes when leaving a
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
}

function Invoke-KisaEsxAuditTool {
[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [string]$Server,

    [System.Management.Automation.PSCredential]$Credential,

    [System.Management.Automation.PSCredential]$HostCredential,

    [switch]$IgnoreCertificate,

    [string]$OutputDir = (Join-Path $OutputRoot "kisa_esx\output_esxi"),

    [string]$ReportBaseName,

    [int]$SnapshotDaysThreshold = 30
)


#region 초기화 -----------------------------------------------------------------

$ErrorActionPreference = 'Stop'

if (-not (Test-Path -Path $OutputDir)) {
    New-Item -ItemType Directory -Path $OutputDir -Force | Out-Null
}
$OutputDir = (Resolve-Path -Path $OutputDir).Path

if (-not $ReportBaseName) {
    $ts = Get-Date -Format 'yyyyMMdd_HHmmss'
    $ReportBaseName = "kisa_virtualization_report_$ts"
}
$ReportPath = Join-Path -Path $OutputDir -ChildPath "$ReportBaseName.txt"
$CsvPath = Join-Path -Path $OutputDir -ChildPath "$ReportBaseName.csv"
$HtmlPath = Join-Path -Path $OutputDir -ChildPath "$ReportBaseName.html"

# 결과 저장용 리스트 (HostName 포함 - 호스트별 구분/정렬에 사용)
$script:Results = New-Object System.Collections.Generic.List[object]

function Write-Log {
    param([string]$Message)
    Write-Host $Message
    Add-Content -Path $ReportPath -Value $Message
}

function Write-Section {
    param([string]$Title)
    Write-Log ''
    Write-Log ('=' * 79)
    Write-Log "  $Title"
    Write-Log ('=' * 79)
}

function Add-Result {
    param(
        [string]$HostName,
        [string]$Code,
        [string]$Title,
        [string]$Importance,
        [ValidateSet('PASS', 'FAIL', 'WARN', 'MANUAL', 'ERROR')]
        [string]$Status,
        [string]$Detail
    )
    $script:Results.Add([PSCustomObject]@{
        HostName   = $HostName
        Code       = $Code
        Title      = $Title
        Importance = $Importance
        Status     = $Status
        Detail     = $Detail
    })

    $color = switch ($Status) {
        'PASS'   { 'Green' }
        'FAIL'   { 'Red' }
        'WARN'   { 'Yellow' }
        'MANUAL' { 'Cyan' }
        default  { 'Magenta' }
    }
    Write-Host "[$Status] $Code ($Importance) $Title" -ForegroundColor $color
    Write-Host "        -> $Detail"
    Add-Content -Path $ReportPath -Value "[$Status] $Code ($Importance) $Title"
    Add-Content -Path $ReportPath -Value "        -> $Detail"
}

function Sort-KisaResults {
    param($Results)
    $Results | Sort-Object HostName, { [int]($_.Code -replace '\D', '') }
}

# PowerCLI 모듈 로드
try {
    if (-not (Get-Module -Name VMware.VimAutomation.Core -ListAvailable -ErrorAction SilentlyContinue) `
        -and -not (Get-Module -Name VMware.PowerCLI -ListAvailable -ErrorAction SilentlyContinue)) {
        throw "Could not find the PowerCLI module. Install it with 'Install-Module VMware.PowerCLI -Scope CurrentUser' and run this again."
    }
    Import-Module VMware.VimAutomation.Core -ErrorAction SilentlyContinue | Out-Null
}
catch {
    Write-Error $_
    return
}

if ($IgnoreCertificate) {
    Set-PowerCLIConfiguration -InvalidCertificateAction Ignore -Confirm:$false -Scope Session | Out-Null
}
Set-PowerCLIConfiguration -ParticipateInCeip:$false -Confirm:$false -Scope Session -ErrorAction SilentlyContinue | Out-Null

if (-not $Credential) {
    $Credential = Get-Credential -Message "Enter vSphere login credentials (e.g. root, or a vCenter account)"
}
if (-not $HostCredential) {
    $HostCredential = $Credential
}

Write-Log "KISA Virtualization Security Audit - Script Execution Results (PowerCLI)"
Write-Log "Run time     : $(Get-Date)"
Write-Log "Target server: $Server"
Write-Log "Output folder: $OutputDir"
Write-Log "Report file  : $ReportPath (CSV/HTML created at the same path)"

try {
    $null = Connect-VIServer -Server $Server -Credential $Credential -ErrorAction Stop
}
catch {
    Write-Error "Failed to connect to vCenter/ESXi: $($_.Exception.Message)"
    return
}

#endregion

#region 헬퍼 함수 ---------------------------------------------------------------

function Get-AdvSettingValue {
    param($Entity, [string]$Name)
    try {
        $s = Get-AdvancedSetting -Entity $Entity -Name $Name -ErrorAction Stop
        if ($s) { return $s.Value }
        return $null
    } catch { return $null }
}

function New-KisaHtmlReport {
    param(
        [System.Collections.Generic.List[object]]$Results,
        [string]$Path,
        [string]$ServerName,
        [int]$HostCount
    )

    $enc = { param($s) [System.Net.WebUtility]::HtmlEncode([string]$s) }

    $pass = ($Results | Where-Object Status -eq 'PASS').Count
    $fail = ($Results | Where-Object Status -eq 'FAIL').Count
    $warn = ($Results | Where-Object Status -eq 'WARN').Count
    $manual = ($Results | Where-Object Status -eq 'MANUAL').Count
    $errorCnt = ($Results | Where-Object Status -eq 'ERROR').Count

    $sorted = Sort-KisaResults -Results $Results
    $hostGroups = $sorted | Group-Object HostName

    $hostBlocks = foreach ($grp in $hostGroups) {
        $hp = ($grp.Group | Where-Object Status -eq 'PASS').Count
        $hf = ($grp.Group | Where-Object Status -eq 'FAIL').Count
        $hw = ($grp.Group | Where-Object Status -eq 'WARN').Count
        $hm = ($grp.Group | Where-Object Status -eq 'MANUAL').Count
        $he = ($grp.Group | Where-Object Status -eq 'ERROR').Count

        $rows = foreach ($r in $grp.Group) {
            @"
<tr class="row" data-status="$($r.Status)"><td>$(& $enc $r.Code)</td><td>$(& $enc $r.Title)</td><td class="imp-$(& $enc $r.Importance)">$(& $enc $r.Importance)</td><td><span class="badge badge-$($r.Status)">$($r.Status)</span></td><td>$(& $enc $r.Detail)</td></tr>
"@
        }

        @"
<details class="host-block" data-host="$(& $enc $grp.Name)">
  <summary>
    <span class="host-name">$(& $enc $grp.Name)</span>
    <span class="host-counts">
      <span class="mini mini-PASS">PASS $hp</span>
      <span class="mini mini-FAIL">FAIL $hf</span>
      <span class="mini mini-WARN">WARN $hw</span>
      <span class="mini mini-MANUAL">MANUAL $hm</span>
      <span class="mini mini-ERROR">ERROR $he</span>
    </span>
  </summary>
  <table>
    <thead>
      <tr><th style="width:70px">코드</th><th style="width:200px">항목</th><th style="width:60px">중요도</th><th style="width:90px">결과</th><th>상세</th></tr>
    </thead>
    <tbody>
$($rows -join "`n")
    </tbody>
  </table>
</details>
"@
    }

    $html = @"
<!doctype html>
<html lang="ko">
<head>
<meta charset="utf-8">
<title>KISA 가상화(vSphere) 보안 점검 리포트</title>
<style>
  :root {
    --grid: #b7c0ca;
    --grid-strong: #7a8794;
  }
  body { font-family: -apple-system, "Malgun Gothic", "Segoe UI", sans-serif; background:#f4f5f7; color:#1f2328; margin:0; padding:24px; }
  h1 { font-size:20px; margin:0 0 4px; }
  h2 { font-size:15px; margin:28px 0 10px; }
  .meta { color:#57606a; font-size:13px; margin-bottom:20px; }
  .cards { display:flex; gap:12px; flex-wrap:wrap; margin-bottom:8px; }
  .card { flex:1; min-width:110px; background:#fff; border:1px solid var(--grid); border-radius:8px; padding:12px 16px; text-align:center;
          cursor:pointer; user-select:none; transition:box-shadow .12s, transform .12s; }
  .card:hover { box-shadow:0 2px 8px rgba(0,0,0,.08); }
  .card.active { box-shadow:0 0 0 2px #24292f inset; background:#f6f8fa; }
  .card .num { font-size:24px; font-weight:700; }
  .card .lbl { font-size:12px; color:#57606a; margin-top:2px; }
  .filter-hint { font-size:12px; color:#57606a; margin:0 0 24px; }
  .PASS   { color:#1a7f37; }
  .FAIL   { color:#cf222e; }
  .WARN   { color:#9a6700; }
  .MANUAL { color:#0969da; }
  .ERROR  { color:#8250df; }
  table { width:100%; border-collapse:collapse; background:#fff; }
  table, th, td { border:1px solid var(--grid); }
  th, td { padding:9px 12px; text-align:left; font-size:13px; vertical-align:top; }
  th { background:#eef1f4; font-size:12px; text-transform:uppercase; letter-spacing:.03em; color:#3a4552; border-bottom:2px solid var(--grid-strong); }
  tr.row:nth-child(even) td { background:#fafbfc; }
  .badge { display:inline-block; padding:2px 8px; border-radius:12px; font-size:12px; font-weight:600; color:#fff; white-space:nowrap; }
  .badge-PASS   { background:#1a7f37; }
  .badge-FAIL   { background:#cf222e; }
  .badge-WARN   { background:#9a6700; }
  .badge-MANUAL { background:#0969da; }
  .badge-ERROR  { background:#8250df; }
  .imp-상 { font-weight:700; }
  .footer-note { margin-top:20px; font-size:12px; color:#57606a; }

  .host-block { background:#fff; border:1px solid var(--grid); border-radius:8px; margin-bottom:10px; overflow:hidden; }
  .host-block > summary { list-style:none; cursor:pointer; padding:12px 16px; display:flex; align-items:center;
                           justify-content:space-between; flex-wrap:wrap; gap:8px; font-weight:600; }
  .host-block > summary::-webkit-details-marker { display:none; }
  .host-block > summary::before { content:"▸"; margin-right:8px; color:#57606a; display:inline-block; transition:transform .12s; }
  .host-block[open] > summary::before { transform:rotate(90deg); }
  .host-block > summary:hover { background:#f6f8fa; }
  .host-name { flex:1; min-width:160px; }
  .host-counts { display:flex; gap:6px; flex-wrap:wrap; font-weight:400; }
  .mini { font-size:11px; padding:2px 7px; border-radius:10px; border:1px solid var(--grid); color:#3a4552; }
  .mini-PASS   { border-color:#1a7f37; color:#1a7f37; }
  .mini-FAIL   { border-color:#cf222e; color:#cf222e; }
  .mini-WARN   { border-color:#9a6700; color:#9a6700; }
  .mini-MANUAL { border-color:#0969da; color:#0969da; }
  .mini-ERROR  { border-color:#8250df; color:#8250df; }
  .host-block table { border-top:2px solid var(--grid-strong); }
</style>
</head>
<body>
<h1>KISA 가상화(vSphere) 보안 점검 리포트</h1>
<div class="meta">
  실행 시각: $(Get-Date) &nbsp;|&nbsp; 대상 서버: $(& $enc $ServerName) &nbsp;|&nbsp; 점검 호스트 수: $HostCount 대
</div>
<div class="cards" id="filterCards">
  <div class="card" data-status="PASS"><div class="num PASS">$pass</div><div class="lbl">PASS 양호</div></div>
  <div class="card" data-status="FAIL"><div class="num FAIL">$fail</div><div class="lbl">FAIL 취약</div></div>
  <div class="card" data-status="WARN"><div class="num WARN">$warn</div><div class="lbl">WARN 주의/권고</div></div>
  <div class="card" data-status="MANUAL"><div class="num MANUAL">$manual</div><div class="lbl">MANUAL 수동확인</div></div>
  <div class="card" data-status="ERROR"><div class="num ERROR">$errorCnt</div><div class="lbl">ERROR 조회실패</div></div>
</div>
<p class="filter-hint">위 카드를 클릭하면 해당 결과만 필터링되어 표시됩니다(다시 클릭하면 전체 보기로 복귀). 호스트 이름을 클릭하면 상세 항목이 펼쳐집니다.</p>

<h2>호스트 목록 (클릭하여 상세 보기)</h2>
<div id="hostList">
$($hostBlocks -join "`n")
</div>

<div class="footer-note">
  * FAIL/WARN 항목은 우선적으로 조치하시고, MANUAL 항목은 조직의 보안정책/운영기록과 대조하여 확인하시기 바랍니다.<br>
  * 근거: KISA 주요정보통신기반시설 기술적 취약점 분석·평가 방법 상세가이드 - 가상화 장비 취약점 분석·평가 항목 (HV-01~HV-25)
</div>

<script>
(function () {
  var activeStatus = null;
  var cards = document.querySelectorAll('#filterCards .card');
  var hostBlocks = document.querySelectorAll('.host-block');

  cards.forEach(function (card) {
    card.addEventListener('click', function () {
      var status = card.getAttribute('data-status');
      activeStatus = (activeStatus === status) ? null : status;
      cards.forEach(function (c) {
        c.classList.toggle('active', c.getAttribute('data-status') === activeStatus);
      });
      applyFilter();
    });
  });

  function applyFilter() {
    hostBlocks.forEach(function (block) {
      var rows = block.querySelectorAll('tr.row');
      var visible = 0;
      rows.forEach(function (row) {
        var show = !activeStatus || row.getAttribute('data-status') === activeStatus;
        row.style.display = show ? '' : 'none';
        if (show) { visible++; }
      });
      if (activeStatus) {
        block.style.display = visible > 0 ? '' : 'none';
        block.open = visible > 0;
      } else {
        block.style.display = '';
      }
    });
  }
})();
</script>
</body>
</html>
"@

    Set-Content -Path $Path -Value $html -Encoding UTF8
}

#endregion

try {
    $VMHosts = Get-VMHost -ErrorAction Stop
    if (-not $VMHosts) { throw "Could not find any ESXi hosts to audit." }

    foreach ($VMHost in $VMHosts) {
        $hn = $VMHost.Name

        Write-Section "[$hn] 1. Account Management (HV-01 ~ HV-07)"

        # ESXi 로컬 계정/SNMP 관련 cmdlet(Get-VMHostAccount, Get-VMHostSnmp)은 -Server 파라미터가
        # "실제 접속(VIServer) 연결"을 요구하며 vCenter로 접속한 상태에서 VMHost 객체를 그대로 넘기면
        # 타입 오류(ERROR)가 발생한다. 이를 해결하기 위해 각 호스트에 대해 별도의 direct 연결을
        # (실패해도 전체 스크립트에는 영향 없도록) 시도한다.
        $hostConn = $null
        $hostConnErrMsg = $null
        try {
            $hostConn = Connect-VIServer -Server $hn -Credential $HostCredential -NotDefault -ErrorAction Stop
        } catch {
            $hostConnErrMsg = $_.Exception.Message
        }

        # --- HV-01 / HV-04 공용: 로컬 계정 목록 조회 ---
        $accounts = $null
        $acctErrMsg = $null
        if ($hostConn) {
            try {
                $accounts = Get-VMHostAccount -Server $hostConn -ErrorAction Stop
            } catch {
                $acctErrMsg = $_.Exception.Message
            }
        }

        # --- HV-01: 기본 관리자 계정 변경 ---
        if ($accounts) {
            $rootAcct = $accounts | Where-Object { $_.Id -eq 'root' }
            Add-Result $hn 'HV-01' '기본 관리자 계정 변경' '상' 'MANUAL' `
                "ESXi는 root 계정명을 변경할 수 없음. root 계정 존재 확인됨(Id=$($rootAcct.Id)). 최초 설치 후 root 비밀번호를 기본값에서 변경했는지는 조직 운영기록으로 별도 확인 필요."
        } elseif ($hostConn) {
            Add-Result $hn 'HV-01' '기본 관리자 계정 변경' '상' 'ERROR' "Get-VMHostAccount 조회 실패: $acctErrMsg"
        } else {
            Add-Result $hn 'HV-01' '기본 관리자 계정 변경' '상' 'MANUAL' `
                "ESXi 호스트에 직접 연결하지 못해 로컬 계정 조회 불가(사유: $hostConnErrMsg). vCenter 계정과 호스트 root 계정이 다른 경우 -HostCredential 파라미터로 호스트 root 계정 정보를 전달하면 자동 점검이 가능합니다."
        }

        # --- HV-02: 비밀번호 복잡성 설정 ---
        $pqc = Get-AdvSettingValue -Entity $VMHost -Name 'Security.PasswordQualityControl'
        if ($null -ne $pqc) {
            if ($pqc -match 'retry\s*=\s*3') {
                Add-Result $hn 'HV-02' '비밀번호 복잡성 설정' '상' 'PASS' "PasswordQualityControl: $pqc"
            } else {
                Add-Result $hn 'HV-02' '비밀번호 복잡성 설정' '상' 'WARN' "현재 값: [$pqc]. 권고 형식(retry=3, 최소 7자 이상 등)과 비교하여 검토 필요."
            }
        } else {
            Add-Result $hn 'HV-02' '비밀번호 복잡성 설정' '상' 'ERROR' "Security.PasswordQualityControl 설정값 조회 실패"
        }

        # --- HV-03: 계정 잠금 임계값 설정 ---
        $lockFail = Get-AdvSettingValue -Entity $VMHost -Name 'Security.AccountLockFailures'
        $unlockTime = Get-AdvSettingValue -Entity $VMHost -Name 'Security.AccountUnlockTime'
        if ($null -ne $lockFail) {
            $lockFailInt = [int]$lockFail
            if ($lockFailInt -gt 0 -and $lockFailInt -le 5) {
                Add-Result $hn 'HV-03' '계정 잠금 임계값 설정' '상' 'PASS' "AccountLockFailures=$lockFailInt (5회 이하), AccountUnlockTime=$unlockTime 초"
            } elseif ($lockFailInt -eq 0) {
                Add-Result $hn 'HV-03' '계정 잠금 임계값 설정' '상' 'FAIL' "AccountLockFailures=0 (계정 잠금 기능 비활성화 상태)"
            } else {
                Add-Result $hn 'HV-03' '계정 잠금 임계값 설정' '상' 'WARN' "AccountLockFailures=$lockFailInt (권고: 5회 이하), AccountUnlockTime=$unlockTime 초"
            }
        } else {
            Add-Result $hn 'HV-03' '계정 잠금 임계값 설정' '상' 'ERROR' "Security.AccountLockFailures 조회 실패"
        }

        # --- HV-04: 불필요한 계정 제거 ---
        if ($accounts) {
            $extra = $accounts | Where-Object { $_.Id -notin @('root', 'dcui', 'vpxuser') }
            if ($extra) {
                Add-Result $hn 'HV-04' '불필요한 계정 제거' '상' 'WARN' `
                    "root/dcui/vpxuser 외 로컬 계정 존재: [$(($extra.Id) -join ', ')] (총 $($accounts.Count)개 계정). 사용 목적 확인 후 불필요 시 제거 권고."
            } else {
                Add-Result $hn 'HV-04' '불필요한 계정 제거' '상' 'PASS' "표준 계정 외 추가 로컬 계정 없음 (총 $($accounts.Count)개)"
            }
        } elseif ($hostConn) {
            Add-Result $hn 'HV-04' '불필요한 계정 제거' '상' 'ERROR' "Get-VMHostAccount 조회 실패: $acctErrMsg"
        } else {
            Add-Result $hn 'HV-04' '불필요한 계정 제거' '상' 'MANUAL' `
                "ESXi 호스트에 직접 연결하지 못해 로컬 계정 조회 불가(사유: $hostConnErrMsg). -HostCredential 파라미터로 호스트 root 계정 정보를 전달하면 자동 점검이 가능합니다."
        }

        # --- HV-05: 관리자 권한 최소화 ---
        try {
            $perms = Get-VIPermission -Entity $VMHost -ErrorAction Stop
            $admins = $perms | Where-Object { $_.Role -like '*Admin*' -and $_.Principal -ne 'root' -and $_.Principal -notlike '*vpxuser*' }
            if ($admins) {
                Add-Result $hn 'HV-05' '관리자 권한 최소화' '상' 'WARN' `
                    "root 외 Admin 계열 권한 보유 계정/그룹: [$(($admins.Principal) -join ', ')]. 최소 인원/그룹으로 제한되어 있는지 확인 필요."
            } else {
                Add-Result $hn 'HV-05' '관리자 권한 최소화' '상' 'PASS' "root 외 Admin 권한이 부여된 계정 없음"
            }
        } catch {
            Add-Result $hn 'HV-05' '관리자 권한 최소화' '상' 'MANUAL' "Get-VIPermission 조회 불가(권한 부족 또는 미지원 환경일 수 있음): $($_.Exception.Message). vSphere Client > 호스트 > 권한 탭에서 수동 확인 필요."
        }

        # --- HV-06: 세션 타임아웃 설정 ---
        $shellInteractive = Get-AdvSettingValue -Entity $VMHost -Name 'UserVars.ESXiShellInteractiveTimeOut'
        $shellTimeout = Get-AdvSettingValue -Entity $VMHost -Name 'UserVars.ESXiShellTimeOut'
        $hostClientTimeout = Get-AdvSettingValue -Entity $VMHost -Name 'UserVars.HostClientSessionTimeout'
        if ($shellInteractive -and [int]$shellInteractive -gt 0) {
            Add-Result $hn 'HV-06' '세션 타임아웃 설정' '중' 'PASS' `
                "ESXiShellInteractiveTimeOut=$shellInteractive 초, ESXiShellTimeOut=$shellTimeout 초, HostClientSessionTimeout=$hostClientTimeout 초"
        } else {
            Add-Result $hn 'HV-06' '세션 타임아웃 설정' '중' 'FAIL' `
                "ESXiShellInteractiveTimeOut=$shellInteractive (0/미설정=무제한). 유휴 세션 자동 종료 시간 설정 필요."
        }

        # --- HV-07: 로그인 경고 메시지 설정 ---
        $welcome = Get-AdvSettingValue -Entity $VMHost -Name 'Annotations.WelcomeMessage'
        if ($welcome) {
            Add-Result $hn 'HV-07' '로그인 경고 메시지 설정' '하' 'PASS' "배너 설정됨: '$welcome'"
        } else {
            Add-Result $hn 'HV-07' '로그인 경고 메시지 설정' '하' 'FAIL' "로그인 경고 배너(Annotations.WelcomeMessage)가 설정되어 있지 않음"
        }

        Write-Section "[$hn] 2. System Service Management (HV-08 ~ HV-16)"

        $services = Get-VMHostService -VMHost $VMHost

        # --- HV-08: 불필요한 서비스 비활성화 ---
        $riskyOn = $services | Where-Object { $_.Running -and $_.Key -in @('TSM-SSH', 'TSM', 'slpd', 'snmpd') }
        if ($riskyOn) {
            Add-Result $hn 'HV-08' '불필요한 서비스 비활성화' '상' 'WARN' `
                "실행 중인 위험 서비스: [$(($riskyOn.Key) -join ', ')]. 업무상 필요 여부 확인 후 불필요 시 Set-VMHostService/Stop-VMHostService 로 비활성화."
        } else {
            Add-Result $hn 'HV-08' '불필요한 서비스 비활성화' '상' 'PASS' "SSH/ESXi Shell/SLP/SNMP 등 대표적 위험 서비스 모두 비활성 상태"
        }

        # --- HV-09: SSH 보안 설정 ---
        $sshSvc = $services | Where-Object { $_.Key -eq 'TSM-SSH' }
        if ($sshSvc -and $sshSvc.Running) {
            Add-Result $hn 'HV-09' 'SSH 보안 설정' '상' 'WARN' `
                "SSH(TSM-SSH) 서비스가 활성화되어 있음. 상시 활성화는 권고되지 않으며 필요 시에만 임시 사용 권고. (root 직접 로그인 제한, 접속 IP 제한 등은 sshd_config 로 별도 확인 필요)"
        } else {
            Add-Result $hn 'HV-09' 'SSH 보안 설정' '상' 'PASS' "SSH(TSM-SSH) 서비스 비활성화 상태"
        }

        # --- HV-10: SNMP 보안 설정 ---
        if ($hostConn) {
            try {
                $snmp = Get-VMHostSnmp -Server $hostConn -ErrorAction Stop
                if ($snmp.Enabled) {
                    if ($snmp.ReadOnlyCommunity -contains 'public') {
                        Add-Result $hn 'HV-10' 'SNMP 보안 설정' '상' 'FAIL' "SNMP 활성화 상태이며 기본 Community 문자열('public') 사용 중"
                    } else {
                        Add-Result $hn 'HV-10' 'SNMP 보안 설정' '상' 'WARN' "SNMP 활성화 상태. Community=[$(($snmp.ReadOnlyCommunity) -join ', ')]. 가능하면 SNMPv3 사용 권고."
                    }
                } else {
                    Add-Result $hn 'HV-10' 'SNMP 보안 설정' '상' 'PASS' "SNMP 비활성화 상태"
                }
            } catch {
                Add-Result $hn 'HV-10' 'SNMP 보안 설정' '상' 'ERROR' "Get-VMHostSnmp 조회 실패: $($_.Exception.Message)"
            }
        } else {
            Add-Result $hn 'HV-10' 'SNMP 보안 설정' '상' 'MANUAL' `
                "ESXi 호스트에 직접 연결하지 못해 SNMP 설정 조회 불가(사유: $hostConnErrMsg). -HostCredential 파라미터로 호스트 root 계정 정보를 전달하면 자동 점검이 가능합니다."
        }

        # --- HV-11: NTP 시각 동기화 ---
        try {
            $ntpServers = Get-VMHostNtpServer -VMHost $VMHost -ErrorAction Stop
            $ntpSvc = $services | Where-Object { $_.Key -eq 'ntpd' }
            if ($ntpServers -and $ntpSvc -and $ntpSvc.Running) {
                Add-Result $hn 'HV-11' 'NTP 시각 동기화' '중' 'PASS' "NTP 서버: [$($ntpServers -join ', ')], ntpd 서비스 실행 중"
            } else {
                Add-Result $hn 'HV-11' 'NTP 시각 동기화' '중' 'FAIL' "NTP 미설정 또는 서비스 미실행 (서버:[$($ntpServers -join ', ')], ntpd 실행:$($ntpSvc.Running))"
            }
        } catch {
            Add-Result $hn 'HV-11' 'NTP 시각 동기화' '중' 'ERROR' "NTP 설정 조회 실패: $($_.Exception.Message)"
        }

        # --- HV-12: 호스트 방화벽 설정 ---
        try {
            $fwEx = Get-VMHostFirewallException -VMHost $VMHost -ErrorAction Stop
            $openAll = $fwEx | Where-Object { $_.Enabled -and $_.ExtensionData.AllowedHosts.AllIp -eq $true }
            if ($openAll) {
                Add-Result $hn 'HV-12' '호스트 방화벽 설정' '상' 'WARN' `
                    "'모든 IP 허용'으로 설정된 활성 방화벽 규칙 존재: [$(($openAll.Name) -join ', ')]. 관리 대역 IP로 제한 권고."
            } else {
                Add-Result $hn 'HV-12' '호스트 방화벽 설정' '상' 'PASS' "활성 방화벽 규칙 중 '모든 IP 허용' 설정 없음"
            }
        } catch {
            Add-Result $hn 'HV-12' '호스트 방화벽 설정' '상' 'ERROR' "Get-VMHostFirewallException 조회 실패: $($_.Exception.Message)"
        }

        # --- HV-13: 보안 패치 적용 ---
        Add-Result $hn 'HV-13' '보안 패치 적용' '상' 'MANUAL' `
            "현재 버전: $($VMHost.Version), 빌드: $($VMHost.Build). 최신 VMware 보안 패치(KB)와 대조하여 수동 확인 필요 (폐쇄망 등 자동 비교 불가 환경 고려)."

        # --- HV-14: 로그 설정 및 관리 ---
        $logHost = Get-AdvSettingValue -Entity $VMHost -Name 'Syslog.global.logHost'
        $logDir = Get-AdvSettingValue -Entity $VMHost -Name 'Syslog.global.logDir'
        if ($logHost) {
            Add-Result $hn 'HV-14' '로그 설정 및 관리' '중' 'PASS' "원격 Syslog 서버 설정됨: [$logHost], 로컬 로그 경로: $logDir"
        } else {
            Add-Result $hn 'HV-14' '로그 설정 및 관리' '중' 'WARN' "원격 Syslog 서버(Syslog.global.logHost)가 설정되어 있지 않음. 로컬 로그 경로: $logDir"
        }

        # --- HV-15: 백업 정책 수립 ---
        Add-Result $hn 'HV-15' '백업 정책 수립' '중' 'MANUAL' `
            "호스트/VM 백업 정책 수립 및 정기 백업 운영 여부는 조직 문서(백업 솔루션 운영기록 등)로 별도 확인 필요."

        # --- HV-16: SSL/TLS 관리 콘솔 암호화 ---
        $disabledProto = Get-AdvSettingValue -Entity $VMHost -Name 'UserVars.ESXiVPsDisabledProtocols'
        if ($disabledProto -and ($disabledProto -match 'sslv3|tlsv1\.0|tlsv1\.1')) {
            Add-Result $hn 'HV-16' 'SSL/TLS 관리 콘솔 암호화' '상' 'PASS' "취약 프로토콜 비활성화 설정됨: [$disabledProto]"
        } else {
            Add-Result $hn 'HV-16' 'SSL/TLS 관리 콘솔 암호화' '상' 'WARN' `
                "ESXiVPsDisabledProtocols=[$disabledProto]. SSLv3/TLSv1.0/1.1 비활성화 및 TLS1.2 이상만 허용 권고."
        }

        if ($hostConn) {
            Disconnect-VIServer -Server $hostConn -Confirm:$false -ErrorAction SilentlyContinue
        }

        Write-Section "[$hn] 3. Virtual Machine Management (HV-17 ~ HV-21)"

        $vms = Get-VM -Location $VMHost -ErrorAction SilentlyContinue

        if (-not $vms) {
            Add-Result $hn 'HV-17' 'VM 간 격리 설정' '상' 'MANUAL' "해당 호스트에 등록된 VM 없음"
            Add-Result $hn 'HV-18' 'VM 리소스 제한 설정' '중' 'MANUAL' "해당 호스트에 등록된 VM 없음"
            Add-Result $hn 'HV-19' 'VM 스냅샷 관리' '중' 'MANUAL' "해당 호스트에 등록된 VM 없음"
            Add-Result $hn 'HV-20' 'VM 이동/복제 시 보안' '상' 'MANUAL' "해당 호스트에 등록된 VM 없음"
            Add-Result $hn 'HV-21' '불필요한 VM 제거' '중' 'MANUAL' "해당 호스트에 등록된 VM 없음"
        } else {
            $isoOptionsMustBeTrue = @(
                'isolation.tools.copy.disable',
                'isolation.tools.dnd.disable',
                'isolation.tools.diskWiper.disable',
                'isolation.tools.diskShrink.disable',
                'isolation.tools.hgfsServerSet.disable'
            )

            $isoBadVms = @(); $resUnlimitedVms = @(); $snapVms = @(); $migRiskVms = @(); $poweroffVms = @()

            foreach ($vm in $vms) {

                # HV-17: VM 간 격리 설정
                $missing = @()
                foreach ($optName in $isoOptionsMustBeTrue) {
                    $val = Get-AdvSettingValue -Entity $vm -Name $optName
                    if (-not $val -or $val.ToString().ToUpper() -ne 'TRUE') { $missing += $optName }
                }
                $guiOptVal = Get-AdvSettingValue -Entity $vm -Name 'isolation.tools.setGUIOptions.enable'
                if (-not $guiOptVal -or $guiOptVal.ToString().ToUpper() -ne 'FALSE') {
                    $missing += 'isolation.tools.setGUIOptions.enable(FALSE 권고)'
                }
                if ($missing.Count -gt 0) { $isoBadVms += $vm.Name }

                # HV-18: 리소스 제한
                try {
                    $resCfg = Get-VMResourceConfiguration -VM $vm -ErrorAction Stop
                    if (-not $resCfg.CpuLimitMhz -or $resCfg.CpuLimitMhz -eq -1) {
                        $resUnlimitedVms += $vm.Name
                    }
                } catch { $resUnlimitedVms += "$($vm.Name)(조회실패)" }

                # HV-19: 스냅샷 관리
                $snaps = Get-Snapshot -VM $vm -ErrorAction SilentlyContinue
                if ($snaps) {
                    foreach ($s in $snaps) {
                        $ageDays = [int]((Get-Date) - $s.Created).TotalDays
                        $snapVms += "$($vm.Name):$($s.Name)(${ageDays}일 경과)"
                    }
                }

                # HV-20: 이동/복제 시 보안 (vMotion 암호화)
                $migEnc = Get-AdvSettingValue -Entity $vm -Name 'migrate.encryption'
                if (-not $migEnc -or $migEnc -eq 'disabled') {
                    $migRiskVms += "$($vm.Name):$(if ($migEnc) { $migEnc } else { '미설정' })"
                }

                # HV-21: 불필요한 VM (전원 꺼짐 목록)
                if ($vm.PowerState -eq 'PoweredOff') { $poweroffVms += $vm.Name }
            }

            if ($isoBadVms.Count -gt 0) {
                Add-Result $hn 'HV-17' 'VM 간 격리 설정' '상' 'WARN' "격리(isolation.tools.*) 옵션이 권고값으로 설정되지 않은 VM: [$($isoBadVms -join ', ')]"
            } else {
                Add-Result $hn 'HV-17' 'VM 간 격리 설정' '상' 'PASS' "전체 $($vms.Count)개 VM에서 주요 isolation.tools.* 옵션 권고값 적용 확인"
            }

            if ($resUnlimitedVms.Count -gt 0) {
                Add-Result $hn 'HV-18' 'VM 리소스 제한 설정' '중' 'WARN' "CPU 리소스 제한이 무제한으로 설정된 VM: [$($resUnlimitedVms -join ', ')] (멀티테넌시/DoS 방지 위해 제한 설정 검토)"
            } else {
                Add-Result $hn 'HV-18' 'VM 리소스 제한 설정' '중' 'PASS' "전체 VM에서 CPU 리소스 제한이 설정됨"
            }

            if ($snapVms.Count -gt 0) {
                $oldCount = ($snapVms | Where-Object { $_ -match '(\d+)일 경과' -and [int]([regex]::Match($_, '(\d+)일 경과').Groups[1].Value) -ge $SnapshotDaysThreshold }).Count
                Add-Result $hn 'HV-19' 'VM 스냅샷 관리' '중' 'WARN' `
                    "잔존 스냅샷: [$($snapVms -join '; ')] (임계값 ${SnapshotDaysThreshold}일 이상 경과 항목: ${oldCount}개 - 정리 권고, 스토리지/성능 영향 주의)"
            } else {
                Add-Result $hn 'HV-19' 'VM 스냅샷 관리' '중' 'PASS' "잔존 스냅샷 없음"
            }

            if ($migRiskVms.Count -gt 0) {
                Add-Result $hn 'HV-20' 'VM 이동/복제 시 보안' '상' 'WARN' "vMotion 암호화(migrate.encryption)가 disabled/미설정인 VM: [$($migRiskVms -join ', ')] (opportunistic 이상 권고)"
            } else {
                Add-Result $hn 'HV-20' 'VM 이동/복제 시 보안' '상' 'PASS' "전체 VM에서 vMotion 암호화 옵션 확인됨"
            }

            if ($poweroffVms.Count -gt 0) {
                Add-Result $hn 'HV-21' '불필요한 VM 제거' '중' 'MANUAL' "전원이 꺼진(Off) VM: [$($poweroffVms -join ', ')] - 운영대장과 대조하여 장기 미사용 시 제거 권고 (자동 판별 불가)"
            } else {
                Add-Result $hn 'HV-21' '불필요한 VM 제거' '중' 'PASS' "전원이 꺼진 상태로 방치된 VM 없음"
            }
        }

        Write-Section "[$hn] 4. Virtual Network Management (HV-22 ~ HV-25)"

        $stdSwitches = Get-VirtualSwitch -VMHost $VMHost -Standard -ErrorAction SilentlyContinue
        $macChangeBad = @(); $forgedBad = @(); $promiscBad = @()

        foreach ($sw in $stdSwitches) {
            try {
                $sec = Get-SecurityPolicy -VirtualSwitch $sw -ErrorAction Stop
                if ($sec.MacChanges) { $macChangeBad += $sw.Name }
                if ($sec.ForgedTransmits) { $forgedBad += $sw.Name }
                if ($sec.AllowPromiscuous) { $promiscBad += $sw.Name }
            } catch { }
        }

        # --- HV-22: 가상 스위치 보안 설정 ---
        if ($macChangeBad.Count -gt 0 -or $forgedBad.Count -gt 0) {
            Add-Result $hn 'HV-22' '가상 스위치 보안 설정' '상' 'WARN' `
                "MAC Address Changes 허용:[$($macChangeBad -join ', ')] / Forged Transmits 허용:[$($forgedBad -join ', ')] -> 모두 Reject 권고"
        } elseif ($stdSwitches.Count -eq 0) {
            Add-Result $hn 'HV-22' '가상 스위치 보안 설정' '상' 'MANUAL' "표준 vSwitch 없음(vDS만 존재 시 vSphere Client에서 별도 확인 필요)"
        } else {
            Add-Result $hn 'HV-22' '가상 스위치 보안 설정' '상' 'PASS' "전체 $($stdSwitches.Count)개 표준 vSwitch에서 MAC 변경/위조 전송 Reject 설정 확인"
        }

        # --- HV-23: VLAN 분리 설정 ---
        $pgList = Get-VirtualPortGroup -VMHost $VMHost -Standard -ErrorAction SilentlyContinue
        $vlan4095 = $pgList | Where-Object { $_.VLanId -eq 4095 }
        if ($vlan4095) {
            Add-Result $hn 'HV-23' 'VLAN 분리 설정' '상' 'FAIL' "VLAN ID 4095(전체 트렁크, VGT)로 설정된 포트그룹: [$(($vlan4095.Name) -join ', ')] - 특정 VLAN으로 제한 필요"
        } else {
            Add-Result $hn 'HV-23' 'VLAN 분리 설정' '상' 'PASS' "VLAN 4095(전체 트렁크) 설정된 포트그룹 없음"
        }

        # --- HV-24: 가상 네트워크 모니터링 (해당 호스트가 속한 vDS 기준) ---
        $hostVds = Get-VDSwitch -VMHost $VMHost -ErrorAction SilentlyContinue
        if ($hostVds) {
            Add-Result $hn 'HV-24' '가상 네트워크 모니터링' '중' 'MANUAL' `
                "이 호스트가 연결된 분산 스위치(vDS): [$(($hostVds.Name) -join ', ')]. NetFlow/포트미러링 세부 설정은 vSphere Client(네트워킹 > vDS > 설정) 에서 별도 확인 필요."
        } else {
            Add-Result $hn 'HV-24' '가상 네트워크 모니터링' '중' 'MANUAL' `
                "표준 vSwitch만 사용 중(연결된 vDS 없음) - NetFlow/포트미러링 기능이 없으므로 외부 IDS/모니터링 솔루션 구성 여부를 별도 확인 필요."
        }

        # --- HV-25: 무차별 모드(Promiscuous Mode) 제한 ---
        if ($promiscBad.Count -gt 0) {
            Add-Result $hn 'HV-25' '무차별 모드(Promiscuous Mode) 제한' '상' 'FAIL' "Promiscuous Mode 허용된 vSwitch: [$($promiscBad -join ', ')] -> Reject로 변경 필요"
        } elseif ($stdSwitches.Count -eq 0) {
            Add-Result $hn 'HV-25' '무차별 모드(Promiscuous Mode) 제한' '상' 'MANUAL' "표준 vSwitch 없음 - vDS 포트그룹은 vSphere Client에서 별도 확인 필요"
        } else {
            Add-Result $hn 'HV-25' '무차별 모드(Promiscuous Mode) 제한' '상' 'PASS' "전체 표준 vSwitch에서 Promiscuous Mode = Reject 확인"
        }
    }

    #region 결과 요약 -----------------------------------------------------------
    Write-Section 'Audit Result Summary'

    $pass = ($script:Results | Where-Object Status -eq 'PASS').Count
    $fail = ($script:Results | Where-Object Status -eq 'FAIL').Count
    $warn = ($script:Results | Where-Object Status -eq 'WARN').Count
    $manual = ($script:Results | Where-Object Status -eq 'MANUAL').Count
    $errorCnt = ($script:Results | Where-Object Status -eq 'ERROR').Count
    $total = $script:Results.Count

    Write-Log "Total results    : $total (hosts $($VMHosts.Count) x 25 items [HV-01~HV-25])"
    Write-Log "  - PASS   (OK)           : $pass"
    Write-Log "  - FAIL   (Vulnerable)   : $fail"
    Write-Log "  - WARN   (Caution)      : $warn"
    Write-Log "  - MANUAL (Needs review) : $manual"
    Write-Log "  - ERROR  (Lookup failed): $errorCnt"

    # 호스트별로 구분되도록, 각 호스트 내에서는 HV-01~HV-25 오름차순으로 정렬하여 CSV/HTML 생성
    $sortedResults = Sort-KisaResults -Results $script:Results

    # CSV는 한글이 깨지지 않도록 BOM 포함 UTF-8로 직접 기록 (PowerShell 버전에 따라
    # Export-Csv -Encoding UTF8 이 BOM 없이 저장되어 Excel에서 한글이 깨지는 문제를 방지)
    $csvLines = $sortedResults | ConvertTo-Csv -NoTypeInformation
    [System.IO.File]::WriteAllLines($CsvPath, $csvLines, (New-Object System.Text.UTF8Encoding($true)))

    New-KisaHtmlReport -Results $sortedResults -Path $HtmlPath -ServerName $Server -HostCount $VMHosts.Count

    Write-Log ''
    Write-Log "Output folder: $OutputDir"
    Write-Log "Detailed results were saved to the following files:"
    Write-Log "  - Text  : $ReportPath"
    Write-Log "  - CSV   : $CsvPath"
    Write-Log "  - HTML  : $HtmlPath"
    #endregion
}
finally {
    Disconnect-VIServer -Server $Server -Confirm:$false -ErrorAction SilentlyContinue
}
}

function Write-Title {
    param([string]$Text)
    Write-Host ""
    Write-Host ("=" * 62) -ForegroundColor Cyan
    Write-Host ("  " + $Text) -ForegroundColor Cyan
    Write-Host ("=" * 62) -ForegroundColor Cyan
}

function Pause-Return {
    Write-Host ""
    Read-Host "Press Enter to return to the menu" | Out-Null
}

# Runs an inlined tool function. Wrapped in try/catch so an error inside the
# tool can't kill this launcher (it no longer calls out to a separate file,
# so there's no Push-Location/Test-Path to worry about either).
function Invoke-ToolFunction {
    param(
        [Parameter(Mandatory)][string]$FunctionName,
        [hashtable]$BoundParameters = @{}
    )

    Write-Host ""
    Write-Host "[RUN] $FunctionName" -ForegroundColor DarkGray
    if ($BoundParameters.Count -gt 0) {
        Write-Host "      Params: $($BoundParameters.Keys -join ', ')" -ForegroundColor DarkGray
    }
    Write-Host ""

    try {
        & $FunctionName @BoundParameters
    }
    catch {
        Write-Host ""
        Write-Host "[ERROR] An exception occurred while running:" -ForegroundColor Red
        Write-Host $_.Exception.Message -ForegroundColor Red
    }

    Pause-Return
}

# Lists the vSphere_Inventory_* folders under output\vcf_9_upgrade and lets
# the user pick one (or type a path directly).
function Select-Vcf9InventoryFolder {
    $vcfDir = Join-Path $OutputRoot "vcf_9_upgrade"
    $invFolders = @(Get-ChildItem -Path $vcfDir -Directory -Filter "vSphere_Inventory_*" -ErrorAction SilentlyContinue |
        Sort-Object LastWriteTime -Descending)

    if ($invFolders.Count -eq 0) {
        Write-Host ""
        Write-Host "[INFO] No vSphere_Inventory_* folder was found under $vcfDir." -ForegroundColor Yellow
        $manual = Read-Host "Enter the inventory folder path directly (Enter to cancel)"
        if ([string]::IsNullOrWhiteSpace($manual)) { return $null }
        return $manual
    }

    Write-Host ""
    Write-Host "Inventory folders under [vcf_9_upgrade] (most recently modified first):" -ForegroundColor Cyan
    for ($i = 0; $i -lt $invFolders.Count; $i++) {
        Write-Host ("  [{0}] {1}  (modified: {2})" -f ($i + 1), $invFolders[$i].Name, $invFolders[$i].LastWriteTime)
    }
    Write-Host "  [0] Enter a path directly"

    $choice = Read-Host "`nSelection"
    if ($choice -eq "0") {
        $manual = Read-Host "Enter the inventory folder path"
        if ([string]::IsNullOrWhiteSpace($manual)) { return $null }
        return $manual
    }

    $idx = 0
    if ([int]::TryParse($choice, [ref]$idx) -and $idx -ge 1 -and $idx -le $invFolders.Count) {
        return $invFolders[$idx - 1].FullName
    }

    Write-Host "Invalid selection." -ForegroundColor Yellow
    return $null
}

# ============================================================
# Sub-menu: VCF 9 Upgrade (vcf_9_upgrade)
#   [1] is the new automatic chain (Change A): inventory collection + HCL
#       compatibility check run back-to-back, then the resulting
#       vSphere_Inventory_* folder is fed straight into the NVMe memory
#       tiering analysis - no submenu, no manual folder selection.
#   [2]-[5] expose the same standalone operations the tool's own internal
#   menu used to offer (NVMe-tiering-only / inventory-only / HCL-check-only /
#   performance-report-only), unchanged - only [1]'s flow is new.
# ============================================================
function Show-Vcf9UpgradeMenu {
    while ($true) {
        Write-Title "VCF 9 Upgrade (vcf_9_upgrade)"
        Write-Host "  [1] Auto: inventory collection + HCL check + NVMe tiering analysis (fully automatic)"
        Write-Host "  [2] NVMe memory tiering analysis only (choose an existing inventory folder)"
        Write-Host "  [3] Inventory collection only"
        Write-Host "  [4] HCL compatibility check only (existing inventory folder)"
        Write-Host "  [5] Performance report only (existing inventory folder)"
        Write-Host "  [0] Back to the main menu"
        $sel = Read-Host "`nSelection"

        switch ($sel) {
            "1" { Invoke-ToolFunction -FunctionName 'Invoke-Vcf9PrecheckToolkitTool' -BoundParameters @{ MenuChoice = '1'; AutoChainToNvmeTiering = $true } }
            "2" {
                $inv = Select-Vcf9InventoryFolder
                if ([string]::IsNullOrWhiteSpace($inv)) {
                    Write-Host "No inventory folder was selected." -ForegroundColor Yellow
                }
                else {
                    $bp = @{ InventoryPath = $inv }

                    $cpu = Read-Host "Max CPU % (Enter = default 80)"
                    if (-not [string]::IsNullOrWhiteSpace($cpu)) { $bp.MaxCpuPct = [double]$cpu }

                    $ratio = Read-Host "Max Active/Alloc memory ratio % (Enter = default 40)"
                    if (-not [string]::IsNullOrWhiteSpace($ratio)) { $bp.MaxActiveRatioPct = [double]$ratio }

                    $factor = Read-Host "Physical/Active memory minimum ratio (Enter = default 2.0)"
                    if (-not [string]::IsNullOrWhiteSpace($factor)) { $bp.PhysMemFactor = [double]$factor }

                    Invoke-ToolFunction -FunctionName 'Invoke-Vcf9NvmeTieringTool' -BoundParameters $bp
                }
            }
            "3" { Invoke-ToolFunction -FunctionName 'Invoke-Vcf9PrecheckToolkitTool' -BoundParameters @{ MenuChoice = '2' } }
            "4" {
                $inv = Select-Vcf9InventoryFolder
                if ([string]::IsNullOrWhiteSpace($inv)) {
                    Write-Host "No inventory folder was selected." -ForegroundColor Yellow
                }
                else {
                    Invoke-ToolFunction -FunctionName 'Invoke-Vcf9PrecheckToolkitTool' -BoundParameters @{ MenuChoice = '3'; ExistingInventoryPath = $inv }
                }
            }
            "5" {
                $inv = Select-Vcf9InventoryFolder
                if ([string]::IsNullOrWhiteSpace($inv)) {
                    Write-Host "No inventory folder was selected." -ForegroundColor Yellow
                }
                else {
                    Invoke-ToolFunction -FunctionName 'Invoke-Vcf9PrecheckToolkitTool' -BoundParameters @{ MenuChoice = '4'; ExistingInventoryPath = $inv }
                }
            }
            "0" { return }
            default { Write-Host "Invalid selection." -ForegroundColor Yellow }
        }
    }
}

# Strips the scheme (http://, https://) off whatever the user typed, then
# re-adds https:// (so the user can type just the host/address, no scheme).
function ConvertTo-HttpsHostUrl {
    param([string]$RawHost)
    if ([string]::IsNullOrWhiteSpace($RawHost)) { return $null }
    $clean = $RawHost.Trim() -replace '^(https?://)', ''
    $clean = $clean.TrimEnd('/')
    if ([string]::IsNullOrWhiteSpace($clean)) { return $null }
    return "https://$clean"
}

# ============================================================
# VCF Operations report (Operations) - live collection only (the old Mock
# preview path was removed upstream; this always runs a real VCF Operations
# collection).
# ============================================================
function Invoke-OperationsConnect {
    Write-Title "VCF Operations Report (Operations)"

    $hostInput = Read-Host "VCF Operations host address (without https://)"
    $username  = Read-Host "Username (Enter = use the VCFOPS_USERNAME environment variable)"
    $customer  = Read-Host "Customer name (Enter = Customer)"

    $bp = @{}
    $hostUrl = ConvertTo-HttpsHostUrl $hostInput
    if ($hostUrl) { $bp.HostUrl = $hostUrl }
    if (-not [string]::IsNullOrWhiteSpace($username)) { $bp.Username = $username }
    if (-not [string]::IsNullOrWhiteSpace($customer)) { $bp.CustomerName = $customer }
    $bp.SkipCertCheck = $true
    # The password is safely prompted for by New-VCFOpsReport.ps1 itself while running, unless -Password is passed here.
    Invoke-ToolFunction -FunctionName 'Invoke-OperationsReportTool' -BoundParameters $bp
}

# ============================================================
# Change D: vCenter Security Suite - security hardening audit + VMSA version
# check + KISA audit, consolidated into one menu entry because all three need
# a vCenter login. The user is asked for the vCenter address/credentials
# exactly ONCE here, and that same address/credential is then handed to all
# three tools in turn (each tool still makes its own Connect-VIServer /
# Disconnect-VIServer call internally, same as it always has - this only
# avoids asking the PERSON to type the same login 3 times; see CHANGE-NOTES
# for why a single shared PowerCLI session object was not used instead).
# ============================================================
function Invoke-VCenterConnectedAuditSuite {
    Write-Title "vCenter Security Suite (security-hardening + VMSA version check + KISA)"
    Write-Host "Logs in to vCenter once, then runs all three checks below in sequence:" -ForegroundColor Gray
    Write-Host "  1) Security hardening audit (audit_runner -> audit-reporter)" -ForegroundColor Gray
    Write-Host "  2) VMSA version check (vmsa_environment_report)" -ForegroundColor Gray
    Write-Host "  3) KISA virtualization security audit" -ForegroundColor Gray
    Write-Host ""

    $vc = Read-Host "Enter vCenter Server IP or FQDN"
    if ([string]::IsNullOrWhiteSpace($vc)) {
        Write-Host "A vCenter address is required." -ForegroundColor Yellow
        return
    }
    $cred = Get-Credential -Message "Enter vCenter credentials (used for all 3 checks below)"
    if (-not $cred) {
        Write-Host "Credentials are required." -ForegroundColor Yellow
        return
    }

    Write-Host ""
    Write-Host "[1/3] Security hardening audit..." -ForegroundColor Cyan
    Invoke-SecurityHardeningAuditAndReport -SharedVcAddress $vc -SharedCredential $cred

    Write-Host ""
    Write-Host "[2/3] VMSA version check..." -ForegroundColor Cyan
    Invoke-VmsaEnvironmentReportTool -SharedVcAddress $vc -SharedCredential $cred

    Write-Host ""
    Write-Host "[3/3] KISA virtualization security audit..." -ForegroundColor Cyan
    Invoke-KisaEsxAuditTool -Server $vc -Credential $cred -IgnoreCertificate

    Write-Host ""
    Write-Host "All 3 checks completed." -ForegroundColor Green
}

# ============================================================
# Change E: VMSA full-list download + CVE detail lookup, combined into one
# chained action - the downloader's VMSA_CVE_List_*.csv output is located
# automatically and fed straight into the CVE lookup step.
# ============================================================
function Invoke-VmsaDownloadAndCveLookup {
    Write-Title "VMSA Vulnerability Management Toolkit (vmsa)"
    Write-Host "Downloads the full VMSA list, then automatically runs the CVE detail lookup against it." -ForegroundColor Gray
    Write-Host ""

    Write-Host "[1/2] Downloading the full VMSA list..." -ForegroundColor Cyan
    Invoke-VmsaDownloaderTool

    $vmsaDir = Join-Path $OutputRoot "vmsa"
    $csvFile = Get-ChildItem -Path $vmsaDir -Filter "VMSA_CVE_List_*.csv" -File -ErrorAction SilentlyContinue |
        Sort-Object LastWriteTime -Descending | Select-Object -First 1

    if ($csvFile) {
        Write-Host ""
        Write-Host "[2/2] Running the CVE detail lookup against '$($csvFile.Name)'..." -ForegroundColor Cyan
        Invoke-VmsaCveLookupTool -CveListCsv $csvFile.FullName
    }
    else {
        Write-Host ""
        Write-Host "[ERROR] Could not find a VMSA_CVE_List_*.csv produced by the downloader - skipping the CVE lookup step." -ForegroundColor Red
    }
}

# ============================================================
# Main menu
# ============================================================
function Show-MainMenu {
    while ($true) {
        Write-Title "infra_assessment All-in-One Toolkit"
        Write-Host "  [1] VCF 9 Upgrade (Pre-check / NVMe Tiering Analysis)           (vcf_9_upgrade)"
        Write-Host "  [2] VCF Operations Report                                       (Operations)"
        Write-Host "  [3] vCenter Security Suite: Hardening Audit + VMSA Version Check + KISA Audit"
        Write-Host "                                                                  (single vCenter login)"
        Write-Host "  [4] vCenter Daily Comprehensive Report                          (vcenter)"
        Write-Host "  [5] VMSA Full List Download + CVE Lookup  (Internet connection required - takes a long time)"
        Write-Host "  [6] Regenerate Security Hardening Report (existing logs, no vCenter needed)"
        Write-Host ""
        Write-Host "  [0] Exit"
        Write-Host ""
        Write-Host "  infra_assessment repo : $RepoRoot" -ForegroundColor DarkGray

        $sel = Read-Host "`nSelection"

        switch ($sel.ToUpper()) {
            "1" { Show-Vcf9UpgradeMenu }
            "2" { Invoke-OperationsConnect }
            "3" { Invoke-ToolFunction -FunctionName 'Invoke-VCenterConnectedAuditSuite' }
            "4" {
                $vc = Read-Host "vCenter server address (comma-separated for more than one, Enter to be asked while running)"
                $bp = @{}
                if (-not [string]::IsNullOrWhiteSpace($vc)) {
                    $bp.VCenterServer = ($vc -split "," | ForEach-Object { $_.Trim() })
                }
                Invoke-ToolFunction -FunctionName 'Invoke-VCenterDailyReportTool' -BoundParameters $bp
            }
            "5" { Invoke-ToolFunction -FunctionName 'Invoke-VmsaDownloadAndCveLookup' }
            "6" { Invoke-ToolFunction -FunctionName 'Invoke-AuditReporterTool' }
            "0" { return }
            default { Write-Host "Invalid selection." -ForegroundColor Yellow }
        }
    }
}

Show-MainMenu