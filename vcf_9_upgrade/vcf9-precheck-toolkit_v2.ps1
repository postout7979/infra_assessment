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
param()

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
$ReportDir = if ($PSScriptRoot) { Join-Path $PSScriptRoot $DirName } else { ".\$DirName" }
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
$ReportDir   = Join-Path $ScriptBase "compatibility_$TimeStamp"
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
$Idx_Vsan90    = Build-HCLIndex -Table $VsanHCL90  -Fields $IOFields -NoiseWords $Script:IONoise
$Idx_Vsan91    = Build-HCLIndex -Table $VsanHCL91  -Fields $IOFields -NoiseWords $Script:IONoise
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

# Storage Controller: unique key based on Model (excluding USB); vSAN is cached together
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
        Vsan = Get-VersionedMatch `
            -Table90 $VsanHCL90 -Table91 $VsanHCL91 `
            -Index90 $Idx_Vsan90 -Index91 $Idx_Vsan91 `
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
    $VsanMatch = $Cached.Vsan

    $CtrlScore   = if ($CtrlMatch.Best) { $CtrlMatch.Best.Score } else { 0 }
    $CtrlHCLText = if ($CtrlMatch.Best) { "$($CtrlMatch.Best.Row.'Brand Name') $($CtrlMatch.Best.Row.Model)" } else { "N/A" }
    $CtrlNote    = if ($CtrlMatch.Best) { "ESXi Releases: $(Format-ReleaseText $CtrlMatch.Best.Row.'Supported Releases')" } else { "No matching entry in IO Devices" }
    if ($CtrlMatch.Status90 -eq "MISMATCH" -or $CtrlMatch.Status91 -eq "MISMATCH") { $CtrlNote = "[Best candidate, manual verification required] " + $CtrlNote }
    if ($VsanMatch.Best) { $CtrlNote += "  |  vSAN candidate: $($VsanMatch.Best.Row.'Brand Name') $($VsanMatch.Best.Row.Model) (score $($VsanMatch.Best.Score)%, 9.0:$($VsanMatch.Status90)/9.1:$($VsanMatch.Status91))" }
    else { $CtrlNote += "  |  No vSAN I/O Controller match (not relevant if vSAN is not in use)" }

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
    $ReportDir    = Join-Path $ScriptBasePR "performance_$TimeStampPR"
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
$ScriptDirMain = if ($PSScriptRoot) { $PSScriptRoot } else { Split-Path -Parent $MyInvocation.MyCommand.Definition }

Write-Host "===============================================================================" -ForegroundColor Cyan
Write-Host "                    VCF 9 Pre-check Integrated Tool" -ForegroundColor Cyan
Write-Host "===============================================================================" -ForegroundColor Cyan
Write-Host " [1] Inventory collection + HCL compatibility check (run automatically in sequence)" -ForegroundColor White
Write-Host " [2] Run inventory collection only (vCenter connection, CSV output only)" -ForegroundColor White
Write-Host " [3] Specify an existing inventory folder -> run HCL compatibility check only" -ForegroundColor White
Write-Host " [4] Specify an existing inventory folder -> generate a performance report only" -ForegroundColor White
Write-Host "===============================================================================" -ForegroundColor Cyan
$MenuChoice = Read-Host "> Enter a menu number (1/2/3/4)"

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
        $InputPath = Read-Host "> Enter the inventory folder name (or full path) created by Menu [2]"
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
        $InputPath4 = Read-Host "> Enter the inventory folder name (or full path) created by Menu [2]"
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
