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
    $subFolders = Get-ChildItem -Path $PSScriptRoot\vmware-tools -Directory | Sort-Object LastWriteTime -Descending

    if ($subFolders.Count -eq 0) {
        Write-Host "  ! No subfolders found in current directory." -ForegroundColor Red
        exit
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
        exit
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
$targetDir = Select-Audit-Folder

# Discover and classify the log files directly from their content
$logFiles = Discover-LogFiles -TargetDir $targetDir

# Load the SCG controls CSV if one is sitting next to the script (optional)
$scgData = Import-ScgControls

# Process
$data = Parse-Logs -LogFiles $logFiles -ScgData $scgData

# Create an output folder next to this script (not inside the log folder)
$reportFolderName = "Output_" + (Get-Date -Format "yyyyMMdd_HHmmss")
$outputDir = Join-Path $PSScriptRoot $reportFolderName
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
