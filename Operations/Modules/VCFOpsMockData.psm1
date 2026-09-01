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

Export-ModuleMember -Function New-MockReportData
