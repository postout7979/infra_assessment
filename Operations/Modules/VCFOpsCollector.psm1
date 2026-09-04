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

Import-Module (Join-Path $PSScriptRoot "VCFOpsStatKeys.psm1")
Import-Module (Join-Path $PSScriptRoot "VCFOpsApiClient.psm1")
Import-Module (Join-Path $PSScriptRoot "VCFOpsSnapshotCache.psm1")
Import-Module (Join-Path $PSScriptRoot "VCFOpsTheme.psm1")
Import-Module (Join-Path $PSScriptRoot "VCFOpsProgress.psm1")

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
        Write-Warning "vCenter(어댑터) 수량 조회 실패 - /suite-api/api/adapters 응답 구조 확인 필요: $($_.Exception.Message)"
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
        Write-Warning "vSphere World 리소스 탐색 실패: $($_.Exception.Message)"
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
            Write-Verbose "vSphere World 리소스 발견: $($world.resourceKey.name) ($($world.identifier))"
            $atMs = [DateTimeOffset]::new($Now.AddDays(-$CompareDaysAgo)).ToUnixTimeMilliseconds()
            $keys = @($labelToMetricKey.Values)
            $lookup = $null
            try {
                $lookup = Get-VCFOpsStatsPointInTime -ResourceIds @($world.identifier) -StatKeys $keys -AtMs $atMs -WindowMinutes 720
            }
            catch { Write-Warning "vSphere World 통계 조회 실패: $($_.Exception.Message)" }

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
                Write-Verbose "인벤토리 수량 - vSphere World 메트릭으로 비교됨: $($metricPrev.Keys -join ', ')"
            }
            else {
                Write-Warning "vSphere World 리소스는 찾았지만 해당 시점의 수량 메트릭을 찾지 못했습니다. 캐시 비교로 폴백합니다."
            }
        }
        else {
            Write-Warning "vSphere World 리소스를 찾지 못했습니다. 캐시 비교로 폴백합니다."
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
        Write-Warning "인벤토리 수량: $CompareDaysAgo 일 전 비교 데이터를 찾지 못해 비교 없이 출력합니다 (스냅샷 캐시 누적 필요)."
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
            Write-Warning "vCPU 속성 조회 실패($name): $($_.Exception.Message)"
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

    Write-Verbose "$CompareDaysAgo 일 전 시점 클러스터 통계 조회 중..."
    $atMs = [DateTimeOffset]::new($Now.AddDays(-$CompareDaysAgo)).ToUnixTimeMilliseconds()
    $ids = @($ClusterList | ForEach-Object { $_.identifier })
    $keys = @($StatKeysCluster.Values)
    $prevLookup = if ($ids.Count -gt 0) {
        Get-VCFOpsStatsPointInTime -ResourceIds $ids -StatKeys $keys -AtMs $atMs -WindowMinutes 180
    } else { @{} }

    if (-not $prevLookup -or $prevLookup.Keys.Count -eq 0) {
        Write-Warning "$CompareDaysAgo 일 전 시점의 통계를 찾지 못했습니다 (보존기간 초과 또는 미수집). 비교 없이 표시합니다."
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
            Write-Warning "데이터스토어 과거시점 조회 실패: $($_.Exception.Message)"
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
            Write-Warning "데이터스토어 properties 조회 실패($name): $($_.Exception.Message)"
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
        Write-Verbose "로컬 데이터스토어 $excludedLocal 개를 목록에서 제외했습니다."
    }
    if ($excludedDuplicate -gt 0) {
        Write-Verbose "동일 UUID 중복 데이터스토어 $excludedDuplicate 개를 목록에서 제외했습니다."
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
            Write-Warning "properties 조회 실패($($idName[$vid])): $($_.Exception.Message)"
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
            Write-Warning "VM 인벤토리 분포: $CompareDaysAgo 일 전 저장본을 찾지 못해 비교 없이 출력합니다 (스냅샷 캐시 누적 필요)."
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
            Write-Warning "비교 대상 날짜가 올바르지 않습니다 (-CompareDays $CompareDaysAgo). 비교 없이 현재값만 출력합니다."
            $compareEnabled = $false
        }
    }
    $previousDate = if ($compareEnabled) { $now.AddDays(-$CompareDaysAgo) } else { $null }

    Write-VCFOpsSubStep "리소스 인벤토리 조회 중... (데이터센터/클러스터/호스트/VM)"
    Write-Verbose "리소스 인벤토리 조회 중..."
    $dcList      = Get-VCFOpsResources -ResourceKind $ResourceKind.datacenter -AdapterKind $AdapterKindVMware
    $clusterList = Get-VCFOpsResources -ResourceKind $ResourceKind.cluster    -AdapterKind $AdapterKindVMware
    $hostList    = Get-VCFOpsResources -ResourceKind $ResourceKind.host      -AdapterKind $AdapterKindVMware
    $vmList      = Get-VCFOpsResources -ResourceKind $ResourceKind.vm        -AdapterKind $AdapterKindVMware
    $datastoreList = Get-VCFOpsResources -ResourceKind $ResourceKind.datastore -AdapterKind $AdapterKindVMware
    Write-VCFOpsSubStep "vCenter 수량 조회 중..."
    $vCenterCount = Get-VCenterCount

    if ($MaxVMs -gt 0 -and $vmList.Count -gt $MaxVMs) {
        $vmList = $vmList[0..($MaxVMs - 1)]
    }

    $clusterName = @{}; foreach ($c in $clusterList) { $clusterName[$c.identifier] = $c.resourceKey.name }
    # ESXi 호스트명은 마스킹 처리(FQDN 도메인 -> vcf.local, IP -> 앞 3옥텟 ***)된 값으로 저장합니다.
    # 이 맵을 참조하는 모든 곳(호스트 Top10, VM 인벤토리/Top 리스트의 Host 컬럼)에 자동 반영됩니다.
    $hostName    = @{}; foreach ($h in $hostList)    { $hostName[$h.identifier]    = Protect-VCFOpsHostIdentifier -Value $h.resourceKey.name }
    $dcName      = @{}; foreach ($d in $dcList)       { $dcName[$d.identifier]      = $d.resourceKey.name }

    Write-VCFOpsSubStep "리소스 관계(상하위) 매핑 중..."
    Write-Verbose "리소스 관계(상하위) 매핑 중..."
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

    Write-VCFOpsSubStep "인벤토리 수량 비교(vSphere World/캐시) 처리 중..."
    $inventoryCounts = Get-InventoryCountsWithDelta -DcList $dcList -ClusterList $clusterList -HostList $hostList `
        -VmList $vmList -VCenterCount $vCenterCount -Now $now -CompareDaysAgo $CompareDaysAgo `
        -CacheDir $SnapshotCacheDir -CompareEnabled $compareEnabled

    Write-VCFOpsSubStep "클러스터 성능 통계 조회 중..."
    Write-Verbose "클러스터 성능 통계 조회 중..."
    $clusters = Get-ClusterMetricsFromApi -ClusterList $clusterList -ClusterDc $clusterDc `
        -HostCluster $hostCluster -HostVmMap $hostVmMap -DcName $dcName

    # N일 전 시점 클러스터 통계는 한 번만 조회해서 (1)클러스터 카드 비교, (2)Executive Summary
    # 비교 양쪽에 재사용합니다.
    $prevClusters = Get-PrevClusters -ClusterList $clusterList -ClusterDc $clusterDc -HostCluster $hostCluster `
        -HostVmMap $hostVmMap -DcName $dcName -Now $now -CompareDaysAgo $CompareDaysAgo -CompareEnabled $compareEnabled
    $clusters = Merge-ClusterPrevious -Clusters $clusters -PrevClusters $prevClusters -CompareEnabled $compareEnabled

    Write-VCFOpsSubStep "호스트 성능 통계 조회 중..."
    Write-Verbose "호스트 성능 통계 조회 중..."
    $hosts = Get-HostMetricsFromApi -HostList $hostList -HostCluster $hostCluster -ClusterName $clusterName

    Write-VCFOpsSubStep "VM 성능 통계 조회 중... ($($vmList.Count)대)"
    Write-Verbose "VM 성능 통계 조회 중... ($($vmList.Count)대)"
    $vmPerfResult = Get-VmPerformanceFromApi -VmList $vmList -VmHost $vmHost -HostName $hostName `
        -HostCluster $hostCluster -ClusterName $clusterName

    $perfSummary = Get-PerfSummaryWithDelta -Clusters $clusters -PrevClusters $prevClusters -CompareEnabled $compareEnabled

    Write-VCFOpsSubStep "데이터스토어 현황(용량 비교) 조회 중..."
    $datastoreInfo = Get-DatastoreInfoWithDelta -DatastoreList $datastoreList -DatastoreClusterNames $datastoreClusterNames `
        -Now $now -CompareDaysAgo $CompareDaysAgo -CompareEnabled $compareEnabled

    Write-VCFOpsSubStep "VM 인벤토리 상세(properties) 조회 중... ($($vmList.Count)대, 시간이 다소 걸릴 수 있습니다)"
    Write-Verbose "VM 인벤토리 상세(properties) 조회 중... ($($vmList.Count)대, 시간이 다소 걸릴 수 있습니다)"
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

    Write-VCFOpsSubStep "VM 인벤토리 분포(OS/Tools/HW/vCPU) 계산 중..."
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

Export-ModuleMember -Function Invoke-VCFOpsCollection, Protect-VCFOpsHostIdentifier
