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

Export-ModuleMember -Function Export-VCFOpsCsv
