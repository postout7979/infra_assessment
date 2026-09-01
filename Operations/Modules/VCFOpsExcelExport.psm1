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
            Write-Warning "Excel 시트 '$SheetName' 차트 포함 작성 실패 - 차트 없이 데이터만 다시 작성합니다: $($_.Exception.Message)"
        }
    }

    try {
        $items | Export-Excel -Path $Path -WorksheetName $SheetName `
            -AutoSize -BoldTopRow -FreezeTopRow -TableStyle Medium2 -ErrorAction Stop
        return $true
    }
    catch {
        Write-Warning "Excel 시트 '$SheetName' 작성 실패: $($_.Exception.Message)"
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
        Write-Warning "ImportExcel 모듈이 설치되어 있지 않아 Excel 출력을 건너뜁니다."
        Write-Warning "  -> 설치: Install-Module ImportExcel -Scope CurrentUser  (설치 후 재실행하면 Excel로 출력됩니다)"
        Write-Warning "  -> 대신 데이터셋별 CSV 파일로 출력합니다."
        return $null
    }

    try {
        Import-Module ImportExcel -ErrorAction Stop
    }
    catch {
        Write-Warning "ImportExcel 모듈 로드 실패: $($_.Exception.Message) - CSV로 폴백합니다."
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
        catch { Write-Warning "클러스터 차트 정의 생성 실패(차트 없이 진행): $($_.Exception.Message)"; $clusterChart = $null }
    }
    $osChart = $null
    if ($osRows.Count -gt 0) {
        try {
            $osChart = New-ExcelChartDefinition -Title "Guest OS별 VM 수량" -ChartType Pie `
                -XRange "Label" -YRange "Count" -Width 500 -Height 350 -ErrorAction Stop
        }
        catch { Write-Warning "Guest OS 차트 정의 생성 실패(차트 없이 진행): $($_.Exception.Message)"; $osChart = $null }
    }
    $dsChart = $null
    if ($dsRows.Count -gt 0) {
        try {
            $dsChart = New-ExcelChartDefinition -Title "데이터스토어별 용량(GB) - 현재/이전" -ChartType ColumnClustered `
                -XRange "Name" -YRange @("CapacityGb", "PrevCapacityGb") -Width 700 -Height 350 -ErrorAction Stop
        }
        catch { Write-Warning "데이터스토어 차트 정의 생성 실패(차트 없이 진행): $($_.Exception.Message)"; $dsChart = $null }
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
        Write-Warning "Excel 시트를 하나도 만들지 못했습니다 - CSV로 폴백합니다."
        return $null
    }
    return $Path
}

Export-ModuleMember -Function Export-VCFOpsExcel, Test-VCFOpsImportExcelAvailable
