<#
.SYNOPSIS
    vCenter comprehensive inventory / performance / storage / VM detail report
    generator. PowerCLI only - no VCF Operations dependency.

.DESCRIPTION
    Collects and reports on 11 sections: inventory summary, performance
    summary (overall + per-cluster + Top3 hosts), storage summary (shared
    datastores), VM performance Top5 lists, old snapshots, connected virtual
    devices, full VM inventory, VM distribution, shared virtual disks, RDM
    disks, and a VM performance distribution summary.

    Uses PowerCLI's bulk cmdlets (Get-VMHost, Get-VM, Get-Datastore without
    -Location filters), which already return the full inventory with parent
    references (.Parent, .VMHost) populated in a single call each, so no
    per-object relationship walk is needed. Get-Stat calls are batched per
    entity type.

    Output: 15+ section CSVs plus one comprehensive summary HTML.
    Written for Windows PowerShell 5.1 compatibility (works on PS7 too).

.NOTES
    - Metric IDs (cpu.ready.summation, virtualDisk.totalReadLatency.average,
      datastore.totalReadLatency.average, etc.) are the commonly available
      PowerCLI Get-Stat metrics, but exact availability can vary by vSphere
      version/license. Verify with `Get-StatType -Entity <obj>` if a section
      returns no data.
    - "Shared datastore" is inferred as any datastore visible from more than
      one host (ExtensionData.Host.Count -gt 1). Adjust if your environment
      uses a different convention (e.g. naming pattern).
    - "Shared virtual disk" is inferred from the VMDK's multi-writer sharing
      setting (ExtensionData.Backing.Sharing -eq 'sharingMultiWriter').
    - virtualDisk.totalReadLatency.average / totalWriteLatency.average are
      realtime-only counters under vCenter's default statistics level - they
      are NOT retained in historical rollups, so they are queried separately
      with -Realtime (only works for powered-on VMs, ~1 hour of retention).
      They are also reported per virtual disk instance, not per VM, so a VM
      with multiple disks is reduced to its worst-case (max) latency across
      disks.
    - CPU Ready % (computed from cpu.ready.summation) is an approximation
      converted from milliseconds assuming a sampling interval of
      $Script:ReadyIntervalSeconds. Adjust to match your environment.
#>

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
    [string]$OutputFolder = ".\DailyReport_$(Get-Date -Format 'yyyyMMdd_HHmm')"
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

    Write-Host "[Perf] Querying host CPU/Mem/latency stats ($StartTime to $FinishTime, 1 batch call)..."
    $hostStats = Get-Stat -Entity $VMHosts -Stat @("cpu.usage.average","cpu.usagemhz.average","mem.usage.average","mem.consumed.average","cpu.latency.average") `
        -Start $StartTime -Finish $FinishTime -ErrorAction SilentlyContinue

    $hostRows = foreach ($h in $VMHosts) {
        $capacityGHz = [math]::Round((($h.ExtensionData.Hardware.CpuInfo.NumCpuCores * $h.ExtensionData.Hardware.CpuInfo.Hz) / 1e9), 2)
        [PSCustomObject]@{
            HostName       = $h.Name
            ClusterName    = $h.Parent.Name
            CpuUsagePct    = Get-AvgStat -StatResults $hostStats -EntityId $h.Id -MetricId "cpu.usage.average"
            CpuUsageGHz    = [math]::Round(((Get-AvgStat -StatResults $hostStats -EntityId $h.Id -MetricId "cpu.usagemhz.average")) / 1000, 2)
            CpuCapacityGHz = $capacityGHz
            MemUsagePct    = Get-AvgStat -StatResults $hostStats -EntityId $h.Id -MetricId "mem.usage.average"
            MemUsageGB     = [math]::Round(((Get-AvgStat -StatResults $hostStats -EntityId $h.Id -MetricId "mem.consumed.average")) / 1MB, 2)
            CpuContentionPct = Get-AvgStat -StatResults $hostStats -EntityId $h.Id -MetricId "cpu.latency.average"
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
    param($Datastores, $StartTime, $FinishTime)

    $sharedDs = @($Datastores | Where-Object { $_.ExtensionData.Host.Count -gt 1 })

    Write-Host "[Storage] Querying datastore latency/IOPS stats ($($sharedDs.Count) shared datastores, 1 batch call)..."
    $dsStats = if ($sharedDs.Count -gt 0) {
        Get-Stat -Entity $sharedDs -Stat @("datastore.totalReadLatency.average","datastore.totalWriteLatency.average","datastore.numberReadAveraged.average","datastore.numberWriteAveraged.average") `
            -Start $StartTime -Finish $FinishTime -ErrorAction SilentlyContinue
    } else { @() }

    $rows = foreach ($ds in $sharedDs) {
        [PSCustomObject]@{
            DatastoreName  = $ds.Name
            CapacityGB     = [math]::Round($ds.CapacityGB, 1)
            UsedGB         = [math]::Round(($ds.CapacityGB - $ds.FreeSpaceGB), 1)
            FreeGB         = [math]::Round($ds.FreeSpaceGB, 1)
            ReadLatencyMs  = Get-AvgStat -StatResults $dsStats -EntityId $ds.Id -MetricId "datastore.totalReadLatency.average"
            WriteLatencyMs = Get-AvgStat -StatResults $dsStats -EntityId $ds.Id -MetricId "datastore.totalWriteLatency.average"
            ReadIOPS       = Get-AvgStat -StatResults $dsStats -EntityId $ds.Id -MetricId "datastore.numberReadAveraged.average"
            WriteIOPS      = Get-AvgStat -StatResults $dsStats -EntityId $ds.Id -MetricId "datastore.numberWriteAveraged.average"
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
            HostName       = $vm.VMHost.Name
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
            HostName       = $vm.VMHost.Name
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
                HostName    = $vm.VMHost.Name
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
                HostName      = $vm.VMHost.Name
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
                    HostName      = $vm.VMHost.Name
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
                HostName    = $vm.VMHost.Name
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
                HostName    = $vm.VMHost.Name
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
    return "<div class=`"section-head`" id=`"$Id`"><div><h2>$Title</h2><div class=`"desc`">$Desc</div></div></div>"
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
  <div class="sub-stats"><div class="sub-stat">CPU Contention <b>$CpuContentionPct%</b></div></div>
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
    $storage = Get-StorageSummaryReport -Datastores $datastores -StartTime $start -FinishTime $finish
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
  --bg:#f5f6fb; --surface:#ffffff; --surface-alt:#f0f2fa; --border:#e3e6f2;
  --text:#2e3148; --text2:#6b7090; --muted:#9498b0;
  --primary:#6c7fe8; --primary-dark:#4c5fcb; --primary-tint:#e7eafb;
  --mint:#7fd8c4; --mint-dark:#2f9c82; --mint-tint:#e3f7f1;
  --peach:#f6b88a; --peach-dark:#c97a33; --peach-tint:#fceadc;
  --coral:#f08c8c; --coral-dark:#c84b4b; --coral-tint:#fce3e3;
  --sky:#8fc7f2; --sky-dark:#3e7fb0; --sky-tint:#e7f3fc;
  --good-bg:var(--mint-tint); --good-text:var(--mint-dark);
  --warn-bg:var(--peach-tint); --warn-text:var(--peach-dark);
  --crit-bg:var(--coral-tint); --crit-text:var(--coral-dark);
  --info-bg:var(--sky-tint); --info-text:var(--sky-dark);
  --neutral-bg:#eeeeee; --neutral-text:#666666;
}
*{box-sizing:border-box;}
html,body{margin:0; padding:0; background:var(--bg); color:var(--text);
  font-family:"Segoe UI",Arial,sans-serif; font-size:15px; line-height:1.6;}
.wrap{max-width:1280px; margin:0 auto; padding:0 28px 80px;}
.hero{background:linear-gradient(135deg, var(--primary-tint) 0%, var(--sky-tint) 60%, var(--mint-tint) 100%);
  padding:36px 28px 28px; border-radius:0 0 24px 24px; margin-bottom:6px;}
.hero-inner{max-width:1280px; margin:0 auto; display:flex; justify-content:space-between; align-items:flex-end; flex-wrap:wrap; gap:16px;}
.hero-eyebrow{color:var(--primary-dark); font-weight:700; letter-spacing:.04em; font-size:12.5px; text-transform:uppercase;}
.hero h1{font-size:26px; font-weight:800; margin:8px 0 6px; color:var(--text);}
.hero .sub{color:var(--text2); font-size:13.5px;}
.hero .meta-box{background:rgba(255,255,255,.7); border-radius:14px; padding:12px 18px; font-size:13px; color:var(--text2); min-width:220px;}
.hero .meta-box b{color:var(--text);}
.nav{position:sticky; top:0; z-index:50; background:rgba(245,246,251,.94); backdrop-filter:blur(6px);
  border-bottom:1px solid var(--border); padding:9px 28px; display:flex; gap:4px; flex-wrap:wrap;}
.nav a{color:var(--text2); text-decoration:none; font-size:12.5px; font-weight:600; padding:6px 12px;
  border-radius:20px; white-space:nowrap;}
.nav a:hover{background:var(--primary-tint); color:var(--primary-dark);}
section{margin:36px 0;}
.section-head{margin-bottom:16px; padding-top:8px;}
.section-head h2{font-size:19px; font-weight:800; margin:0; color:var(--text);}
.section-head .desc{color:var(--muted); font-size:12.5px; margin-top:2px;}
.grid2,.grid3,.grid4{display:flex; flex-wrap:wrap; gap:16px;}
.grid2>*{flex:1 1 calc(50% - 16px); min-width:280px;}
.grid3>*{flex:1 1 calc(33.333% - 16px); min-width:260px;}
.grid4>*{flex:1 1 calc(25% - 14px); min-width:200px;}
.card{background:var(--surface); border:1px solid var(--border); border-radius:16px; padding:18px 20px;
  box-shadow:0 2px 12px rgba(46,49,72,.05);}
.kpi-card .label{font-size:12.5px; color:var(--text2); font-weight:600;}
.kpi-card .value{font-size:26px; font-weight:800; margin:6px 0 2px; color:var(--text);}
.kpi-card .value .unit{font-size:13px; font-weight:600; color:var(--muted); margin-left:4px;}
.kpi-card .kpi-sub{font-size:11.5px; color:var(--text2); margin-top:4px;}
.cluster-card .ch{display:flex; justify-content:space-between; align-items:center; margin-bottom:12px;}
.cluster-card .ch .name{font-weight:800; font-size:15px;}
.cluster-card .ch .dc{font-size:11.5px; color:var(--muted);}
.metric-row{margin-bottom:10px;}
.metric-row .mrow-top{display:flex; justify-content:space-between; font-size:12.5px; margin-bottom:4px;}
.metric-row .mrow-top .mlabel{color:var(--text2); font-weight:600;}
.metric-row .mrow-top .mval{font-weight:700; color:var(--text);}
.bar-track{height:8px; border-radius:6px; background:var(--surface-alt); overflow:hidden;}
.bar-fill{height:100%; border-radius:6px;}
.sub-stats{display:flex; gap:14px; margin-top:12px; padding-top:10px; border-top:1px dashed var(--border);}
.sub-stat{font-size:11.5px; color:var(--text2);}
.sub-stat b{color:var(--text); font-weight:800; margin-left:4px;}
.table-card{background:var(--surface); border:1px solid var(--border); border-radius:16px; padding:8px 8px 12px;
  box-shadow:0 2px 12px rgba(46,49,72,.05); overflow:hidden; margin-bottom:6px;}
table{width:100%; border-collapse:collapse; font-size:13px;}
thead th{background:var(--surface-alt); color:var(--text2); font-weight:700; text-align:left; padding:9px 12px; font-size:12px;}
tbody td{padding:8px 12px; border-bottom:1px solid var(--border); color:var(--text);}
tbody tr:hover td{background:var(--primary-tint);}
.badge{display:inline-block; padding:3px 12px; border-radius:14px; background:var(--info-bg); color:var(--info-text); font-weight:600; font-size:12px; margin-right:6px;}
.badge-good{display:inline-block; padding:2px 10px; border-radius:12px; background:var(--good-bg); color:var(--good-text); font-weight:700; font-size:12px;}
.badge-warn{display:inline-block; padding:2px 10px; border-radius:12px; background:var(--warn-bg); color:var(--warn-text); font-weight:700; font-size:12px;}
.badge-crit{display:inline-block; padding:2px 10px; border-radius:12px; background:var(--crit-bg); color:var(--crit-text); font-weight:700; font-size:12px;}
.badge-info{display:inline-block; padding:2px 10px; border-radius:12px; background:var(--info-bg); color:var(--info-text); font-weight:700; font-size:12px;}
.badge-neutral{display:inline-block; padding:2px 10px; border-radius:12px; background:var(--neutral-bg); color:var(--neutral-text); font-weight:700; font-size:12px;}
.subhead{font-size:12px; color:var(--muted); margin:14px 4px 6px; font-weight:700; letter-spacing:.2px;}
.note{color:var(--muted); font-size:12px;}
.bd-title{font-weight:800; font-size:13.5px; color:var(--text); margin:14px 4px 10px;}
.bd-title .bd-total{font-weight:600; font-size:11.5px; color:var(--muted); margin-left:6px;}
.bd-row{display:flex; align-items:center; gap:10px; margin:0 4px 8px; font-size:12px;}
.bd-label{width:34%; color:var(--text2); font-weight:600; overflow:hidden; text-overflow:ellipsis; white-space:nowrap;}
.bd-bar-track{flex:1; height:9px; border-radius:6px; background:var(--surface-alt); overflow:hidden;}
.bd-bar-fill{height:100%; border-radius:6px; background:var(--primary);}
.bd-count{width:90px; text-align:right; color:var(--text); font-weight:700; white-space:nowrap;}
.bd-count .bd-pct{color:var(--muted); font-weight:500;}
.stacked-bar{display:flex; height:14px; border-radius:7px; overflow:hidden; background:var(--surface-alt); margin:0 4px 10px;}
.stacked-bar .seg.normal{background:var(--mint);}
.stacked-bar .seg.warning{background:var(--peach);}
.stacked-bar .seg.critical{background:var(--coral);}
.status-legend-row{display:flex; gap:16px; font-size:12px; color:var(--text2); flex-wrap:wrap; margin:0 4px 4px;}
.status-legend-row .dot{width:9px; height:9px; border-radius:50%; display:inline-block; margin-right:6px;}
.status-legend-row .dot.normal{background:var(--mint-dark);}
.status-legend-row .dot.warning{background:var(--peach-dark);}
.status-legend-row .dot.critical{background:var(--coral-dark);}
.foot{text-align:center; color:var(--muted); font-size:12px; margin-top:50px;}
</style>
</head>
<body>

<div class="hero"><div class="hero-inner">
  <div>
    <div class="hero-eyebrow">VCENTER REPORT</div>
    <h1>vCenter Comprehensive Report</h1>
    <div class="sub">$($VCenterServer -join ', ')</div>
  </div>
  <div class="meta-box">Generated <b>$dateStr</b><br>Window <b>last $DaysBack day(s)</b></div>
</div></div>

<div class="nav">
  <a href="#inventory">Inventory</a><a href="#perf">Performance</a><a href="#storage">Storage</a>
  <a href="#vmperf">VM Perf</a><a href="#snapshot">Snapshots</a><a href="#device">Devices</a>
  <a href="#vminv">VM Inventory</a><a href="#dist">Distribution</a><a href="#shared">Shared Disks</a>
  <a href="#rdm">RDM</a><a href="#summary">Perf Summary</a>
</div>

<div class="wrap">

<section>
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

<section>
$(ConvertTo-SectionHead -Id "perf" -Title "2. Performance Summary" -Desc "Overall + per-cluster CPU/Memory, Top 3 hosts")
<p><span class="badge">Overall Avg CPU: $($perf.OverallAvgCpuPct)%</span><span class="badge">Overall Avg Mem: $($perf.OverallAvgMemPct)%</span></p>
<div class="grid3">
$clusterCardsHtml
</div>
<div class="subhead">Top 3 Hosts by CPU</div>
$(ConvertTo-TableCard -InnerHtml (ConvertTo-HtmlTable -Data $perf.Top3CpuHosts -Columns @('HostName','ClusterName','CpuUsagePct')))
<div class="subhead">Top 3 Hosts by Memory</div>
$(ConvertTo-TableCard -InnerHtml (ConvertTo-HtmlTable -Data $perf.Top3MemHosts -Columns @('HostName','ClusterName','MemUsagePct')))
<div class="subhead">Top 3 Hosts by CPU Contention</div>
$(ConvertTo-TableCard -InnerHtml (ConvertTo-HtmlTable -Data $perf.Top3ReadyHosts -Columns @('HostName','ClusterName','CpuContentionPct')))
</section>

<section>
$(ConvertTo-SectionHead -Id "storage" -Title "3. Storage Summary" -Desc "Shared datastores only - capacity, latency, IOPS")
$(ConvertTo-TableCard -InnerHtml (ConvertTo-HtmlTable -Data $storage))
</section>

<section>
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

<section>
$(ConvertTo-SectionHead -Id "snapshot" -Title "5. Snapshots Older Than $SnapshotAgeDays Days" -Desc "Count, oldest age, total size per VM")
$(ConvertTo-TableCard -InnerHtml (ConvertTo-HtmlTable -Data $oldSnapshots))
</section>

<section>
$(ConvertTo-SectionHead -Id "device" -Title "6. VMs With a Connected Virtual Device" -Desc "Mounted ISO / CD-DVD, etc.")
$(ConvertTo-TableCard -InnerHtml (ConvertTo-HtmlTable -Data $connectedDevices))
</section>

<section>
$(ConvertTo-SectionHead -Id "vminv" -Title "7. Full VM Inventory" -Desc "Compute, memory, virtual disk and datastore detail")
<p class="note">See 07_VmInventory_$dateStr.csv for the complete list (one row per virtual disk).</p>
</section>

<section>
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

<section>
$(ConvertTo-SectionHead -Id "shared" -Title "9. Shared (Multi-Writer) Virtual Disks" -Desc "VMDKs configured with multi-writer sharing")
$(ConvertTo-TableCard -InnerHtml (ConvertTo-HtmlTable -Data $sharedDisks))
</section>

<section>
$(ConvertTo-SectionHead -Id "rdm" -Title "10. RDM (Raw Device Mapping) Disks" -Desc "Physical and virtual RDM-mapped disks")
$(ConvertTo-TableCard -InnerHtml (ConvertTo-HtmlTable -Data $rdmDisks))
</section>

<section>
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
}

# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

Write-Host "`n=== Starting vCenter Comprehensive Report collection ===" -ForegroundColor Cyan

Write-Host "`n--- Login: vCenter ---"
if (-not $VCenterServer) {
    $VCenterServer = (Read-Host "vCenter server address(es) - comma-separated for multiple") -split "," | ForEach-Object { $_.Trim() }
}
if (-not $VCenterCredential) { $VCenterCredential = Get-Credential -Message "vCenter credentials" }

Write-Host "`n[Connect] Connecting to vCenter: $($VCenterServer -join ', ')..."
Connect-VIServer -Server $VCenterServer -Credential $VCenterCredential -Force | Out-Null

Invoke-ComprehensiveVCenterReport -VCenterServer $VCenterServer -DaysBack $DaysBack `
    -SnapshotAgeDays $SnapshotAgeDays -OutputFolder $OutputFolder

Disconnect-VIServer -Server $VCenterServer -Confirm:$false -ErrorAction SilentlyContinue

Write-Host "`n=== Done ===" -ForegroundColor Green