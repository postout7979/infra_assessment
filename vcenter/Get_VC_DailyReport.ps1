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

function Get-InstanceStat {
    param($GroupItems, [string]$MetricId)
    $vals = $GroupItems | Where-Object { $_.MetricId -eq $MetricId } | Select-Object -ExpandProperty Value
    if (-not $vals) { return $null }
    return [math]::Round((($vals | Measure-Object -Average).Average), 2)
}

# Per-host, per-datastore Latency/Throughput/IOPS (Total/Read/Write each) - shows which
# host is driving load on a shared datastore, not just the datastore-wide aggregate.
function Get-HostDatastorePerfReport {
    param($VMHosts, $Datastores, $StartTime, $FinishTime)

    $sharedDs = @($Datastores | Where-Object { $_.ExtensionData.Host.Count -gt 1 })

    # vCenter reports these per-host datastore counters keyed by an "Instance" identifier
    # that is usually the datastore name but can be a UUID/URL depending on version - map
    # every identifier we can derive from each datastore object so a lookup miss is rare.
    # If DatastoreName below ever shows a raw GUID-looking string instead of a friendly
    # name, that means this environment uses an identifier not covered here - add it.
    $dsNameByKey = @{}
    foreach ($ds in $sharedDs) {
        $dsNameByKey[$ds.Name] = $ds.Name
        if ($ds.ExtensionData.Info.Url) { $dsNameByKey[$ds.ExtensionData.Info.Url] = $ds.Name }
        if ($ds.Id) { $dsNameByKey[$ds.Id] = $ds.Name }
    }

    $statKeys = @(
        "datastore.totalReadLatency.average",
        "datastore.totalWriteLatency.average",
        "datastore.read.average",
        "datastore.write.average",
        "datastore.numberReadAveraged.average",
        "datastore.numberWriteAveraged.average"
    )

    Write-Host "[Storage] Querying per-host datastore latency/throughput/IOPS stats ($($VMHosts.Count) hosts, 1 batch call)..."
    $stats = Get-Stat -Entity $VMHosts -Stat $statKeys -Instance "*" -Start $StartTime -Finish $FinishTime -ErrorAction SilentlyContinue

    # One row per (host, datastore instance) pair
    $groups = @($stats | Where-Object { $_.Instance } | Group-Object { "$($_.Entity.Id)|$($_.Instance)" })

    $rows = foreach ($g in $groups) {
        $sample = $g.Group[0]
        $dsName = if ($dsNameByKey.ContainsKey($sample.Instance)) { $dsNameByKey[$sample.Instance] } else { $sample.Instance }

        $readLatMs     = Get-InstanceStat -GroupItems $g.Group -MetricId "datastore.totalReadLatency.average"
        $writeLatMs    = Get-InstanceStat -GroupItems $g.Group -MetricId "datastore.totalWriteLatency.average"
        $readTputKBps  = Get-InstanceStat -GroupItems $g.Group -MetricId "datastore.read.average"
        $writeTputKBps = Get-InstanceStat -GroupItems $g.Group -MetricId "datastore.write.average"
        $readIops      = Get-InstanceStat -GroupItems $g.Group -MetricId "datastore.numberReadAveraged.average"
        $writeIops     = Get-InstanceStat -GroupItems $g.Group -MetricId "datastore.numberWriteAveraged.average"

        $totalIops = [math]::Round((($readIops + $writeIops)), 2)
        # "Total" latency is IOPS-weighted between read and write (falls back to a simple
        # average if IOPS data is unavailable) - there is no single vSphere counter for it.
        $totalLatMs = if (($readIops + $writeIops) -gt 0) {
            [math]::Round(((($readLatMs * $readIops) + ($writeLatMs * $writeIops)) / ($readIops + $writeIops)), 2)
        } elseif ($readLatMs -or $writeLatMs) {
            [math]::Round(((@($readLatMs, $writeLatMs) | Where-Object { $_ } | Measure-Object -Average).Average), 2)
        } else { $null }
        $totalTputKBps = [math]::Round((($readTputKBps + $writeTputKBps)), 2)

        [PSCustomObject]@{
            HostName            = (ConvertTo-MaskedHostName -HostName $sample.Entity.Name)
            ClusterName         = $sample.Entity.Parent.Name
            DatastoreName       = $dsName
            LatencyTotalMs      = $totalLatMs
            LatencyReadMs       = $readLatMs
            LatencyWriteMs      = $writeLatMs
            ThroughputTotalKBps = $totalTputKBps
            ThroughputReadKBps  = $readTputKBps
            ThroughputWriteKBps = $writeTputKBps
            IopsTotal           = $totalIops
            IopsRead            = $readIops
            IopsWrite           = $writeIops
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
            return "$shortName.vcf.local"
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
    param($VCenterServer, $DaysBack, $DateStr, $Inventory, $Perf, $Storage, $HostDsPerf, $VmPerf, $OldSnapshots, $ConnectedDevices, $Distribution, $SharedDisks, $RdmDisks, $PerfDistribution)

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
$(ConvertTo-EmailTable -Data $HostDsPerf -Title "Per-Host Datastore Latency / Throughput / IOPS")
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

    $hostDsPerf = Get-HostDatastorePerfReport -VMHosts $vmhosts -Datastores $datastores -StartTime $start -FinishTime $finish
    Export-CsvSafe -Data $hostDsPerf -Path "$OutputFolder\03_HostDatastorePerf_$dateStr.csv"

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
$(ConvertTo-SectionHead -Id "storage" -Title "3. Storage Summary" -Desc "Shared datastores only - capacity, plus per-host latency/throughput/IOPS")
<div class="subhead">Capacity</div>
$(ConvertTo-TableCard -InnerHtml (ConvertTo-HtmlTable -Data $storage))
<div class="subhead">Per-Host Datastore Latency / Throughput / IOPS</div>
$(ConvertTo-TableCard -InnerHtml (ConvertTo-HtmlTable -Data $hostDsPerf) -Note "Latency in ms, Throughput in KBps, IOPS as operations/sec. Total = Read+Write (latency is IOPS-weighted).")
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
        -Inventory $inventory -Perf $perf -Storage $storage -HostDsPerf $hostDsPerf -VmPerf $vmPerf `
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
        exit 1
    }
    if (-not $VCenterCredential) { $VCenterCredential = Get-Credential -Message "vCenter credentials" }
    if (-not $VCenterCredential) {
        # Get-Credential returns $null if the prompt is cancelled (Esc/Cancel) - passing that
        # straight into Connect-VIServer's -Credential (typed as PSCredential) produces a
        # generic, unhelpful .NET ArgumentException instead of a clear message.
        Write-Error "No credentials were provided (the credential prompt may have been cancelled). Re-run the script and complete the credential prompt, or pass -VCenterCredential."
        exit 1
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
    exit 1
}
finally {
    if ($VCenterServer) {
        Disconnect-VIServer -Server $VCenterServer -Confirm:$false -ErrorAction SilentlyContinue
    }
}
