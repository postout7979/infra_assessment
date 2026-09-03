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
        Exit
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
    Exit
}

# ── 출력 폴더 생성 ──
$ScriptBase = if ($PSScriptRoot) { $PSScriptRoot } else { Split-Path -Parent $MyInvocation.MyCommand.Definition }
$TimeStamp  = Get-Date -Format "yyyyMMdd_HHmm"
$OutDir     = Join-Path $ScriptBase "nvme_tiering_$TimeStamp"
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
Write-Host " CSV(클러스터 요약) : $ClusterCsvPath" -ForegroundColor Gray

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
Write-Host " NVMe Memory Tiering 전환 효과 요약" -ForegroundColor Yellow
Write-Host "===============================================================================" -ForegroundColor Yellow
Write-Host " 현재 운영 VM: $TotalVMs 개" -ForegroundColor Gray
Write-Host " 현재 기준 추가 가능: +$TotalCurrAdd 개" -ForegroundColor Gray
Write-Host " NVMe 전환 후 추가 가능: +$TotalNvmeAdd 개 (순 증가: +$TotalNvmeGain 개)" -ForegroundColor Green
Write-Host " NVMe 전환 가능 호스트: $TotalEligible 개 / $(@($Results).Count) 개" -ForegroundColor Gray
Write-Host " 현재 VM 수량 유지 기준 호스트 축소 가능: $TotalHostsWithVMs 대 -> $TotalHostsNeeded 대 (축소 -$TotalHostReduction 대)" -ForegroundColor Green
Write-Host " (※ 클러스터 내 VM 자유 재배치 가정 / HA 여유 호스트(N+1)는 미반영 이론치)" -ForegroundColor DarkGray
Write-Host "-------------------------------------------------------------------------------" -ForegroundColor Yellow
$ClusterSummary | Format-Table @{L='클러스터';E={$_.Cluster}},
    @{L='호스트';E={$_.Hosts}}, @{L='현재VM';E={$_.TotalVMs}},
    @{L='현재추가';E={"+$($_.CurrAddVM)"}}, @{L='NVMe추가';E={"+$($_.NvmeAddVM)"}},
    @{L='순증가';E={"+$($_.NvmeGain)"}},
    @{L='필요호스트';E={$_.HostsNeeded}}, @{L='축소가능';E={"-$($_.HostReduction)"}} -AutoSize
Write-Host "===============================================================================" -ForegroundColor Yellow
Write-Host " CSV(호스트별)   : $CsvPath" -ForegroundColor Gray
Write-Host " CSV(클러스터요약): $ClusterCsvPath" -ForegroundColor Gray
Write-Host " HTML: $HtmlPath" -ForegroundColor Gray
Write-Host "===============================================================================" -ForegroundColor Yellow
