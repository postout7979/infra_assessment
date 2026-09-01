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

Export-ModuleMember -Function Save-InventorySnapshot, Get-ClosestSnapshot
