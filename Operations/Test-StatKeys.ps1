<#
.SYNOPSIS
    클러스터/호스트 리소스에서 실제로 수집되는 statKey 목록을 뽑아 cpu/mem/contention/
    diskspace 관련 키만 필터링해서 보여줍니다. (Modules/VCFOpsApiClient.psm1 필요)

.EXAMPLE
    .\Test-StatKeys.ps1 -HostUrl https://vcfops.corp.local -Username admin -SkipCertCheck
#>
param(
    [string]$HostUrl = $env:VCFOPS_HOST,
    [string]$Username = $env:VCFOPS_USERNAME,
    [string]$Password = $env:VCFOPS_PASSWORD,
    [switch]$SkipCertCheck
)

Remove-Module -Name "VCFOpsApiClient" -Force -ErrorAction SilentlyContinue
Import-Module (Join-Path $PSScriptRoot "Modules\VCFOpsApiClient.psm1") -Force

if (-not $HostUrl) { $HostUrl = Read-Host "VCF Operations URL" }
if (-not $Username) { $Username = Read-Host "사용자명" }
if (-not $Password) {
    $sp = Read-Host "비밀번호" -AsSecureString
    $Password = [System.Net.NetworkCredential]::new("", $sp).Password
}

Connect-VCFOps -HostUrl $HostUrl -Username $Username -Password $Password -SkipCertCheck:$SkipCertCheck | Out-Null

try {
    # 1) 실제 클러스터 1개, 호스트 1개를 가져와서 "그 리소스에 실제로 값이 들어오고 있는" 통계키만 추출
    #    (adapterkinds/.../statkeys 는 "정의된 모든 키" 목록이라 너무 많아서,
    #     latest 값이 있는 키만 보는 게 실제 진단에 더 유용합니다)
    $cluster = (Get-VCFOpsResources -ResourceKind "ClusterComputeResource" -PageSize 1) | Select-Object -First 1
    $hostRes = (Get-VCFOpsResources -ResourceKind "HostSystem" -PageSize 1) | Select-Object -First 1
    $vmRes   = (Get-VCFOpsResources -ResourceKind "VirtualMachine" -PageSize 1) | Select-Object -First 1
    $dcRes   = (Get-VCFOpsResources -ResourceKind "Datacenter" -PageSize 1) | Select-Object -First 1

    function Show-WorkingKeys {
        param($Resource, [string]$Label, [string]$Pattern)
        if (-not $Resource) { Write-Host "[$Label] 리소스를 찾지 못했습니다." -ForegroundColor Yellow; return }
        Write-Host "`n=== $Label : $($Resource.resourceKey.name) ($($Resource.identifier)) ===" -ForegroundColor Cyan

        # 최근 6시간 내 값이 있는 모든 statKey를 가져와 패턴에 맞는 것만 필터
        $end = [DateTimeOffset]::UtcNow.ToUnixTimeMilliseconds()
        $begin = $end - (6 * 60 * 60 * 1000)
        $data = Invoke-VCFOpsApi -Method GET -Path "/suite-api/api/resources/$($Resource.identifier)/stats" `
            -QueryParams @{ begin = $begin; end = $end; rollUpType = "AVG"; intervalType = "HOURS"; intervalQuantity = 1 }

        $statList = @($data.values.'stat-list'.stat)
        if (-not $statList -or $statList.Count -eq 0) { $statList = @($data.'stat-list'.stat) }

        $matched = $statList | Where-Object { $_.statKey.key -match $Pattern } | ForEach-Object {
            $lastVal = if ($_.data -and $_.data.Count -gt 0) { $_.data[-1] } else { $null }
            [PSCustomObject]@{ Key = $_.statKey.key; LastValue = $lastVal }
        }
        if ($matched) {
            $matched | Sort-Object Key | Format-Table -AutoSize | Out-String | Write-Host
        }
        else {
            Write-Host "(관련 키를 찾지 못했습니다 — 응답 구조가 예상과 다를 수 있어 원본을 $($Label)_raw.json 으로 저장합니다)" -ForegroundColor Yellow
            $data | ConvertTo-Json -Depth 10 | Set-Content "$($Label)_raw.json" -Encoding utf8
        }
    }

    $perfPattern = 'cpu|mem|contention|ready|diskspace|latency|datastore|virtualDisk|net\||iops|disk\|'
    # 수량(인벤토리) 관련 메트릭은 별도 패턴으로 — "summary|number_running_vcpus" 처럼
    # "summary|number_*" / "summary|total_number_*" 형태의 카운트 계열 supermetric을 찾습니다.
    $countPattern = 'number|count|summary\|total'

    Show-WorkingKeys -Resource $cluster -Label "Cluster" -Pattern $perfPattern
    Show-WorkingKeys -Resource $hostRes -Label "Host" -Pattern $perfPattern
    Show-WorkingKeys -Resource $vmRes -Label "VM" -Pattern $perfPattern

    Write-Host "`n--- 수량(인벤토리) 관련 메트릭 확인 (클러스터/데이터센터) ---" -ForegroundColor Magenta
    Show-WorkingKeys -Resource $cluster -Label "Cluster-Count" -Pattern $countPattern
    Show-WorkingKeys -Resource $dcRes -Label "Datacenter-Count" -Pattern $countPattern

    Write-Host "`n--- vSphere World 리소스 확인 (인벤토리 수량 시계열 비교용) ---" -ForegroundColor Magenta
    $world = $null
    try {
        $wdata = Invoke-VCFOpsApi -Method GET -Path "/suite-api/api/resources" -QueryParams @{ resourceKind = "vSphere World"; pageSize = 10 }
        $world = @($wdata.resourceList) | Select-Object -First 1
    } catch { }
    if (-not $world) {
        Write-Host "resourceKind='vSphere World' 로 직접 찾지 못해 전체 탐색합니다..." -ForegroundColor Yellow
        for ($p = 0; $p -lt 5 -and -not $world; $p++) {
            $wdata = Invoke-VCFOpsApi -Method GET -Path "/suite-api/api/resources" -QueryParams @{ adapterKind = "VMWARE"; pageSize = 1000; page = $p }
            $world = @($wdata.resourceList) | Where-Object { $_.resourceKey.resourceKindKey -match "(?i)world" } | Select-Object -First 1
            $totalPages = 1
            if ($wdata.pageInfo -and $wdata.pageInfo.totalPages) { $totalPages = $wdata.pageInfo.totalPages }
            if ($p + 1 -ge $totalPages) { break }
        }
    }
    if ($world) {
        Write-Host "찾음: $($world.resourceKey.name)  (resourceKindKey=$($world.resourceKey.resourceKindKey), id=$($world.identifier))" -ForegroundColor Green
        Show-WorkingKeys -Resource $world -Label "World-Count" -Pattern $countPattern
    }
    else {
        Write-Host "vSphere World 리소스를 찾지 못했습니다." -ForegroundColor Red
    }

    Write-Host "`n--- Datastore 리소스 capacity/used 키 확인 (데이터스토어 현황용) ---" -ForegroundColor Magenta
    $dsRes = (Get-VCFOpsResources -ResourceKind "Datastore" -PageSize 1) | Select-Object -First 1
    Show-WorkingKeys -Resource $dsRes -Label "Datastore" -Pattern 'diskspace|capacity|used|datastore'
}
finally {
    Disconnect-VCFOps
}

Write-Host "`n위 표(특히 cpu/mem/contention/diskspace 와 수량 관련 줄)를 복사해서 보내주시면 stat_keys 매핑을 정확히 고쳐드리겠습니다." -ForegroundColor Green
