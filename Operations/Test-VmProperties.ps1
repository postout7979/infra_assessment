<#
.SYNOPSIS
    리소스 1대의 전체 properties를 가져와 관련 키만 필터링해서 보여줍니다.
    (VM 인벤토리 항목, 데이터스토어 isLocal 등이 비어있거나 의심스러울 때 사용)

.EXAMPLE
    .\Test-VmProperties.ps1 -HostUrl https://vcfops.corp.local -Username admin -SkipCertCheck
    .\Test-VmProperties.ps1 -VmName "kdw-harbor" -SkipCertCheck                       # 특정 VM 지정
    .\Test-VmProperties.ps1 -ResourceKind Datastore -SkipCertCheck                    # 데이터스토어 properties 확인 (isLocal 등)
    .\Test-VmProperties.ps1 -ResourceKind Datastore -VmName "datastore1" -SkipCertCheck # 특정 데이터스토어 지정
#>
param(
    [string]$HostUrl = $env:VCFOPS_HOST,
    [string]$Username = $env:VCFOPS_USERNAME,
    [string]$Password = $env:VCFOPS_PASSWORD,
    [string]$VmName,                                  # 리소스 이름 지정 (VM 이외의 ResourceKind에도 동일하게 사용)
    [string]$ResourceKind = "VirtualMachine",          # 예: VirtualMachine, Datastore, HostSystem, ClusterComputeResource
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
    $list = Get-VCFOpsResources -ResourceKind $ResourceKind -PageSize 50
    $target = if ($VmName) { $list | Where-Object { $_.resourceKey.name -eq $VmName } | Select-Object -First 1 }
              else { $list | Select-Object -First 1 }

    if (-not $target) { Write-Host "[$ResourceKind] 리소스를 찾지 못했습니다." -ForegroundColor Red; return }

    Write-Host "`n=== $ResourceKind : $($target.resourceKey.name) ($($target.identifier)) ===" -ForegroundColor Cyan
    $props = Get-VCFOpsProperties -ResourceId $target.identifier

    Write-Host "`n전체 property 개수: $($props.Keys.Count)" -ForegroundColor DarkGray

    # VM은 속성이 많아 주요 키워드로 필터링, 그 외(Datastore 등)는 보통 적어서 전체를 보여줍니다.
    if ($ResourceKind -eq "VirtualMachine") {
        $pattern = 'memory|hardware|tools|disk|snapshot|guestFullName|powerState|version'
        $matched = $props.Keys | Where-Object { $_ -match $pattern } | Sort-Object | ForEach-Object {
            [PSCustomObject]@{ Key = $_; Value = $props[$_] }
        }
    }
    else {
        $matched = $props.Keys | Sort-Object | ForEach-Object {
            [PSCustomObject]@{ Key = $_; Value = $props[$_] }
        }
    }

    if ($matched) {
        $matched | Format-Table -AutoSize -Wrap | Out-String | Write-Host
    }
    else {
        Write-Host "관련 키를 찾지 못했습니다. 전체 목록을 properties_raw.json 으로 저장합니다." -ForegroundColor Yellow
    }
    $props | ConvertTo-Json -Depth 5 | Set-Content "properties_raw.json" -Encoding utf8
    Write-Host "`n(전체 목록은 properties_raw.json 에도 저장했습니다)" -ForegroundColor DarkGray
}
finally {
    Disconnect-VCFOps
}

Write-Host "`n위 표를 복사해서 보내주시면 정확히 고쳐드리겠습니다." -ForegroundColor Green
