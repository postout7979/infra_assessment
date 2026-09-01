# VCFOpsApiClient.psm1
# -----------------------------------------------------------------------------
# VCF Operations (Aria Operations / vRealize Operations) suite-api 클라이언트
#
#   인증:        POST /suite-api/api/auth/token/acquire
#   리소스 목록:  GET  /suite-api/api/resources
#   관계(상하위): GET  /suite-api/api/resources/{id}/relationships
#   속성:        GET  /suite-api/api/resources/{id}/properties
#   통계(다건):   POST /suite-api/api/resources/stats/query   (대량 조회는 이 엔드포인트 권장)
#
# PowerShell 7+ 기준으로 작성했습니다(Invoke-RestMethod -SkipCertificateCheck 사용).
# Windows PowerShell 5.1에서 자체서명 인증서를 건너뛰려면 별도의 인증서 콜백 설정이
# 필요하니, 가능하면 PowerShell 7+ (pwsh) 사용을 권장합니다.
# -----------------------------------------------------------------------------

$Script:VCFOpsSession = $null

function Connect-VCFOps {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$HostUrl,
        [Parameter(Mandatory)][string]$Username,
        [Parameter(Mandatory)][string]$Password,
        [string]$AuthSource = "LOCAL",
        [switch]$SkipCertCheck,
        [int]$TimeoutSec = 60
    )
    $base = $HostUrl.TrimEnd('/')
    $bodyObj = @{ username = $Username; password = $Password; authSource = $AuthSource }
    $bodyJson = $bodyObj | ConvertTo-Json

    $irmParams = @{
        Method      = "POST"
        Uri         = "$base/suite-api/api/auth/token/acquire"
        Body        = $bodyJson
        ContentType = "application/json"
        Headers     = @{ Accept = "application/json" }
        TimeoutSec  = $TimeoutSec
    }
    if ($SkipCertCheck) { $irmParams["SkipCertificateCheck"] = $true }

    try {
        $resp = Invoke-RestMethod @irmParams
    }
    catch {
        throw "VCF Operations 로그인 실패: $($_.Exception.Message)"
    }

    $token = $resp.token
    if (-not $token) {
        throw "로그인 응답에서 토큰을 찾을 수 없습니다: $($resp | ConvertTo-Json -Depth 3 -Compress)"
    }

    $Script:VCFOpsSession = @{
        BaseUrl       = $base
        Token         = $token
        Username      = $Username
        Password      = $Password
        AuthSource    = $AuthSource
        SkipCertCheck = [bool]$SkipCertCheck
        TimeoutSec    = $TimeoutSec
    }
    Write-Verbose "VCF Operations 로그인 성공 ($base)"
    return $Script:VCFOpsSession
}

function Disconnect-VCFOps {
    [CmdletBinding()]
    param()
    if (-not $Script:VCFOpsSession) { return }
    try {
        Invoke-VCFOpsApi -Method POST -Path "/suite-api/api/auth/token/release" -AllowRetry:$false | Out-Null
        Write-Verbose "VCF Operations 로그아웃 완료"
    }
    catch {
        Write-Verbose "로그아웃 중 오류(무시): $($_.Exception.Message)"
    }
    $Script:VCFOpsSession = $null
}

function Invoke-VCFOpsApi {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$Method,
        [Parameter(Mandatory)][string]$Path,
        [hashtable]$QueryParams,
        $Body,
        [switch]$AllowRetry = $true
    )
    if (-not $Script:VCFOpsSession) {
        throw "VCF Operations에 연결되어 있지 않습니다. 먼저 Connect-VCFOps를 호출하세요."
    }

    $uri = "$($Script:VCFOpsSession.BaseUrl)$Path"
    $headers = @{
        Authorization = "vRealizeOpsToken $($Script:VCFOpsSession.Token)"
        Accept        = "application/json"
    }

    $irmParams = @{
        Method      = $Method
        Uri         = $uri
        Headers     = $headers
        ContentType = "application/json"
        TimeoutSec  = $Script:VCFOpsSession.TimeoutSec
    }
    if ($Script:VCFOpsSession.SkipCertCheck) { $irmParams["SkipCertificateCheck"] = $true }
    if ($QueryParams) { $irmParams["Body"] = $QueryParams }                      # GET -> 쿼리스트링 자동 변환
    if ($null -ne $Body) { $irmParams["Body"] = ($Body | ConvertTo-Json -Depth 8) }  # POST -> JSON 본문

    try {
        return Invoke-RestMethod @irmParams
    }
    catch {
        $statusCode = $null
        if ($_.Exception.Response) {
            try { $statusCode = [int]$_.Exception.Response.StatusCode } catch { $statusCode = $null }
        }
        if ($statusCode -eq 401 -and $AllowRetry) {
            Write-Verbose "토큰 만료로 재로그인 시도"
            Connect-VCFOps -HostUrl $Script:VCFOpsSession.BaseUrl -Username $Script:VCFOpsSession.Username `
                -Password $Script:VCFOpsSession.Password -AuthSource $Script:VCFOpsSession.AuthSource `
                -SkipCertCheck:$Script:VCFOpsSession.SkipCertCheck -TimeoutSec $Script:VCFOpsSession.TimeoutSec | Out-Null
            return Invoke-VCFOpsApi -Method $Method -Path $Path -QueryParams $QueryParams -Body $Body -AllowRetry:$false
        }
        throw "VCFOps API 호출 실패 [$Method $Path]: $($_.Exception.Message)"
    }
}

function Get-VCFOpsResources {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$ResourceKind,
        [string]$AdapterKind = "VMWARE",
        [int]$PageSize = 1000,
        [int]$MaxPages = 50
    )
    $results = @()
    $page = 0
    while ($page -lt $MaxPages) {
        $q = @{ resourceKind = $ResourceKind; adapterKind = $AdapterKind; pageSize = $PageSize; page = $page }
        $data = Invoke-VCFOpsApi -Method GET -Path "/suite-api/api/resources" -QueryParams $q
        $chunk = @($data.resourceList)
        $results += $chunk
        $totalPages = 1
        if ($data.pageInfo -and $data.pageInfo.totalPages) { $totalPages = $data.pageInfo.totalPages }
        $page++
        if ($page -ge $totalPages -or $chunk.Count -eq 0) { break }
    }
    Write-Verbose "$ResourceKind 리소스 $($results.Count)건 조회"
    return $results
}

function Get-VCFOpsChildren {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$ResourceId,
        [Parameter(Mandatory)][string]$ChildResourceKind,
        [int]$PageSize = 1000,
        [int]$MaxPages = 20
    )
    $out = @()
    $page = 0
    while ($page -lt $MaxPages) {
        try {
            $data = Invoke-VCFOpsApi -Method GET -Path "/suite-api/api/resources/$ResourceId/relationships" `
                -QueryParams @{ relationshipType = "CHILD"; page = $page; pageSize = $PageSize }
        }
        catch {
            Write-Warning "relationships 조회 실패($ResourceId): $($_.Exception.Message)"
            return $out
        }
        $chunk = @($data.resourceList)
        foreach ($r in $chunk) {
            if ($r.resourceKey.resourceKindKey -eq $ChildResourceKind) { $out += $r.identifier }
        }
        $totalPages = 1
        if ($data.pageInfo -and $data.pageInfo.totalPages) { $totalPages = $data.pageInfo.totalPages }
        $page++
        if ($page -ge $totalPages -or $chunk.Count -eq 0) { break }
    }
    return $out
}

function Get-VCFOpsProperties {
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$ResourceId)
    $data = Invoke-VCFOpsApi -Method GET -Path "/suite-api/api/resources/$ResourceId/properties"
    $out = @{}
    foreach ($p in @($data.property)) {
        $out[$p.name] = $p.value
    }
    return $out
}

function Get-VCFOpsStatsQuery {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string[]]$ResourceIds,
        [Parameter(Mandatory)][string[]]$StatKeys,
        [Parameter(Mandatory)][long]$BeginMs,
        [Parameter(Mandatory)][long]$EndMs,
        [string]$RollUpType = "AVG",
        [string]$IntervalType = "HOURS",
        [int]$IntervalQuantity = 1,
        [int]$BatchSize = 200
    )
    $out = @{}
    if (-not $ResourceIds -or $ResourceIds.Count -eq 0) { return $out }

    for ($i = 0; $i -lt $ResourceIds.Count; $i += $BatchSize) {
        $endIdx = [Math]::Min($i + $BatchSize, $ResourceIds.Count) - 1
        $chunk = $ResourceIds[$i..$endIdx]
        $body = @{
            resourceId       = @($chunk)
            statKey          = @($StatKeys)
            begin            = $BeginMs
            end              = $EndMs
            rollUpType       = $RollUpType
            intervalType     = $IntervalType
            intervalQuantity = $IntervalQuantity
        }
        $data = Invoke-VCFOpsApi -Method POST -Path "/suite-api/api/resources/stats/query" -Body $body
        foreach ($v in @($data.values)) {
            $rid = $v.resourceId
            if (-not $out.ContainsKey($rid)) { $out[$rid] = @{} }
            foreach ($s in @($v.'stat-list'.stat)) {
                $key = $s.statKey.key
                $out[$rid][$key] = @($s.data)
            }
        }
    }
    return $out
}

function Get-VCFOpsStatsLatest {
    # 최신 값 - cpu/mem 현재 사용률 등에 사용
    # 윈도우를 3시간으로 넉넉히 잡은 이유: 클러스터 레벨 등 일부 supermetric은
    # 집계 주기가 길어 30분 윈도우로는 값이 비어있는 경우가 실제 환경에서 확인됨.
    [CmdletBinding()]
    param(
        [string[]]$ResourceIds,
        [Parameter(Mandatory)][string[]]$StatKeys,
        [int]$BatchSize = 200,
        [int]$WindowMinutes = 180
    )
    $out = @{}
    if (-not $ResourceIds -or $ResourceIds.Count -eq 0) { return $out }

    $endMs = [DateTimeOffset]::UtcNow.ToUnixTimeMilliseconds()
    $beginMs = $endMs - ($WindowMinutes * 60 * 1000)
    $raw = Get-VCFOpsStatsQuery -ResourceIds $ResourceIds -StatKeys $StatKeys -BeginMs $beginMs -EndMs $endMs `
        -IntervalType "MINUTES" -IntervalQuantity 5 -BatchSize $BatchSize

    foreach ($rid in $raw.Keys) {
        $out[$rid] = @{}
        foreach ($k in $raw[$rid].Keys) {
            $vals = $raw[$rid][$k]
            $out[$rid][$k] = if ($vals.Count -gt 0) { [double]$vals[$vals.Count - 1] } else { 0.0 }
        }
    }
    return $out
}

function Get-VCFOpsStatsPointInTime {
    # 특정 시점(예: 7일 전) 기준 평균값 조회 - WoW 비교용
    [CmdletBinding()]
    param(
        [string[]]$ResourceIds,
        [Parameter(Mandatory)][string[]]$StatKeys,
        [Parameter(Mandatory)][long]$AtMs,
        [int]$WindowMinutes = 60,
        [int]$BatchSize = 200
    )
    $out = @{}
    if (-not $ResourceIds -or $ResourceIds.Count -eq 0) { return $out }

    $beginMs = $AtMs - ($WindowMinutes * 60 * 1000)
    $endMs = $AtMs + ($WindowMinutes * 60 * 1000)
    $raw = Get-VCFOpsStatsQuery -ResourceIds $ResourceIds -StatKeys $StatKeys -BeginMs $beginMs -EndMs $endMs `
        -IntervalType "MINUTES" -IntervalQuantity 5 -BatchSize $BatchSize

    foreach ($rid in $raw.Keys) {
        $out[$rid] = @{}
        foreach ($k in $raw[$rid].Keys) {
            $vals = $raw[$rid][$k]
            $out[$rid][$k] = if ($vals.Count -gt 0) { ($vals | Measure-Object -Average).Average } else { 0.0 }
        }
    }
    return $out
}

Export-ModuleMember -Function Connect-VCFOps, Disconnect-VCFOps, Invoke-VCFOpsApi, Get-VCFOpsResources, `
    Get-VCFOpsChildren, Get-VCFOpsProperties, Get-VCFOpsStatsQuery, Get-VCFOpsStatsLatest, Get-VCFOpsStatsPointInTime
