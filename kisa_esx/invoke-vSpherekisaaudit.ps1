<#
.SYNOPSIS
    KISA 주요정보통신기반시설 기술적 취약점 분석·평가 - 가상화(하이퍼바이저) 점검 스크립트 (PowerCLI 버전)

.DESCRIPTION
    KISA 가상화 장비 취약점 분석·평가 항목(HV-01 ~ HV-25, 총 25항목)을
    VMware vSphere PowerCLI 를 이용해 원격에서 점검합니다.
    ESXi 호스트에 SSH로 접속할 필요 없이, Windows(또는 PowerCLI가 설치된 환경)에서
    vCenter 또는 개별 ESXi 호스트에 연결하여 점검합니다.

    근거 문서: KISA 주요정보통신기반시설 기술적 취약점 분석·평가 방법 상세가이드 (2026)
              - 가상화 장비 취약점 분석·평가 항목
              https://raw.githubusercontent.com/cdppcorp/KESE-KIT/refs/heads/main/skills-ko/kesekit-start-ko/templates/cii/virtualization.md

.PARAMETER Server
    점검 대상 vCenter 또는 ESXi 호스트의 주소(IP/FQDN).

.PARAMETER Credential
    vCenter(또는 ESXi) 접속 계정 정보(PSCredential). 생략 시 Get-Credential 로 대화형 입력받음.

.PARAMETER HostCredential
    vCenter로 접속한 경우, 각 ESXi 호스트의 로컬 계정(root 등) 정보를 관리하는 일부 항목
    (HV-01/HV-04/HV-10)은 vCenter 계정만으로는 조회가 되지 않아 호스트에 직접 연결해야 합니다.
    이 파라미터로 호스트 root 계정 정보를 전달하면 해당 항목도 자동 점검됩니다.
    생략 시 -Credential 값을 그대로 사용해 시도하며(같은 계정이면 그대로 동작), 연결에
    실패하는 호스트는 해당 항목이 [MANUAL]로 표시되고 사유가 안내됩니다.

.PARAMETER IgnoreCertificate
    자체서명 인증서 등으로 인증서 오류가 발생하는 경우 지정 (Set-PowerCLIConfiguration -InvalidCertificateAction Ignore).

.PARAMETER OutputDir
    결과 파일(txt/csv/html)을 저장할 폴더. 생략 시 현재 폴더 아래 "output_esxi" 폴더에 자동 생성됩니다.

.PARAMETER ReportBaseName
    결과 파일의 기본 이름(확장자 제외). 생략 시 "kisa_virtualization_report_YYYYMMDD_HHmmss" 형식으로 자동 생성됩니다.

.PARAMETER SnapshotDaysThreshold
    스냅샷 경과일 경고 임계값(기본 30일).

.EXAMPLE
    .\Invoke-KisaVirtualizationAudit.ps1 -Server esxi01.corp.local -IgnoreCertificate

.EXAMPLE
    .\Invoke-KisaVirtualizationAudit.ps1 -Server vcenter.corp.local -Credential (Get-Credential) -HostCredential (Get-Credential -Message 'ESXi root 계정') -OutputDir C:\powercli\kisa\output_esxi

.NOTES
    - 이 스크립트는 조회(Read-Only)만 수행하며 설정을 변경하지 않습니다.
    - PowerCLI(VMware.PowerCLI 모듈)가 설치되어 있어야 합니다: Install-Module VMware.PowerCLI -Scope CurrentUser
    - 일부 항목(HV-13, HV-15, HV-21 등)은 조직 정책/운영기록과 대조가 필요하여
      자동 판정이 불가능하므로 [MANUAL] 로 표시됩니다.
    - 분산 스위치(vDS)의 NetFlow/포트미러링 세부 설정 등 일부는 vSphere Client에서 추가 확인이 필요합니다.
    - 결과는 -OutputDir 폴더(기본 .\output_esxi) 아래에 .txt / .csv / .html 3종으로 저장되며,
      ESXi 호스트별로 구분되고 각 호스트 내에서는 HV-01~HV-25 오름차순으로 정렬됩니다.
    - CSV는 한글이 깨지지 않도록 BOM 포함 UTF-8로 저장됩니다.
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [string]$Server,

    [System.Management.Automation.PSCredential]$Credential,

    [System.Management.Automation.PSCredential]$HostCredential,

    [switch]$IgnoreCertificate,

    [string]$OutputDir = 'output_esxi',

    [string]$ReportBaseName,

    [int]$SnapshotDaysThreshold = 30
)

#region 초기화 -----------------------------------------------------------------

$ErrorActionPreference = 'Stop'

if (-not (Test-Path -Path $OutputDir)) {
    New-Item -ItemType Directory -Path $OutputDir -Force | Out-Null
}
$OutputDir = (Resolve-Path -Path $OutputDir).Path

if (-not $ReportBaseName) {
    $ts = Get-Date -Format 'yyyyMMdd_HHmmss'
    $ReportBaseName = "kisa_virtualization_report_$ts"
}
$ReportPath = Join-Path -Path $OutputDir -ChildPath "$ReportBaseName.txt"
$CsvPath = Join-Path -Path $OutputDir -ChildPath "$ReportBaseName.csv"
$HtmlPath = Join-Path -Path $OutputDir -ChildPath "$ReportBaseName.html"

# 결과 저장용 리스트 (HostName 포함 - 호스트별 구분/정렬에 사용)
$script:Results = New-Object System.Collections.Generic.List[object]

function Write-Log {
    param([string]$Message)
    Write-Host $Message
    Add-Content -Path $ReportPath -Value $Message
}

function Write-Section {
    param([string]$Title)
    Write-Log ''
    Write-Log ('=' * 79)
    Write-Log "  $Title"
    Write-Log ('=' * 79)
}

function Add-Result {
    param(
        [string]$HostName,
        [string]$Code,
        [string]$Title,
        [string]$Importance,
        [ValidateSet('PASS', 'FAIL', 'WARN', 'MANUAL', 'ERROR')]
        [string]$Status,
        [string]$Detail
    )
    $script:Results.Add([PSCustomObject]@{
        HostName   = $HostName
        Code       = $Code
        Title      = $Title
        Importance = $Importance
        Status     = $Status
        Detail     = $Detail
    })

    $color = switch ($Status) {
        'PASS'   { 'Green' }
        'FAIL'   { 'Red' }
        'WARN'   { 'Yellow' }
        'MANUAL' { 'Cyan' }
        default  { 'Magenta' }
    }
    Write-Host "[$Status] $Code ($Importance) $Title" -ForegroundColor $color
    Write-Host "        -> $Detail"
    Add-Content -Path $ReportPath -Value "[$Status] $Code ($Importance) $Title"
    Add-Content -Path $ReportPath -Value "        -> $Detail"
}

function Sort-KisaResults {
    param($Results)
    $Results | Sort-Object HostName, { [int]($_.Code -replace '\D', '') }
}

# PowerCLI 모듈 로드
try {
    if (-not (Get-Module -Name VMware.VimAutomation.Core -ListAvailable -ErrorAction SilentlyContinue) `
        -and -not (Get-Module -Name VMware.PowerCLI -ListAvailable -ErrorAction SilentlyContinue)) {
        throw "PowerCLI 모듈을 찾을 수 없습니다. 'Install-Module VMware.PowerCLI -Scope CurrentUser' 로 설치 후 다시 실행하세요."
    }
    Import-Module VMware.VimAutomation.Core -ErrorAction SilentlyContinue | Out-Null
}
catch {
    Write-Error $_
    exit 1
}

if ($IgnoreCertificate) {
    Set-PowerCLIConfiguration -InvalidCertificateAction Ignore -Confirm:$false -Scope Session | Out-Null
}
Set-PowerCLIConfiguration -ParticipateInCeip:$false -Confirm:$false -Scope Session -ErrorAction SilentlyContinue | Out-Null

if (-not $Credential) {
    $Credential = Get-Credential -Message "vSphere 접속 계정 정보를 입력하세요 (예: root 또는 vCenter 계정)"
}
if (-not $HostCredential) {
    $HostCredential = $Credential
}

Write-Log "KISA 가상화 보안 점검 스크립트 실행 결과 (PowerCLI)"
Write-Log "실행 시각    : $(Get-Date)"
Write-Log "대상 서버    : $Server"
Write-Log "출력 폴더    : $OutputDir"
Write-Log "리포트 파일  : $ReportPath (CSV/HTML 동일 경로에 생성)"

try {
    $null = Connect-VIServer -Server $Server -Credential $Credential -ErrorAction Stop
}
catch {
    Write-Error "vCenter/ESXi 접속에 실패했습니다: $($_.Exception.Message)"
    exit 1
}

#endregion

#region 헬퍼 함수 ---------------------------------------------------------------

function Get-AdvSettingValue {
    param($Entity, [string]$Name)
    try {
        $s = Get-AdvancedSetting -Entity $Entity -Name $Name -ErrorAction Stop
        if ($s) { return $s.Value }
        return $null
    } catch { return $null }
}

function New-KisaHtmlReport {
    param(
        [System.Collections.Generic.List[object]]$Results,
        [string]$Path,
        [string]$ServerName,
        [int]$HostCount
    )

    $enc = { param($s) [System.Net.WebUtility]::HtmlEncode([string]$s) }

    $pass = ($Results | Where-Object Status -eq 'PASS').Count
    $fail = ($Results | Where-Object Status -eq 'FAIL').Count
    $warn = ($Results | Where-Object Status -eq 'WARN').Count
    $manual = ($Results | Where-Object Status -eq 'MANUAL').Count
    $errorCnt = ($Results | Where-Object Status -eq 'ERROR').Count

    $sorted = Sort-KisaResults -Results $Results
    $hostGroups = $sorted | Group-Object HostName

    $hostBlocks = foreach ($grp in $hostGroups) {
        $hp = ($grp.Group | Where-Object Status -eq 'PASS').Count
        $hf = ($grp.Group | Where-Object Status -eq 'FAIL').Count
        $hw = ($grp.Group | Where-Object Status -eq 'WARN').Count
        $hm = ($grp.Group | Where-Object Status -eq 'MANUAL').Count
        $he = ($grp.Group | Where-Object Status -eq 'ERROR').Count

        $rows = foreach ($r in $grp.Group) {
            @"
<tr class="row" data-status="$($r.Status)"><td>$(& $enc $r.Code)</td><td>$(& $enc $r.Title)</td><td class="imp-$(& $enc $r.Importance)">$(& $enc $r.Importance)</td><td><span class="badge badge-$($r.Status)">$($r.Status)</span></td><td>$(& $enc $r.Detail)</td></tr>
"@
        }

        @"
<details class="host-block" data-host="$(& $enc $grp.Name)">
  <summary>
    <span class="host-name">$(& $enc $grp.Name)</span>
    <span class="host-counts">
      <span class="mini mini-PASS">PASS $hp</span>
      <span class="mini mini-FAIL">FAIL $hf</span>
      <span class="mini mini-WARN">WARN $hw</span>
      <span class="mini mini-MANUAL">MANUAL $hm</span>
      <span class="mini mini-ERROR">ERROR $he</span>
    </span>
  </summary>
  <table>
    <thead>
      <tr><th style="width:70px">코드</th><th style="width:200px">항목</th><th style="width:60px">중요도</th><th style="width:90px">결과</th><th>상세</th></tr>
    </thead>
    <tbody>
$($rows -join "`n")
    </tbody>
  </table>
</details>
"@
    }

    $html = @"
<!doctype html>
<html lang="ko">
<head>
<meta charset="utf-8">
<title>KISA 가상화(vSphere) 보안 점검 리포트</title>
<style>
  :root {
    --grid: #b7c0ca;
    --grid-strong: #7a8794;
  }
  body { font-family: -apple-system, "Malgun Gothic", "Segoe UI", sans-serif; background:#f4f5f7; color:#1f2328; margin:0; padding:24px; }
  h1 { font-size:20px; margin:0 0 4px; }
  h2 { font-size:15px; margin:28px 0 10px; }
  .meta { color:#57606a; font-size:13px; margin-bottom:20px; }
  .cards { display:flex; gap:12px; flex-wrap:wrap; margin-bottom:8px; }
  .card { flex:1; min-width:110px; background:#fff; border:1px solid var(--grid); border-radius:8px; padding:12px 16px; text-align:center;
          cursor:pointer; user-select:none; transition:box-shadow .12s, transform .12s; }
  .card:hover { box-shadow:0 2px 8px rgba(0,0,0,.08); }
  .card.active { box-shadow:0 0 0 2px #24292f inset; background:#f6f8fa; }
  .card .num { font-size:24px; font-weight:700; }
  .card .lbl { font-size:12px; color:#57606a; margin-top:2px; }
  .filter-hint { font-size:12px; color:#57606a; margin:0 0 24px; }
  .PASS   { color:#1a7f37; }
  .FAIL   { color:#cf222e; }
  .WARN   { color:#9a6700; }
  .MANUAL { color:#0969da; }
  .ERROR  { color:#8250df; }
  table { width:100%; border-collapse:collapse; background:#fff; }
  table, th, td { border:1px solid var(--grid); }
  th, td { padding:9px 12px; text-align:left; font-size:13px; vertical-align:top; }
  th { background:#eef1f4; font-size:12px; text-transform:uppercase; letter-spacing:.03em; color:#3a4552; border-bottom:2px solid var(--grid-strong); }
  tr.row:nth-child(even) td { background:#fafbfc; }
  .badge { display:inline-block; padding:2px 8px; border-radius:12px; font-size:12px; font-weight:600; color:#fff; white-space:nowrap; }
  .badge-PASS   { background:#1a7f37; }
  .badge-FAIL   { background:#cf222e; }
  .badge-WARN   { background:#9a6700; }
  .badge-MANUAL { background:#0969da; }
  .badge-ERROR  { background:#8250df; }
  .imp-상 { font-weight:700; }
  .footer-note { margin-top:20px; font-size:12px; color:#57606a; }

  .host-block { background:#fff; border:1px solid var(--grid); border-radius:8px; margin-bottom:10px; overflow:hidden; }
  .host-block > summary { list-style:none; cursor:pointer; padding:12px 16px; display:flex; align-items:center;
                           justify-content:space-between; flex-wrap:wrap; gap:8px; font-weight:600; }
  .host-block > summary::-webkit-details-marker { display:none; }
  .host-block > summary::before { content:"▸"; margin-right:8px; color:#57606a; display:inline-block; transition:transform .12s; }
  .host-block[open] > summary::before { transform:rotate(90deg); }
  .host-block > summary:hover { background:#f6f8fa; }
  .host-name { flex:1; min-width:160px; }
  .host-counts { display:flex; gap:6px; flex-wrap:wrap; font-weight:400; }
  .mini { font-size:11px; padding:2px 7px; border-radius:10px; border:1px solid var(--grid); color:#3a4552; }
  .mini-PASS   { border-color:#1a7f37; color:#1a7f37; }
  .mini-FAIL   { border-color:#cf222e; color:#cf222e; }
  .mini-WARN   { border-color:#9a6700; color:#9a6700; }
  .mini-MANUAL { border-color:#0969da; color:#0969da; }
  .mini-ERROR  { border-color:#8250df; color:#8250df; }
  .host-block table { border-top:2px solid var(--grid-strong); }
</style>
</head>
<body>
<h1>KISA 가상화(vSphere) 보안 점검 리포트</h1>
<div class="meta">
  실행 시각: $(Get-Date) &nbsp;|&nbsp; 대상 서버: $(& $enc $ServerName) &nbsp;|&nbsp; 점검 호스트 수: $HostCount 대
</div>
<div class="cards" id="filterCards">
  <div class="card" data-status="PASS"><div class="num PASS">$pass</div><div class="lbl">PASS 양호</div></div>
  <div class="card" data-status="FAIL"><div class="num FAIL">$fail</div><div class="lbl">FAIL 취약</div></div>
  <div class="card" data-status="WARN"><div class="num WARN">$warn</div><div class="lbl">WARN 주의/권고</div></div>
  <div class="card" data-status="MANUAL"><div class="num MANUAL">$manual</div><div class="lbl">MANUAL 수동확인</div></div>
  <div class="card" data-status="ERROR"><div class="num ERROR">$errorCnt</div><div class="lbl">ERROR 조회실패</div></div>
</div>
<p class="filter-hint">위 카드를 클릭하면 해당 결과만 필터링되어 표시됩니다(다시 클릭하면 전체 보기로 복귀). 호스트 이름을 클릭하면 상세 항목이 펼쳐집니다.</p>

<h2>호스트 목록 (클릭하여 상세 보기)</h2>
<div id="hostList">
$($hostBlocks -join "`n")
</div>

<div class="footer-note">
  * FAIL/WARN 항목은 우선적으로 조치하시고, MANUAL 항목은 조직의 보안정책/운영기록과 대조하여 확인하시기 바랍니다.<br>
  * 근거: KISA 주요정보통신기반시설 기술적 취약점 분석·평가 방법 상세가이드 - 가상화 장비 취약점 분석·평가 항목 (HV-01~HV-25)
</div>

<script>
(function () {
  var activeStatus = null;
  var cards = document.querySelectorAll('#filterCards .card');
  var hostBlocks = document.querySelectorAll('.host-block');

  cards.forEach(function (card) {
    card.addEventListener('click', function () {
      var status = card.getAttribute('data-status');
      activeStatus = (activeStatus === status) ? null : status;
      cards.forEach(function (c) {
        c.classList.toggle('active', c.getAttribute('data-status') === activeStatus);
      });
      applyFilter();
    });
  });

  function applyFilter() {
    hostBlocks.forEach(function (block) {
      var rows = block.querySelectorAll('tr.row');
      var visible = 0;
      rows.forEach(function (row) {
        var show = !activeStatus || row.getAttribute('data-status') === activeStatus;
        row.style.display = show ? '' : 'none';
        if (show) { visible++; }
      });
      if (activeStatus) {
        block.style.display = visible > 0 ? '' : 'none';
        block.open = visible > 0;
      } else {
        block.style.display = '';
      }
    });
  }
})();
</script>
</body>
</html>
"@

    Set-Content -Path $Path -Value $html -Encoding UTF8
}

#endregion

try {
    $VMHosts = Get-VMHost -ErrorAction Stop
    if (-not $VMHosts) { throw "점검 대상 ESXi 호스트를 찾을 수 없습니다." }

    foreach ($VMHost in $VMHosts) {
        $hn = $VMHost.Name

        Write-Section "[$hn] 1. 계정 관리 (HV-01 ~ HV-07)"

        # ESXi 로컬 계정/SNMP 관련 cmdlet(Get-VMHostAccount, Get-VMHostSnmp)은 -Server 파라미터가
        # "실제 접속(VIServer) 연결"을 요구하며 vCenter로 접속한 상태에서 VMHost 객체를 그대로 넘기면
        # 타입 오류(ERROR)가 발생한다. 이를 해결하기 위해 각 호스트에 대해 별도의 direct 연결을
        # (실패해도 전체 스크립트에는 영향 없도록) 시도한다.
        $hostConn = $null
        $hostConnErrMsg = $null
        try {
            $hostConn = Connect-VIServer -Server $hn -Credential $HostCredential -NotDefault -ErrorAction Stop
        } catch {
            $hostConnErrMsg = $_.Exception.Message
        }

        # --- HV-01 / HV-04 공용: 로컬 계정 목록 조회 ---
        $accounts = $null
        $acctErrMsg = $null
        if ($hostConn) {
            try {
                $accounts = Get-VMHostAccount -Server $hostConn -ErrorAction Stop
            } catch {
                $acctErrMsg = $_.Exception.Message
            }
        }

        # --- HV-01: 기본 관리자 계정 변경 ---
        if ($accounts) {
            $rootAcct = $accounts | Where-Object { $_.Id -eq 'root' }
            Add-Result $hn 'HV-01' '기본 관리자 계정 변경' '상' 'MANUAL' `
                "ESXi는 root 계정명을 변경할 수 없음. root 계정 존재 확인됨(Id=$($rootAcct.Id)). 최초 설치 후 root 비밀번호를 기본값에서 변경했는지는 조직 운영기록으로 별도 확인 필요."
        } elseif ($hostConn) {
            Add-Result $hn 'HV-01' '기본 관리자 계정 변경' '상' 'ERROR' "Get-VMHostAccount 조회 실패: $acctErrMsg"
        } else {
            Add-Result $hn 'HV-01' '기본 관리자 계정 변경' '상' 'MANUAL' `
                "ESXi 호스트에 직접 연결하지 못해 로컬 계정 조회 불가(사유: $hostConnErrMsg). vCenter 계정과 호스트 root 계정이 다른 경우 -HostCredential 파라미터로 호스트 root 계정 정보를 전달하면 자동 점검이 가능합니다."
        }

        # --- HV-02: 비밀번호 복잡성 설정 ---
        $pqc = Get-AdvSettingValue -Entity $VMHost -Name 'Security.PasswordQualityControl'
        if ($null -ne $pqc) {
            if ($pqc -match 'retry\s*=\s*3') {
                Add-Result $hn 'HV-02' '비밀번호 복잡성 설정' '상' 'PASS' "PasswordQualityControl: $pqc"
            } else {
                Add-Result $hn 'HV-02' '비밀번호 복잡성 설정' '상' 'WARN' "현재 값: [$pqc]. 권고 형식(retry=3, 최소 7자 이상 등)과 비교하여 검토 필요."
            }
        } else {
            Add-Result $hn 'HV-02' '비밀번호 복잡성 설정' '상' 'ERROR' "Security.PasswordQualityControl 설정값 조회 실패"
        }

        # --- HV-03: 계정 잠금 임계값 설정 ---
        $lockFail = Get-AdvSettingValue -Entity $VMHost -Name 'Security.AccountLockFailures'
        $unlockTime = Get-AdvSettingValue -Entity $VMHost -Name 'Security.AccountUnlockTime'
        if ($null -ne $lockFail) {
            $lockFailInt = [int]$lockFail
            if ($lockFailInt -gt 0 -and $lockFailInt -le 5) {
                Add-Result $hn 'HV-03' '계정 잠금 임계값 설정' '상' 'PASS' "AccountLockFailures=$lockFailInt (5회 이하), AccountUnlockTime=$unlockTime 초"
            } elseif ($lockFailInt -eq 0) {
                Add-Result $hn 'HV-03' '계정 잠금 임계값 설정' '상' 'FAIL' "AccountLockFailures=0 (계정 잠금 기능 비활성화 상태)"
            } else {
                Add-Result $hn 'HV-03' '계정 잠금 임계값 설정' '상' 'WARN' "AccountLockFailures=$lockFailInt (권고: 5회 이하), AccountUnlockTime=$unlockTime 초"
            }
        } else {
            Add-Result $hn 'HV-03' '계정 잠금 임계값 설정' '상' 'ERROR' "Security.AccountLockFailures 조회 실패"
        }

        # --- HV-04: 불필요한 계정 제거 ---
        if ($accounts) {
            $extra = $accounts | Where-Object { $_.Id -notin @('root', 'dcui', 'vpxuser') }
            if ($extra) {
                Add-Result $hn 'HV-04' '불필요한 계정 제거' '상' 'WARN' `
                    "root/dcui/vpxuser 외 로컬 계정 존재: [$(($extra.Id) -join ', ')] (총 $($accounts.Count)개 계정). 사용 목적 확인 후 불필요 시 제거 권고."
            } else {
                Add-Result $hn 'HV-04' '불필요한 계정 제거' '상' 'PASS' "표준 계정 외 추가 로컬 계정 없음 (총 $($accounts.Count)개)"
            }
        } elseif ($hostConn) {
            Add-Result $hn 'HV-04' '불필요한 계정 제거' '상' 'ERROR' "Get-VMHostAccount 조회 실패: $acctErrMsg"
        } else {
            Add-Result $hn 'HV-04' '불필요한 계정 제거' '상' 'MANUAL' `
                "ESXi 호스트에 직접 연결하지 못해 로컬 계정 조회 불가(사유: $hostConnErrMsg). -HostCredential 파라미터로 호스트 root 계정 정보를 전달하면 자동 점검이 가능합니다."
        }

        # --- HV-05: 관리자 권한 최소화 ---
        try {
            $perms = Get-VIPermission -Entity $VMHost -ErrorAction Stop
            $admins = $perms | Where-Object { $_.Role -like '*Admin*' -and $_.Principal -ne 'root' -and $_.Principal -notlike '*vpxuser*' }
            if ($admins) {
                Add-Result $hn 'HV-05' '관리자 권한 최소화' '상' 'WARN' `
                    "root 외 Admin 계열 권한 보유 계정/그룹: [$(($admins.Principal) -join ', ')]. 최소 인원/그룹으로 제한되어 있는지 확인 필요."
            } else {
                Add-Result $hn 'HV-05' '관리자 권한 최소화' '상' 'PASS' "root 외 Admin 권한이 부여된 계정 없음"
            }
        } catch {
            Add-Result $hn 'HV-05' '관리자 권한 최소화' '상' 'MANUAL' "Get-VIPermission 조회 불가(권한 부족 또는 미지원 환경일 수 있음): $($_.Exception.Message). vSphere Client > 호스트 > 권한 탭에서 수동 확인 필요."
        }

        # --- HV-06: 세션 타임아웃 설정 ---
        $shellInteractive = Get-AdvSettingValue -Entity $VMHost -Name 'UserVars.ESXiShellInteractiveTimeOut'
        $shellTimeout = Get-AdvSettingValue -Entity $VMHost -Name 'UserVars.ESXiShellTimeOut'
        $hostClientTimeout = Get-AdvSettingValue -Entity $VMHost -Name 'UserVars.HostClientSessionTimeout'
        if ($shellInteractive -and [int]$shellInteractive -gt 0) {
            Add-Result $hn 'HV-06' '세션 타임아웃 설정' '중' 'PASS' `
                "ESXiShellInteractiveTimeOut=$shellInteractive 초, ESXiShellTimeOut=$shellTimeout 초, HostClientSessionTimeout=$hostClientTimeout 초"
        } else {
            Add-Result $hn 'HV-06' '세션 타임아웃 설정' '중' 'FAIL' `
                "ESXiShellInteractiveTimeOut=$shellInteractive (0/미설정=무제한). 유휴 세션 자동 종료 시간 설정 필요."
        }

        # --- HV-07: 로그인 경고 메시지 설정 ---
        $welcome = Get-AdvSettingValue -Entity $VMHost -Name 'Annotations.WelcomeMessage'
        if ($welcome) {
            Add-Result $hn 'HV-07' '로그인 경고 메시지 설정' '하' 'PASS' "배너 설정됨: '$welcome'"
        } else {
            Add-Result $hn 'HV-07' '로그인 경고 메시지 설정' '하' 'FAIL' "로그인 경고 배너(Annotations.WelcomeMessage)가 설정되어 있지 않음"
        }

        Write-Section "[$hn] 2. 시스템 서비스 관리 (HV-08 ~ HV-16)"

        $services = Get-VMHostService -VMHost $VMHost

        # --- HV-08: 불필요한 서비스 비활성화 ---
        $riskyOn = $services | Where-Object { $_.Running -and $_.Key -in @('TSM-SSH', 'TSM', 'slpd', 'snmpd') }
        if ($riskyOn) {
            Add-Result $hn 'HV-08' '불필요한 서비스 비활성화' '상' 'WARN' `
                "실행 중인 위험 서비스: [$(($riskyOn.Key) -join ', ')]. 업무상 필요 여부 확인 후 불필요 시 Set-VMHostService/Stop-VMHostService 로 비활성화."
        } else {
            Add-Result $hn 'HV-08' '불필요한 서비스 비활성화' '상' 'PASS' "SSH/ESXi Shell/SLP/SNMP 등 대표적 위험 서비스 모두 비활성 상태"
        }

        # --- HV-09: SSH 보안 설정 ---
        $sshSvc = $services | Where-Object { $_.Key -eq 'TSM-SSH' }
        if ($sshSvc -and $sshSvc.Running) {
            Add-Result $hn 'HV-09' 'SSH 보안 설정' '상' 'WARN' `
                "SSH(TSM-SSH) 서비스가 활성화되어 있음. 상시 활성화는 권고되지 않으며 필요 시에만 임시 사용 권고. (root 직접 로그인 제한, 접속 IP 제한 등은 sshd_config 로 별도 확인 필요)"
        } else {
            Add-Result $hn 'HV-09' 'SSH 보안 설정' '상' 'PASS' "SSH(TSM-SSH) 서비스 비활성화 상태"
        }

        # --- HV-10: SNMP 보안 설정 ---
        if ($hostConn) {
            try {
                $snmp = Get-VMHostSnmp -Server $hostConn -ErrorAction Stop
                if ($snmp.Enabled) {
                    if ($snmp.ReadOnlyCommunity -contains 'public') {
                        Add-Result $hn 'HV-10' 'SNMP 보안 설정' '상' 'FAIL' "SNMP 활성화 상태이며 기본 Community 문자열('public') 사용 중"
                    } else {
                        Add-Result $hn 'HV-10' 'SNMP 보안 설정' '상' 'WARN' "SNMP 활성화 상태. Community=[$(($snmp.ReadOnlyCommunity) -join ', ')]. 가능하면 SNMPv3 사용 권고."
                    }
                } else {
                    Add-Result $hn 'HV-10' 'SNMP 보안 설정' '상' 'PASS' "SNMP 비활성화 상태"
                }
            } catch {
                Add-Result $hn 'HV-10' 'SNMP 보안 설정' '상' 'ERROR' "Get-VMHostSnmp 조회 실패: $($_.Exception.Message)"
            }
        } else {
            Add-Result $hn 'HV-10' 'SNMP 보안 설정' '상' 'MANUAL' `
                "ESXi 호스트에 직접 연결하지 못해 SNMP 설정 조회 불가(사유: $hostConnErrMsg). -HostCredential 파라미터로 호스트 root 계정 정보를 전달하면 자동 점검이 가능합니다."
        }

        # --- HV-11: NTP 시각 동기화 ---
        try {
            $ntpServers = Get-VMHostNtpServer -VMHost $VMHost -ErrorAction Stop
            $ntpSvc = $services | Where-Object { $_.Key -eq 'ntpd' }
            if ($ntpServers -and $ntpSvc -and $ntpSvc.Running) {
                Add-Result $hn 'HV-11' 'NTP 시각 동기화' '중' 'PASS' "NTP 서버: [$($ntpServers -join ', ')], ntpd 서비스 실행 중"
            } else {
                Add-Result $hn 'HV-11' 'NTP 시각 동기화' '중' 'FAIL' "NTP 미설정 또는 서비스 미실행 (서버:[$($ntpServers -join ', ')], ntpd 실행:$($ntpSvc.Running))"
            }
        } catch {
            Add-Result $hn 'HV-11' 'NTP 시각 동기화' '중' 'ERROR' "NTP 설정 조회 실패: $($_.Exception.Message)"
        }

        # --- HV-12: 호스트 방화벽 설정 ---
        try {
            $fwEx = Get-VMHostFirewallException -VMHost $VMHost -ErrorAction Stop
            $openAll = $fwEx | Where-Object { $_.Enabled -and $_.ExtensionData.AllowedHosts.AllIp -eq $true }
            if ($openAll) {
                Add-Result $hn 'HV-12' '호스트 방화벽 설정' '상' 'WARN' `
                    "'모든 IP 허용'으로 설정된 활성 방화벽 규칙 존재: [$(($openAll.Name) -join ', ')]. 관리 대역 IP로 제한 권고."
            } else {
                Add-Result $hn 'HV-12' '호스트 방화벽 설정' '상' 'PASS' "활성 방화벽 규칙 중 '모든 IP 허용' 설정 없음"
            }
        } catch {
            Add-Result $hn 'HV-12' '호스트 방화벽 설정' '상' 'ERROR' "Get-VMHostFirewallException 조회 실패: $($_.Exception.Message)"
        }

        # --- HV-13: 보안 패치 적용 ---
        Add-Result $hn 'HV-13' '보안 패치 적용' '상' 'MANUAL' `
            "현재 버전: $($VMHost.Version), 빌드: $($VMHost.Build). 최신 VMware 보안 패치(KB)와 대조하여 수동 확인 필요 (폐쇄망 등 자동 비교 불가 환경 고려)."

        # --- HV-14: 로그 설정 및 관리 ---
        $logHost = Get-AdvSettingValue -Entity $VMHost -Name 'Syslog.global.logHost'
        $logDir = Get-AdvSettingValue -Entity $VMHost -Name 'Syslog.global.logDir'
        if ($logHost) {
            Add-Result $hn 'HV-14' '로그 설정 및 관리' '중' 'PASS' "원격 Syslog 서버 설정됨: [$logHost], 로컬 로그 경로: $logDir"
        } else {
            Add-Result $hn 'HV-14' '로그 설정 및 관리' '중' 'WARN' "원격 Syslog 서버(Syslog.global.logHost)가 설정되어 있지 않음. 로컬 로그 경로: $logDir"
        }

        # --- HV-15: 백업 정책 수립 ---
        Add-Result $hn 'HV-15' '백업 정책 수립' '중' 'MANUAL' `
            "호스트/VM 백업 정책 수립 및 정기 백업 운영 여부는 조직 문서(백업 솔루션 운영기록 등)로 별도 확인 필요."

        # --- HV-16: SSL/TLS 관리 콘솔 암호화 ---
        $disabledProto = Get-AdvSettingValue -Entity $VMHost -Name 'UserVars.ESXiVPsDisabledProtocols'
        if ($disabledProto -and ($disabledProto -match 'sslv3|tlsv1\.0|tlsv1\.1')) {
            Add-Result $hn 'HV-16' 'SSL/TLS 관리 콘솔 암호화' '상' 'PASS' "취약 프로토콜 비활성화 설정됨: [$disabledProto]"
        } else {
            Add-Result $hn 'HV-16' 'SSL/TLS 관리 콘솔 암호화' '상' 'WARN' `
                "ESXiVPsDisabledProtocols=[$disabledProto]. SSLv3/TLSv1.0/1.1 비활성화 및 TLS1.2 이상만 허용 권고."
        }

        if ($hostConn) {
            Disconnect-VIServer -Server $hostConn -Confirm:$false -ErrorAction SilentlyContinue
        }

        Write-Section "[$hn] 3. 가상 머신 관리 (HV-17 ~ HV-21)"

        $vms = Get-VM -Location $VMHost -ErrorAction SilentlyContinue

        if (-not $vms) {
            Add-Result $hn 'HV-17' 'VM 간 격리 설정' '상' 'MANUAL' "해당 호스트에 등록된 VM 없음"
            Add-Result $hn 'HV-18' 'VM 리소스 제한 설정' '중' 'MANUAL' "해당 호스트에 등록된 VM 없음"
            Add-Result $hn 'HV-19' 'VM 스냅샷 관리' '중' 'MANUAL' "해당 호스트에 등록된 VM 없음"
            Add-Result $hn 'HV-20' 'VM 이동/복제 시 보안' '상' 'MANUAL' "해당 호스트에 등록된 VM 없음"
            Add-Result $hn 'HV-21' '불필요한 VM 제거' '중' 'MANUAL' "해당 호스트에 등록된 VM 없음"
        } else {
            $isoOptionsMustBeTrue = @(
                'isolation.tools.copy.disable',
                'isolation.tools.dnd.disable',
                'isolation.tools.diskWiper.disable',
                'isolation.tools.diskShrink.disable',
                'isolation.tools.hgfsServerSet.disable'
            )

            $isoBadVms = @(); $resUnlimitedVms = @(); $snapVms = @(); $migRiskVms = @(); $poweroffVms = @()

            foreach ($vm in $vms) {

                # HV-17: VM 간 격리 설정
                $missing = @()
                foreach ($optName in $isoOptionsMustBeTrue) {
                    $val = Get-AdvSettingValue -Entity $vm -Name $optName
                    if (-not $val -or $val.ToString().ToUpper() -ne 'TRUE') { $missing += $optName }
                }
                $guiOptVal = Get-AdvSettingValue -Entity $vm -Name 'isolation.tools.setGUIOptions.enable'
                if (-not $guiOptVal -or $guiOptVal.ToString().ToUpper() -ne 'FALSE') {
                    $missing += 'isolation.tools.setGUIOptions.enable(FALSE 권고)'
                }
                if ($missing.Count -gt 0) { $isoBadVms += $vm.Name }

                # HV-18: 리소스 제한
                try {
                    $resCfg = Get-VMResourceConfiguration -VM $vm -ErrorAction Stop
                    if (-not $resCfg.CpuLimitMhz -or $resCfg.CpuLimitMhz -eq -1) {
                        $resUnlimitedVms += $vm.Name
                    }
                } catch { $resUnlimitedVms += "$($vm.Name)(조회실패)" }

                # HV-19: 스냅샷 관리
                $snaps = Get-Snapshot -VM $vm -ErrorAction SilentlyContinue
                if ($snaps) {
                    foreach ($s in $snaps) {
                        $ageDays = [int]((Get-Date) - $s.Created).TotalDays
                        $snapVms += "$($vm.Name):$($s.Name)(${ageDays}일 경과)"
                    }
                }

                # HV-20: 이동/복제 시 보안 (vMotion 암호화)
                $migEnc = Get-AdvSettingValue -Entity $vm -Name 'migrate.encryption'
                if (-not $migEnc -or $migEnc -eq 'disabled') {
                    $migRiskVms += "$($vm.Name):$(if ($migEnc) { $migEnc } else { '미설정' })"
                }

                # HV-21: 불필요한 VM (전원 꺼짐 목록)
                if ($vm.PowerState -eq 'PoweredOff') { $poweroffVms += $vm.Name }
            }

            if ($isoBadVms.Count -gt 0) {
                Add-Result $hn 'HV-17' 'VM 간 격리 설정' '상' 'WARN' "격리(isolation.tools.*) 옵션이 권고값으로 설정되지 않은 VM: [$($isoBadVms -join ', ')]"
            } else {
                Add-Result $hn 'HV-17' 'VM 간 격리 설정' '상' 'PASS' "전체 $($vms.Count)개 VM에서 주요 isolation.tools.* 옵션 권고값 적용 확인"
            }

            if ($resUnlimitedVms.Count -gt 0) {
                Add-Result $hn 'HV-18' 'VM 리소스 제한 설정' '중' 'WARN' "CPU 리소스 제한이 무제한으로 설정된 VM: [$($resUnlimitedVms -join ', ')] (멀티테넌시/DoS 방지 위해 제한 설정 검토)"
            } else {
                Add-Result $hn 'HV-18' 'VM 리소스 제한 설정' '중' 'PASS' "전체 VM에서 CPU 리소스 제한이 설정됨"
            }

            if ($snapVms.Count -gt 0) {
                $oldCount = ($snapVms | Where-Object { $_ -match '(\d+)일 경과' -and [int]([regex]::Match($_, '(\d+)일 경과').Groups[1].Value) -ge $SnapshotDaysThreshold }).Count
                Add-Result $hn 'HV-19' 'VM 스냅샷 관리' '중' 'WARN' `
                    "잔존 스냅샷: [$($snapVms -join '; ')] (임계값 ${SnapshotDaysThreshold}일 이상 경과 항목: ${oldCount}개 - 정리 권고, 스토리지/성능 영향 주의)"
            } else {
                Add-Result $hn 'HV-19' 'VM 스냅샷 관리' '중' 'PASS' "잔존 스냅샷 없음"
            }

            if ($migRiskVms.Count -gt 0) {
                Add-Result $hn 'HV-20' 'VM 이동/복제 시 보안' '상' 'WARN' "vMotion 암호화(migrate.encryption)가 disabled/미설정인 VM: [$($migRiskVms -join ', ')] (opportunistic 이상 권고)"
            } else {
                Add-Result $hn 'HV-20' 'VM 이동/복제 시 보안' '상' 'PASS' "전체 VM에서 vMotion 암호화 옵션 확인됨"
            }

            if ($poweroffVms.Count -gt 0) {
                Add-Result $hn 'HV-21' '불필요한 VM 제거' '중' 'MANUAL' "전원이 꺼진(Off) VM: [$($poweroffVms -join ', ')] - 운영대장과 대조하여 장기 미사용 시 제거 권고 (자동 판별 불가)"
            } else {
                Add-Result $hn 'HV-21' '불필요한 VM 제거' '중' 'PASS' "전원이 꺼진 상태로 방치된 VM 없음"
            }
        }

        Write-Section "[$hn] 4. 가상 네트워크 관리 (HV-22 ~ HV-25)"

        $stdSwitches = Get-VirtualSwitch -VMHost $VMHost -Standard -ErrorAction SilentlyContinue
        $macChangeBad = @(); $forgedBad = @(); $promiscBad = @()

        foreach ($sw in $stdSwitches) {
            try {
                $sec = Get-SecurityPolicy -VirtualSwitch $sw -ErrorAction Stop
                if ($sec.MacChanges) { $macChangeBad += $sw.Name }
                if ($sec.ForgedTransmits) { $forgedBad += $sw.Name }
                if ($sec.AllowPromiscuous) { $promiscBad += $sw.Name }
            } catch { }
        }

        # --- HV-22: 가상 스위치 보안 설정 ---
        if ($macChangeBad.Count -gt 0 -or $forgedBad.Count -gt 0) {
            Add-Result $hn 'HV-22' '가상 스위치 보안 설정' '상' 'WARN' `
                "MAC Address Changes 허용:[$($macChangeBad -join ', ')] / Forged Transmits 허용:[$($forgedBad -join ', ')] -> 모두 Reject 권고"
        } elseif ($stdSwitches.Count -eq 0) {
            Add-Result $hn 'HV-22' '가상 스위치 보안 설정' '상' 'MANUAL' "표준 vSwitch 없음(vDS만 존재 시 vSphere Client에서 별도 확인 필요)"
        } else {
            Add-Result $hn 'HV-22' '가상 스위치 보안 설정' '상' 'PASS' "전체 $($stdSwitches.Count)개 표준 vSwitch에서 MAC 변경/위조 전송 Reject 설정 확인"
        }

        # --- HV-23: VLAN 분리 설정 ---
        $pgList = Get-VirtualPortGroup -VMHost $VMHost -Standard -ErrorAction SilentlyContinue
        $vlan4095 = $pgList | Where-Object { $_.VLanId -eq 4095 }
        if ($vlan4095) {
            Add-Result $hn 'HV-23' 'VLAN 분리 설정' '상' 'FAIL' "VLAN ID 4095(전체 트렁크, VGT)로 설정된 포트그룹: [$(($vlan4095.Name) -join ', ')] - 특정 VLAN으로 제한 필요"
        } else {
            Add-Result $hn 'HV-23' 'VLAN 분리 설정' '상' 'PASS' "VLAN 4095(전체 트렁크) 설정된 포트그룹 없음"
        }

        # --- HV-24: 가상 네트워크 모니터링 (해당 호스트가 속한 vDS 기준) ---
        $hostVds = Get-VDSwitch -VMHost $VMHost -ErrorAction SilentlyContinue
        if ($hostVds) {
            Add-Result $hn 'HV-24' '가상 네트워크 모니터링' '중' 'MANUAL' `
                "이 호스트가 연결된 분산 스위치(vDS): [$(($hostVds.Name) -join ', ')]. NetFlow/포트미러링 세부 설정은 vSphere Client(네트워킹 > vDS > 설정) 에서 별도 확인 필요."
        } else {
            Add-Result $hn 'HV-24' '가상 네트워크 모니터링' '중' 'MANUAL' `
                "표준 vSwitch만 사용 중(연결된 vDS 없음) - NetFlow/포트미러링 기능이 없으므로 외부 IDS/모니터링 솔루션 구성 여부를 별도 확인 필요."
        }

        # --- HV-25: 무차별 모드(Promiscuous Mode) 제한 ---
        if ($promiscBad.Count -gt 0) {
            Add-Result $hn 'HV-25' '무차별 모드(Promiscuous Mode) 제한' '상' 'FAIL' "Promiscuous Mode 허용된 vSwitch: [$($promiscBad -join ', ')] -> Reject로 변경 필요"
        } elseif ($stdSwitches.Count -eq 0) {
            Add-Result $hn 'HV-25' '무차별 모드(Promiscuous Mode) 제한' '상' 'MANUAL' "표준 vSwitch 없음 - vDS 포트그룹은 vSphere Client에서 별도 확인 필요"
        } else {
            Add-Result $hn 'HV-25' '무차별 모드(Promiscuous Mode) 제한' '상' 'PASS' "전체 표준 vSwitch에서 Promiscuous Mode = Reject 확인"
        }
    }

    #region 결과 요약 -----------------------------------------------------------
    Write-Section '점검 결과 요약'

    $pass = ($script:Results | Where-Object Status -eq 'PASS').Count
    $fail = ($script:Results | Where-Object Status -eq 'FAIL').Count
    $warn = ($script:Results | Where-Object Status -eq 'WARN').Count
    $manual = ($script:Results | Where-Object Status -eq 'MANUAL').Count
    $errorCnt = ($script:Results | Where-Object Status -eq 'ERROR').Count
    $total = $script:Results.Count

    Write-Log "총 점검 결과 수 : $total (호스트 $($VMHosts.Count)대 x 25항목[HV-01~HV-25])"
    Write-Log "  - PASS   (양호)         : $pass"
    Write-Log "  - FAIL   (취약)         : $fail"
    Write-Log "  - WARN   (주의/권고)    : $warn"
    Write-Log "  - MANUAL (수동확인필요) : $manual"
    Write-Log "  - ERROR  (조회실패)     : $errorCnt"

    # 호스트별로 구분되도록, 각 호스트 내에서는 HV-01~HV-25 오름차순으로 정렬하여 CSV/HTML 생성
    $sortedResults = Sort-KisaResults -Results $script:Results

    # CSV는 한글이 깨지지 않도록 BOM 포함 UTF-8로 직접 기록 (PowerShell 버전에 따라
    # Export-Csv -Encoding UTF8 이 BOM 없이 저장되어 Excel에서 한글이 깨지는 문제를 방지)
    $csvLines = $sortedResults | ConvertTo-Csv -NoTypeInformation
    [System.IO.File]::WriteAllLines($CsvPath, $csvLines, (New-Object System.Text.UTF8Encoding($true)))

    New-KisaHtmlReport -Results $sortedResults -Path $HtmlPath -ServerName $Server -HostCount $VMHosts.Count

    Write-Log ''
    Write-Log "출력 폴더    : $OutputDir"
    Write-Log "상세 결과는 다음 파일에 저장되었습니다:"
    Write-Log "  - 텍스트: $ReportPath"
    Write-Log "  - CSV   : $CsvPath"
    Write-Log "  - HTML  : $HtmlPath"
    #endregion
}
finally {
    Disconnect-VIServer -Server $Server -Confirm:$false -ErrorAction SilentlyContinue
}