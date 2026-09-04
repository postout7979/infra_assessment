<#
    Script Name : allinonevmw.ps1
    Description : infra_assessment 저장소(postout7979/infra_assessment) 하위 6개 폴더의 스크립트를
                  메뉴에서 선택해 실행하는 통합 런처. (powercli 저장소는 더 이상 사용하지 않음)
                    [1] vcf_9_upgrade      - VCF9 사전점검 / NVMe 메모리 티어링 분석
                    [2] Operations         - VCF Operations 운영현황 리포트
                    [3] security-hardening - 보안 하드닝 감사
                    [4] vcenter            - vCenter 일일 종합 리포트
                    [5] vmsa               - VMSA 취약점 관리 툴킷
                    [6] kisa_esx           - KISA 가상화(하이퍼바이저) 취약점 점검
                  이 런처 자체는 수집/분석 로직을 갖지 않고 각 폴더의 원본 .ps1을 그대로
                  호출만 합니다 - 원본 스크립트가 업데이트돼도 이 파일은 그대로 두면 됩니다.

    사전 준비   : 이 스크립트를 infra_assessment 저장소 루트(폴더들과 같은 위치)에 두세요.

                  infra_assessment\                      <- git clone https://github.com/postout7979/infra_assessment
                   ├─ allinonevmw.ps1                    <- 이 파일
                   ├─ vcf_9_upgrade\
                   ├─ Operations\
                   ├─ security-hardening\
                   ├─ vcenter\
                   ├─ vmsa\
                   └─ kisa_esx\

                  저장소 루트가 아닌 다른 위치에 두고 싶다면 환경변수 VMWTOOLS_INFRA_PATH 로
                  infra_assessment 저장소 루트 경로를 지정하세요.

    실행 방법   : .\allinonevmw.ps1
                  (Set-ExecutionPolicy -Scope CurrentUser RemoteSigned 필요할 수 있음)

    참고        : 이 스크립트는 실행 시작 시 저장소 폴더 전체에 대해 Unblock-File을 자동으로
                  수행합니다. GitHub에서 ZIP으로 내려받아 압축을 푼 경우(예: infra_assessment-main
                  폴더) Windows가 파일을 "인터넷에서 받음"으로 표시해 두는데, 이 상태로
                  RemoteSigned 정책에서 실행하면 "is not digitally signed" 에러가 납니다.
                  자동 Unblock으로 대부분 해결되지만, 그래도 같은 에러가 나면 아래를 수동 실행하세요.

                    Get-ChildItem -Path . -Recurse | Unblock-File
#>

param()

Set-StrictMode -Off
$ErrorActionPreference = "Continue"

# ============================================================
# 0. 경로 설정 - infra_assessment 저장소 루트
#    보통은 이 스크립트가 저장소 루트에 있으므로 $PSScriptRoot 그대로 사용하면 됩니다.
#    다른 위치에 둔다면 환경변수 VMWTOOLS_INFRA_PATH 로 재정의하세요.
# ============================================================
$RepoRoot = if ($env:VMWTOOLS_INFRA_PATH) { $env:VMWTOOLS_INFRA_PATH } else { $PSScriptRoot }

# 메뉴에서 실제로 호출할 스크립트 경로 모음 (원본 저장소 파일명을 그대로 참조)
$Scripts = @{
    Vcf9Precheck       = Join-Path $RepoRoot "vcf_9_upgrade\vcf9-precheck-toolkit_v2.ps1"
    Vcf9NvmeTiering    = Join-Path $RepoRoot "vcf_9_upgrade\vcf9-nvme-tiering-analysis.ps1"
    Operations         = Join-Path $RepoRoot "Operations\New-VCFOpsReport.ps1"
    AuditRunner        = Join-Path $RepoRoot "security-hardening\vmware-tools\audit_runner.ps1"
    AuditReporter      = Join-Path $RepoRoot "security-hardening\audit-reporter.ps1"
    VCenterDailyReport = Join-Path $RepoRoot "vcenter\Get_VC_DailyReport.ps1"
    VmsaDownloader     = Join-Path $RepoRoot "vmsa\vmsa_fulllist_downloader.ps1"
    VmsaCveLookup      = Join-Path $RepoRoot "vmsa\vmsa_cve_lookup.ps1"
    VmsaEnvironmentReport = Join-Path $RepoRoot "vmsa\vmsa_environment_report.ps1"
    KisaEsxAudit       = Join-Path $RepoRoot "kisa_esx\invoke-vSpherekisaaudit.ps1"
}

# ============================================================
# 0.5 Windows "인터넷에서 받은 파일" 차단 자동 해제 (Unblock-File)
#     GitHub에서 ZIP으로 내려받아 압축을 풀었거나(예: infra_assessment-main 폴더),
#     이메일/공유 폴더 등으로 옮겨 받은 .ps1/.psm1 파일은 Windows가 Zone.Identifier로
#     "인터넷에서 받은 파일"로 표시해 둡니다. 이 상태에서 실행 정책이 RemoteSigned면
#     "is not digitally signed. You cannot run this script on the current system." 에러로
#     실행이 막힙니다. 매번 메뉴를 띄우기 전에 저장소 전체를 한 번 Unblock-File 처리해서
#     이 문제를 예방합니다(실패해도 조용히 무시 - 권한 부족 등으로 실패해도 런처는 계속 진행).
# ============================================================
if (Test-Path -LiteralPath $RepoRoot) {
    try {
        Get-ChildItem -Path $RepoRoot -Recurse -File -Include *.ps1, *.psm1, *.psd1 -ErrorAction SilentlyContinue |
            Unblock-File -ErrorAction SilentlyContinue
    }
    catch { }
}

# ============================================================
# 공통 헬퍼
# ============================================================
function Write-Title {
    param([string]$Text)
    Write-Host ""
    Write-Host ("=" * 62) -ForegroundColor Cyan
    Write-Host ("  " + $Text) -ForegroundColor Cyan
    Write-Host ("=" * 62) -ForegroundColor Cyan
}

function Pause-Return {
    Write-Host ""
    Read-Host "메뉴로 돌아가려면 Enter" | Out-Null
}

# 실제로 자식 스크립트를 실행. 존재하지 않으면 안내만 하고 메뉴로 복귀.
# 자식 스크립트 실행 중 오류가 나도 이 런처(부모 콘솔)는 죽지 않도록 try/catch로 감쌈.
function Invoke-ToolScript {
    param(
        [Parameter(Mandatory)][string]$Path,
        [hashtable]$BoundParameters = @{}
    )

    if (-not (Test-Path -LiteralPath $Path)) {
        Write-Host ""
        Write-Host "[ERROR] 스크립트를 찾을 수 없습니다: $Path" -ForegroundColor Red
        Write-Host "        저장소 clone 위치를 확인하세요 (환경변수 VMWTOOLS_INFRA_PATH)." -ForegroundColor Yellow
        Pause-Return
        return
    }

    Write-Host ""
    Write-Host "[실행] $Path" -ForegroundColor DarkGray
    if ($BoundParameters.Count -gt 0) {
        Write-Host "       Params: $($BoundParameters.Keys -join ', ')" -ForegroundColor DarkGray
    }
    Write-Host ""

    Push-Location (Split-Path -Parent $Path)
    try {
        & $Path @BoundParameters
    }
    catch {
        Write-Host ""
        Write-Host "[ERROR] 스크립트 실행 중 예외가 발생했습니다:" -ForegroundColor Red
        Write-Host $_.Exception.Message -ForegroundColor Red
    }
    finally {
        Pop-Location
    }

    Pause-Return
}

# vcf_9_upgrade 폴더 안의 vSphere_Inventory_* 폴더 목록을 보여주고 선택받음
# (all-in-one-vmw.ps1을 어디서 실행했는지와 무관하게 항상 vcf_9_upgrade 폴더 기준으로 찾음 -
#  vcf9-precheck-toolkit_v2.ps1 메뉴 1/2가 그 폴더 안에 vSphere_Inventory_YYYYMMDD_HHMM 을 생성하기 때문)
function Select-Vcf9InventoryFolder {
    $vcfDir = Join-Path $RepoRoot "vcf_9_upgrade"
    $invFolders = @(Get-ChildItem -Path $vcfDir -Directory -Filter "vSphere_Inventory_*" -ErrorAction SilentlyContinue |
        Sort-Object LastWriteTime -Descending)

    if ($invFolders.Count -eq 0) {
        Write-Host ""
        Write-Host "[안내] $vcfDir 안에서 vSphere_Inventory_* 폴더를 찾지 못했습니다." -ForegroundColor Yellow
        $manual = Read-Host "인벤토리 폴더 경로를 직접 입력하세요 (취소하려면 Enter)"
        if ([string]::IsNullOrWhiteSpace($manual)) { return $null }
        return $manual
    }

    Write-Host ""
    Write-Host "[vcf_9_upgrade] 안의 인벤토리 폴더 목록 (최근 수정일 순):" -ForegroundColor Cyan
    for ($i = 0; $i -lt $invFolders.Count; $i++) {
        Write-Host ("  [{0}] {1}  (수정일: {2})" -f ($i + 1), $invFolders[$i].Name, $invFolders[$i].LastWriteTime)
    }
    Write-Host "  [0] 직접 경로 입력"

    $choice = Read-Host "`n선택"
    if ($choice -eq "0") {
        $manual = Read-Host "인벤토리 폴더 경로를 입력하세요"
        if ([string]::IsNullOrWhiteSpace($manual)) { return $null }
        return $manual
    }

    $idx = 0
    if ([int]::TryParse($choice, [ref]$idx) -and $idx -ge 1 -and $idx -le $invFolders.Count) {
        return $invFolders[$idx - 1].FullName
    }

    Write-Host "잘못된 선택입니다." -ForegroundColor Yellow
    return $null
}

# ============================================================
# 서브 메뉴: VCF 9 업그레이드 (vcf_9_upgrade)
#   vcf9-precheck-toolkit_v2.ps1     : 인벤토리 수집 + HCL 호환성 검사 (스크립트 자체 내부 메뉴 1~4)
#   vcf9-nvme-tiering-analysis.ps1   : 위 인벤토리 폴더를 입력받아 NVMe 메모리 티어링 효과 분석
# ============================================================
function Show-Vcf9UpgradeMenu {
    while ($true) {
        Write-Title "VCF 9 업그레이드 (vcf_9_upgrade)"
        Write-Host "  [1] 사전점검 통합 스크립트 (인벤토리 수집 + HCL 호환성 검사)  - vcf9-precheck-toolkit_v2.ps1"
        Write-Host "  [2] NVMe 메모리 티어링 효과 분석                             - vcf9-nvme-tiering-analysis.ps1"
        Write-Host "  [0] 상위 메뉴로"
        $sel = Read-Host "`n선택"

        switch ($sel) {
            "1" { Invoke-ToolScript -Path $Scripts.Vcf9Precheck }
            "2" {
                $inv = Select-Vcf9InventoryFolder
                if ([string]::IsNullOrWhiteSpace($inv)) {
                    Write-Host "인벤토리 폴더가 선택되지 않았습니다." -ForegroundColor Yellow
                }
                else {
                    $bp = @{ InventoryPath = $inv }

                    $cpu = Read-Host "Max CPU % (Enter=기본값 80)"
                    if (-not [string]::IsNullOrWhiteSpace($cpu)) { $bp.MaxCpuPct = [double]$cpu }

                    $ratio = Read-Host "Max Active/Alloc 메모리 비율 % (Enter=기본값 40)"
                    if (-not [string]::IsNullOrWhiteSpace($ratio)) { $bp.MaxActiveRatioPct = [double]$ratio }

                    $factor = Read-Host "물리메모리/Active메모리 최소 배율 (Enter=기본값 2.0)"
                    if (-not [string]::IsNullOrWhiteSpace($factor)) { $bp.PhysMemFactor = [double]$factor }

                    Invoke-ToolScript -Path $Scripts.Vcf9NvmeTiering -BoundParameters $bp
                }
            }
            "0" { return }
            default { Write-Host "잘못된 선택입니다." -ForegroundColor Yellow }
        }
    }
}

# ============================================================
# 서브 메뉴: 보안 하드닝 감사 (security-hardening)
#   audit_runner.ps1   : vCenter/ESXi/VM 대상 감사를 새로 실행해서 txt 로그 생성
#   audit-reporter.ps1 : 이미 만들어진 txt 로그 폴더를 읽어 HTML/CSV/Excel 리포트 생성
# ============================================================
function Show-SecurityHardeningMenu {
    while ($true) {
        Write-Title "보안 하드닝 감사 (security-hardening)"
        Write-Host "  [1] 신규 감사 실행 (vCenter/ESXi/VM 접속 -> txt 로그 생성)  - audit_runner.ps1"
        Write-Host "  [2] 기존 로그로 리포트 생성 (HTML/CSV/Excel)                - audit-reporter.ps1"
        Write-Host "  [0] 상위 메뉴로"
        $sel = Read-Host "`n선택"

        switch ($sel) {
            "1" { Invoke-ToolScript -Path $Scripts.AuditRunner }
            "2" { Invoke-ToolScript -Path $Scripts.AuditReporter }
            "0" { return }
            default { Write-Host "잘못된 선택입니다." -ForegroundColor Yellow }
        }
    }
}

# ============================================================
# 서브 메뉴: VMSA 취약점 관리 (vmsa)
#   vmsa_fulllist_downloader.ps1 : 전체 VMSA 목록 수집 (기본 사용 순서상 먼저 실행)
#   vmsa_cve_lookup.ps1          : 위에서 만든 CVE 목록 CSV를 입력받아 NVD 조회 (CSV 경로 필요)
# ============================================================
function Show-VmsaMenu {
    while ($true) {
        Write-Title "VMSA 취약점 관리 툴킷 (vmsa)"
        Write-Host "  [1] VMSA 전체 목록 다운로드          - vmsa_fulllist_downloader.ps1"
        Write-Host "  [2] CVE 상세 조회 (NVD)              - vmsa_cve_lookup.ps1"
        Write-Host "  [3] 버전 확인 조회(vCenter연결)      - vmsa_environment_report.ps1"
        Write-Host "  [0] 상위 메뉴로"
        $sel = Read-Host "`n선택"

        switch ($sel) {
            "1" { Invoke-ToolScript -Path $Scripts.VmsaDownloader }
            "2" {
                $csv = Read-Host "CVE 목록 CSV 경로 (예: vmsa_fulllist_downloader.ps1 실행 결과 VMSA_CVE_List_*.csv)"
                if ([string]::IsNullOrWhiteSpace($csv)) {
                    Write-Host "CSV 경로가 필요합니다." -ForegroundColor Yellow
                }
                else {
                    Invoke-ToolScript -Path $Scripts.VmsaCveLookup -BoundParameters @{ CveListCsv = $csv }
                }
            }
            "3" {
                # vCenter 주소/계정/비밀번호는 원본 스크립트가 실행 중 Read-Host로 직접 안전하게 입력받으므로
                # 여기서는 파라미터 없이 그대로 호출만 함(VMSA_FullList_Data.json이 vmsa 폴더에 없으면
                # 원본 스크립트가 vmsa_fulllist_downloader.ps1을 자동으로 먼저 실행해 생성함).
                Invoke-ToolScript -Path $Scripts.VmsaEnvironmentReport
            }
            "0" { return }
            default { Write-Host "잘못된 선택입니다." -ForegroundColor Yellow }
        }
    }
}

# 사용자가 입력한 호스트 주소에서 스킴(http://, https://)을 떼어낸 뒤 https:// 를 다시 붙임
# (사용자는 "https://" 없이 호스트명/주소만 입력하면 됨)
function ConvertTo-HttpsHostUrl {
    param([string]$RawHost)
    if ([string]::IsNullOrWhiteSpace($RawHost)) { return $null }
    $clean = $RawHost.Trim() -replace '^(https?://)', ''
    $clean = $clean.TrimEnd('/')
    if ([string]::IsNullOrWhiteSpace($clean)) { return $null }
    return "https://$clean"
}

# ============================================================
# VCF Operations 운영현황 리포트 (Operations) - 실제 연동 수집
#   (Mock 미리보기는 제거됨 - 항상 실제 VCF Operations 연동으로 실행)
# ============================================================
function Invoke-OperationsConnect {
    Write-Title "VCF Operations 운영현황 리포트 (Operations)"

    $hostInput = Read-Host "VCF Operations 호스트 주소 (예: vcfops.corp.local - https:// 는 붙이지 마세요. 비워두면 환경변수 VCFOPS_HOST 사용)"
    $username  = Read-Host "Username (비워두면 환경변수 VCFOPS_USERNAME 사용)"
    $customer  = Read-Host "고객사명 (Enter=Customer)"

    $bp = @{}
    $hostUrl = ConvertTo-HttpsHostUrl $hostInput
    if ($hostUrl) { $bp.HostUrl = $hostUrl }
    if (-not [string]::IsNullOrWhiteSpace($username)) { $bp.Username = $username }
    if (-not [string]::IsNullOrWhiteSpace($customer)) { $bp.CustomerName = $customer }
    $bp.SkipCertCheck = $true
    # 비밀번호는 -Password로 넘기지 않으면 New-VCFOpsReport.ps1이 실행 중 안전하게 입력받습니다.
    Invoke-ToolScript -Path $Scripts.Operations -BoundParameters $bp
}

# ============================================================
# KISA 가상화(하이퍼바이저) 취약점 점검 (kisa_esx)
#   invoke-vSpherekisaaudit.ps1 : KISA HV-01~HV-25 항목을 PowerCLI로 원격 점검
#   -Server만 필수이고, -Credential/-HostCredential을 생략하면 스크립트 자체가
#   Get-Credential로 안전하게 입력받으므로(동일 계정이면 -HostCredential도 자동 재사용),
#   기본은 서버 주소만 물어보고 나머지는 그대로 원본 스크립트에 맡깁니다.
# ============================================================
function Invoke-KisaEsxAudit {
    Write-Title "KISA 가상화(하이퍼바이저) 취약점 점검 (kisa_esx)"

    $server = Read-Host "점검 대상 vCenter 또는 ESXi 주소 (필수)"
    if ([string]::IsNullOrWhiteSpace($server)) {
        Write-Host "서버 주소가 필요합니다." -ForegroundColor Yellow
        Pause-Return
        return
    }

    $bp = @{ Server = $server }

    $ignoreCert = Read-Host "인증서 오류 무시 (자체서명 인증서 등)? (Y/n, Enter=Y)"
    if ($ignoreCert -notmatch '^[Nn]') { $bp.IgnoreCertificate = $true }

    $diffHostCred = Read-Host "ESXi 호스트 root 계정이 vCenter 계정과 다릅니까? (y/N, Enter=N이면 같은 계정 재사용)"
    if ($diffHostCred -match '^[Yy]') {
        $bp.HostCredential = Get-Credential -Message "ESXi 호스트 root 계정 정보를 입력하세요"
    }
    # -Credential은 여기서 넘기지 않음 - 생략하면 원본 스크립트가 Get-Credential로 직접 안전하게 입력받음

    $outDir = Read-Host "결과 저장 폴더 (Enter=기본값 .\output_esxi)"
    if (-not [string]::IsNullOrWhiteSpace($outDir)) { $bp.OutputDir = $outDir }

    $snapDays = Read-Host "스냅샷 경과일 경고 임계값 (Enter=기본값 30)"
    if (-not [string]::IsNullOrWhiteSpace($snapDays)) { $bp.SnapshotDaysThreshold = [int]$snapDays }

    Invoke-ToolScript -Path $Scripts.KisaEsxAudit -BoundParameters $bp
}

# ============================================================
# 메인 메뉴
# ============================================================
function Show-MainMenu {
    while ($true) {
        Write-Title "infra_assessment All-in-One Toolkit"
        Write-Host "  [1] VCF 9 업그레이드 (사전점검 / NVMe 티어링 분석)   (vcf_9_upgrade)"
        Write-Host "  [2] VCF Operations 운영현황 리포트                   (Operations)"
        Write-Host "  [3] 보안 하드닝 감사                                 (security-hardening)"
        Write-Host "  [4] vCenter 일일 종합 리포트                         (vcenter)"
        Write-Host "  [5] VMSA 취약점 관리 툴킷                            (vmsa)"
        Write-Host "  [6] KISA 가상화(하이퍼바이저) 취약점 점검             (kisa_esx)"
        Write-Host ""
        Write-Host "  [0] 종료"
        Write-Host ""
        Write-Host "  infra_assessment repo : $RepoRoot" -ForegroundColor DarkGray

        $sel = Read-Host "`n선택"

        switch ($sel.ToUpper()) {
            "1" { Show-Vcf9UpgradeMenu }
            "2" { Invoke-OperationsConnect }
            "3" { Show-SecurityHardeningMenu }
            "4" {
                $vc = Read-Host "vCenter 서버 주소 (여러 개면 쉼표로 구분, 비워두면 실행 중 입력받음)"
                $bp = @{}
                if (-not [string]::IsNullOrWhiteSpace($vc)) {
                    $bp.VCenterServer = ($vc -split "," | ForEach-Object { $_.Trim() })
                }
                Invoke-ToolScript -Path $Scripts.VCenterDailyReport -BoundParameters $bp
            }
            "5" { Show-VmsaMenu }
            "6" { Invoke-KisaEsxAudit }
            "0" { return }
            default { Write-Host "잘못된 선택입니다." -ForegroundColor Yellow }
        }
    }
}

Show-MainMenu
