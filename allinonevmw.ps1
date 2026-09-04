<#
    Script Name : all-in-one-vmw.ps1
    Description : infra_assessment 저장소(postout7979/infra_assessment) 하위 5개 폴더의 스크립트를
                  메뉴에서 선택해 실행하는 통합 런처. (powercli 저장소는 더 이상 사용하지 않음)
                    [1] vcf_9_upgrade      - VCF9 사전점검 / NVMe 메모리 티어링 분석
                    [2] Operations         - VCF Operations 운영현황 리포트
                    [3] security-hardening - 보안 하드닝 감사
                    [4] vcenter            - vCenter 일일 종합 리포트
                    [5] vmsa               - VMSA 취약점 관리 툴킷
                  이 런처 자체는 수집/분석 로직을 갖지 않고 각 폴더의 원본 .ps1을 그대로
                  호출만 합니다 - 원본 스크립트가 업데이트돼도 이 파일은 그대로 두면 됩니다.

    사전 준비   : 이 스크립트를 infra_assessment 저장소 루트(5개 폴더와 같은 위치)에 두세요.

                  infra_assessment\                      <- git clone https://github.com/postout7979/infra_assessment
                   ├─ all-in-one-vmw.ps1                 <- 이 파일
                   ├─ vcf_9_upgrade\
                   ├─ Operations\
                   ├─ security-hardening\
                   ├─ vcenter\
                   └─ vmsa\

                  저장소 루트가 아닌 다른 위치에 두고 싶다면 환경변수 VMWTOOLS_INFRA_PATH 로
                  infra_assessment 저장소 루트 경로를 지정하세요.

    실행 방법   : .\all-in-one-vmw.ps1
                  (Set-ExecutionPolicy -Scope CurrentUser RemoteSigned 필요할 수 있음)
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

function Update-ToolRepo {
    if (Test-Path (Join-Path $RepoRoot ".git")) {
        Write-Host ""
        Write-Host "[git pull] $RepoRoot" -ForegroundColor DarkGray
        Push-Location $RepoRoot
        try { git pull } catch { Write-Host "  git pull 실패: $($_.Exception.Message)" -ForegroundColor Red }
        Pop-Location
    }
    else {
        Write-Host "[SKIP] git 저장소가 아니거나 경로가 없습니다: $RepoRoot" -ForegroundColor Yellow
    }
    Pause-Return
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
                $inv = Read-Host "인벤토리 폴더 경로 (예: vSphere_Inventory_20260827_0930, 사전점검 메뉴 2에서 생성됨)"
                if ([string]::IsNullOrWhiteSpace($inv)) {
                    Write-Host "인벤토리 폴더 경로가 필요합니다." -ForegroundColor Yellow
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
            "0" { return }
            default { Write-Host "잘못된 선택입니다." -ForegroundColor Yellow }
        }
    }
}

# ============================================================
# 서브 메뉴: VCF Operations 리포트 (Operations)
#   Mock 미리보기(연결 불필요) 또는 실제 VCF Operations 연동 중 선택
# ============================================================
function Show-OperationsMenu {
    while ($true) {
        Write-Title "VCF Operations 운영현황 리포트 (Operations)"
        Write-Host "  [1] Mock 데이터로 미리보기 (API 연결 불필요)"
        Write-Host "  [2] 실제 VCF Operations 연동"
        Write-Host "  [0] 상위 메뉴로"
        $sel = Read-Host "`n선택"

        switch ($sel) {
            "1" {
                $customer = Read-Host "고객사명 (Enter=Customer)"
                $bp = @{ Mock = $true }
                if (-not [string]::IsNullOrWhiteSpace($customer)) { $bp.CustomerName = $customer }
                Invoke-ToolScript -Path $Scripts.Operations -BoundParameters $bp
            }
            "2" {
                $hostUrl  = Read-Host "VCF Operations Host URL (예: https://vcfops.corp.local, 비워두면 환경변수 VCFOPS_HOST 사용)"
                $username = Read-Host "Username (비워두면 환경변수 VCFOPS_USERNAME 사용)"
                $customer = Read-Host "고객사명 (Enter=Customer)"
                $bp = @{}
                if (-not [string]::IsNullOrWhiteSpace($hostUrl))  { $bp.HostUrl = $hostUrl }
                if (-not [string]::IsNullOrWhiteSpace($username)) { $bp.Username = $username }
                if (-not [string]::IsNullOrWhiteSpace($customer)) { $bp.CustomerName = $customer }
                $bp.SkipCertCheck = $true
                # 비밀번호는 -Password로 넘기지 않으면 New-VCFOpsReport.ps1이 실행 중 안전하게 입력받습니다.
                Invoke-ToolScript -Path $Scripts.Operations -BoundParameters $bp
            }
            "0" { return }
            default { Write-Host "잘못된 선택입니다." -ForegroundColor Yellow }
        }
    }
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
        Write-Host ""
        Write-Host "  [U] 저장소 git pull로 업데이트"
        Write-Host "  [0] 종료"
        Write-Host ""
        Write-Host "  infra_assessment repo : $RepoRoot" -ForegroundColor DarkGray

        $sel = Read-Host "`n선택"

        switch ($sel.ToUpper()) {
            "1" { Show-Vcf9UpgradeMenu }
            "2" { Show-OperationsMenu }
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
            "U" { Update-ToolRepo }
            "0" { return }
            default { Write-Host "잘못된 선택입니다." -ForegroundColor Yellow }
        }
    }
}

Show-MainMenu
