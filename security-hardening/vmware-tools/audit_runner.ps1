<#
    Script Name: vSphere Audit Orchestrator (Main Launcher)
    Description: 모듈 확인, 인증 관리, 감사 스크립트 실행을 통합 관리하는 스크립트
    Author: Gemini
#>

# ---------------------------------------------------------------------------
# 1. 모듈 설치 확인 및 설치
# ---------------------------------------------------------------------------
Write-Host "Checking required PowerShell modules..." -ForegroundColor Cyan

$requiredModules = @(
    @{ Name = "VCF.PowerCLI"; Version = "9.0.0" }
    @{ Name = "VMware.vSphere.SsoAdmin"; Version = "1.4.0" }
)

foreach ($mod in $requiredModules) {
    $installed = Get-Module -ListAvailable -Name $mod.Name | Where-Object { $_.Version -ge [version]$mod.Version }
    
    if (-not $installed) {
        Write-Host "Module '$($mod.Name)' is missing or outdated. Installing..." -ForegroundColor Yellow
        
        # PSGallery 신뢰 정책 설정 (필요 시)
        $repo = Get-PSRepository -Name PSGallery -ErrorAction SilentlyContinue
        if ($repo.InstallationPolicy -ne 'Trusted') {
            Set-PSRepository -Name PSGallery -InstallationPolicy Trusted -ErrorAction SilentlyContinue
        }

        try {
            # Scope AllUsers는 관리자 권한 필요
            Install-Module -Name $mod.Name -MinimumVersion $mod.Version -Scope AllUsers -Force -AllowClobber -ErrorAction Stop
            Write-Host "Successfully installed '$($mod.Name)'." -ForegroundColor Green
        }
        catch {
            Write-Host "Failed to install module '$($mod.Name)'. Ensure you are running as Administrator." -ForegroundColor Red
            Write-Host "Error details: $_" -ForegroundColor Red
            exit
        }
    } else {
        Write-Host "Module '$($mod.Name)' is already installed." -ForegroundColor Green
    }
}

# ---------------------------------------------------------------------------
# 2. vCenter 연결 및 자격 증명 관리 (Credential Management)
# ---------------------------------------------------------------------------
$credFilePath = "$PSScriptRoot\cached_credential.xml"
$vcAddress = Read-Host "Enter vCenter Server IP or FQDN"

$credential = $null
$useCached = $false

# A. 저장된 계정 정보 확인
if (Test-Path $credFilePath) {
    $response = Read-Host "Saved credential found. Do you want to use it? (Y/N)"
    if ($response -eq "Y" -or $response -eq "y") {
        try {
            $credential = Import-Clixml -Path $credFilePath
            $useCached = $true
        }
        catch {
            Write-Host "Failed to load saved credential. Proceeding to manual input." -ForegroundColor Yellow
        }
    }
}

# B. 계정 정보가 없거나 새로 입력해야 하는 경우
if ($null -eq $credential) {
    Write-Host "Please enter your vCenter credentials:" -ForegroundColor Cyan
    $credential = Get-Credential
    
    # 저장 여부 질문
    $saveResponse = Read-Host "Do you want to save this credential for future use? (Y/N)"
    if ($saveResponse -eq "Y" -or $saveResponse -eq "y") {
        $credential | Export-Clixml -Path $credFilePath
        Write-Host "Credential saved to '$credFilePath'." -ForegroundColor Green
    }
}

# C. 연결 시도 (connect.ps1 로직 통합)
Write-Host "Connecting to vCenter Server ($vcAddress)..." -ForegroundColor Cyan

try {
    # 에러 메시지를 숨기기 위해 ErrorAction Stop 사용 후 catch 블록으로 이동
    Connect-VIServer -Server $vcAddress -Credential $credential -ErrorAction Stop | Out-Null
    Write-Host "Successfully connected to vCenter Server." -ForegroundColor Green
}
catch {
    Write-Host "==========================================" -ForegroundColor Red
    Write-Host "Connection Failed!" -ForegroundColor Red
    Write-Host "Please check your vCenter IP, Username, and Password." -ForegroundColor Red
    Write-Host "==========================================" -ForegroundColor Red
    # PowerShell 기본 에러 스택은 출력하지 않고 종료
    exit
}

# 추가 서비스 연결 (CIS, SSO) - 실패해도 메인 감사는 진행 가능하므로 Warning 처리
try {
    Connect-CisServer -Server $vcAddress -Credential $credential -ErrorAction Stop | Out-Null
    Write-Host "Connected to CIS Server." -ForegroundColor Green
} catch { Write-Host "Warning: Failed to connect to CIS Server." -ForegroundColor Yellow }

try {
    Connect-SsoAdminServer -Server $vcAddress -Credential $credential -SkipCertificateCheck -ErrorAction Stop | Out-Null
    Write-Host "Connected to SSO Admin Server." -ForegroundColor Green
} catch { Write-Host "Warning: Failed to connect to SSO Admin Server." -ForegroundColor Yellow }


# ---------------------------------------------------------------------------
# 3. Audit 실행 (audit-all.ps1 호출)
# ---------------------------------------------------------------------------
$timestamp = Get-Date -Format "yyyyMMdd-HHmm"
$reportDir = "$PSScriptRoot\Audit_Report_$timestamp"
$auditScript = "$PSScriptRoot\audit-all.ps1"

# 결과 폴더 생성
New-Item -ItemType Directory -Force -Path $reportDir | Out-Null

if (Test-Path $auditScript) {
    Write-Host "`nStarting Security Audit..." -ForegroundColor Cyan
    Write-Host "Output Directory: $reportDir" -ForegroundColor Cyan
    
    # audit-all.ps1 호출
    & $auditScript -OutputDirName $reportDir -AcceptEULA
    
    Write-Host "`nAudit Completed. Check the report folder." -ForegroundColor Green
} else {
    Write-Host "Error: '$auditScript' not found in current directory." -ForegroundColor Red
}