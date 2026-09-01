<#
.SYNOPSIS
    VCF Operations 가상화 인프라 운영 현황 리포트 생성기 (PowerShell)

.DESCRIPTION
    VCF Operations(Aria Operations / vRealize Operations) REST API에서 데이터센터·
    클러스터·호스트·VM 현황 및 성능 데이터를 수집해 모던/파스텔 톤 HTML 대시보드와
    Excel(가능 시) 또는 CSV, PDF를 생성합니다.
    (PPTX는 이 PowerShell 버전에서는 다루지 않습니다 — 필요 시 Python 버전의
    --format pptx 를 사용하세요.)

.EXAMPLE
    # 1) Mock 데이터로 결과물 미리보기 (API 연결 불필요)
    ./New-VCFOpsReport.ps1 -Mock -CustomerName "ABC손해보험"

.EXAMPLE
    # 2) 실제 VCF Operations 연동
    ./New-VCFOpsReport.ps1 -HostUrl https://vcfops.corp.local -Username admin `
        -CustomerName "ABC손해보험" -ScopeLabel "vCenter: vc-seoul01" -SkipCertCheck

.EXAMPLE
    # 3) 환경변수로 인증정보 전달 (비밀번호 평문 노출 방지, 권장)
    $env:VCFOPS_HOST = "https://vcfops.corp.local"
    $env:VCFOPS_USERNAME = "admin"
    ./New-VCFOpsReport.ps1 -CustomerName "ABC손해보험"
    # 비밀번호를 지정하지 않으면 실행 중 SecureString으로 안전하게 입력받습니다.

.EXAMPLE
    # 4) 한달 전 시점과 비교
    ./New-VCFOpsReport.ps1 -CustomerName "ABC손해보험" -CompareDays 30
    # CompareDays를 입력하지 않거나 0이면 비교 없이 현재값만 출력합니다.

.EXAMPLE
    # 5) Excel/PDF 출력 건너뛰기
    ./New-VCFOpsReport.ps1 -Mock -SkipData -SkipPdf

.EXAMPLE
    # 6) 생성 후 이메일로 발송 (HTML은 첨부파일로 전달)
    ./New-VCFOpsReport.ps1 -CustomerName "ABC손해보험" -SendEmail `
        -SmtpServer smtp.corp.local -SmtpFrom "vcfops-report@corp.local" `
        -SmtpTo "manager@corp.local","sales@corp.local" -SmtpUsername smtp-user
    # 환경변수(VCFOPS_SMTP_SERVER/PORT/FROM/TO/USERNAME/PASSWORD)로도 지정 가능합니다.
    # SmtpUsername을 지정하고 비밀번호를 안 주면 실행 중 안전하게 입력받습니다.
    # 인증이 필요 없는 내부 릴레이라면 -SmtpUsername 없이 -SmtpServer/-SmtpFrom/-SmtpTo만 지정하면 됩니다.

.EXAMPLE
    # 7) 생성 후 이메일로 발송 (CSS/JS 없이 테이블로만 구성된 이메일용 HTML을 본문에 바로 삽입)
    ./New-VCFOpsReport.ps1 -CustomerName "ABC손해보험" -SendEmail -EmailHtmlInBody `
        -SmtpServer smtp.corp.local -SmtpFrom "vcfops-report@corp.local" `
        -SmtpTo "manager@corp.local","sales@corp.local"
    # 수신자가 메일을 열자마자 리포트를 바로 볼 수 있습니다(첨부파일 열 필요 없음).
    # 이때 본문에는 웹용 HTML(vcfops_report_*.html)이 아니라, <style>/<script> 없이
    # <table>+인라인 style로만 구성된 이메일 전용 HTML(vcfops_report_*_email.html)이
    # 사용되어 Outlook 등 데스크톱 메일 클라이언트에서도 레이아웃이 깨지지 않습니다.
    # Excel/PDF/CSV(zip)는 이 옵션을 켜도 기존과 동일하게 첨부로 함께 발송됩니다.

.NOTES
    PowerShell 7+ (pwsh) 권장. Invoke-RestMethod -SkipCertificateCheck 등 최신 기능을 사용합니다.
    Excel 출력은 ImportExcel 모듈이 있으면 시트 여러 개인 .xlsx 하나로, 없으면
    데이터셋별 CSV 여러 개로 자동 폴백합니다. (Install-Module ImportExcel -Scope CurrentUser)
    PDF 출력은 시스템에 설치된 Microsoft Edge 또는 Chrome의 headless 모드를 사용합니다.
#>

#Requires -Version 7.0

[CmdletBinding()]
param(
    # ---- 데이터 소스 ----
    [switch]$Mock,
    [string]$HostUrl = $env:VCFOPS_HOST,
    [string]$Username = $env:VCFOPS_USERNAME,
    [string]$Password = $env:VCFOPS_PASSWORD,
    [string]$AuthSource = $(if ($env:VCFOPS_AUTH_SOURCE) { $env:VCFOPS_AUTH_SOURCE } else { "LOCAL" }),
    [switch]$SkipCertCheck,
    [int]$MaxVMs = 0,                       # 0 = 제한 없음 (테스트 시 예: 50)

    # ---- 출력 ----
    [string]$OutputDir = "./output",
    [string]$CustomerName = $(if ($env:VCFOPS_CUSTOMER_NAME) { $env:VCFOPS_CUSTOMER_NAME } else { "Customer" }),
    [string]$ScopeLabel = $(if ($env:VCFOPS_SCOPE_LABEL) { $env:VCFOPS_SCOPE_LABEL } else { "All vCenters" }),

    # ---- 동작 옵션 ----
    # CompareDays: N일 전 시점과 비교. 0(기본값) 또는 미입력 시 비교 없이 현재값만 출력.
    # 해당 시점의 데이터가 없으면(보존기간 초과 등) 자동으로 비교 없이 처리됩니다.
    [int]$CompareDays = 0,
    [string]$SnapshotCacheDir = "./snapshots",
    [switch]$SkipData,                        # Excel/CSV 데이터 출력을 모두 건너뛰려면 지정
    [switch]$SkipPdf,                         # PDF 변환을 건너뛰려면 지정

    # ---- 이메일(SMTP) 발송 ----
    [switch]$SendEmail,                                            # 생성된 리포트를 이메일로 발송하려면 지정
    [string]$SmtpServer = $env:VCFOPS_SMTP_SERVER,
    [int]$SmtpPort = $(if ($env:VCFOPS_SMTP_PORT) { [int]$env:VCFOPS_SMTP_PORT } else { 587 }),
    [string]$SmtpFrom = $env:VCFOPS_SMTP_FROM,
    [string[]]$SmtpTo = $(if ($env:VCFOPS_SMTP_TO) { $env:VCFOPS_SMTP_TO -split "[,;]" } else { @() }),
    [string[]]$SmtpCc = @(),
    [string]$SmtpUsername = $env:VCFOPS_SMTP_USERNAME,
    [string]$SmtpPassword = $env:VCFOPS_SMTP_PASSWORD,
    [switch]$SmtpNoSsl,                                            # 기본은 SSL/TLS 사용, 끄려면 지정
    [string]$EmailSubject,
    [switch]$EmailHtmlInBody                                       # HTML을 첨부 대신 메일 본문에 직접 삽입하려면 지정
)

$ErrorActionPreference = "Stop"
if ($PSBoundParameters.ContainsKey('Verbose')) {
    # 모듈 함수(Write-Verbose)까지 전파되도록 전역 스코프로 설정
    $Global:VerbosePreference = 'Continue'
}
$ModulesPath = Join-Path $PSScriptRoot "Modules"

# 같은 PowerShell 세션에서 스크립트를 여러 번 실행할 경우, 모듈 내부에서 중첩 임포트되는
# 의존 모듈(StatKeys/Theme 등)이 "이미 로드됨"으로 판단되어 디스크의 최신 수정사항을
# 반영하지 못하는 문제가 있어, 매번 완전히 제거 후 새로 불러옵니다.
@("VCFOpsTheme", "VCFOpsStatKeys", "VCFOpsApiClient", "VCFOpsSnapshotCache", "VCFOpsProgress",
  "VCFOpsCollector", "VCFOpsMockData", "VCFOpsHtmlReport", "VCFOpsEmailHtmlReport", "VCFOpsCsvExport",
  "VCFOpsExcelExport", "VCFOpsPdfExport", "VCFOpsEmailExport") | ForEach-Object {
    Remove-Module -Name $_ -Force -ErrorAction SilentlyContinue
}

Import-Module (Join-Path $ModulesPath "VCFOpsProgress.psm1") -Force
Import-Module (Join-Path $ModulesPath "VCFOpsTheme.psm1") -Force
Import-Module (Join-Path $ModulesPath "VCFOpsMockData.psm1") -Force
Import-Module (Join-Path $ModulesPath "VCFOpsHtmlReport.psm1") -Force
Import-Module (Join-Path $ModulesPath "VCFOpsEmailHtmlReport.psm1") -Force
Import-Module (Join-Path $ModulesPath "VCFOpsCsvExport.psm1") -Force
Import-Module (Join-Path $ModulesPath "VCFOpsExcelExport.psm1") -Force
Import-Module (Join-Path $ModulesPath "VCFOpsPdfExport.psm1") -Force
Import-Module (Join-Path $ModulesPath "VCFOpsEmailExport.psm1") -Force

if (-not (Test-Path -Path $OutputDir)) {
    New-Item -ItemType Directory -Path $OutputDir -Force | Out-Null
}

if ($SendEmail) {
    if (-not $SmtpServer -or -not $SmtpFrom -or -not $SmtpTo -or $SmtpTo.Count -eq 0) {
        Write-Error "-SendEmail 사용 시 -SmtpServer, -SmtpFrom, -SmtpTo(받는사람)는 필수입니다."
        exit 1
    }
    if ($SmtpUsername -and -not $SmtpPassword) {
        $secureSmtpPw = Read-Host "SMTP 비밀번호 ($SmtpUsername)" -AsSecureString
        $SmtpPassword = [System.Net.NetworkCredential]::new("", $secureSmtpPw).Password
    }
}

$totalSteps = 4
if (-not $SkipData) { $totalSteps++ }
if (-not $SkipPdf) { $totalSteps++ }
if ($SendEmail) { $totalSteps++ }
Initialize-VCFOpsProgress -Total $totalSteps

Write-Host ""
Write-Host "=== VCF Operations 리포트 생성 시작 ===" -ForegroundColor Magenta
Write-Host ""

# ------------------------------------------------------------------
# 1) 데이터 수집
# ------------------------------------------------------------------
if ($Mock) {
    Write-VCFOpsStep "Mock 데이터 생성 중... (-Mock)"
    $data = New-MockReportData -CustomerName $CustomerName
    Write-VCFOpsStepDone
}
else {
    Import-Module (Join-Path $ModulesPath "VCFOpsApiClient.psm1") -Force
    Import-Module (Join-Path $ModulesPath "VCFOpsCollector.psm1") -Force

    if (-not $HostUrl) { $HostUrl = Read-Host "VCF Operations URL (예: https://vcfops.corp.local)" }
    if (-not $Username) { $Username = Read-Host "VCF Operations 사용자명" }
    if (-not $Password) {
        $securePw = Read-Host "VCF Operations 비밀번호" -AsSecureString
        $Password = [System.Net.NetworkCredential]::new("", $securePw).Password
    }

    Write-VCFOpsStep "VCF Operations 로그인 중... ($HostUrl)"
    try {
        Connect-VCFOps -HostUrl $HostUrl -Username $Username -Password $Password `
            -AuthSource $AuthSource -SkipCertCheck:$SkipCertCheck | Out-Null
        Write-VCFOpsStepDone
    }
    catch {
        Write-Error "로그인 실패: $($_.Exception.Message)"
        exit 1
    }

    Write-VCFOpsStep "데이터 수집 중... (리소스/통계/속성 - 환경 크기에 따라 시간이 걸릴 수 있습니다)"
    try {
        $data = Invoke-VCFOpsCollection -CustomerName $CustomerName -VCenterScope $ScopeLabel `
            -CompareDaysAgo $CompareDays -SnapshotCacheDir $SnapshotCacheDir -MaxVMs $MaxVMs
        Write-VCFOpsStepDone
    }
    catch {
        Write-Error "리포트 수집 실패: $($_.Exception.Message)"
        exit 1
    }
    finally {
        Disconnect-VCFOps
    }
}

# ------------------------------------------------------------------
# 2) HTML 출력 생성 (웹용 1개 + 이메일용 1개, 총 2개 파일)
# ------------------------------------------------------------------
Write-VCFOpsStep "HTML 리포트 생성 중..."
$timestamp = Get-Date -Format "yyyyMMdd_HHmm"
$htmlPath = Join-Path $OutputDir "vcfops_report_$timestamp.html"
$emailHtmlPath = Join-Path $OutputDir "vcfops_report_${timestamp}_email.html"

$html = New-VCFOpsHtmlReport -Data $data
Set-Content -Path $htmlPath -Value $html -Encoding utf8
Write-VCFOpsStepDone $htmlPath

# 이메일 본문 삽입/첨부에 최적화된 버전 - <style>/<script>/외부 리소스 없이
# <table> + 인라인 style만 사용해 Outlook 등 데스크톱 메일 클라이언트에서도 깨지지 않습니다.
$emailHtml = New-VCFOpsEmailHtmlReport -Data $data
Set-Content -Path $emailHtmlPath -Value $emailHtml -Encoding utf8
Write-VCFOpsStepDone "$emailHtmlPath  (이메일용, CSS 없이 테이블 기반)"

# ------------------------------------------------------------------
# 3) 데이터 출력 생성 (Excel 우선, 안 되면 CSV 다중 파일로 폴백)
# ------------------------------------------------------------------
if (-not $SkipData) {
    Write-VCFOpsStep "데이터 파일 생성 중... (Excel 시도 -> 안 되면 CSV로 자동 폴백)"
    $xlsxPath = Join-Path $OutputDir "vcfops_report_$timestamp.xlsx"
    $excelResult = Export-VCFOpsExcel -Data $data -Path $xlsxPath
    if ($excelResult) {
        Write-VCFOpsStepDone $excelResult
    }
    else {
        $csvDir = Join-Path $OutputDir "csv_$timestamp"
        $csvFiles = Export-VCFOpsCsv -Data $data -OutputDir $csvDir
        Write-VCFOpsStepDone "$csvDir  ($($csvFiles.Count)개 CSV 파일)"
    }
}

# ------------------------------------------------------------------
# 4) PDF 변환 (Edge/Chrome headless, 둘 다 없으면 건너뜀)
# ------------------------------------------------------------------
if (-not $SkipPdf) {
    Write-VCFOpsStep "PDF 변환 중... (Edge/Chrome headless)"
    $pdfPath = Join-Path $OutputDir "vcfops_report_$timestamp.pdf"
    $pdfResult = Convert-VCFOpsHtmlToPdf -HtmlPath $htmlPath -PdfPath $pdfPath
    if ($pdfResult) {
        Write-VCFOpsStepDone $pdfResult
    }
    else {
        Write-Host "    (PDF 변환을 건너뛰었습니다 - HTML/Excel/CSV는 정상 생성됨)" -ForegroundColor DarkYellow
    }
}

# ------------------------------------------------------------------
# 5) 이메일(SMTP) 발송 - 생성된 파일들을 첨부
#    (-EmailHtmlInBody 지정 시: HTML은 첨부 대신 메일 본문에 직접 삽입)
# ------------------------------------------------------------------
if ($SendEmail) {
    Write-VCFOpsStep "이메일 발송 중... (${SmtpServer}:$SmtpPort)"

    # Excel/PDF/CSV(zip) - HTML을 본문에 넣을지 첨부할지와 무관하게 공통으로 준비
    $otherAttachments = @()
    if ($pdfResult) { $otherAttachments += $pdfResult }
    if ($excelResult) {
        $otherAttachments += $excelResult
    }
    elseif ($csvDir -and (Test-Path -LiteralPath $csvDir)) {
        # CSV 폴백 시 파일이 여러 개라 첨부가 너무 많아지지 않도록 zip으로 한 번에 묶습니다.
        $csvZipPath = Join-Path $OutputDir "vcfops_report_${timestamp}_csv.zip"
        try {
            Compress-Archive -Path (Join-Path $csvDir "*") -DestinationPath $csvZipPath -Force
            $otherAttachments += $csvZipPath
        }
        catch {
            Write-Warning "CSV 압축 실패, CSV는 첨부하지 않습니다: $($_.Exception.Message)"
        }
    }

    $subject = if ($EmailSubject) { $EmailSubject } else { "[$CustomerName] VCF Operations 운영 현황 리포트 ($timestamp)" }

    if ($EmailHtmlInBody) {
        # HTML 리포트를 첨부가 아니라 메일 본문 자체로 삽입 (Excel/PDF/CSV는 그대로 첨부)
        # 웹용 HTML($htmlPath)이 아니라 CSS/JS 없이 테이블로만 구성된 이메일용 HTML을 사용해야
        # Outlook 등에서 레이아웃이 깨지지 않습니다.
        $emailOk = Send-VCFOpsReportEmailWithHtmlBody -SmtpServer $SmtpServer -SmtpPort $SmtpPort -From $SmtpFrom `
            -To $SmtpTo -Cc $SmtpCc -Subject $subject -HtmlPath $emailHtmlPath -AttachmentPaths $otherAttachments `
            -Username $SmtpUsername -Password $SmtpPassword -UseSsl (-not $SmtpNoSsl)
    }
    else {
        $attachments = @($htmlPath) + $otherAttachments
        $bodyText = @"
$CustomerName 가상화 인프라 운영 현황 리포트입니다.

생성 시각: $(Get-Date -Format 'yyyy-MM-dd HH:mm')
대상: $ScopeLabel

첨부파일을 확인해주세요. 이 메일은 자동 생성되었습니다.
"@

        $emailOk = Send-VCFOpsReportEmail -SmtpServer $SmtpServer -SmtpPort $SmtpPort -From $SmtpFrom `
            -To $SmtpTo -Cc $SmtpCc -Subject $subject -Body $bodyText -AttachmentPaths $attachments `
            -Username $SmtpUsername -Password $SmtpPassword -UseSsl (-not $SmtpNoSsl)
    }

    if ($emailOk) {
        Write-VCFOpsStepDone "발송 완료 -> $($SmtpTo -join ', ')"
    }
    else {
        Write-Host "    (이메일 발송 실패 - 위 경고 메시지를 확인하세요. 파일들은 정상 생성됨)" -ForegroundColor DarkYellow
    }
}

Write-Host ""
Write-Host "=== 완료 ===" -ForegroundColor Magenta
