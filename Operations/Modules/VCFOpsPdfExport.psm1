# VCFOpsPdfExport.psm1
# -----------------------------------------------------------------------------
# 생성된 HTML 리포트를 PDF로 변환합니다. 별도 모듈/도구 설치 없이도 동작하도록
# Windows 10/11에 기본 내장된 Microsoft Edge의 headless 모드(--print-to-pdf)를
# 1차로 사용하고, Edge가 없으면 Chrome headless를 시도합니다. 둘 다 없으면
# PDF 생성을 건너뛰고 HTML/Excel/CSV는 정상적으로 유지합니다.
# -----------------------------------------------------------------------------

function Find-VCFOpsPdfBrowser {
    [CmdletBinding()]
    param()
    $candidates = @(
        "$env:ProgramFiles\Microsoft\Edge\Application\msedge.exe",
        "${env:ProgramFiles(x86)}\Microsoft\Edge\Application\msedge.exe",
        "$env:LOCALAPPDATA\Microsoft\Edge\Application\msedge.exe",
        "$env:ProgramFiles\Google\Chrome\Application\chrome.exe",
        "${env:ProgramFiles(x86)}\Google\Chrome\Application\chrome.exe",
        "$env:LOCALAPPDATA\Google\Chrome\Application\chrome.exe"
    )
    foreach ($c in $candidates) {
        if ($c -and (Test-Path -LiteralPath $c)) { return $c }
    }
    # PATH 상에 있는 경우도 시도 (Linux/Mac의 pwsh 등)
    foreach ($name in @("msedge", "google-chrome", "chromium", "chromium-browser")) {
        $cmd = Get-Command -Name $name -ErrorAction SilentlyContinue
        if ($cmd) { return $cmd.Source }
    }
    return $null
}

function Resolve-VCFOpsFullPath {
    # 파일이 아직 존재하지 않아도(생성 전이라도) 절대경로로 바꿔줍니다.
    # PowerShell의 $PWD와 .NET의 Environment.CurrentDirectory가 서로 어긋나는 경우가 있어
    # (cd/Set-Location 후에도 .NET 쪽이 갱신 안 되는 경우) $PWD.Path를 명시적으로 사용합니다.
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$Path)
    if ([System.IO.Path]::IsPathRooted($Path)) { return $Path }
    return [System.IO.Path]::GetFullPath((Join-Path $PWD.Path $Path))
}

function Convert-VCFOpsHtmlToPdf {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$HtmlPath,
        [Parameter(Mandatory)][string]$PdfPath,
        [int]$TimeoutSec = 60
    )

    $browser = Find-VCFOpsPdfBrowser
    if (-not $browser) {
        Write-Warning "Edge/Chrome 실행 파일을 찾지 못해 PDF 변환을 건너뜁니다. (HTML/Excel/CSV는 정상 생성됨)"
        return $null
    }

    $absHtml = (Resolve-Path -LiteralPath $HtmlPath).Path
    $uri = "file:///" + ($absHtml -replace '\\', '/')

    # --print-to-pdf 인자는 브라우저 프로세스 자체의 작업 디렉터리 기준으로 해석되어
    # PowerShell의 현재 위치와 다를 수 있습니다(상대경로 그대로 넘기면 "경로를 찾을 수
    # 없습니다" 오류가 발생). 항상 절대경로로 변환해서 넘깁니다.
    $absPdf = Resolve-VCFOpsFullPath -Path $PdfPath
    $pdfDir = Split-Path -Path $absPdf -Parent
    if ($pdfDir -and -not (Test-Path -LiteralPath $pdfDir)) {
        New-Item -ItemType Directory -Path $pdfDir -Force | Out-Null
    }
    if (Test-Path -LiteralPath $absPdf) { Remove-Item -LiteralPath $absPdf -Force -ErrorAction SilentlyContinue }

    $tempProfile = Join-Path ([System.IO.Path]::GetTempPath()) ("vcfops_pdf_" + [guid]::NewGuid().ToString("N"))
    $pdfArgs = @(
        "--headless",
        "--disable-gpu",
        "--no-sandbox",
        "--disable-extensions",
        "--user-data-dir=$tempProfile",     # 기존 브라우저 프로필/세션과 충돌 방지
        "--print-to-pdf=$absPdf",
        "--print-to-pdf-no-header",
        $uri
    )

    try {
        $proc = Start-Process -FilePath $browser -ArgumentList $pdfArgs -PassThru -WindowStyle Hidden
        if (-not $proc.WaitForExit($TimeoutSec * 1000)) {
            Write-Warning "PDF 변환이 $TimeoutSec 초 내에 끝나지 않아 중단합니다."
            try { $proc.Kill() } catch { }
            return $null
        }
    }
    catch {
        Write-Warning "PDF 변환 실행 실패: $($_.Exception.Message)"
        return $null
    }
    finally {
        Remove-Item -LiteralPath $tempProfile -Recurse -Force -ErrorAction SilentlyContinue
    }

    if (Test-Path -LiteralPath $absPdf) { return $absPdf }
    Write-Warning "PDF 파일이 생성되지 않았습니다 (브라우저 실행은 됐지만 출력 파일 없음)."
    return $null
}

Export-ModuleMember -Function Convert-VCFOpsHtmlToPdf, Find-VCFOpsPdfBrowser
