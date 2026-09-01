# VCFOpsEmailExport.psm1
# -----------------------------------------------------------------------------
# 생성된 리포트(HTML/Excel/CSV/PDF)를 SMTP로 이메일 발송합니다.
# Send-MailMessage는 마이크로소프트가 더 이상 사용을 권장하지 않는(향후 제거 예정)
# cmdlet이라, .NET의 System.Net.Mail.SmtpClient/MailMessage를 직접 사용합니다.
# -----------------------------------------------------------------------------

function Send-VCFOpsReportEmail {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$SmtpServer,
        [int]$SmtpPort = 587,
        [Parameter(Mandatory)][string]$From,
        [Parameter(Mandatory)][string[]]$To,
        [string[]]$Cc = @(),
        [Parameter(Mandatory)][string]$Subject,
        [string]$Body = "",
        [bool]$IsBodyHtml = $false,
        [string[]]$AttachmentPaths = @(),
        [string]$Username = "",
        [string]$Password = "",
        [bool]$UseSsl = $true,
        [int]$TimeoutSec = 60
    )

    $mail = $null
    $smtp = $null
    $attachments = @()
    try {
        $mail = New-Object System.Net.Mail.MailMessage
        $mail.From = $From
        foreach ($t in $To) { if ($t) { $mail.To.Add($t) } }
        foreach ($c in $Cc) { if ($c) { $mail.CC.Add($c) } }
        if ($mail.To.Count -eq 0) {
            Write-Warning "수신자(-SmtpTo)가 없어 이메일을 보내지 않습니다."
            return $false
        }
        $mail.Subject = $Subject
        $mail.Body = $Body
        $mail.IsBodyHtml = $IsBodyHtml

        foreach ($path in $AttachmentPaths) {
            if ($path -and (Test-Path -LiteralPath $path)) {
                $att = New-Object System.Net.Mail.Attachment($path)
                $attachments += $att
                $mail.Attachments.Add($att)
            }
            elseif ($path) {
                Write-Warning "첨부 파일을 찾지 못해 건너뜁니다: $path"
            }
        }

        $smtp = New-Object System.Net.Mail.SmtpClient($SmtpServer, $SmtpPort)
        $smtp.EnableSsl = $UseSsl
        $smtp.Timeout = $TimeoutSec * 1000
        if ($Username) {
            $smtp.Credentials = New-Object System.Net.NetworkCredential($Username, $Password)
        }

        $smtp.Send($mail)
        return $true
    }
    catch {
        Write-Warning "이메일 발송 실패: $($_.Exception.Message)"
        return $false
    }
    finally {
        foreach ($att in $attachments) { try { $att.Dispose() } catch { } }
        if ($mail) { try { $mail.Dispose() } catch { } }
        if ($smtp) { try { $smtp.Dispose() } catch { } }
    }
}

function Send-VCFOpsReportEmailWithHtmlBody {
    # Send-VCFOpsReportEmail과 달리, 생성된 HTML 리포트를 "첨부파일"이 아니라
    # 이메일 "본문 자체"로 삽입해서 발송합니다 (수신자가 메일을 열자마자 바로
    # 리포트를 볼 수 있음 - 첨부파일을 별도로 열 필요 없음).
    # Excel/PDF/CSV(zip) 등 나머지 산출물은 기존과 동일하게 첨부로 보낼 수 있습니다.
    #
    # ⚠️ 참고: Outlook 데스크톱 앱은 자체 렌더링 엔진(Word 기반)을 사용해 CSS
    #    flexbox/grid/position:sticky, 외부 폰트(<link>), <script>(검색창 필터 등)
    #    일부가 그대로 보이지 않을 수 있습니다(표/카드/색상/기본 레이아웃은 정상
    #    표시됩니다). 완전히 동일한 모습이 꼭 필요하면 기존 Send-VCFOpsReportEmail
    #    (HTML 첨부 방식)을 함께 사용하는 것을 권장합니다.
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$SmtpServer,
        [int]$SmtpPort = 587,
        [Parameter(Mandatory)][string]$From,
        [Parameter(Mandatory)][string[]]$To,
        [string[]]$Cc = @(),
        [Parameter(Mandatory)][string]$Subject,
        [Parameter(Mandatory)][string]$HtmlPath,      # New-VCFOpsHtmlReport 로 생성된 HTML 파일 경로
        [string[]]$AttachmentPaths = @(),              # HTML은 본문에 들어가므로 보통 제외하고, Excel/PDF/CSV(zip)만 지정
        [string]$Username = "",
        [string]$Password = "",
        [bool]$UseSsl = $true,
        [int]$TimeoutSec = 60
    )

    if (-not (Test-Path -LiteralPath $HtmlPath)) {
        Write-Warning "HTML 파일을 찾지 못해 이메일 본문에 삽입할 수 없습니다: $HtmlPath"
        return $false
    }
    try {
        $htmlBody = Get-Content -LiteralPath $HtmlPath -Raw -Encoding utf8
    }
    catch {
        Write-Warning "HTML 파일 읽기 실패: $($_.Exception.Message)"
        return $false
    }

    $mail = $null
    $smtp = $null
    $attachments = @()
    try {
        $mail = New-Object System.Net.Mail.MailMessage
        $mail.From = $From
        foreach ($t in $To) { if ($t) { $mail.To.Add($t) } }
        foreach ($c in $Cc) { if ($c) { $mail.CC.Add($c) } }
        if ($mail.To.Count -eq 0) {
            Write-Warning "수신자(-SmtpTo)가 없어 이메일을 보내지 않습니다."
            return $false
        }
        $mail.Subject = $Subject
        $mail.Body = $htmlBody
        $mail.IsBodyHtml = $true
        $mail.BodyEncoding = [System.Text.Encoding]::UTF8
        $mail.SubjectEncoding = [System.Text.Encoding]::UTF8

        foreach ($path in $AttachmentPaths) {
            if ($path -and (Test-Path -LiteralPath $path)) {
                $att = New-Object System.Net.Mail.Attachment($path)
                $attachments += $att
                $mail.Attachments.Add($att)
            }
            elseif ($path) {
                Write-Warning "첨부 파일을 찾지 못해 건너뜁니다: $path"
            }
        }

        $smtp = New-Object System.Net.Mail.SmtpClient($SmtpServer, $SmtpPort)
        $smtp.EnableSsl = $UseSsl
        $smtp.Timeout = $TimeoutSec * 1000
        if ($Username) {
            $smtp.Credentials = New-Object System.Net.NetworkCredential($Username, $Password)
        }

        $smtp.Send($mail)
        return $true
    }
    catch {
        Write-Warning "이메일(HTML 본문) 발송 실패: $($_.Exception.Message)"
        return $false
    }
    finally {
        foreach ($att in $attachments) { try { $att.Dispose() } catch { } }
        if ($mail) { try { $mail.Dispose() } catch { } }
        if ($smtp) { try { $smtp.Dispose() } catch { } }
    }
}

Export-ModuleMember -Function Send-VCFOpsReportEmail, Send-VCFOpsReportEmailWithHtmlBody
