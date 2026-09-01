# VCFOpsTheme.psm1
# -----------------------------------------------------------------------------
# 모던 + 파스텔 톤 디자인 토큰. Python 버전(report/theme.py)과 동일한 값으로 맞춰
# HTML 결과물의 색감/임계치가 동일하게 유지되도록 합니다.
# -----------------------------------------------------------------------------

$Colors = @{
    bg             = "F5F6FB"
    surface        = "FFFFFF"
    surface_alt    = "F0F2FA"
    border         = "E3E6F2"

    text_primary   = "2E3148"
    text_secondary = "6B7090"
    text_muted     = "9498B0"

    primary        = "6C7FE8"
    primary_dark   = "4C5FCB"
    primary_tint   = "E7EAFB"

    mint           = "7FD8C4"
    mint_dark      = "2F9C82"
    mint_tint      = "E3F7F1"

    peach          = "F6B88A"
    peach_dark     = "C97A33"
    peach_tint     = "FCEADC"

    coral          = "F08C8C"
    coral_dark     = "C84B4B"
    coral_tint     = "FCE3E3"

    sky            = "8FC7F2"
    sky_dark       = "3E7FB0"
    sky_tint       = "E7F3FC"

    lilac          = "C6A8E8"
}

$StatusColor = @{
    normal   = @{ fg = $Colors.mint_dark;  bg = $Colors.mint_tint;  label = "정상" }
    warning  = @{ fg = $Colors.peach_dark; bg = $Colors.peach_tint; label = "주의" }
    critical = @{ fg = $Colors.coral_dark; bg = $Colors.coral_tint; label = "위험" }
}

$Threshold = @{
    cpu_warning               = 70
    cpu_critical              = 85
    mem_warning               = 70
    mem_critical              = 85
    storage_warning           = 70
    storage_critical          = 85
    cpu_contention_warning    = 5
    cpu_contention_critical   = 10
    disk_latency_warning_ms   = 15
    disk_latency_critical_ms  = 30
    snapshot_age_warning_days = 7
}

function Get-StatusFromPct {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][double]$Value,
        [Parameter(Mandatory)][double]$Warning,
        [Parameter(Mandatory)][double]$Critical
    )
    if ($Value -ge $Critical) { return "critical" }
    if ($Value -ge $Warning) { return "warning" }
    return "normal"
}

function Get-RangeLabel {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][double]$Warning,
        [Parameter(Mandatory)][double]$Critical,
        [string]$Unit = "%"
    )
    return [PSCustomObject]@{
        Normal = "< $Warning$Unit"
        Warning = "$Warning~$Critical$Unit"
        Critical = "≥ $Critical$Unit"
    }
}

function Format-Number {
    # Python의 f"{v:,.{nd}f}" 와 동일한 결과(천단위 콤마 + 고정 소수점)를 만들기 위해
    # 시스템 로캘에 영향받지 않도록 InvariantCulture를 사용합니다.
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]$Value,
        [int]$Decimals = 1
    )
    $num = 0.0
    try { $num = [double]$Value } catch { $num = 0.0 }
    $fmt = "{0:N$Decimals}"
    return [string]::Format([System.Globalization.CultureInfo]::InvariantCulture, $fmt, $num)
}

function ConvertTo-SafeDouble {
    [CmdletBinding()]
    param($Value, [double]$Default = 0.0)
    if ($null -eq $Value) { return $Default }
    try { return [double]$Value } catch { return $Default }
}

Export-ModuleMember -Variable Colors, StatusColor, Threshold `
                     -Function Get-StatusFromPct, Format-Number, ConvertTo-SafeDouble, Get-RangeLabel
