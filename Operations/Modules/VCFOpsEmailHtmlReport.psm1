# VCFOpsEmailHtmlReport.psm1
# -----------------------------------------------------------------------------
# 이메일 본문 삽입/첨부용 "이메일 세이프(email-safe)" HTML 리포트 렌더러.
#
# Modules/VCFOpsHtmlReport.psm1 이 만드는 메인 HTML 리포트는 <style> 블록,
# flexbox/grid, position:sticky, 외부 폰트(<link>), <script>(검색 필터) 등을 사용해
# 웹 브라우저에서는 예쁘지만, Outlook 등 데스크톱 메일 클라이언트(Word 렌더링 엔진)
# 에서는 다수의 CSS가 무시되거나 레이아웃이 깨질 수 있습니다.
#
# 이 모듈은 동일한 $Data(리포트 데이터)를 받아, 메일 클라이언트 호환성이 검증된
# "전통적인 HTML 이메일 작성법"으로 다시 렌더링합니다:
#   - <style> 블록/외부 리소스/<script> 없음 (전부 인라인 style 속성만 사용)
#   - flexbox/grid 대신 <table>로 레이아웃 구성 (카드형 UI 대신 데이터 테이블 위주)
#   - 검색창 등 JS 상호작용 요소 제거 (정적 테이블로 전체 데이터 표시)
# -----------------------------------------------------------------------------

Import-Module (Join-Path $PSScriptRoot "VCFOpsTheme.psm1")

$Script:EmailFont = "Arial,'Malgun Gothic',Helvetica,sans-serif"

# 첨부 참고 스타일(EmailReport 예시)의 색상 팔레트를 그대로 적용합니다.
# (참고 파일은 구조/문구가 다른 별도 리포트이며, 여기서는 "색상"만 동일하게 맞춥니다.)
# 상태 배지(위험/주의/정상)는 참고 파일에 대응 요소가 없어 기존 $StatusColor를 유지합니다.
$Script:EC = @{
    page_bg        = "f1f4f9"  # 페이지(바깥) 배경
    card_bg        = "ffffff"  # 카드/컨테이너 배경
    border         = "dde1e8"  # 테두리
    text_primary   = "171923"  # 본문 텍스트
    text_muted     = "8b93a7"  # 흐린/보조 텍스트
    subsection     = "4a5062"  # 소제목(라벨) 텍스트
    accent         = "4f46e5"  # 섹션 타이틀 좌측 강조 바
    banner_bg      = "3730a3"  # 상단 배너 배경
    banner_title   = "ffffff"  # 배너 제목 텍스트
    banner_subtle  = "c7d2fe"  # 배너 부제/메타 텍스트
    th_bg          = "1c2130"  # 테이블 헤더(th) 배경
    th_text        = "ffffff"  # 테이블 헤더(th) 텍스트
    row_even       = "ffffff"  # 테이블 짝수 행 배경
    row_odd        = "f6f8fb"  # 테이블 홀수 행 배경
    stat_bg        = "fafafc"  # 통계 타일 배경
    footer_bg      = "f6f8fb"  # 푸터 배경
}

function Get-EmailArrowHtml {
    param([double]$Delta)
    if ($Delta -gt 0) { return "<span style=`"color:#$($Colors.coral_dark);font-weight:bold;`">▲$(Format-Number ([Math]::Abs($Delta)))</span>" }
    if ($Delta -lt 0) { return "<span style=`"color:#$($Colors.mint_dark);font-weight:bold;`">▼$(Format-Number ([Math]::Abs($Delta)))</span>" }
    return "<span style=`"color:#$($Script:EC.text_muted);`">–0.0</span>"
}

function Get-EmailBadgeHtml {
    param([Parameter(Mandatory)][string]$Status)
    $s = $StatusColor[$Status]
    return "<span style=`"display:inline-block;padding:2px 8px;font-size:11px;font-weight:bold;color:#$($s.fg);background-color:#$($s.bg);border-radius:8px;white-space:nowrap;`">$($s.label)</span>"
}

function Get-EmailCompareDaysLabel {
    param($Meta)
    if (-not $Meta.CompareEnabled -or -not $Meta.PreviousDate) { return "비교 없음" }
    $days = [Math]::Round(($Meta.CurrentDate - $Meta.PreviousDate).TotalDays)
    # "$days일"처럼 붙여 쓰면 PowerShell이 "days일"을 하나의 변수명으로 해석해 값이
    # 사라지므로(한글도 식별자로 허용됨) 반드시 ${days}로 변수명을 명시적으로 구분합니다.
    return "${days}일 전"
}

function Get-EmailStatusCounts {
    param($Values, [double]$Warning, [double]$Critical)
    $normal = 0; $warn = 0; $crit = 0
    foreach ($v in $Values) {
        $st = Get-StatusFromPct -Value $v -Warning $Warning -Critical $Critical
        if ($st -eq "critical") { $crit++ } elseif ($st -eq "warning") { $warn++ } else { $normal++ }
    }
    return [PSCustomObject]@{ Normal = $normal; Warning = $warn; Critical = $crit; Total = ($normal + $warn + $crit) }
}

function Build-EmailSectionHeader {
    param([string]$Icon, [string]$Title, [string]$Desc)
    return @"
<table role="presentation" width="100%" cellpadding="0" cellspacing="0" border="0" style="margin:26px 0 10px;">
  <tr><td style="font-size:14px;font-weight:bold;color:#$($Script:EC.text_primary);font-family:$Script:EmailFont;border-left:4px solid #$($Script:EC.accent);padding-left:8px;">$Icon $Title</td></tr>
  <tr><td style="font-size:11.5px;color:#$($Script:EC.text_muted);font-family:$Script:EmailFont;padding-top:2px;padding-bottom:8px;padding-left:12px;">$Desc</td></tr>
</table>
"@
}

function Build-EmailDataTable {
    # 헤더 배열 + 행(각 행은 셀 HTML 문자열의 배열) -> 인라인 style 기반 <table>
    # 첨부 참고 스타일과 동일하게: 진한 네이비 헤더(#th_bg) + 흰 글자, 짝/홀수 행 교차 배경.
    param([string[]]$Headers, $Rows, [string]$EmptyMessage = "데이터가 없습니다")

    $theadCells = ($Headers | ForEach-Object {
        "<th align=`"left`" style=`"padding:7px 10px;background-color:#$($Script:EC.th_bg);color:#$($Script:EC.th_text);font-size:10.5px;font-family:$Script:EmailFont;text-transform:uppercase;letter-spacing:.02em;border:1px solid #$($Script:EC.th_bg);white-space:nowrap;`">$_</th>"
    }) -join ""

    $rowList = @($Rows)
    if ($rowList.Count -eq 0) {
        $bodyRows = "<tr><td colspan=`"$($Headers.Count)`" align=`"center`" style=`"padding:16px;background-color:#$($Script:EC.row_even);border:1px solid #$($Script:EC.border);color:#$($Script:EC.text_muted);font-size:12px;font-family:$Script:EmailFont;`">$EmptyMessage</td></tr>"
    }
    else {
        $i = 0
        $bodyRows = ($rowList | ForEach-Object {
            $rowBg = if ($i % 2 -eq 0) { $Script:EC.row_even } else { $Script:EC.row_odd }
            $i++
            $tds = ($_ | ForEach-Object {
                "<td style=`"padding:6px 10px;background-color:#$rowBg;border:1px solid #$($Script:EC.border);font-size:12px;color:#$($Script:EC.text_primary);font-family:$Script:EmailFont;`">$_</td>"
            }) -join ""
            "<tr>$tds</tr>"
        }) -join ""
    }

    return @"
<table role="presentation" width="100%" cellpadding="0" cellspacing="0" border="0" style="border:1px solid #$($Script:EC.border);border-collapse:collapse;margin-bottom:6px;">
  <tr>$theadCells</tr>
  $bodyRows
</table>
"@
}

function Build-EmailHeaderHtml {
    param($Data)
    $m = $Data.Meta
    $cur = $m.CurrentDate.ToString("yyyy-MM-dd")
    $cmpLine = if ($m.CompareEnabled -and $m.PreviousDate) {
        "비교 기준일 ($(Get-EmailCompareDaysLabel -Meta $m)): <b>$($m.PreviousDate.ToString('yyyy-MM-dd'))</b>"
    } else { "비교 기준일: <b>비교 없음</b>" }

    return @"
<table role="presentation" width="100%" cellpadding="0" cellspacing="0" border="0" style="background-color:#$($Script:EC.banner_bg);margin-bottom:6px;">
  <tr><td style="padding:20px;font-family:$Script:EmailFont;">
    <div style="font-size:11px;font-weight:bold;letter-spacing:.04em;color:#$($Script:EC.banner_subtle);text-transform:uppercase;">VCF Operations · Capacity &amp; Health Report</div>
    <div style="font-size:19px;font-weight:bold;color:#$($Script:EC.banner_title);margin:8px 0 4px;">$($m.CustomerName) 가상화 인프라 운영 현황 리포트</div>
    <div style="font-size:12.5px;color:#$($Script:EC.banner_subtle);margin-bottom:12px;">$($m.VCenterScope)</div>
    <div style="font-size:12px;color:#$($Script:EC.banner_subtle);line-height:1.7;">
      조회 기준일: <b style="color:#$($Script:EC.banner_title);">$cur</b><br>
      $cmpLine<br>
      생성: $($m.GeneratedBy)
    </div>
  </td></tr>
</table>
"@
}

function Build-EmailExecSummarySection {
    param($Data)
    $cmpLabel = Get-EmailCompareDaysLabel -Meta $Data.Meta
    $rows = @($Data.PerfSummary | ForEach-Object {
        $p = $_
        $deltaCell = if ($p.HasComparison) { Get-EmailArrowHtml -Delta ($p.Current - $p.Previous) } else { "<span style=`"color:#$($Script:EC.text_muted);`">비교 없음</span>" }
        , @($p.Label, "$(Format-Number $p.Current) $($p.Unit)", "$(Format-Number $p.Previous) $($p.Unit)", $deltaCell)
    })
    $head = Build-EmailSectionHeader -Icon "Σ" -Title "Executive Summary" -Desc "최근 인프라 성능 요약 ($cmpLabel 대비)"
    $table = Build-EmailDataTable -Headers @("지표", "현재", "이전", "증감") -Rows $rows
    return "$head$table"
}

function Build-EmailInventorySection {
    param($Data)
    $rows = @($Data.InventoryCounts | ForEach-Object {
        $inv = $_
        $deltaCell = if ($inv.HasComparison) {
            $srcTag = if ($inv.PSObject.Properties.Name -contains "CompareSource" -and $inv.CompareSource -eq "metric") { " (실측)" } else { "" }
            "$(Get-EmailArrowHtml -Delta $inv.Delta) ($(Format-Number $inv.DeltaPct)%)$srcTag"
        } else { "<span style=`"color:#$($Script:EC.text_muted);`">비교 없음</span>" }
        $note = if ($inv.PSObject.Properties.Name -contains "PoweredOnCount") {
            "켜짐 $($inv.PoweredOnCount.ToString('N0'))대 / 꺼짐 $($inv.PoweredOffCount.ToString('N0'))대"
        } else { "" }
        , @($inv.Label, "$($inv.Current.ToString('N0'))대", "$($inv.Previous.ToString('N0'))대", $deltaCell, $note)
    })
    $head = Build-EmailSectionHeader -Icon "📊" -Title "리소스 현황 (수량 변화)" -Desc "vCenter / 데이터센터 / 클러스터 / 호스트 / VM 수량"
    $table = Build-EmailDataTable -Headers @("항목", "현재", "이전", "증감", "비고") -Rows $rows
    return "$head$table"
}

function Build-EmailClusterSection {
    param($Data)
    $cmpLabel = Get-EmailCompareDaysLabel -Meta $Data.Meta
    $rows = @($Data.Clusters | ForEach-Object {
        $cm = $_
        $contSt = Get-StatusFromPct -Value $cm.CpuContentionPct -Warning $Threshold.cpu_contention_warning -Critical $Threshold.cpu_contention_critical

        $cpuCell = "$($cm.CpuPct)%" + $(if ($cm.HasComparison) { " " + (Get-EmailArrowHtml -Delta ($cm.CpuPct - $cm.PrevCpuPct)) } else { "" })
        $memCell = "$($cm.MemPct)%" + $(if ($cm.HasComparison) { " " + (Get-EmailArrowHtml -Delta ($cm.MemPct - $cm.PrevMemPct)) } else { "" })
        $stoCell = "$($cm.StoragePct)%" + $(if ($cm.HasComparison) { " " + (Get-EmailArrowHtml -Delta ($cm.StoragePct - $cm.PrevStoragePct)) } else { "" })
        $contCell = "<span style=`"color:#$($StatusColor[$contSt].fg);font-weight:bold;`">$($cm.CpuContentionPct)%</span>"

        , @(
            "$($cm.Name)<br><span style=`"color:#$($Script:EC.text_muted);font-size:11px;`">$($cm.Datacenter)</span>",
            "$($cm.HostCount)대", "$($cm.VmCount)대",
            $cpuCell, $memCell, $stoCell, $contCell,
            (Get-EmailBadgeHtml -Status $cm.Status)
        )
    })
    $head = Build-EmailSectionHeader -Icon "🧩" -Title "클러스터별 성능 현황" -Desc "CPU / Memory / Storage 사용률, CPU 경합률 ($cmpLabel 대비)"
    $table = Build-EmailDataTable -Headers @("클러스터", "호스트", "VM", "CPU", "MEM", "Storage", "경합", "상태") -Rows $rows
    return "$head$table"
}

function Build-EmailDatastoreSection {
    param($Data)
    $cmpLabel = Get-EmailCompareDaysLabel -Meta $Data.Meta
    $rows = @($Data.DatastoreInfo | ForEach-Object {
        $d = $_
        $usedPct = if ($d.CapacityGb -gt 0) { [Math]::Round($d.UsedGb / $d.CapacityGb * 100, 1) } else { 0 }
        $deltaCell = if ($d.HasComparison) { Get-EmailArrowHtml -Delta $d.DeltaUsedGb } else { "<span style=`"color:#$($Script:EC.text_muted);`">비교 없음</span>" }
        , @($d.Name, $d.Cluster, "$(Format-Number $d.CapacityGb) GB", "$(Format-Number $d.UsedGb) GB ($usedPct%)", $deltaCell, "$(Format-Number $d.FreeGb) GB")
    })
    $anyComparison = [bool]($Data.DatastoreInfo | Where-Object { $_.HasComparison } | Select-Object -First 1)
    $desc = if ($anyComparison) { "데이터스토어 용량/사용량 — $cmpLabel 대비 증감" } else { "데이터스토어 용량/사용량" }
    $head = Build-EmailSectionHeader -Icon "💾" -Title "데이터스토어 현황" -Desc $desc
    $table = Build-EmailDataTable -Headers @("데이터스토어", "클러스터", "총량", "사용량", "증감", "잔여") -Rows $rows
    return "$head$table"
}

function Build-EmailHostsSection {
    param($Data)
    $head = Build-EmailSectionHeader -Icon "🖥️" -Title "ESXi 호스트 Top 리스트" -Desc "CPU 사용률 / MEM 사용률 / CPU 경합률 각각 상위 10대"

    $cpuTop = @($Data.Hosts | Sort-Object -Property CpuPct -Descending | Select-Object -First 10)
    $memTop = @($Data.Hosts | Sort-Object -Property MemPct -Descending | Select-Object -First 10)
    $contTop = @($Data.Hosts | Sort-Object -Property CpuContentionPct -Descending | Select-Object -First 10)

    function Get-TopRows {
        param($List, [string]$ValueProp, [double]$Warn, [double]$Crit)
        $i = 0
        @($List | ForEach-Object {
            $i++
            $val = $_.$ValueProp
            $st = Get-StatusFromPct -Value $val -Warning $Warn -Critical $Crit
            , @("$i", $_.Name, $_.Cluster, "$val%", (Get-EmailBadgeHtml -Status $st))
        })
    }

    $cpuRows = Get-TopRows -List $cpuTop -ValueProp "CpuPct" -Warn $Threshold.cpu_warning -Crit $Threshold.cpu_critical
    $memRows = Get-TopRows -List $memTop -ValueProp "MemPct" -Warn $Threshold.mem_warning -Crit $Threshold.mem_critical
    $contRows = Get-TopRows -List $contTop -ValueProp "CpuContentionPct" -Warn $Threshold.cpu_contention_warning -Crit $Threshold.cpu_contention_critical

    $sub1 = "<div style=`"font-weight:bold;font-size:13px;margin:4px 0 6px;color:#$($Script:EC.text_primary);font-family:$Script:EmailFont;`">CPU 사용률 Top10</div>"
    $sub2 = "<div style=`"font-weight:bold;font-size:13px;margin:14px 0 6px;color:#$($Script:EC.text_primary);font-family:$Script:EmailFont;`">MEM 사용률 Top10</div>"
    $sub3 = "<div style=`"font-weight:bold;font-size:13px;margin:14px 0 6px;color:#$($Script:EC.text_primary);font-family:$Script:EmailFont;`">CPU 경합률 Top10</div>"

    $cpuTable = Build-EmailDataTable -Headers @("#", "호스트명", "클러스터", "CPU 사용률", "상태") -Rows $cpuRows
    $memTable = Build-EmailDataTable -Headers @("#", "호스트명", "클러스터", "MEM 사용률", "상태") -Rows $memRows
    $contTable = Build-EmailDataTable -Headers @("#", "호스트명", "클러스터", "CPU 경합률", "상태") -Rows $contRows

    return "$head$sub1$cpuTable$sub2$memTable$sub3$contTable"
}

function Build-EmailVmTopListsSection {
    param($Data)
    $head = Build-EmailSectionHeader -Icon "🔥" -Title "VM Top 리스트" -Desc "vCPU 사용률 / CPU 경합(Ready) / 가상디스크 레이턴시 각각 상위 10대"

    $cpuRows = @(); $i = 0
    foreach ($v in $Data.TopCpuVMs) {
        $i++
        $st = Get-StatusFromPct -Value $v.CpuUsagePct -Warning $Threshold.cpu_warning -Critical $Threshold.cpu_critical
        $cpuRows += , @("$i", $v.Name, $v.Cluster, $v.Host, "$($v.VcpuCount)", "$($v.CpuUsagePct)%", (Get-EmailBadgeHtml -Status $st))
    }
    $readyRows = @(); $i = 0
    foreach ($v in $Data.TopReadyVMs) {
        $i++
        $st = Get-StatusFromPct -Value $v.CpuReadyPct -Warning $Threshold.cpu_contention_warning -Critical $Threshold.cpu_contention_critical
        $readyRows += , @("$i", $v.Name, $v.Cluster, $v.Host, "$($v.VcpuCount)", "$($v.CpuReadyPct)%", (Get-EmailBadgeHtml -Status $st))
    }
    $diskRows = @(); $i = 0
    foreach ($v in $Data.DiskLatencyVMs) {
        $i++
        $maxLat = [Math]::Max($v.ReadLatencyMs, $v.WriteLatencyMs)
        $st = Get-StatusFromPct -Value $maxLat -Warning $Threshold.disk_latency_warning_ms -Critical $Threshold.disk_latency_critical_ms
        $diskRows += , @("$i", $v.Name, $v.Cluster, $v.Datastore, "$($v.ReadLatencyMs) ms", "$($v.WriteLatencyMs) ms", (Get-EmailBadgeHtml -Status $st))
    }

    $sub1 = "<div style=`"font-weight:bold;font-size:13px;margin:4px 0 6px;color:#$($Script:EC.text_primary);font-family:$Script:EmailFont;`">vCPU 사용률 Top10</div>"
    $sub2 = "<div style=`"font-weight:bold;font-size:13px;margin:14px 0 6px;color:#$($Script:EC.text_primary);font-family:$Script:EmailFont;`">CPU 경합(Ready) Top10</div>"
    $sub3 = "<div style=`"font-weight:bold;font-size:13px;margin:14px 0 6px;color:#$($Script:EC.text_primary);font-family:$Script:EmailFont;`">가상디스크 레이턴시 Top10</div>"

    $cpuTable = Build-EmailDataTable -Headers @("#", "VM명", "클러스터", "호스트", "vCPU", "사용률", "상태") -Rows $cpuRows
    $readyTable = Build-EmailDataTable -Headers @("#", "VM명", "클러스터", "호스트", "vCPU", "Ready %", "상태") -Rows $readyRows
    $diskTable = Build-EmailDataTable -Headers @("#", "VM명", "클러스터", "데이터스토어", "Read", "Write", "상태") -Rows $diskRows

    return "$head$sub1$cpuTable$sub2$readyTable$sub3$diskTable"
}

function Build-EmailOpsNotesSection {
    param($Data)
    $head = Build-EmailSectionHeader -Icon "🛠️" -Title "운영 참고사항" -Desc "1주 이상 보존된 VM 스냅샷 — 스토리지 점유 및 성능 영향 점검 필요"
    $rows = @($Data.SnapshotAlerts | ForEach-Object {
        $s = $_
        $st = if ($s.OldestSnapshotAgeDays -ge 30) { "critical" } else { "warning" }
        , @($s.Name, $s.Cluster, "$($s.SnapshotCount)", "$($s.OldestSnapshotAgeDays)일", "$(Format-Number $s.TotalSnapshotSizeGb) GB", (Get-EmailBadgeHtml -Status $st))
    })
    $table = Build-EmailDataTable -Headers @("VM명", "클러스터", "스냅샷 수", "최장 보존기간", "총 용량", "상태") -Rows $rows -EmptyMessage "7일 이상 보존된 스냅샷이 없습니다"
    return "$head$table"
}

function Build-EmailBreakdownTable {
    param([string]$Title, $Rows, [int]$Total)
    $tblRows = @($Rows | ForEach-Object {
        $deltaCell = if ($_.HasComparison) { Get-EmailArrowHtml -Delta $_.Delta } else { "<span style=`"color:#$($Script:EC.text_muted);`">비교 없음</span>" }
        , @($_.Label, "$($_.Count)대", "$($_.Pct)%", $deltaCell)
    })
    $sub = "<div style=`"font-weight:bold;font-size:13px;margin:14px 0 6px;color:#$($Script:EC.text_primary);font-family:$Script:EmailFont;`">$Title <span style=`"font-weight:normal;color:#$($Script:EC.text_muted);font-size:11px;`">(전체 $Total 대)</span></div>"
    $table = Build-EmailDataTable -Headers @("구분", "수량", "비중", "증감") -Rows $tblRows
    return "$sub$table"
}

function Build-EmailVmInventorySection {
    param($Data)
    $head = Build-EmailSectionHeader -Icon "🧱" -Title "VM 인벤토리 요약" -Desc "Guest OS / VMware Tools 버전 / 가상 HW버전 / vCPU 구간별 VM 수량 분포"
    $total = $Data.VmBreakdown.Total
    $os = Build-EmailBreakdownTable -Title "Guest OS별 VM 수량" -Rows $Data.VmBreakdown.OsRows -Total $total
    $tools = Build-EmailBreakdownTable -Title "VMware Tools 버전별 VM 수량" -Rows $Data.VmBreakdown.ToolsRows -Total $total
    $hw = Build-EmailBreakdownTable -Title "Virtual Hardware 버전별 VM 수량" -Rows $Data.VmBreakdown.HwRows -Total $total
    $vcpu = Build-EmailBreakdownTable -Title "vCPU 구간별 VM 수량" -Rows $Data.VmBreakdown.VcpuRows -Total $total
    return "$head$os$tools$hw$vcpu"
}

function Build-EmailThickDiskSection {
    param($Data)
    $head = Build-EmailSectionHeader -Icon "🟦" -Title "Thick 프로비저닝 디스크 목록" -Desc "디스크 유형이 Thick(Eager/Lazy Zeroed)인 가상 디스크 목록"
    $rows = @()
    foreach ($v in $Data.VmInventory) {
        foreach ($d in $v.Disks) {
            if ($d.ProvisioningKind -eq "Thick") {
                $rows += , @($v.Name, $v.Cluster, $v.Host, $d.Label, "$(Format-Number $d.CapacityGb 0) GB", $d.Datastore)
            }
        }
    }
    $table = Build-EmailDataTable -Headers @("VM명", "클러스터", "ESXi Host", "디스크", "용량", "데이터스토어") -Rows $rows -EmptyMessage "Thick 프로비저닝 디스크가 없습니다"
    return "$head$table"
}

function Build-EmailSharedDiskSection {
    param($Data)
    $head = Build-EmailSectionHeader -Icon "🟧" -Title "공유 디스크 목록" -Desc "Shared(멀티라이터 등) 가상 디스크 목록"
    $rows = @()
    foreach ($v in $Data.VmInventory) {
        foreach ($d in $v.Disks) {
            if ($d.Shared) {
                $rows += , @($v.Name, $v.Cluster, $v.Host, $d.Label, "$(Format-Number $d.CapacityGb 0) GB", $d.Datastore)
            }
        }
    }
    $table = Build-EmailDataTable -Headers @("VM명", "클러스터", "ESXi Host", "디스크", "용량", "데이터스토어") -Rows $rows -EmptyMessage "공유 디스크가 없습니다"
    return "$head$table"
}

function Build-EmailVmPerformanceSection {
    param($Data)
    $head = Build-EmailSectionHeader -Icon "📈" -Title "VM 성능정보 요약" -Desc "CPU 사용률 / CPU 경합(Ready) / MEM 사용률 / 가상디스크 레이턴시 — 등급별 VM 수량"

    $cpuCounts = Get-EmailStatusCounts -Values ($Data.VmPerformance | ForEach-Object { $_.CpuUsagePct }) -Warning $Threshold.cpu_warning -Critical $Threshold.cpu_critical
    $readyCounts = Get-EmailStatusCounts -Values ($Data.VmPerformance | ForEach-Object { $_.CpuReadyPct }) -Warning $Threshold.cpu_contention_warning -Critical $Threshold.cpu_contention_critical
    $memCounts = Get-EmailStatusCounts -Values ($Data.VmPerformance | ForEach-Object { $_.MemUsagePct }) -Warning $Threshold.mem_warning -Critical $Threshold.mem_critical
    $diskCounts = Get-EmailStatusCounts -Values ($Data.VmPerformance | ForEach-Object { $_.DiskLatencyMs }) -Warning $Threshold.disk_latency_warning_ms -Critical $Threshold.disk_latency_critical_ms

    $rows = @(
        , @("CPU 사용률", "$($cpuCounts.Normal)대", "$($cpuCounts.Warning)대", "$($cpuCounts.Critical)대", "$($cpuCounts.Total)대")
        , @("CPU 경합(Ready)", "$($readyCounts.Normal)대", "$($readyCounts.Warning)대", "$($readyCounts.Critical)대", "$($readyCounts.Total)대")
        , @("MEM 사용률", "$($memCounts.Normal)대", "$($memCounts.Warning)대", "$($memCounts.Critical)대", "$($memCounts.Total)대")
        , @("디스크 레이턴시", "$($diskCounts.Normal)대", "$($diskCounts.Warning)대", "$($diskCounts.Critical)대", "$($diskCounts.Total)대")
    )
    $table = Build-EmailDataTable -Headers @("지표", "정상", "주의", "위험", "전체") -Rows $rows
    return "$head$table"
}

function New-VCFOpsEmailHtmlReport {
    # 이메일 발송(본문 삽입/첨부)용 - <style>/<script>/외부 리소스 없이 <table> +
    # 인라인 style 속성만으로 구성된 정적 HTML을 생성합니다.
    [CmdletBinding()]
    param([Parameter(Mandatory)]$Data)

    $bodyParts = @(
        (Build-EmailHeaderHtml -Data $Data)
        (Build-EmailExecSummarySection -Data $Data)
        (Build-EmailInventorySection -Data $Data)
        (Build-EmailClusterSection -Data $Data)
        (Build-EmailDatastoreSection -Data $Data)
        (Build-EmailHostsSection -Data $Data)
        (Build-EmailVmTopListsSection -Data $Data)
        (Build-EmailOpsNotesSection -Data $Data)
        (Build-EmailVmInventorySection -Data $Data)
        (Build-EmailThickDiskSection -Data $Data)
        (Build-EmailSharedDiskSection -Data $Data)
        (Build-EmailVmPerformanceSection -Data $Data)
    )
    $body = $bodyParts -join ""
    $title = "$($Data.Meta.CustomerName) 가상화 인프라 운영 현황 리포트 (이메일용)"

    return @"
<!DOCTYPE html>
<html lang="ko">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<meta name="x-apple-disable-message-reformatting">
<title>$title</title>
</head>
<body style="margin:0;padding:0;background-color:#$($Script:EC.page_bg);">
<table role="presentation" width="100%" cellpadding="0" cellspacing="0" border="0" style="background-color:#$($Script:EC.page_bg);">
<tr><td align="center" style="padding:20px 12px;">
<table role="presentation" width="680" cellpadding="0" cellspacing="0" border="0" style="max-width:680px;width:100%;background-color:#$($Script:EC.card_bg);border:1px solid #$($Script:EC.border);">
<tr><td style="padding:20px;">
$body
</td></tr>
<tr><td style="padding:12px 20px;background-color:#$($Script:EC.footer_bg);border-top:1px solid #$($Script:EC.border);text-align:center;">
<div style="color:#$($Script:EC.text_muted);font-size:11px;font-family:$Script:EmailFont;">$($Data.Meta.GeneratedBy) &middot; 생성 시각 $(Get-Date -Format 'yyyy-MM-dd HH:mm')</div>
</td></tr>
</table>
</td></tr>
</table>
</body>
</html>
"@
}

Export-ModuleMember -Function New-VCFOpsEmailHtmlReport
