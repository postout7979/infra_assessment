# VCFOpsHtmlReport.psm1
# -----------------------------------------------------------------------------
# HTML 리포트 렌더러 (PowerShell 버전)
# Python 버전(report/html_report.py)과 동일한 CSS 클래스/색상/구조를 사용해
# 동일한 모던+파스텔 대시보드 결과물을 생성합니다.
# -----------------------------------------------------------------------------

Import-Module (Join-Path $PSScriptRoot "VCFOpsTheme.psm1")

function Get-ArrowHtml {
    param([double]$Delta)
    if ($Delta -gt 0) { return "<span class=`"delta up`">▲ $(Format-Number ([Math]::Abs($Delta)))</span>" }
    if ($Delta -lt 0) { return "<span class=`"delta down`">▼ $(Format-Number ([Math]::Abs($Delta)))</span>" }
    return "<span class=`"delta flat`">– 0.0</span>"
}

function Get-BadgeHtml {
    param([Parameter(Mandatory)][string]$Status)
    $s = $StatusColor[$Status]
    return "<span class=`"badge`" style=`"color:#$($s.fg);background:#$($s.bg);`">$($s.label)</span>"
}

function Get-BarHtml {
    param([double]$Pct, [Parameter(Mandatory)][string]$Status)
    $s = $StatusColor[$Status]
    $clamped = [Math]::Max(0, [Math]::Min(100, $Pct))
    return "<div class=`"bar-track`"><div class=`"bar-fill`" style=`"width:$($clamped)%;background:#$($s.fg);`"></div></div>"
}

function Get-CssBlock {
    $c = $Colors
    return @"
:root {
  --bg:#$($c.bg); --surface:#$($c.surface); --surface-alt:#$($c.surface_alt);
  --border:#$($c.border);
  --text:#$($c.text_primary); --text2:#$($c.text_secondary); --muted:#$($c.text_muted);
  --primary:#$($c.primary); --primary-dark:#$($c.primary_dark); --primary-tint:#$($c.primary_tint);
  --mint:#$($c.mint); --mint-dark:#$($c.mint_dark); --mint-tint:#$($c.mint_tint);
  --peach:#$($c.peach); --peach-dark:#$($c.peach_dark); --peach-tint:#$($c.peach_tint);
  --coral:#$($c.coral); --coral-dark:#$($c.coral_dark); --coral-tint:#$($c.coral_tint);
  --sky:#$($c.sky); --sky-dark:#$($c.sky_dark); --sky-tint:#$($c.sky_tint);
  --lilac:#$($c.lilac);
}
* { box-sizing:border-box; }
html,body { margin:0; padding:0; background:var(--bg); color:var(--text);
  font-family:'Pretendard','Noto Sans KR','Segoe UI',sans-serif; font-size:15px; line-height:1.6; }
.wrap { max-width:1280px; margin:0 auto; padding:0 28px 80px; }

.hero { background:linear-gradient(135deg, var(--primary-tint) 0%, var(--sky-tint) 60%, var(--mint-tint) 100%);
  padding:40px 28px 32px; border-radius:0 0 28px 28px; margin-bottom:28px; }
.hero-inner { max-width:1280px; margin:0 auto; display:flex; justify-content:space-between; align-items:flex-end; flex-wrap:wrap; gap:16px;}
.hero-eyebrow { color:var(--primary-dark); font-weight:700; letter-spacing:.04em; font-size:13px; text-transform:uppercase; }
.hero h1 { font-size:30px; font-weight:800; margin:8px 0 6px; color:var(--text); }
.hero .sub { color:var(--text2); font-size:14.5px; }
.hero .meta-box { background:rgba(255,255,255,.7); border-radius:16px; padding:14px 20px; font-size:13.5px; color:var(--text2); min-width:260px; }
.hero .meta-box b { color:var(--text); }

.nav { position:sticky; top:0; z-index:50; background:rgba(245,246,251,.92); backdrop-filter:blur(6px);
  border-bottom:1px solid var(--border); padding:10px 28px; display:flex; gap:6px; flex-wrap:wrap; }
.nav a { color:var(--text2); text-decoration:none; font-size:13px; font-weight:600; padding:7px 13px;
  border-radius:20px; white-space:nowrap; margin-right:4px; }
.nav a:hover { background:var(--primary-tint); color:var(--primary-dark); }

section { margin:46px 0; }
.section-head { display:flex; align-items:center; gap:12px; margin-bottom:18px; }
.section-icon { width:36px; height:36px; border-radius:50%; display:flex; align-items:center; justify-content:center;
  font-size:17px; background:var(--primary-tint); color:var(--primary-dark); flex-shrink:0; }
.section-head h2 { font-size:21px; font-weight:800; margin:0; color:var(--text); }
.section-head .desc { color:var(--muted); font-size:13px; margin-top:2px; }

.grid3, .grid4, .grid2 { display:flex; flex-wrap:wrap; gap:18px; }
.grid3 > * { flex:1 1 calc(33.333% - 18px); min-width:280px; }
.grid4 > * { flex:1 1 calc(25% - 16px); min-width:230px; }
.grid2 > * { flex:1 1 calc(50% - 18px); min-width:320px; }
@media (max-width:980px) { .grid3 > *, .grid4 > * { flex:1 1 calc(50% - 18px); } }
@media (max-width:640px) { .grid3 > *, .grid4 > *, .grid2 > * { flex:1 1 100%; } }

.card { background:var(--surface); border:1px solid var(--border); border-radius:18px; padding:22px;
  box-shadow:0 2px 14px rgba(46,49,72,.05); }
.kpi-card .label { font-size:13px; color:var(--text2); font-weight:600; }
.kpi-card .value { font-size:30px; font-weight:800; margin:6px 0 4px; color:var(--text); }
.kpi-card .value .unit { font-size:15px; font-weight:600; color:var(--muted); margin-left:4px;}
.delta { font-size:12.5px; font-weight:700; padding:2px 8px; border-radius:10px; }
.delta.up { color:var(--coral-dark); background:var(--coral-tint); }
.delta.down { color:var(--mint-dark); background:var(--mint-tint); }
.delta.flat { color:var(--text2); background:var(--surface-alt); }
.kpi-card .delta-row { display:flex; align-items:center; gap:8px; font-size:12.5px; color:var(--muted); }
.kpi-card .delta-row .delta { margin-right:6px; }

.cluster-card .ch { display:flex; justify-content:space-between; align-items:center; margin-bottom:14px;}
.cluster-card .ch .name { font-weight:800; font-size:16px; }
.cluster-card .ch .dc { font-size:12px; color:var(--muted); }
.metric-row { margin-bottom:12px; }
.metric-row .mrow-top { display:flex; justify-content:space-between; font-size:13px; margin-bottom:5px; }
.metric-row .mrow-top .mlabel { color:var(--text2); font-weight:600; }
.metric-row .mrow-top .mval { font-weight:700; color:var(--text); }
.bar-track { height:8px; border-radius:6px; background:var(--surface-alt); overflow:hidden; }
.bar-fill { height:100%; border-radius:6px; }
.sub-stats { display:flex; gap:14px; margin-top:14px; padding-top:12px; border-top:1px dashed var(--border); }
.sub-stat { font-size:12px; color:var(--text2); margin-right:14px; }
.sub-stat:last-child { margin-right:0; }
.sub-stat b { display:block; font-size:14px; color:var(--text); font-weight:800; }

.table-card { background:var(--surface); border:1px solid var(--border); border-radius:18px; padding:6px 6px 14px;
  box-shadow:0 2px 14px rgba(46,49,72,.05); overflow:hidden; }
.table-toolbar { display:flex; justify-content:space-between; align-items:center; padding:14px 18px 8px; gap:10px; flex-wrap:wrap;}
.table-toolbar .count { font-size:12.5px; color:var(--muted); }
.search-box { border:1px solid var(--border); border-radius:10px; padding:7px 12px; font-size:13px;
  background:var(--surface-alt); color:var(--text); width:230px; }
.search-box:focus { outline:2px solid var(--primary-tint); }
table { width:100%; border-collapse:collapse; font-size:13.5px; }
thead th { background:var(--surface-alt); color:var(--text2); font-weight:700; text-align:left;
  padding:10px 14px; font-size:12.5px; position:sticky; top:0; }
tbody td { padding:9px 14px; border-bottom:1px solid var(--border); color:var(--text); }
tbody tr:hover { background:var(--primary-tint); }
.badge { font-size:11.5px; font-weight:700; padding:3px 10px; border-radius:10px; white-space:nowrap; }
.num { text-align:center; font-weight:600; }
.scroll-y { max-height:560px; overflow-y:auto; }
.mono { font-family:'SF Mono','Consolas',monospace; font-size:12.5px; color:var(--text2); }
.tag { display:inline-block; font-size:11px; padding:2px 8px; border-radius:8px; background:var(--surface-alt); color:var(--text2); margin-right:4px;}
.tag.thin { background:var(--mint-tint); color:var(--mint-dark); }
.tag.thick { background:var(--sky-tint); color:var(--sky-dark); }
.tag.shared { background:var(--peach-tint); color:var(--peach-dark); }

.foot { text-align:center; color:var(--muted); font-size:12px; margin-top:60px; }
.legend { display:flex; gap:16px; font-size:12px; color:var(--text2); margin-top:10px; flex-wrap:wrap;}
.legend span { display:inline-flex; align-items:center; gap:6px; margin-right:16px; }
.legend i { width:10px; height:10px; border-radius:50%; display:inline-block; margin-right:6px; }

.bd-title { font-weight:800; font-size:14.5px; color:var(--text); margin-bottom:14px; }
.bd-title .bd-total { font-weight:600; font-size:12px; color:var(--muted); margin-left:8px; }
.bd-row { display:flex; align-items:center; gap:10px; margin-bottom:10px; font-size:12.5px; }
.bd-label { width:38%; color:var(--text2); font-weight:600; overflow:hidden; text-overflow:ellipsis; white-space:nowrap; }
.bd-bar-track { flex:1; height:9px; border-radius:6px; background:var(--surface-alt); overflow:hidden; }
.bd-bar-fill { height:100%; border-radius:6px; background:var(--primary); }
.bd-count { width:88px; text-align:right; color:var(--text); font-weight:700; white-space:nowrap; }
.bd-count .bd-pct { color:var(--muted); font-weight:500; }

.stacked-bar { display:flex; height:14px; border-radius:7px; overflow:hidden; background:var(--surface-alt); margin-bottom:14px; }
.stacked-bar .seg.normal { background:var(--mint); }
.stacked-bar .seg.warning { background:var(--peach); }
.stacked-bar .seg.critical { background:var(--coral); }
.status-legend-row { display:flex; gap:16px; font-size:12.5px; color:var(--text2); flex-wrap:wrap; }
.status-legend-row .dot { width:9px; height:9px; border-radius:50%; display:inline-block; margin-right:6px; }
.status-legend-row .dot.normal { background:var(--mint-dark); }
.status-legend-row .dot.warning { background:var(--peach-dark); }
.status-legend-row .dot.critical { background:var(--coral-dark); }

@media print {
  .nav { position:static; }
  .search-box { display:none; }
  .table-toolbar .search-box { display:none; }
  .scroll-y { max-height:none !important; overflow:visible !important; }
  section { break-inside:avoid-page; }
  body { background:#fff; }
}
"@
}

function Get-JsBlock {
    return @"
function filterTable(inputId, tableId) {
  var q = document.getElementById(inputId).value.trim().toLowerCase();
  var rows = document.querySelectorAll('#' + tableId + ' tbody tr');
  var visible = 0;
  rows.forEach(function (r) {
    var hit = r.innerText.toLowerCase().indexOf(q) !== -1;
    r.style.display = hit ? '' : 'none';
    if (hit) visible++;
  });
  var counter = document.getElementById(tableId + '-count');
  if (counter) counter.innerText = visible + ' 행 표시';
}
"@
}

function Build-SectionHead {
    param([string]$Icon, [string]$Title, [string]$Desc, [string]$Anchor)
    return @"
<div class="section-head" id="$Anchor">
  <div class="section-icon">$Icon</div>
  <div><h2>$Title</h2><div class="desc">$Desc</div></div>
</div>
"@
}

function Build-HeroSection {
    param($Data)
    $m = $Data.Meta
    $cur = $m.CurrentDate.ToString("yyyy-MM-dd")
    $cmpLabel = Get-CompareDaysLabel -Meta $m
    $cmpLine = if ($m.CompareEnabled -and $m.PreviousDate) {
        "비교 기준일($cmpLabel) &nbsp;<b>$($m.PreviousDate.ToString("yyyy-MM-dd"))</b><br>"
    } else {
        "비교 기준일 &nbsp;<b>비교 없음</b><br>"
    }
    return @"
<div class="hero"><div class="hero-inner">
  <div>
    <div class="hero-eyebrow">VCF Operations · Capacity &amp; Health Report</div>
    <h1>$($m.CustomerName) 가상화 인프라 운영 현황 리포트</h1>
    <div class="sub">$($m.VCenterScope)</div>
  </div>
  <div class="meta-box">
    조회 기준일 &nbsp;<b>$cur</b><br>
    $cmpLine
    생성: $($m.GeneratedBy)
  </div>
</div></div>
"@
}

function Build-NavSection {
    $items = @(
        @{ Id = "exec"; Label = "Executive Summary" }
        @{ Id = "inventory"; Label = "리소스 현황" }
        @{ Id = "cluster"; Label = "클러스터 성능" }
        @{ Id = "datastore"; Label = "데이터스토어" }
        @{ Id = "hosts"; Label = "ESXi 호스트" }
        @{ Id = "vm-top"; Label = "VM Top 리스트" }
        @{ Id = "ops"; Label = "운영 참고사항" }
        @{ Id = "vm-inv"; Label = "VM 인벤토리" }
        @{ Id = "vm-thick"; Label = "Thick 디스크" }
        @{ Id = "vm-shared"; Label = "공유 디스크" }
        @{ Id = "vm-perf"; Label = "VM 성능정보" }
    )
    $links = ($items | ForEach-Object { "<a href=`"#$($_.Id)`">$($_.Label)</a>" }) -join ""
    return "<div class=`"nav`">$links</div>"
}

function Get-CompareDaysLabel {
    param($Meta)
    if (-not $Meta.CompareEnabled -or -not $Meta.PreviousDate) { return "비교 없음" }
    $days = [Math]::Round(($Meta.CurrentDate - $Meta.PreviousDate).TotalDays)
    # 주의: "$days일"처럼 변수 뒤에 한글을 바로 붙이면 PowerShell이 "$days일"을
    # 통째로 하나의 변수명으로 해석해버려(한글도 식별자로 허용됨) 값이 사라집니다.
    # 반드시 ${days}처럼 중괄호로 변수명을 명시적으로 구분해야 합니다.
    return "${days}일 전"
}

function Build-ExecSummarySection {
    param($Data)
    $cmpLabel = Get-CompareDaysLabel -Meta $Data.Meta
    $cards = ($Data.PerfSummary | ForEach-Object {
        $p = $_
        $deltaRow = if ($p.HasComparison) {
            "<div class=`"delta-row`">$(Get-ArrowHtml -Delta ($p.Current - $p.Previous)) <span>$cmpLabel 대비 (이전 $(Format-Number $p.Previous)$($p.Unit))</span></div>"
        } else {
            "<div class=`"delta-row`"><span style=`"color:var(--muted);`">비교 없음</span></div>"
        }
        @"
<div class="card kpi-card">
  <div class="label">$($p.Label)</div>
  <div class="value">$(Format-Number $p.Current)<span class="unit">$($p.Unit)</span></div>
  $deltaRow
</div>
"@
    }) -join ""
    $desc = if ($Data.Meta.CompareEnabled) { "최근 인프라 성능 요약 ($cmpLabel 대비)" } else { "최근 인프라 성능 요약 (비교 없음)" }
    $head = Build-SectionHead -Icon "Σ" -Title "Executive Summary" -Desc $desc -Anchor "exec"
    return "<section>$head<div class=`"grid3`">$cards</div></section>"
}

function Build-InventorySection {
    param($Data)
    $icons = @{ "vCenter" = "🌐"; "데이터센터" = "🏢"; "클러스터" = "🧩"; "ESXi 호스트" = "🖥️"; "가상머신" = "🧱" }
    $cards = ($Data.InventoryCounts | ForEach-Object {
        $inv = $_
        $icon = if ($icons.ContainsKey($inv.Label)) { $icons[$inv.Label] } else { "•" }
        $srcTag = if ($inv.PSObject.Properties.Name -contains "CompareSource" -and $inv.CompareSource -eq "metric") {
            " <span style=`"color:var(--mint-dark);font-size:10.5px;`">(실측)</span>"
        } else { "" }
        $deltaRow = if ($inv.HasComparison) {
            "<div class=`"delta-row`">$(Get-ArrowHtml -Delta $inv.Delta) <span>이전 $($inv.Previous.ToString("N0")) → 변화율 $(Format-Number $inv.DeltaPct)%$srcTag</span></div>"
        } else {
            "<div class=`"delta-row`"><span style=`"color:var(--muted);`">비교 없음</span></div>"
        }
        $powerRow = ""
        if ($inv.PSObject.Properties.Name -contains "PoweredOnCount") {
            $powerRow = "<div style=`"font-size:11.5px;color:var(--text2);margin-top:6px;`">🟢 켜짐 $($inv.PoweredOnCount.ToString("N0"))대 &nbsp;·&nbsp; ⚪ 꺼짐 $($inv.PoweredOffCount.ToString("N0"))대</div>"
        }
        @"
<div class="card kpi-card">
  <div class="label">$icon $($inv.Label)</div>
  <div class="value">$($inv.Current.ToString("N0"))<span class="unit">대</span></div>
  $deltaRow
  $powerRow
</div>
"@
    }) -join ""
    $head = Build-SectionHead -Icon "📊" -Title "리소스 현황 (수량 변화)" -Desc "vCenter / 데이터센터 / 클러스터 / 호스트 / VM 수량" -Anchor "inventory"
    return "<section>$head<div class=`"grid3`">$cards</div></section>"
}

function Build-ClusterSection {
    param($Data)
    $cmpLabel = Get-CompareDaysLabel -Meta $Data.Meta
    $cards = ($Data.Clusters | ForEach-Object {
        $cm = $_
        $cpuSt = Get-StatusFromPct -Value $cm.CpuPct -Warning $Threshold.cpu_warning -Critical $Threshold.cpu_critical
        $memSt = Get-StatusFromPct -Value $cm.MemPct -Warning $Threshold.mem_warning -Critical $Threshold.mem_critical
        $stoSt = Get-StatusFromPct -Value $cm.StoragePct -Warning $Threshold.storage_warning -Critical $Threshold.storage_critical
        $contSt = Get-StatusFromPct -Value $cm.CpuContentionPct -Warning $Threshold.cpu_contention_warning -Critical $Threshold.cpu_contention_critical

        $cpuDelta = if ($cm.HasComparison) { " $(Get-ArrowHtml -Delta ($cm.CpuPct - $cm.PrevCpuPct))" } else { "" }
        $memDelta = if ($cm.HasComparison) { " $(Get-ArrowHtml -Delta ($cm.MemPct - $cm.PrevMemPct))" } else { "" }
        $stoDelta = if ($cm.HasComparison) { " $(Get-ArrowHtml -Delta ($cm.StoragePct - $cm.PrevStoragePct))" } else { "" }
        $contDelta = if ($cm.HasComparison) { " $(Get-ArrowHtml -Delta ($cm.CpuContentionPct - $cm.PrevCpuContentionPct))" } else { "" }
        $cmpNote = if ($cm.HasComparison) { "<div style=`"font-size:11px;color:var(--muted);margin-top:8px;`">$cmpLabel 대비</div>" } else { "" }

        @"
<div class="card cluster-card">
  <div class="ch">
    <div><div class="name">$($cm.Name)</div><div class="dc">$($cm.Datacenter) · 호스트 $($cm.HostCount)대 · VM $($cm.VmCount)대</div></div>
    $(Get-BadgeHtml -Status $cm.Status)
  </div>

  <div class="metric-row">
    <div class="mrow-top"><span class="mlabel">CPU</span><span class="mval">$(Format-Number $cm.CpuUsedGhz) / $(Format-Number $cm.CpuTotalGhz) GHz &nbsp;($($cm.CpuPct)%)$cpuDelta</span></div>
    $(Get-BarHtml -Pct $cm.CpuPct -Status $cpuSt)
  </div>
  <div class="metric-row">
    <div class="mrow-top"><span class="mlabel">Memory</span><span class="mval">$(Format-Number $cm.MemUsedGb) / $(Format-Number $cm.MemTotalGb) GB &nbsp;($($cm.MemPct)%)$memDelta</span></div>
    $(Get-BarHtml -Pct $cm.MemPct -Status $memSt)
  </div>
  <div class="metric-row">
    <div class="mrow-top"><span class="mlabel">Storage</span><span class="mval">$(Format-Number $cm.StorageUsedTb 2) / $(Format-Number $cm.StorageTotalTb 2) TB &nbsp;($($cm.StoragePct)%)$stoDelta</span></div>
    $(Get-BarHtml -Pct $cm.StoragePct -Status $stoSt)
  </div>

  <div class="sub-stats">
    <div class="sub-stat">CPU 경합(Ready)<b style="color:#$($StatusColor[$contSt].fg)">$($cm.CpuContentionPct)%</b>$contDelta</div>
  </div>
  $cmpNote
</div>
"@
    }) -join ""

    $desc = if ($Data.Meta.CompareEnabled) { "CPU / Memory / Storage 실사용량·비율, CPU 경합률 ($cmpLabel 대비)" } else { "CPU / Memory / Storage 실사용량·비율, CPU 경합률" }
    $head = Build-SectionHead -Icon "🧩" -Title "클러스터별 성능 현황" -Desc $desc -Anchor "cluster"
    $legend = @"
<div class="legend">
  <span><i style="background:var(--mint-dark)"></i>정상(&lt;70%)</span>
  <span><i style="background:var(--peach-dark)"></i>주의(70~85%)</span>
  <span><i style="background:var(--coral-dark)"></i>위험(≥85% 또는 경합 ≥10%)</span>
</div>
"@
    return "<section>$head<div class=`"grid3`">$cards</div>$legend</section>"
}

function Build-DatastoreSection {
    param($Data)
    $cmpLabel = Get-CompareDaysLabel -Meta $Data.Meta
    $rows = $Data.DatastoreInfo
    $anyComparison = [bool]($rows | Where-Object { $_.HasComparison } | Select-Object -First 1)
    $desc = if ($anyComparison) { "데이터스토어 용량/사용량 — $cmpLabel 대비 증감" } else { "데이터스토어 용량/사용량" }
    $head = Build-SectionHead -Icon "💾" -Title "데이터스토어 현황" -Desc $desc -Anchor "datastore"

    $rowsHtml = ($rows | ForEach-Object {
        $d = $_
        $usedPct = if ($d.CapacityGb -gt 0) { [Math]::Round($d.UsedGb / $d.CapacityGb * 100, 1) } else { 0 }
        $freePct = if ($d.CapacityGb -gt 0) { [Math]::Round($d.FreeGb / $d.CapacityGb * 100, 1) } else { 0 }
        $prevCell = if ($d.HasComparison) { "$(Format-Number $d.PrevUsedGb) GB" } else { "<span style=`"color:var(--muted);`">비교 없음</span>" }
        $deltaCell = if ($d.HasComparison) { Get-ArrowHtml -Delta $d.DeltaUsedGb } else { "<span style=`"color:var(--muted);`">비교 없음</span>" }
        "<tr><td>$($d.Name)</td><td class=`"num`">$(Format-Number $d.CapacityGb) GB</td><td class=`"num`">$(Format-Number $d.UsedGb) GB ($usedPct%)</td><td class=`"num`">$prevCell</td><td class=`"num`">$deltaCell</td><td class=`"num`">$(Format-Number $d.FreeGb) GB ($freePct%)</td></tr>"
    }) -join ""
    if (-not $rowsHtml) {
        $rowsHtml = "<tr><td colspan=`"6`" style=`"text-align:center;color:var(--muted);padding:24px;`">데이터스토어 정보가 없습니다</td></tr>"
    }

    return @"
<section>$head
<div class="table-card">
  <div class="table-toolbar">
    <input class="search-box" id="dsSearch" placeholder="데이터스토어 검색..." onkeyup="filterTable('dsSearch','dsTable')">
    <span class="count" id="dsTable-count">$(@($rows).Count) 행 표시</span>
  </div>
  <div class="scroll-y">
  <table id="dsTable">
    <thead><tr><th>데이터스토어</th><th>총량</th><th>현재 사용량</th><th>이전 사용량</th><th>증감</th><th>잔여 용량</th></tr></thead>
    <tbody>$rowsHtml</tbody>
  </table>
  </div>
</div>
</section>
"@
}

function Build-FullWidthTableCard {
    param([string]$Title, [string]$CountLabel, [string]$TableId, [string]$HeaderHtml, [string]$RowsHtml)
    return @"
<div class="card" style="padding:0;margin-bottom:18px;">
  <div style="padding:18px 20px 4px;font-weight:800;font-size:14.5px;">$Title</div>
  <div class="table-toolbar"><span class="count">$CountLabel</span></div>
  <div class="scroll-y" style="max-height:480px;">
  <table id="$TableId"><thead><tr>$HeaderHtml</tr></thead><tbody>$RowsHtml</tbody></table>
  </div>
</div>
"@
}

function Build-HostsSection {
    param($Data)
    $head = Build-SectionHead -Icon "🖥️" -Title "ESXi 호스트 Top 리스트" `
        -Desc "IP 주소 제외 · CPU 사용률 / MEM 사용률 / CPU 경합률 각각 상위 10대" -Anchor "hosts"

    $cpuTop = @($Data.Hosts | Sort-Object -Property CpuPct -Descending | Select-Object -First 10)
    $memTop = @($Data.Hosts | Sort-Object -Property MemPct -Descending | Select-Object -First 10)
    $contTop = @($Data.Hosts | Sort-Object -Property CpuContentionPct -Descending | Select-Object -First 10)

    $cpuRows = ""; $i = 0
    foreach ($h in $cpuTop) {
        $i++
        $st = Get-StatusFromPct -Value $h.CpuPct -Warning $Threshold.cpu_warning -Critical $Threshold.cpu_critical
        $cpuRows += "<tr><td>$i</td><td>$($h.Name)</td><td>$($h.Cluster)</td><td class=`"num`">$($h.CpuPct)%</td><td>$(Get-BadgeHtml -Status $st)</td></tr>"
    }
    $memRows = ""; $i = 0
    foreach ($h in $memTop) {
        $i++
        $st = Get-StatusFromPct -Value $h.MemPct -Warning $Threshold.mem_warning -Critical $Threshold.mem_critical
        $memRows += "<tr><td>$i</td><td>$($h.Name)</td><td>$($h.Cluster)</td><td class=`"num`">$($h.MemPct)%</td><td>$(Get-BadgeHtml -Status $st)</td></tr>"
    }
    $contRows = ""; $i = 0
    foreach ($h in $contTop) {
        $i++
        $st = Get-StatusFromPct -Value $h.CpuContentionPct -Warning $Threshold.cpu_contention_warning -Critical $Threshold.cpu_contention_critical
        $contRows += "<tr><td>$i</td><td>$($h.Name)</td><td>$($h.Cluster)</td><td class=`"num`">$($h.CpuContentionPct)%</td><td>$(Get-BadgeHtml -Status $st)</td></tr>"
    }

    $cpuCard = Build-FullWidthTableCard -Title "CPU 사용률 Top10" -CountLabel "상위 $($cpuTop.Count)대" `
        -TableId "hostCpuTop" -HeaderHtml "<th>#</th><th>호스트명</th><th>클러스터</th><th>CPU 사용률</th><th>상태</th>" -RowsHtml $cpuRows
    $memCard = Build-FullWidthTableCard -Title "MEM 사용률 Top10" -CountLabel "상위 $($memTop.Count)대" `
        -TableId "hostMemTop" -HeaderHtml "<th>#</th><th>호스트명</th><th>클러스터</th><th>MEM 사용률</th><th>상태</th>" -RowsHtml $memRows
    $contCard = Build-FullWidthTableCard -Title "CPU 경합률 Top10" -CountLabel "상위 $($contTop.Count)대" `
        -TableId "hostContTop" -HeaderHtml "<th>#</th><th>호스트명</th><th>클러스터</th><th>CPU 경합률</th><th>상태</th>" -RowsHtml $contRows

    return "<section>$head$cpuCard$memCard$contCard</section>"
}

function Build-VmTopListsSection {
    param($Data)
    $head = Build-SectionHead -Icon "🔥" -Title "VM Top 리스트" `
        -Desc "vCPU 사용률 / CPU 경합(Ready) / 가상디스크 레이턴시 각각 상위 10대" -Anchor "vm-top"

    $cpuRows = ""; $i = 0
    foreach ($v in $Data.TopCpuVMs) {
        $i++
        $st = Get-StatusFromPct -Value $v.CpuUsagePct -Warning $Threshold.cpu_warning -Critical $Threshold.cpu_critical
        $cpuRows += "<tr><td>$i</td><td>$($v.Name)</td><td>$($v.Cluster)</td><td>$($v.Host)</td><td class=`"num`">$($v.VcpuCount)</td><td class=`"num`">$($v.CpuUsagePct)%</td><td>$(Get-BadgeHtml -Status $st)</td></tr>"
    }
    $readyRows = ""; $i = 0
    foreach ($v in $Data.TopReadyVMs) {
        $i++
        $st = Get-StatusFromPct -Value $v.CpuReadyPct -Warning $Threshold.cpu_contention_warning -Critical $Threshold.cpu_contention_critical
        $readyRows += "<tr><td>$i</td><td>$($v.Name)</td><td>$($v.Cluster)</td><td>$($v.Host)</td><td class=`"num`">$($v.VcpuCount)</td><td class=`"num`">$($v.CpuReadyPct)%</td><td>$(Get-BadgeHtml -Status $st)</td></tr>"
    }
    $diskRows = ""; $i = 0
    foreach ($v in $Data.DiskLatencyVMs) {
        $i++
        $maxLat = [Math]::Max($v.ReadLatencyMs, $v.WriteLatencyMs)
        $st = Get-StatusFromPct -Value $maxLat -Warning $Threshold.disk_latency_warning_ms -Critical $Threshold.disk_latency_critical_ms
        $diskRows += "<tr><td>$i</td><td>$($v.Name)</td><td>$($v.Cluster)</td><td>$($v.Datastore)</td><td class=`"num`">$($v.ReadLatencyMs) ms</td><td class=`"num`">$($v.WriteLatencyMs) ms</td><td>$(Get-BadgeHtml -Status $st)</td></tr>"
    }

    $cpuCard = Build-FullWidthTableCard -Title "vCPU 사용률 Top10" -CountLabel "상위 $($Data.TopCpuVMs.Count)건" `
        -TableId "vmCpuTop" -HeaderHtml "<th>#</th><th>VM명</th><th>클러스터</th><th>호스트</th><th>vCPU</th><th>사용률</th><th>상태</th>" -RowsHtml $cpuRows
    $readyCard = Build-FullWidthTableCard -Title "CPU 경합(Ready) Top10" -CountLabel "상위 $($Data.TopReadyVMs.Count)건" `
        -TableId "vmReadyTop" -HeaderHtml "<th>#</th><th>VM명</th><th>클러스터</th><th>호스트</th><th>vCPU</th><th>Ready %</th><th>상태</th>" -RowsHtml $readyRows
    $diskCard = Build-FullWidthTableCard -Title "가상디스크 레이턴시 Top10" -CountLabel "상위 $($Data.DiskLatencyVMs.Count)건" `
        -TableId "vmDiskTop" -HeaderHtml "<th>#</th><th>VM명</th><th>클러스터</th><th>데이터스토어</th><th>Read</th><th>Write</th><th>상태</th>" -RowsHtml $diskRows

    return "<section>$head$cpuCard$readyCard$diskCard</section>"
}

function Build-OpsNotesSection {
    param($Data)
    $head = Build-SectionHead -Icon "🛠️" -Title "운영 참고사항" -Desc "1주 이상 보존된 VM 스냅샷 — 스토리지 점유 및 성능 영향 점검 필요" -Anchor "ops"

    $rows = ($Data.SnapshotAlerts | ForEach-Object {
        $s = $_
        $st = if ($s.OldestSnapshotAgeDays -ge 30) { "critical" } else { "warning" }
        "<tr><td>$($s.Name)</td><td>$($s.Cluster)</td><td class=`"num`">$($s.SnapshotCount)</td><td class=`"num`">$($s.OldestSnapshotAgeDays)일</td><td class=`"num`">$(Format-Number $s.TotalSnapshotSizeGb) GB</td><td>$(Get-BadgeHtml -Status $st)</td></tr>"
    }) -join ""
    if (-not $rows) {
        $rows = "<tr><td colspan=`"6`" style=`"text-align:center;color:var(--muted);padding:24px;`">7일 이상 보존된 스냅샷이 없습니다</td></tr>"
    }

    return @"
<section>$head
<div class="table-card">
  <div class="table-toolbar">
    <input class="search-box" id="snapSearch" placeholder="VM/클러스터 검색..." onkeyup="filterTable('snapSearch','snapTable')">
    <span class="count" id="snapTable-count">$($Data.SnapshotAlerts.Count) 행 표시</span>
  </div>
  <div class="scroll-y">
  <table id="snapTable">
    <thead><tr><th>VM명</th><th>클러스터</th><th>스냅샷 수</th><th>최장 보존기간</th><th>총 용량</th><th>상태</th></tr></thead>
    <tbody>$rows</tbody>
  </table>
  </div>
</div>
</section>
"@
}

function Build-BreakdownCard {
    param([string]$Title, $Rows, [int]$Total)
    $rowsHtml = ($Rows | ForEach-Object {
        $barPct = [Math]::Max(2, $_.Pct)
        "<div class=`"bd-row`"><div class=`"bd-label`" title=`"$($_.Label)`">$($_.Label)</div><div class=`"bd-bar-track`"><div class=`"bd-bar-fill`" style=`"width:$($barPct)%;`"></div></div><div class=`"bd-count`">$($_.Count)대 <span class=`"bd-pct`">($($_.Pct)%)</span></div></div>"
    }) -join ""
    if (-not $rowsHtml) {
        $rowsHtml = "<div style=`"color:var(--muted);font-size:12.5px;`">데이터가 없습니다</div>"
    }
    return @"
<div class="card">
  <div class="bd-title">$Title<span class="bd-total">전체 $Total 대</span></div>
  $rowsHtml
</div>
"@
}

function Build-VmInventorySection {
    param($Data)
    $head = Build-SectionHead -Icon "🧱" -Title "VM 인벤토리 요약" `
        -Desc "Guest OS / VMware Tools 버전 / 가상 HW버전 / vCPU 구간별 VM 수량 분포" -Anchor "vm-inv"

    $total = $Data.VmBreakdown.Total
    $osCard = Build-BreakdownCard -Title "Guest OS별 VM 수량" -Rows $Data.VmBreakdown.OsRows -Total $total
    $toolsCard = Build-BreakdownCard -Title "VMware Tools 버전별 VM 수량" -Rows $Data.VmBreakdown.ToolsRows -Total $total
    $hwCard = Build-BreakdownCard -Title "Virtual Hardware 버전별 VM 수량" -Rows $Data.VmBreakdown.HwRows -Total $total
    $vcpuCard = Build-BreakdownCard -Title "vCPU 구간별 VM 수량" -Rows $Data.VmBreakdown.VcpuRows -Total $total

    return "<section>$head<div class=`"grid2`">$osCard$toolsCard$hwCard$vcpuCard</div></section>"
}

function Build-ThickDiskSection {
    param($Data)
    $head = Build-SectionHead -Icon "🟦" -Title "Thick 프로비저닝 디스크 목록" `
        -Desc "디스크 유형이 Thick(Eager/Lazy Zeroed)인 가상 디스크 목록" -Anchor "vm-thick"

    $rows = ""
    foreach ($v in $Data.VmInventory) {
        foreach ($d in $v.Disks) {
            if ($d.ProvisioningKind -eq "Thick") {
                $rows += "<tr><td>$($v.Name)</td><td>$($v.Cluster)</td><td>$($v.Host)</td><td>$($d.Label)</td><td class=`"num`">$(Format-Number $d.CapacityGb 0) GB</td><td>$($d.Datastore)</td></tr>"
            }
        }
    }
    $count = ([regex]::Matches($rows, "<tr>")).Count
    if (-not $rows) {
        $rows = "<tr><td colspan=`"6`" style=`"text-align:center;color:var(--muted);padding:24px;`">Thick 프로비저닝 디스크가 없습니다</td></tr>"
    }

    return @"
<section>$head
<div class="table-card">
  <div class="table-toolbar">
    <input class="search-box" id="thickSearch" placeholder="VM/클러스터 검색..." onkeyup="filterTable('thickSearch','thickTable')">
    <span class="count" id="thickTable-count">$count 행 표시</span>
  </div>
  <div class="scroll-y">
  <table id="thickTable">
    <thead><tr><th>VM명</th><th>클러스터</th><th>ESXi Host</th><th>디스크</th><th>용량</th><th>데이터스토어</th></tr></thead>
    <tbody>$rows</tbody>
  </table>
  </div>
</div>
</section>
"@
}

function Build-SharedDiskSection {
    param($Data)
    $head = Build-SectionHead -Icon "🟧" -Title "공유 디스크 목록" `
        -Desc "Shared(멀티라이터 등) 가상 디스크 목록" -Anchor "vm-shared"

    $rows = ""
    foreach ($v in $Data.VmInventory) {
        foreach ($d in $v.Disks) {
            if ($d.Shared) {
                $rows += "<tr><td>$($v.Name)</td><td>$($v.Cluster)</td><td>$($v.Host)</td><td>$($d.Label)</td><td class=`"num`">$(Format-Number $d.CapacityGb 0) GB</td><td>$($d.Datastore)</td></tr>"
            }
        }
    }
    $count = ([regex]::Matches($rows, "<tr>")).Count
    if (-not $rows) {
        $rows = "<tr><td colspan=`"6`" style=`"text-align:center;color:var(--muted);padding:24px;`">공유 디스크가 없습니다</td></tr>"
    }

    return @"
<section>$head
<div class="table-card">
  <div class="table-toolbar">
    <input class="search-box" id="sharedSearch" placeholder="VM/클러스터 검색..." onkeyup="filterTable('sharedSearch','sharedTable')">
    <span class="count" id="sharedTable-count">$count 행 표시</span>
  </div>
  <div class="scroll-y">
  <table id="sharedTable">
    <thead><tr><th>VM명</th><th>클러스터</th><th>ESXi Host</th><th>디스크</th><th>용량</th><th>데이터스토어</th></tr></thead>
    <tbody>$rows</tbody>
  </table>
  </div>
</div>
</section>
"@
}

function Get-StatusCounts {
    param($Values, [double]$Warning, [double]$Critical)
    $normal = 0; $warn = 0; $crit = 0
    foreach ($v in $Values) {
        $st = Get-StatusFromPct -Value $v -Warning $Warning -Critical $Critical
        if ($st -eq "critical") { $crit++ } elseif ($st -eq "warning") { $warn++ } else { $normal++ }
    }
    return [PSCustomObject]@{ Normal = $normal; Warning = $warn; Critical = $crit; Total = ($normal + $warn + $crit) }
}

function Build-StatusBreakdownCard {
    param([string]$Title, $Counts, $RangeLabel)
    $total = [Math]::Max(1, $Counts.Total)
    $nPct = [Math]::Round($Counts.Normal / $total * 100, 1)
    $wPct = [Math]::Round($Counts.Warning / $total * 100, 1)
    $cPct = [Math]::Round($Counts.Critical / $total * 100, 1)
    return @"
<div class="card">
  <div class="bd-title">$Title<span class="bd-total">전체 $($Counts.Total)대</span></div>
  <div class="stacked-bar">
    <div class="seg normal" style="width:$($nPct)%;"></div>
    <div class="seg warning" style="width:$($wPct)%;"></div>
    <div class="seg critical" style="width:$($cPct)%;"></div>
  </div>
  <div class="status-legend-row">
    <span><span class="dot normal"></span>정상 $($Counts.Normal)대 <span style="color:var(--muted);">($($RangeLabel.Normal))</span></span>
    <span><span class="dot warning"></span>주의 $($Counts.Warning)대 <span style="color:var(--muted);">($($RangeLabel.Warning))</span></span>
    <span><span class="dot critical"></span>위험 $($Counts.Critical)대 <span style="color:var(--muted);">($($RangeLabel.Critical))</span></span>
  </div>
</div>
"@
}

function Build-VmPerformanceSection {
    param($Data)
    $head = Build-SectionHead -Icon "📈" -Title "VM 성능정보 요약" `
        -Desc "CPU 사용률 / CPU 경합(Ready) / MEM 사용률 / 가상디스크 레이턴시 — 등급별 VM 수량" -Anchor "vm-perf"

    $cpuCounts = Get-StatusCounts -Values ($Data.VmPerformance | ForEach-Object { $_.CpuUsagePct }) `
        -Warning $Threshold.cpu_warning -Critical $Threshold.cpu_critical
    $readyCounts = Get-StatusCounts -Values ($Data.VmPerformance | ForEach-Object { $_.CpuReadyPct }) `
        -Warning $Threshold.cpu_contention_warning -Critical $Threshold.cpu_contention_critical
    $memCounts = Get-StatusCounts -Values ($Data.VmPerformance | ForEach-Object { $_.MemUsagePct }) `
        -Warning $Threshold.mem_warning -Critical $Threshold.mem_critical
    $diskCounts = Get-StatusCounts -Values ($Data.VmPerformance | ForEach-Object { $_.DiskLatencyMs }) `
        -Warning $Threshold.disk_latency_warning_ms -Critical $Threshold.disk_latency_critical_ms

    $cpuRange = Get-RangeLabel -Warning $Threshold.cpu_warning -Critical $Threshold.cpu_critical -Unit "%"
    $readyRange = Get-RangeLabel -Warning $Threshold.cpu_contention_warning -Critical $Threshold.cpu_contention_critical -Unit "%"
    $memRange = Get-RangeLabel -Warning $Threshold.mem_warning -Critical $Threshold.mem_critical -Unit "%"
    $diskRange = Get-RangeLabel -Warning $Threshold.disk_latency_warning_ms -Critical $Threshold.disk_latency_critical_ms -Unit "ms"

    $c1 = Build-StatusBreakdownCard -Title "CPU 사용률" -Counts $cpuCounts -RangeLabel $cpuRange
    $c2 = Build-StatusBreakdownCard -Title "CPU 경합(Ready)" -Counts $readyCounts -RangeLabel $readyRange
    $c3 = Build-StatusBreakdownCard -Title "MEM 사용률" -Counts $memCounts -RangeLabel $memRange
    $c4 = Build-StatusBreakdownCard -Title "가상디스크 레이턴시" -Counts $diskCounts -RangeLabel $diskRange

    return "<section>$head<div class=`"grid4`">$c1$c2$c3$c4</div></section>"
}

function New-VCFOpsHtmlReport {
    [CmdletBinding()]
    param([Parameter(Mandatory)]$Data)

    $bodyParts = @(
        (Build-NavSection)
        '<div class="wrap">'
        (Build-HeroSection -Data $Data)
        (Build-ExecSummarySection -Data $Data)
        (Build-InventorySection -Data $Data)
        (Build-ClusterSection -Data $Data)
        (Build-DatastoreSection -Data $Data)
        (Build-HostsSection -Data $Data)
        (Build-VmTopListsSection -Data $Data)
        (Build-OpsNotesSection -Data $Data)
        (Build-VmInventorySection -Data $Data)
        (Build-ThickDiskSection -Data $Data)
        (Build-SharedDiskSection -Data $Data)
        (Build-VmPerformanceSection -Data $Data)
        "<div class=`"foot`">$($Data.Meta.GeneratedBy) · 생성 시각 $(Get-Date -Format 'yyyy-MM-dd HH:mm')</div>"
        '</div>'
    )
    $body = $bodyParts -join ""
    $css = Get-CssBlock
    $js = Get-JsBlock
    $title = "$($Data.Meta.CustomerName) 가상화 인프라 운영 현황 리포트"

    return @"
<!DOCTYPE html>
<html lang="ko">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>$title</title>
<link rel="stylesheet" href="https://cdn.jsdelivr.net/gh/orioncactus/pretendard@v1.3.9/dist/web/static/pretendard.css">
<style>$css</style>
</head>
<body>
$body
<script>$js</script>
</body>
</html>
"@
}

Export-ModuleMember -Function New-VCFOpsHtmlReport
