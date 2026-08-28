<#
    Script Name: vSphere Audit Reporter (Standalone)
    Description: Generates an HTML report from existing audit logs without running new audits
                 or connecting to vCenter. Log type (vCenter/ESXi/VM) is auto-detected from
                 each log file's own banner text.
    Author: Gemini
#>

# ---------------------------------------------------------------------------
# 1. Select Audit Folder (Interactive)
# ---------------------------------------------------------------------------
function Select-Audit-Folder {
    Write-Host "`n[1/3] Select Audit Log Folder..." -ForegroundColor Cyan

    # Get subdirectories
    $subFolders = Get-ChildItem -Path $PSScriptRoot -Directory | Sort-Object LastWriteTime -Descending

    if ($subFolders.Count -eq 0) {
        Write-Host "  ! No subfolders found in current directory." -ForegroundColor Red
        exit
    }

    # List folders
    Write-Host "  Available Folders:" -ForegroundColor Yellow
    for ($i = 0; $i -lt $subFolders.Count; $i++) {
        Write-Host "    [$($i+1)] $($subFolders[$i].Name)  (Last Modified: $($subFolders[$i].LastWriteTime))"
    }

    # User Input
    while ($true) {
        $selection = Read-Host "  > Enter the number of the folder to process"
        if ($selection -match "^\d+$" -and [int]$selection -gt 0 -and [int]$selection -le $subFolders.Count) {
            $selectedFolder = $subFolders[[int]$selection - 1]
            Write-Host "  - Selected: $($selectedFolder.FullName)" -ForegroundColor Green
            return $selectedFolder.FullName
        } else {
            Write-Host "  ! Invalid selection. Please try again." -ForegroundColor Red
        }
    }
}

# ---------------------------------------------------------------------------
# 2. Discover & Classify Log Files (No vCenter connection required)
# ---------------------------------------------------------------------------
# Each audit log's first lines carry a banner identifying what kind of
# object it audited, e.g.:
#   "VMware vCenter ... Security Settings Audit Utility ..."       -> vCenter
#   "VMware ESX Host Security Settings Audit Utility ..."          -> ESXi
#   "VMware Virtual Machine Security Settings Audit Utility ..."   -> VM
# We read that banner directly instead of querying vCenter for inventory.
function Discover-LogFiles {
    param ($TargetDir)
    Write-Host "`n[2/3] Discovering and classifying log files..." -ForegroundColor Cyan

    $files = Get-ChildItem -Path $TargetDir -Filter "*.txt" -File | Sort-Object Name
    if ($files.Count -eq 0) {
        Write-Host "  ! No .txt log files found in the selected folder." -ForegroundColor Red
        exit
    }

    $classified = @{ vCenter = @(); ESXi = @(); VM = @() }

    foreach ($file in $files) {
        # Only need the first few lines to find the banner / "Audit of X started" line
        $headLines = Get-Content -Path $file.FullName -TotalCount 5
        $headerText = $headLines -join " "

        $type = $null
        if ($headerText -match "VMware vCenter") { $type = "vCenter" }
        elseif ($headerText -match "ESX Host") { $type = "ESXi" }
        elseif ($headerText -match "Virtual Machine") { $type = "VM" }

        if (-not $type) {
            Write-Host "  ! Skipped (unrecognized audit type): $($file.Name)" -ForegroundColor Yellow
            continue
        }

        # Prefer the object name reported inside the log ("Audit of <name> started"),
        # fall back to the file name if that line isn't found.
        $objName = [System.IO.Path]::GetFileNameWithoutExtension($file.Name)
        $nameMatch = $headLines | Select-String -Pattern "Audit of (\S+) started"
        if ($nameMatch) {
            $objName = $nameMatch.Matches[0].Groups[1].Value
        }

        $classified[$type] += [PSCustomObject]@{ Name = $objName; Path = $file.FullName }
    }

    Write-Host "  - Classified: $($classified.vCenter.Count) vCenter, $($classified.ESXi.Count) ESXi, $($classified.VM.Count) VM log(s)." -ForegroundColor Gray
    return $classified
}

# ---------------------------------------------------------------------------
# 3. Parse Logs
# ---------------------------------------------------------------------------
function Parse-Logs {
    param ($LogFiles)
    Write-Host "`n[3/3] Analyzing logs and creating report..." -ForegroundColor Cyan

    $results = @{
        Summary = @{ TotalPass = 0; TotalFail = 0; TotalInfo = 0 }
        Data = @{ vCenter = @(); ESXi = @(); VM = @() }
    }

    foreach ($type in $LogFiles.Keys) {
        foreach ($fileEntry in $LogFiles[$type]) {
            $objData = @{ Name = $fileEntry.Name; Type = $type; Pass = 0; Fail = 0; Info = 0; Details = @() }

            $content = Get-Content $fileEntry.Path
            foreach ($line in $content) {
                if ($line -match "\[(PASS|FAIL|INFO|WARNING|ERROR)\]") {
                    $match = $matches[1]
                    switch ($match) {
                        "PASS" { $objData.Pass++; $results.Summary.TotalPass++ }
                        "FAIL" { $objData.Fail++; $results.Summary.TotalFail++ }
                        "INFO"    { $objData.Info++; $results.Summary.TotalInfo++ }
                        "WARNING" { $objData.Info++; $results.Summary.TotalInfo++ }
                        "ERROR"   { $objData.Fail++; $results.Summary.TotalFail++ }
                    }

                    $cssClass = switch ($match) { "PASS"{"status-pass"} "FAIL"{"status-fail"} default{"status-info"} }
                    $objData.Details += @{ Status = $match; Message = ($line -replace "\[.*?\]\s*", ""); CssClass = $cssClass }
                }
            }
            $results.Data[$type] += $objData
        }
    }
    return $results
}

# ---------------------------------------------------------------------------
# 4. Generate HTML
# ---------------------------------------------------------------------------
function Generate-Html {
    param ($Results, $FilePath)
    $jsonData = $Results | ConvertTo-Json -Depth 10 -Compress
    $date = Get-Date -Format "yyyy-MM-dd HH:mm:ss"

    $html = @"
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<title>vSphere Security Audit Report</title>
<style>
:root {
  --bg:#f1f5f9; --bg-alt:#e2e8f0; --card:#ffffff; --border:#e2e8f0;
  --text:#1e293b; --text-muted:#64748b;
  --pass:#16a34a; --pass-bg:#dcfce7;
  --fail:#dc2626; --fail-bg:#fee2e2;
  --info:#0891b2; --info-bg:#cffafe;
  --accent:#2563eb; --radius:10px;
  --shadow:0 1px 3px rgba(0,0,0,0.08), 0 1px 2px rgba(0,0,0,0.06);
}
* { box-sizing: border-box; }
body { margin:0; font-family:'Segoe UI',Roboto,-apple-system,sans-serif; background:var(--bg); color:var(--text); }
.container { max-width:1280px; margin:0 auto; padding:24px 20px 60px; }
.report-header { background:linear-gradient(135deg,#1e293b,#334155); color:#fff; padding:32px 28px; border-radius:var(--radius); margin-bottom:24px; box-shadow:var(--shadow); }
.report-header h1 { margin:0 0 8px; font-size:1.7em; }
.header-meta { color:#cbd5e1; font-size:0.9em; margin-top:4px; }

.dashboard { display:grid; grid-template-columns:repeat(5,1fr); gap:16px; margin-bottom:24px; }
.stat-card { background:var(--card); border-radius:var(--radius); box-shadow:var(--shadow); padding:18px 16px; text-align:center; border-top:4px solid var(--border); }
.stat-card.total{ border-top-color:#64748b; }
.stat-card.pass{ border-top-color:var(--pass); }
.stat-card.fail{ border-top-color:var(--fail); }
.stat-card.info{ border-top-color:var(--info); }
.stat-card.rate{ border-top-color:var(--accent); }
.stat-label { font-size:0.8em; color:var(--text-muted); text-transform:uppercase; letter-spacing:.05em; margin-bottom:6px; }
.stat-value { font-size:2em; font-weight:700; }
.stat-card.pass .stat-value{ color:var(--pass); }
.stat-card.fail .stat-value{ color:var(--fail); }
.stat-card.info .stat-value{ color:var(--info); }
.stat-card.rate .stat-value{ color:var(--accent); }

.toolbar{ display:flex; gap:12px; align-items:center; margin-bottom:20px; flex-wrap:wrap; }
#searchBox{ flex:1; min-width:220px; padding:10px 14px; border:1px solid var(--border); border-radius:8px; font-size:0.95em; }
.type-filters{ display:flex; gap:8px; flex-wrap:wrap; }
.filter-btn{ padding:8px 16px; border:1px solid var(--border); background:var(--card); border-radius:20px; cursor:pointer; font-size:0.85em; color:var(--text-muted); }
.filter-btn.active{ background:var(--accent); color:#fff; border-color:var(--accent); }

.section{ margin-bottom:28px; }
.section-header{ display:flex; align-items:center; justify-content:space-between; margin-bottom:12px; }
.section-title{ font-size:1.2em; font-weight:600; display:flex; align-items:center; gap:8px; }
.type-badge{ background:var(--accent); color:#fff; font-size:0.7em; padding:2px 10px; border-radius:12px; }

table{ width:100%; border-collapse:collapse; background:var(--card); border-radius:var(--radius); overflow:hidden; box-shadow:var(--shadow); }
thead th{ background:var(--bg-alt); padding:12px 14px; text-align:left; font-size:0.8em; text-transform:uppercase; letter-spacing:.03em; color:var(--text-muted); }
tbody td{ padding:12px 14px; border-top:1px solid var(--border); font-size:0.92em; vertical-align:middle; }
tr.obj-row{ cursor:pointer; }
tr.obj-row:hover{ background:#f8fafc; }
.obj-name{ font-weight:600; }
.count-pill{ display:inline-flex; align-items:center; justify-content:center; min-width:34px; padding:3px 8px; border-radius:6px; font-size:0.8em; font-weight:600; margin-right:4px; }
.count-pill.pass{ background:var(--pass-bg); color:var(--pass); }
.count-pill.fail{ background:var(--fail-bg); color:var(--fail); }
.count-pill.info{ background:var(--info-bg); color:var(--info); }
.bar{ width:100px; height:8px; border-radius:4px; overflow:hidden; display:flex; background:var(--border); }
.bar span{ height:100%; }
.b-pass{ background:var(--pass); }
.b-fail{ background:var(--fail); }
.b-info{ background:var(--info); }
.detail-btn{ border:1px solid var(--border); background:var(--card); color:var(--accent); font-weight:600; cursor:pointer; padding:6px 14px; border-radius:6px; font-size:0.85em; }
.detail-row{ display:none; }
.detail-row.open{ display:table-row; }
.detail-wrap{ background:#f8fafc; padding:16px; }
.tabs{ display:flex; gap:8px; margin-bottom:10px; border-bottom:1px solid var(--border); padding-bottom:10px; flex-wrap:wrap; }
.tab-btn{ padding:6px 14px; border-radius:6px; border:1px solid var(--border); background:#fff; cursor:pointer; font-size:0.85em; font-weight:600; color:var(--text-muted); }
.tab-btn.active[data-status="pass"]{ background:var(--pass); border-color:var(--pass); color:#fff; }
.tab-btn.active[data-status="fail"]{ background:var(--fail); border-color:var(--fail); color:#fff; }
.tab-btn.active[data-status="info"]{ background:var(--info); border-color:var(--info); color:#fff; }
.tab-panel{ display:none; max-height:360px; overflow-y:auto; }
.tab-panel.active{ display:block; }
.log-line{ display:flex; gap:10px; padding:7px 4px; border-bottom:1px dashed var(--border); font-family:Consolas,monospace; font-size:0.85em; align-items:flex-start; }
.log-line:last-child{ border-bottom:none; }
.badge{ flex-shrink:0; padding:2px 8px; border-radius:4px; color:#fff; font-size:0.75em; font-weight:700; width:44px; text-align:center; }
.badge.status-pass{ background:var(--pass); }
.badge.status-fail{ background:var(--fail); }
.badge.status-info{ background:var(--info); }
.empty-panel{ color:var(--text-muted); font-size:0.85em; padding:12px 4px; }
.no-results{ text-align:center; color:var(--text-muted); padding:40px; }
@media (max-width:900px){ .dashboard{ grid-template-columns:repeat(2,1fr); } }
</style>
</head>
<body>
<div class="container">
  <header class="report-header">
    <h1>vSphere Security Hardening Audit Report</h1>
    <div class="header-meta">Generated: $date</div>
    <div class="header-meta" id="objCountMeta"></div>
  </header>

  <section class="dashboard">
    <div class="stat-card total"><div class="stat-label">Total Checks</div><div class="stat-value" id="t-total">0</div></div>
    <div class="stat-card pass"><div class="stat-label">PASS</div><div class="stat-value" id="t-pass">0</div></div>
    <div class="stat-card fail"><div class="stat-label">FAIL</div><div class="stat-value" id="t-fail">0</div></div>
    <div class="stat-card info"><div class="stat-label">INFO</div><div class="stat-value" id="t-info">0</div></div>
    <div class="stat-card rate"><div class="stat-label">Pass Rate</div><div class="stat-value" id="t-rate">0%</div></div>
  </section>

  <section class="toolbar">
    <input type="text" id="searchBox" placeholder="Search object name...">
    <div class="type-filters" id="typeFilters"></div>
  </section>

  <div id="content"></div>
</div>

<script>
var data = $jsonData;

var totalPass = data.Summary.TotalPass;
var totalFail = data.Summary.TotalFail;
var totalInfo = data.Summary.TotalInfo;
var totalAll = totalPass + totalFail + totalInfo;
var rate = (totalPass + totalFail) > 0 ? Math.round((totalPass / (totalPass + totalFail)) * 1000) / 10 : 0;

document.getElementById('t-total').textContent = totalAll;
document.getElementById('t-pass').textContent = totalPass;
document.getElementById('t-fail').textContent = totalFail;
document.getElementById('t-info').textContent = totalInfo;
document.getElementById('t-rate').textContent = rate + '%';

var typeOrder = ['vCenter', 'ESXi', 'VM'];
var availableTypes = typeOrder.filter(function (t) {
    return data.Data[t] && data.Data[t].length > 0;
});

var countsText = availableTypes.map(function (t) {
    return t + ': ' + data.Data[t].length;
}).join('   |   ');
document.getElementById('objCountMeta').textContent = 'Objects Audited: ' + countsText;

var currentFilter = 'All';
var currentSearch = '';
var idCounter = 0;

var filtersEl = document.getElementById('typeFilters');

function setFilter(type, btnEl) {
    currentFilter = type;
    var all = filtersEl.querySelectorAll('.filter-btn');
    for (var i = 0; i < all.length; i++) { all[i].classList.remove('active'); }
    btnEl.classList.add('active');
    render();
}

function buildFilters() {
    var allBtn = document.createElement('button');
    allBtn.className = 'filter-btn active';
    allBtn.textContent = 'All';
    allBtn.onclick = function () { setFilter('All', allBtn); };
    filtersEl.appendChild(allBtn);
    availableTypes.forEach(function (t) {
        var btn = document.createElement('button');
        btn.className = 'filter-btn';
        btn.textContent = t;
        btn.onclick = function () { setFilter(t, btn); };
        filtersEl.appendChild(btn);
    });
}

document.getElementById('searchBox').addEventListener('input', function (e) {
    currentSearch = e.target.value.trim().toLowerCase();
    render();
});

function statusLabel(cssClass) {
    if (cssClass === 'status-pass') return 'pass';
    if (cssClass === 'status-fail') return 'fail';
    return 'info';
}

function activateTab(uid, key) {
    var root = document.getElementById('detail-' + uid);
    var btns = root.querySelectorAll('.tab-btn');
    for (var i = 0; i < btns.length; i++) { btns[i].classList.remove('active'); }
    var panels = root.querySelectorAll('.tab-panel');
    for (var j = 0; j < panels.length; j++) { panels[j].classList.remove('active'); }
    var activeBtn = root.querySelector('[data-status="' + key + '"]');
    if (activeBtn) { activeBtn.classList.add('active'); }
    var activePanel = document.getElementById('panel-' + uid + '-' + key);
    if (activePanel) { activePanel.classList.add('active'); }
}

function toggleDetail(uid) {
    var row = document.getElementById('detail-' + uid);
    row.classList.toggle('open');
}

function buildDetailBlock(obj, uid) {
    var groups = { fail: [], pass: [], info: [] };
    obj.Details.forEach(function (d) {
        groups[statusLabel(d.CssClass)].push(d);
    });

    var tabsWrap = document.createElement('div');
    tabsWrap.className = 'tabs';
    var panelWrap = document.createElement('div');
    panelWrap.className = 'panels';

    var order = ['fail', 'pass', 'info'];
    var firstSet = false;
    order.forEach(function (key) {
        var items = groups[key];
        var btn = document.createElement('button');
        btn.className = 'tab-btn';
        btn.setAttribute('data-status', key);
        btn.textContent = key.toUpperCase() + ' (' + items.length + ')';
        btn.onclick = function () { activateTab(uid, key); };
        tabsWrap.appendChild(btn);

        var panel = document.createElement('div');
        panel.className = 'tab-panel';
        panel.id = 'panel-' + uid + '-' + key;

        if (items.length === 0) {
            var empty = document.createElement('div');
            empty.className = 'empty-panel';
            empty.textContent = 'No ' + key.toUpperCase() + ' items.';
            panel.appendChild(empty);
        } else {
            items.forEach(function (d) {
                var line = document.createElement('div');
                line.className = 'log-line';
                var badge = document.createElement('span');
                badge.className = 'badge ' + d.CssClass;
                badge.textContent = d.Status;
                var msg = document.createElement('span');
                msg.textContent = d.Message;
                line.appendChild(badge);
                line.appendChild(msg);
                panel.appendChild(line);
            });
        }
        panelWrap.appendChild(panel);

        if (!firstSet && items.length > 0) {
            btn.classList.add('active');
            panel.classList.add('active');
            firstSet = true;
        }
    });

    if (!firstSet) {
        var firstBtn = tabsWrap.querySelector('.tab-btn');
        var firstPanel = panelWrap.querySelector('.tab-panel');
        if (firstBtn) { firstBtn.classList.add('active'); }
        if (firstPanel) { firstPanel.classList.add('active'); }
    }

    var container = document.createElement('div');
    container.className = 'detail-wrap';
    container.appendChild(tabsWrap);
    container.appendChild(panelWrap);
    return container;
}

function buildObjectRow(obj, type) {
    idCounter++;
    var uid = type + '-' + idCounter;
    var tr = document.createElement('tr');
    tr.className = 'obj-row';
    tr.onclick = function () { toggleDetail(uid); };

    var tdName = document.createElement('td');
    tdName.className = 'obj-name';
    tdName.textContent = obj.Name;

    var tdCounts = document.createElement('td');
    var pillPass = document.createElement('span');
    pillPass.className = 'count-pill pass';
    pillPass.textContent = 'PASS ' + obj.Pass;
    var pillFail = document.createElement('span');
    pillFail.className = 'count-pill fail';
    pillFail.textContent = 'FAIL ' + obj.Fail;
    var pillInfo = document.createElement('span');
    pillInfo.className = 'count-pill info';
    pillInfo.textContent = 'INFO ' + obj.Info;
    tdCounts.appendChild(pillPass);
    tdCounts.appendChild(pillFail);
    tdCounts.appendChild(pillInfo);

    var tdBar = document.createElement('td');
    var total = obj.Pass + obj.Fail + obj.Info;
    var bar = document.createElement('div');
    bar.className = 'bar';
    if (total > 0) {
        var segPass = document.createElement('span');
        segPass.className = 'b-pass';
        segPass.style.width = (obj.Pass / total * 100) + '%';
        var segFail = document.createElement('span');
        segFail.className = 'b-fail';
        segFail.style.width = (obj.Fail / total * 100) + '%';
        var segInfo = document.createElement('span');
        segInfo.className = 'b-info';
        segInfo.style.width = (obj.Info / total * 100) + '%';
        bar.appendChild(segPass);
        bar.appendChild(segFail);
        bar.appendChild(segInfo);
    }
    tdBar.appendChild(bar);

    var tdBtn = document.createElement('td');
    tdBtn.style.width = '90px';
    tdBtn.style.textAlign = 'right';
    var btn = document.createElement('button');
    btn.className = 'detail-btn';
    btn.textContent = 'Details';
    btn.onclick = function (e) { e.stopPropagation(); toggleDetail(uid); };
    tdBtn.appendChild(btn);

    tr.appendChild(tdName);
    tr.appendChild(tdCounts);
    tr.appendChild(tdBar);
    tr.appendChild(tdBtn);

    var detailTr = document.createElement('tr');
    detailTr.className = 'detail-row';
    detailTr.id = 'detail-' + uid;
    var detailTd = document.createElement('td');
    detailTd.colSpan = 4;
    detailTd.appendChild(buildDetailBlock(obj, uid));
    detailTr.appendChild(detailTd);

    return [tr, detailTr];
}

function render() {
    idCounter = 0;
    var content = document.getElementById('content');
    content.innerHTML = '';
    var anyRendered = false;

    var typesToRender = currentFilter === 'All' ? availableTypes : [currentFilter];

    typesToRender.forEach(function (type) {
        var objs = (data.Data[type] || []).filter(function (o) {
            return !currentSearch || o.Name.toLowerCase().indexOf(currentSearch) !== -1;
        });
        if (objs.length === 0) { return; }
        anyRendered = true;

        var section = document.createElement('div');
        section.className = 'section';

        var header = document.createElement('div');
        header.className = 'section-header';
        var title = document.createElement('div');
        title.className = 'section-title';
        var titleText = document.createElement('span');
        titleText.textContent = type + ' Objects';
        var badge = document.createElement('span');
        badge.className = 'type-badge';
        badge.textContent = objs.length;
        title.appendChild(titleText);
        title.appendChild(badge);
        header.appendChild(title);
        section.appendChild(header);

        var table = document.createElement('table');
        var thead = document.createElement('thead');
        var headRow = document.createElement('tr');
        ['Object', 'Status', 'Distribution', ''].forEach(function (h) {
            var th = document.createElement('th');
            th.textContent = h;
            headRow.appendChild(th);
        });
        thead.appendChild(headRow);
        table.appendChild(thead);

        var tbody = document.createElement('tbody');
        objs.forEach(function (obj) {
            var rows = buildObjectRow(obj, type);
            tbody.appendChild(rows[0]);
            tbody.appendChild(rows[1]);
        });
        table.appendChild(tbody);
        section.appendChild(table);

        content.appendChild(section);
    });

    if (!anyRendered) {
        var empty = document.createElement('div');
        empty.className = 'no-results';
        empty.textContent = 'No objects match the current filter/search.';
        content.appendChild(empty);
    }
}

buildFilters();
render();
</script>
</body>
</html>
"@
    $html | Out-File -FilePath $FilePath -Encoding UTF8
    Write-Host "  - HTML Report generated: $FilePath" -ForegroundColor Green
}

# ---------------------------------------------------------------------------
# MAIN EXECUTION
# ---------------------------------------------------------------------------
Write-Host "vSphere Audit Reporter (Standalone - no vCenter connection required)" -ForegroundColor Cyan

# Select Folder
$targetDir = Select-Audit-Folder

# Discover and classify the log files directly from their content
$logFiles = Discover-LogFiles -TargetDir $targetDir

# Process
$data = Parse-Logs -LogFiles $logFiles

# Create an output folder next to this script (not inside the log folder)
$reportFolderName = "Output_" + (Get-Date -Format "yyyyMMdd_HHmmss")
$outputDir = Join-Path $PSScriptRoot $reportFolderName
New-Item -ItemType Directory -Path $outputDir -Force | Out-Null
Write-Host "  - Output folder created: $outputDir" -ForegroundColor Gray

# Save HTML
$htmlPath = Join-Path $outputDir "audit_report.html"
Generate-Html -Results $data -FilePath $htmlPath

Write-Host "`n★ Reporting Completed!" -ForegroundColor Green
Invoke-Item $outputDir