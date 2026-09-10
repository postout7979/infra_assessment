# allinonevmw.ps1 — change notes

## Latest delivery: VMSA PPTX per-category severity table now scoped to vCenter/ESX only (this delivery)

**Request:** in `pptx-reports/generate_security_decks.py`'s VMSA deck, the cover slide's
"Severity Breakdown by Detected Category / Version" table should only calculate/show
**vCenter** and **ESX** rows.

**Why this matters:** a real VMSA environment match CSV has up to 4 distinct `Category`
values - `vCenter` and `ESX` are actual detected/live components, while `Tools` and
`VCF/VVF` are reference-only rows (VMSA advisories expanded from bundle/product version
mapping, not tied to a live-detected version - their own `MatchedAgainst` labels say
"(reference - no live version detected)" and "(reference - 5.x / 9.x only)"). Mixing
those reference rows into a table titled "Detected Category / Version" was misleading, so
the table is now filtered to the two categories that represent an actually-detected
target. The table's header was updated to "...(vCenter / ESX only)" to make the scope
explicit. This does **not** change the KPI row, executive summary, or the Advisory
Overview donut chart - those still reflect all 82 matched advisories across every
category, since the request was specifically about the per-category breakdown table.

**Testing done:** regenerated the VMSA deck against the same real 82-row production CSV
used for the previous bugfix and confirmed via `python-pptx` table inspection and a
LibreOffice+`pdftoppm` render that the table now shows only the `vCenter` and `ESX` rows
(4/6/1/0 and 5/3/1/0 respectively) while the KPI row (Critical 20 / Important-High 44)
and executive summary are unchanged. Also re-ran the existing synthetic sample dataset
(which only ever produces vCenter/ESX categories) to confirm no rows are dropped there.

## Previous delivery: bug fix — VMSA PPTX cover slide showed Critical/Important-High as 0 against real data

**The bug (Python side only — `pptx-reports/generate_security_decks.py`; the PowerShell/HTML
side was already correct and was not touched):** against a real production
`VMSA_Environment_Match_*.csv` (82 rows, confirmed 20 Critical / 44 High / 14 Medium / 4 Low
by direct inspection), the VMSA deck's cover slide showed **"Critical: 0"** and **"Important /
High: 0"** in the KPI row and in the executive-summary sentence, and the severity counts
were wrong on the "Advisory Overview" donut chart and the closing recommendations slide too.

**Root cause:** the counts were built from an exact, case-sensitive string match against the
raw `Severity` column (`sev_counter.get("Critical", 0)`, `sev_counter.get("Important", 0) +
sev_counter.get("High", 0)`, and a literal `["Critical", "Important", "High", "Moderate",
"Medium", "Low"]` lookup list for the donut chart). That happened to work against the
synthetic test data used during development (which used title-case values like `"Critical"`/
`"Important"`), but the real VMSA export used **all-caps** values (`"CRITICAL"`, `"HIGH"`,
`"MEDIUM"`, `"LOW"`) — an exact match against `"Critical"` never matches `"CRITICAL"`, so
every count silently came back 0. The one place that was already correct was the new
"Severity Breakdown by Detected Category / Version" table added in the previous delivery,
because it went through `_sev_bucket_name()`'s case-insensitive normalization instead of a
raw string match — which is why the bug report showed the KPI numbers wrong while that table
(once regenerated with the current script) works correctly.

**The fix:** every severity count on the VMSA cover, overview, and recommendations slides now
goes through the same `_sev_bucket_name()` case-insensitive normalization already used for
the per-category/version breakdown table and already proven correct in the HTML report's
`Get-SeverityBadgeClass` — never a raw exact-string match against the CSV's `Severity`
column. This makes the counts correct regardless of whether the source data uses
`"Critical"`/`"Important"` (title case) or `"CRITICAL"`/`"HIGH"` (all caps), or any mix of
the two. Any severity value that doesn't map to one of the 4 known buckets (Critical/High/
Medium/Low) is still counted and shown on the donut chart rather than silently dropped, just
under its own raw label instead of being folded into a bucket.

**Testing done:** regenerated the VMSA deck against the user's actual real production CSV
(82 rows) and visually confirmed via LibreOffice + `pdftoppm` that the cover slide's KPI row
(Critical 20 / Important-High 44), executive summary sentence, "Severity Breakdown by
Detected Category / Version" table, the Advisory Overview donut chart, and the closing
"Patch Priority Recommendations" slide's counts are now all correct and internally
consistent (column totals across the breakdown table sum to the KPI row's totals). Also
re-ran the existing synthetic sample dataset (title-case severities) through the same code
path to confirm the fix doesn't regress the previously-working case.

## Previous delivery: per-category/version severity counts in the VMSA HTML report and the PPTX cover slide

Two related, small additions, both showing the same information in the two places you
view VMSA Version Check results.

**1. `allinonevmw.ps1` - VMSA Version Check HTML report:** the "Detected Versions" table
at the top of the report (one row per detected vCenter/ESXi category+version) now has 4
extra columns - **Critical / High / Medium / Low** - showing how many of the advisories
matched against that specific category/version fall into each severity bucket (a
colored badge with the count, or a plain "0" when there are none, using the exact same
severity-bucket classification - `Get-SeverityBadgeClass` - and badge colors already
used on every individual advisory card further down the same report). Source file
changed: `vmsa/vmsa_environment_report.ps1` (read verbatim into the merged file by
`build.py`, so no other file needed touching for this).

**2. `pptx-reports/generate_security_decks.py` - VMSA deck's cover slide:** added a
matching "Severity Breakdown by Detected Category / Version" table right below the
executive-summary callout, with one row per detected `MatchedAgainst` target (e.g.
`vCenter 8.0.2`, `ESXi 8.0.1`) and the same Critical/High/Medium/Low count columns,
colored the same way. This replaces the previous overall (not per-category) "Advisory
Mix by Severity" progress-bar gauges on the cover slide, which are now redundant with
this more specific breakdown (the overall severity mix is still shown via the KPI row
and the donut chart on the Advisory Overview slide right after the cover). Rows are
sorted by matched-advisory count, and if more than 7 distinct targets are detected only
the top 7 are shown (with a "(top 7 of N)" note) so the table never overflows the
slide - the full per-advisory detail is still on the "Matched Advisories" pages later in
the deck. `deck_style.py`'s `add_table()` helper gained multi-column badge-coloring
support (`badge_cols` / `zero_muted_cols`) to build this without a wall of colored
zeros.

**Testing done:** re-ran the same PowerShell-parser checks as every prior delivery
against the rebuilt `allinonevmw.ps1` (zero parse errors, same 290 functions, zero
`exit` statements, +27 lines from this addition) and unit-tested the new HTML
counting/rendering logic standalone against synthetic `$MatchResults` data (2 targets,
mixed severities) to confirm the per-target counts and badge/zero rendering are
correct before rebuilding the full file. For the Python side, regenerated the VMSA deck
against both the small sample dataset and a larger synthetic one (11 detected targets)
and visually inspected the rendered slide (LibreOffice + `pdftoppm`, as with the
previous PPTX delivery) to confirm the table renders correctly, colors match the
severity buckets, and the "top 7 of N" cap holds up without layout overflow.

## Previous delivery: new standalone Python tool - 3 separate PowerPoint decks from menu [3]'s results

Added `pptx-reports/generate_security_decks.py` - a completely independent Python script
(not part of `allinonevmw.ps1`, not called by it, and `allinonevmw.ps1` itself is
unchanged in this delivery) that reads the CSV result files menu `[3]`'s three security
checks already produce and builds **three separate** PowerPoint (.pptx) files, one per
check, rather than one combined deck:

| Output file | Source data |
|---|---|
| `KISA_Security_Summary_<timestamp>.pptx` | `kisa_virtualization_report_*.csv` |
| `Security_Compliance_Guide_Summary_<timestamp>.pptx` | `audit_report_summary.csv` + `audit_report_details.csv` |
| `VMSA_Version_Mapping_Summary_<timestamp>.pptx` | `VMSA_Environment_Match_*.csv` |

**Why Python this time, and why 3 files instead of 1:** the previous
`Export-SecurityAssessmentSummaryPptx.ps1` (PowerShell + PowerPoint COM automation,
delivered then removed - see below) wasn't a good fit, so this delivery switches
approach on both fronts you asked for: it is written in Python using the `python-pptx`
library (`pip install python-pptx`) instead of PowerShell + COM, and it produces one
PPTX file per check (KISA / Security Compliance Guide / VMSA version mapping) instead of
one combined deck. A useful side effect of the Python/`python-pptx` approach: unlike the
COM-based script, this one needs no Microsoft Office installation at all (it writes the
`.pptx` XML directly), so it runs on Windows, macOS, or Linux, and - importantly - it
could actually be executed and visually verified end-to-end in this development
environment (details under "Testing done" below), which the COM-based script never
could be.

**Design, per your requirements:**

- **Bright/light tone** - white/near-white slide backgrounds throughout; color is used
  only on small elements (KPI-card top accent bars, status/priority/severity badges,
  chart series, a colored left-edge accent on card and callout shapes) rather than any
  full-slide colored fill. The previous COM-based script's full-navy section-divider
  slides (likely why it felt "not bright") are not used here at all.
- **Organized like the HTML reports** - the color palette is taken directly from
  `allinonevmw.ps1`'s own embedded HTML report CSS: the VMSA report's
  navy/critical-red/high-orange/medium-amber/low-green palette, the hardening audit
  report's pass-green/fail-red/info-cyan palette, and the KISA report's
  PASS/FAIL/WARN/MANUAL/ERROR status colors - so all three decks read as the same
  product family as the existing HTML output rather than a generic PowerPoint theme.
- **Compact shapes, dense layout** - KPI cards, slim horizontal progress-bar gauges, and
  colored-badge tables (up to ~14 rows per slide, sized to fit rather than a slide per
  finding) replace the large, sparsely-filled cards the previous script tended toward.
  Each finding/recommendation card is now sized to its actual bullet count instead of a
  fixed oversized box, and a short "executive summary" / "observation" / "next steps"
  callout banner fills the space next to KPI rows and chart rows with an actual written
  takeaway sentence instead of leaving it blank.
- **C-level structure** - each deck follows the same short arc: cover (KPI row + a
  one-paragraph plain-language executive summary + small breakdown gauges) → overview
  (a chart, a breakdown table, and a one-line observation) → paginated findings table(s),
  worst-first → a highlights/remediation page (e.g. the distinct P0 controls, or the
  Critical CVEs with their NVD descriptions pulled from `CVE_Lookup_Cache.json` via the
  existing lookup mechanism from the "CVE Lookup cache" change further down this file) →
  a closing recommendations slide. Findings tables are capped (`--top-n`, default 60,
  worst-first) so a very large result set doesn't produce an unbounded number of slides.
- **Language** - the KISA deck's chrome (titles, labels, recommendations) is in Korean,
  matching the KISA HTML report's own language; the Security Compliance Guide and VMSA
  decks are in English, matching their HTML reports. All source data (host names, SCG
  IDs, advisory titles, etc.) is shown as-is regardless.

**How it works:** point `--input-folder` at the toolkit's `output\` folder (or a more
specific subfolder) and it auto-discovers the most recent matching file(s) for each
deck, or pass `--kisa-csv` / `--scg-summary-csv` / `--scg-details-csv` / `--vmsa-csv`
explicitly. Only the decks whose required input(s) are actually found get built - the
others are skipped with a one-line warning, so this works fine even if you've only run
part of menu `[3]`. `--only kisa,scg,vmsa` builds a subset; `--max-rows-per-slide` and
`--top-n` control pagination and how many findings are shown. Full usage is in
`pptx-reports/README.md`.

**Testing done:** unlike the previous COM-based script, `python-pptx` needed no mock -
it was installed and run directly in this environment. A synthetic-data generator
(`pptx-reports/tests/make_sample_data.py`) builds a larger, more realistic dataset (6
ESXi hosts × 15 KISA checks, 7 hardening-audit objects with a P0/P1/P2/Advanced spread
of findings, 22 VMSA advisories across all 4 severities) than the tiny 3-4-row fixtures
used previously, to properly exercise sorting, pagination, and the charts. All three
decks were generated end-to-end with no errors, then converted to PDF and rendered to
PNG images (LibreOffice + `pdftoppm`, both available in this environment) so every slide
of all three decks could actually be visually inspected - this caught and fixed several
real layout bugs before delivery (a long deck title wrapping onto and overlapping its
subtitle; a percentage-axis bar chart whose auto-scaled axis didn't start at 0; oversized
finding cards leaving large empty gaps; and duplicate highlight cards for the same
control ID appearing on different objects). This is a meaningfully stronger verification
pass than was possible for the earlier PowerShell/COM script, which could not be run in
this environment at all.

## Previous delivery: PowerPoint summary script removed

The standalone `Export-SecurityAssessmentSummaryPptx.ps1` script (delivered previously -
reads menu `[3]`'s security-check CSV results and builds a PowerPoint summary via
PowerPoint COM automation) has been removed at your request. It was never part of
`allinonevmw.ps1` and nothing else in this toolkit called it, so removing it has no
effect on anything else here - `allinonevmw.ps1` itself is unchanged in this delivery.
The corresponding "PowerPoint summary" section that had been added to `README.md` was
removed as well. If a PPT/report-summary need comes up again later, happy to revisit it
with a different approach.

## Previous delivery: new standalone script - PowerPoint summary of security-check results

Added `Export-SecurityAssessmentSummaryPptx.ps1` - a completely independent script (not
part of `allinonevmw.ps1`, and not called by it) that reads the CSV result files menu
`[3]`'s three security checks (security hardening audit, VMSA version check, KISA audit)
already produce, and builds one PowerPoint (.pptx) executive-summary deck from them.

**Why a separate script, and why COM automation:** per your answers, this is delivered
as a fully separate `.ps1` file you run on demand, not a new `allinonevmw.ps1` menu item.
It generates the deck via PowerPoint COM automation (`New-Object -ComObject
PowerPoint.Application`) - the same technique widely used by enterprise PowerShell
reporting scripts - rather than hand-building the OOXML file format from scratch or
shelling out to Python's `python-pptx` (the approach the Operations folder's README
mentions as a possible fallback for the VCF Operations report, which deliberately left
PPTX out of its PowerShell rewrite for the same reason: no clean native-PowerShell path
existed). This requires Microsoft PowerPoint to be installed on whichever machine you
run *this* script on - not on the vCenter/ESXi/audit target - and no internet access
either way.

**How it works:** point `-InputFolder` at either one specific tool's output folder, or a
higher-level folder like `output\`, and it recursively searches for the three known
result filenames:

| Check | File(s) it looks for |
|---|---|
| Security Hardening Audit | `audit_report_summary.csv` + `audit_report_details.csv` |
| VMSA Version Check | `VMSA_Environment_Match_*.csv` |
| KISA Audit | `kisa_virtualization_report_*.csv` |

Only whichever of the three are actually found go into the deck (any subset is fine); if
more than one match of a given type exists, the most recently modified one is used. The
generated deck: a title slide, an executive-summary slide with one KPI card per detected
check (pass rate / critical-severity count / fail count, colored green-to-red by
severity), then per-check sections - a summary table plus a FAIL/WARN/Critical findings
table sorted by severity (VMSA: Critical > Important/High > Moderate/Medium > Low, same
ranking the VMSA HTML report already uses; Security Hardening: SCG priority P0 > P1 > P2;
KISA: Importance 상 > 중 > 하) - automatically paginated across multiple slides if there
are more findings than fit on one (capped at 6 pages per section by default, with a
"...N more, see the full CSV" note rather than generating unbounded slides), and a
closing slide listing the exact source file paths used. Parameters
`-MaxRowsPerSlide`/`-MaxSlidesPerSection` control the pagination if the defaults (14
rows/slide, 6 slides/section) don't fit your data well.

**Testing done, and its limits:** this environment has no Windows/PowerPoint to run the
actual COM automation against, so validation here was: (1) PowerShell's own parser -
zero syntax errors; (2) the file-detection logic run against sample CSV files matching
the real schemas from all three tools, confirming it correctly finds/parses each one
whether pointed at a specific tool folder or a shared parent folder, and correctly
reports "nothing found" or "PowerPoint not installed" with a clear message in those
cases; (3) the entire slide-building code path (sorting, KPI math, pagination, table/text
population) run end-to-end against that sample data with a lightweight mock standing in
for the PowerPoint COM objects, to catch property-name or logic errors independent of
COM itself. What could **not** be verified here is real PowerPoint's actual rendering of
the generated tables/shapes/colors - please do one test run against a real result folder
and let me know if the slide layout, table sizing, or colors need adjusting.

## Earlier delivery: menu [1] runs its process automatically, no submenu

Main-menu option `[1]` (VCF 9 Upgrade) used to open its own 5-choice submenu
(`Show-Vcf9UpgradeMenu`): `[1]` the automatic inventory+HCL+NVMe-tiering chain, and
`[2]`-`[5]` standalone NVMe-tiering-only / inventory-only / HCL-check-only /
performance-report-only operations. Per a follow-up request, selecting `[1]` from the
main menu now always runs that automatic chain directly — no submenu is shown at all,
and choices `[2]`-`[5]` are no longer reachable from the menu.

This makes menu `[1]` behave exactly like menus `[3]` and `[5]`, which already run
their process(es) immediately with no intermediate submenu. The underlying automatic
chain itself (inventory collection → HCL compatibility check → NVMe tiering analysis,
all in one run) is unchanged — only the extra menu screen in front of it is gone.

Since `Show-Vcf9UpgradeMenu` and its `Select-Vcf9InventoryFolder` helper (used only by
the now-removed choices `[2]`/`[4]`/`[5]` to pick an existing inventory folder) have no
remaining callers anywhere else in the file, both were removed entirely rather than
left as dead code — following the same precedent as the earlier removal of the old
standalone `Show-SecurityHardeningMenu`/`Show-VmsaMenu` submenus once their paths were
folded into a single consolidated menu entry.

**Note:** the standalone NVMe-tiering-only, inventory-only, HCL-check-only, and
performance-report-only operations these choices used to expose are no longer reachable
from the menu at all (their underlying tool functions still exist in the file and are
still used internally by the automatic chain, but there is no longer a menu path to run
any of them individually). Let me know if you'd like any of those kept as a separate
menu option after all.

Rebuilt and re-verified: **zero parse errors**, **15,415 total lines** (down from
15,512 — reflects the ~105 lines removed), **290 functions** (down from 292, the two
removed functions), **zero `exit` statements**, no unintended function-name collisions
(same 2 pre-existing nested-duplicate cases as every prior delivery). Confirmed
`Show-Vcf9UpgradeMenu`/`Select-Vcf9InventoryFolder` no longer appear anywhere in the
built file except in an explanatory comment, and that `Show-MainMenu`'s `[1]` case now
calls `Invoke-Vcf9PrecheckToolkitTool -MenuChoice '1' -AutoChainToNvmeTiering` directly.

## Previous delivery: VMSA Version Check HTML now shows real CVE descriptions from CVE_Lookup_Cache.json

In menu `[3]`'s VMSA Version Check step (`Invoke-VmsaEnvironmentReportTool`), the HTML
report's per-CVE detail line now pulls its description directly from the repo-root
`CVE_Lookup_Cache.json` cache (the same file `Invoke-VmsaCveLookupTool`, menu `[5]`,
builds and maintains) instead of the old ad-hoc lookup mechanism.

**What changed:** previously, this step looked for a `CVE_Lookup_<yyyyMMdd-HHmm>`
subfolder next to its output (left over from before the two VMSA tools were
consolidated behind one persistent cache) and, if found, generically flattened any
CSV/JSON column whose name started with "NVD " into the report. In practice this only
worked if a CVE lookup happened to have been run into a folder still sitting under
`output\vmsa\`, and required guessing a folder-name timestamp format. It now reads
`CVE_Lookup_Cache.json` at the repo root directly — the same fixed file menu `[5]`
already keeps up to date — and matches each CVE ID it finds there to pull its NVD
**Description**, **Severity**, **CVSSv3**, **Published** date, and **References**
(fields with no data, like "N/A" or an unattempted lookup, are simply omitted rather
than shown blank).

**Where it shows up:** the HTML report's "CVEs" list under each matched advisory (in
all three sections — version-matched, VMware Tools reference, and VCF/VVF reference) —
each CVE ID now shows its real NVD description text (not just the short VMSA-supplied
one-liner already shown above it) whenever a cache entry exists for that CVE. The same
enrichment also still flows into the CSV's `CveLookupInfo` column and the report
header's "CVE Lookup source" line, both of which continue to work unchanged since the
new code fills the exact same internal data shape the existing rendering logic already
expected.

**If the cache doesn't exist yet or has no entry for a given CVE:** the report says so
plainly ("`CVE_Lookup_Cache.json not found...`" in the header, "`no CVE Lookup match for
this ID`" per CVE) rather than silently omitting anything — run menu `[5]` (VMSA Full
List Download + CVE Lookup) at least once first to populate the cache. The `-SkipCveLookup`
switch still works exactly as before (skips this enrichment entirely, by design, for a
faster run).

Rebuilt and re-verified: **zero parse errors**, **15,512 total lines**, **292
functions**, **zero `exit` statements**, **29 top-level functions**, no unintended
function-name collisions. Also unit-tested the new JSON-parsing/field-extraction logic
standalone against sample cache data (a fully-populated CVE and a failed-lookup
placeholder entry) to confirm the field filtering (dropping "N/A"/blank values) and
the downstream `<b>Key</b>: Value` HTML rendering behave as expected before rebuilding
the full file.

## Previous delivery: fixed-name VMSA CSVs, optional Excel companions everywhere, and a restructured vCenter Security Suite

Three separate requests, delivered together. Summary first, details in the subsections
after.

| # | Change | Status |
|---|---|---|
| 1 | `VMSA_All_Advisories_*.csv` / `VMSA_CVE_List_*.csv` no longer get a timestamp — fixed names, overwritten in place each run | Done |
| 2 | Every CSV-producing tool in the toolkit now also writes one combined Excel workbook alongside its CSV(s), but only when the `ImportExcel` PowerShell module is installed | Done |
| 3 | Menu `[3]` (vCenter Security Suite) now asks for the vCenter host address **first**, before credentials, with no submenu; menu `[6]` was removed entirely | Done |

### 1 — VMSA CSV filenames fixed (no more timestamp)

`Invoke-VmsaDownloaderTool`'s two summary CSVs — previously
`VMSA_All_Advisories_<timestamp>.csv` and `VMSA_CVE_List_<timestamp>.csv` — are now
always named exactly `VMSA_All_Advisories.csv` and `VMSA_CVE_List.csv` (still under
`output\vmsa\`). `Export-Csv` overwrites an existing file at a given path by default,
so each run replaces the previous file in place rather than accumulating a new
timestamped copy every time. Nothing else about these two files' content or the rest of
the downloader's output (the JSON cache at the repo root, the HTML report, the
`VMSA_By_Category_*`/`VMSA_Excel_*` subfolders) changed.

The launcher's combined "VMSA Full List Download + CVE Lookup" menu option (`[5]`,
`Invoke-VmsaDownloadAndCveLookup`) previously found the CSV to feed into the CVE lookup
step by sorting the `vmsa` output folder for the newest `VMSA_CVE_List_*.csv`. That
wildcard/sort logic is no longer needed now that the name is fixed — it now just checks
for `output\vmsa\VMSA_CVE_List.csv` directly and passes that path straight to
`Invoke-VmsaCveLookupTool`.

### 2 — Optional combined Excel workbook for every CSV output

Two new shared helper functions were added near the top of the file (available to every
tool, since they're brand-new code, not sourced from any of the original 14 scripts):

- **`Test-ExcelExportAvailable`** — returns `$true` only if the `ImportExcel` module is
  installed (`Get-Module -ListAvailable -Name ImportExcel`). If it isn't, every Excel
  step below silently does nothing — no error, no missing-module warning spam, CSV
  output is completely unaffected either way.
- **`Export-CsvSetAsExcelWorkbook -XlsxPath <path> -Sheets @(@{Name=...;Path=...}, ...)`**
  — builds **one** `.xlsx` file with one worksheet per CSV given to it (this matches the
  same "one combined multi-sheet workbook, not one file per CSV" pattern already used
  by the existing VCF Operations report and security-hardening audit-reporter Excel
  exports — I matched their precedent rather than inventing a new shape). Worksheet
  names are sanitized for Excel's rules (31-char max, no `[ ] * ? / \ :`) and
  de-duplicated if two CSVs would produce the same sheet name.
- **`Export-CsvFolderAsExcelWorkbook -FolderPath <dir> -XlsxPath <path>`** — convenience
  wrapper for tools whose CSVs all land in one folder that's guaranteed fresh for this
  run alone (a timestamped folder name); scans every `.csv` in it and calls the function
  above.

This was applied to every CSV-producing tool that didn't already have Excel export
(VCF Operations, the security-hardening audit-reporter, and the VMSA category-split
export already had their own `ImportExcel`-gated Excel output before this change, and
were left untouched):

| Tool | CSV(s) | Combined workbook |
|---|---|---|
| VCF 9 pre-check (`Invoke-Vcf9PrecheckToolkitTool`) — inventory step | `ESX_Memory_Page.csv` + others in the same folder | `<inventory-folder-name>.xlsx` |
| VCF 9 pre-check — HCL compatibility step | `Compatibility_*.csv`, `Compatibility_Skipped_USB.csv` | `Compatibility_Summary.xlsx` |
| VCF 9 NVMe tiering (`Invoke-Vcf9NvmeTieringTool`) | per-host CSV + cluster-summary CSV | `NVMe_Tiering_Report_<timestamp>.xlsx` |
| vCenter Daily Report (`Invoke-VCenterDailyReportTool`) | all `output\vcenter\...` CSVs for the run | `DailyReport_Summary_<date>.xlsx` |
| VMSA full-list downloader (`Invoke-VmsaDownloaderTool`) | `VMSA_All_Advisories.csv` + `VMSA_CVE_List.csv` | `VMSA_FullList_Report.xlsx` |
| VMSA CVE lookup (`Invoke-VmsaCveLookupTool`) | its output CSV | same name, `.xlsx` extension |
| VMSA environment/version check (`Invoke-VmsaEnvironmentReportTool`) | its output CSV | same name, `.xlsx` extension |
| KISA audit (`Invoke-KisaEsxAuditTool`) | its results CSV | same name, `.xlsx` extension; summary log shows the Excel line only if the file was actually created |

Folder-scan (`Export-CsvFolderAsExcelWorkbook`) was only used where the output folder is
freshly created per run (`vSphere_Inventory_*`, `compatibility_*`, `DailyReport_*`) —
for `Invoke-VmsaEnvironmentReportTool`, whose output folder name is fixed
(`vmsa_environment`) across every run and only the filename is timestamped, the
explicit single-file form is used instead so it never picks up CSVs from a previous
run. `Invoke-VCF9PerformanceReport` produces no CSV (HTML only) and needed no change.

### 3 — vCenter Security Suite: host address asked first, no submenu, menu `[6]` removed

`Invoke-VCenterConnectedAuditSuite` (menu `[3]`) now asks for the vCenter server
address/FQDN as the very first prompt, before `Get-Credential` — previously the
numbered "1) security hardening audit 2) VMSA check 3) KISA audit" banner appeared
before the host prompt, which could read like a submenu even though all three steps
already ran automatically with no further input. That banner was removed; a single
"Logged in - running all 3 checks now with no further prompts" line now appears after
credentials are confirmed, immediately before the three checks run back-to-back exactly
as before.

Main-menu option `[6]` ("Regenerate Security Hardening Report") was removed entirely,
along with its `Invoke-ToolFunction -FunctionName 'Invoke-AuditReporterTool'` switch
case. The menu is now:

```
  [1] VCF 9 Upgrade (Pre-check / NVMe Tiering Analysis)           (vcf_9_upgrade)
  [2] VCF Operations Report                                       (Operations)
  [3] vCenter Security Suite: Hardening Audit + VMSA Version Check + KISA Audit
                                                                  (single vCenter login)
  [4] vCenter Daily Comprehensive Report                          (vcenter)
  [5] VMSA Full List Download + CVE Lookup  (Internet connection required - takes a long time)
  [0] Exit
```

`Invoke-AuditReporterTool` itself (regenerate-report-from-existing-logs, no vCenter
needed) still exists in the file and is still called internally by
`Invoke-SecurityHardeningAuditAndReport` — only its standalone main-menu entry point was
removed.

### Re-verification after this delivery

Rebuilt and re-ran the same checks used throughout this project against the updated
file: **zero parse errors**, **15,576 total lines**, **292 functions** (288 + the 4 new
Excel-helper functions, all global-scope since they're new code with no per-tool
isolation requirement), **zero `exit` statements**, **29 top-level functions** (25
original + `Test-ExcelExportAvailable` / `Get-SafeExcelSheetName` /
`Export-CsvSetAsExcelWorkbook` / `Export-CsvFolderAsExcelWorkbook`), no unintended
function-name collisions (same 2 pre-existing nested-duplicate cases as every prior
delivery: `Test-Emptyish`/`Test-LooksLikeVersion` inside the duplicated
`ConvertTo-MatrixColumns`). Every one of the 8 new Excel-export call sites and the
restructured `Invoke-VCenterConnectedAuditSuite` prompt order were also individually
spot-checked in the built file to confirm correct placement, variable references, and
indentation.

## Previous delivery: VMSA cache files moved to the repo root

`VMSA_FullList_Data.json` (produced/maintained by the VMSA full-list downloader) and
`CVE_Lookup_Cache.json` (produced/maintained by the CVE lookup tool) are the two
persistent, incremental caches behind main-menu option `[5]`. Both now get created and
updated directly at the **repo root** (next to `allinonevmw.ps1`), instead of under
`output\vmsa\` as before.

**Why:** these two files are meant to persist indefinitely and grow across every run —
unlike everything else under `output\`, which is timestamped, per-run, and safe to
clear out periodically. Keeping them at the repo root means an `output\` cleanup can
never accidentally delete them, and they're easy to find/back up on their own.

**What did not change:** the incremental compare-and-merge behavior these two files
already had was untouched — this was a pure relocation, not a logic change. Both
tools already worked this way before this delivery: on each run, if the file exists
already, it's loaded first, and only genuinely new items (a new VMSA advisory ID, a
CVE ID not yet looked up) are fetched and added; everything already in the file is
kept as-is rather than being re-fetched or overwritten. That logic lives entirely in
the original scripts (`vmsa_fulllist_downloader.ps1` / `vmsa_cve_lookup.ps1`) and was
carried into the merge unmodified — only the `Join-Path` target for these two specific
files changed, from `$CurrentDir` (`output\vmsa\...`) to `$RepoRoot` (the repo root).
Every other file these two tools produce — the timestamped `VMSA_All_Advisories_*.csv`
/ `VMSA_CVE_List_*.csv`, the HTML report, the `VMSA_By_Category_*\` and
`VMSA_Excel_*\` subfolders, and the CVE lookup's own `CVE_Lookup_<timestamp>\` output
folder — is untouched and still lands under `output\vmsa\` exactly as before.

One more spot needed the same fix for consistency: `Invoke-VmsaEnvironmentReportTool`
(the "VMSA version check" step inside the consolidated vCenter Security Suite, menu
`[3]`) also looks for `VMSA_FullList_Data.json` to decide whether it needs to run the
downloader first. Its lookup path was updated to the repo root too, so it finds the
same file the downloader now maintains there instead of always concluding the file is
missing and re-running the downloader unnecessarily.

Re-verified after this change with the same checks used throughout this project: the
file still parses with **zero errors**, still has **288 functions (25 of them
top-level, no collisions)**, and **zero leftover `exit` statements**.

## Previous delivery: menu automation, hostname masking, consolidated vCenter login, English console

This delivery builds on the full inline merge described below and makes six further
changes to `allinonevmw.ps1`, all driven by one request. Summary first, details in the
subsections after.

| # | Change | Status |
|---|---|---|
| A | VCF 9 menu `[1]` now auto-chains inventory+HCL check straight into NVMe tiering analysis, no inner submenu shown | Done |
| B | Security-hardening audit run (`audit_runner`) now auto-chains straight into report generation (`audit-reporter`) on the same folder | Done |
| C | Every hostname/IP the audit runner touches (vCenter address, ESXi hosts, VM names) is masked in console/log text and in output filenames | Done |
| D | Security hardening + VMSA version check + KISA audit consolidated into one menu item, one vCenter login prompt shared across all three | Done |
| E | VMSA "download full list" + "CVE lookup" combined into one menu item, labeled to warn it needs internet and takes a while | Done |
| F | All console-facing menus/prompts/messages translated to English | Done, with a disclosed scope (see below) |

### A — VCF 9 menu auto-chain

`Show-Vcf9UpgradeMenu` option `[1]` now calls
`Invoke-Vcf9PrecheckToolkitTool -MenuChoice '1' -AutoChainToNvmeTiering`.
Internally, `Invoke-Vcf9PrecheckToolkitTool` gained two new parameters
(`-MenuChoice`, `-ExistingInventoryPath`) so it can skip its own interactive submenu
prompt when called this way, plus a `-AutoChainToNvmeTiering` switch: after its
original "inventory collection + HCL compatibility check" step (submenu choice `1`)
finishes and returns the new `vSphere_Inventory_*` output folder path, it calls
`Invoke-Vcf9NvmeTieringTool -InventoryPath $InvDir` directly instead of returning to a
menu. The tool's other submenu choices (NVMe-only, inventory-only, HCL-only) are still
reachable from `Show-Vcf9UpgradeMenu` as separate options for anyone who wants just one
step.

### B — audit_runner → audit-reporter auto-chain

`Invoke-AuditRunnerTool` now returns the report folder path it produced instead of
just finishing silently. A new top-level function, `Invoke-SecurityHardeningAuditAndReport`,
calls it and — if a folder came back and still exists — immediately calls
`Invoke-AuditReporterTool -TargetDirOverride $reportDir`, which is a new parameter on
`Invoke-AuditReporterTool` that skips its own interactive `Select-Audit-Folder` prompt
and uses the given folder directly. This chained function is what the main menu's
security-suite option (see D) actually calls.

### C — hostname/IP masking (scope confirmed with you: **all hostnames**, not just the vCenter address you type in)

A small helper, `ConvertTo-MaskedAuditName`, was added (nested identically inside every
function that needed it, for the same scoping reasons described under "Collision
handling" below — see `Invoke-AuditVm8Tool`, `Invoke-AuditEsxi8Tool`,
`Invoke-AuditVcenter8Tool`, `Invoke-AuditAllTool`, `Invoke-AuditRunnerTool`):

- An FQDN (`host.corp.local`) becomes `host.***.***` — the leftmost label is kept,
  the domain is masked.
- An IPv4 address (`10.20.30.40`) becomes `***.***.***.40` — the first three octets
  are masked, the last is kept (enough to tell hosts apart in a report without
  exposing the network).
- A bare short hostname (no dot) is left as-is — there's no domain/network part to mask.
- For output **filenames** specifically (e.g. `Audit_Report_.../10.20.30.40.txt`), the
  same function is called with `-ForFileName`, which substitutes `xxx` for `***`,
  since `*` is not a legal character in a Windows filename.

This is applied to: the vCenter address you type in for `audit_runner` (console
"Connecting to vCenter Server (...)" line), and every VM/ESXi/vCenter target name
audited by `audit-vm-8`/`audit-esxi-8`/`audit-vcenter-8` (both the console/log
"Audit of ... started/completed" lines and, via `audit-all`, the per-target output
filenames). The actual API calls (`Get-VM`, `Get-VMHost`, etc.) still use the real,
unmasked name — only display text and filenames are masked, so the audit itself is
unaffected.

### D — consolidated vCenter security suite (shared login, per your answer)

A new main-menu option, "vCenter Security Suite", calls a new function
`Invoke-VCenterConnectedAuditSuite`: it prompts once for a vCenter address and
credentials, then runs, in order: `Invoke-SecurityHardeningAuditAndReport` (B above),
`Invoke-VmsaEnvironmentReportTool`, and `Invoke-KisaEsxAuditTool` — all three using the
one address/credential pair you entered.

**Design note on "shared login":** you asked for a single login rather than three
independent connections, and that's honored at the UX level — you are prompted for
vCenter credentials exactly once for all three checks. Under the hood, each of the
three tools still calls its own `Connect-VIServer`/`Disconnect-VIServer` with the
credentials you gave it, rather than literally reusing one PowerCLI session object
across all three. I chose this because `audit_runner`'s connection-check helper
(`scg-common.psm1`'s `Test-vCenterConnection`) hard-requires `$global:DefaultVIServers.Count -eq 1`
— if a second tool connected to the same vCenter on top of an already-open connection
from the first, that check would fail and the security-hardening audit would refuse to
run. Passing the credentials through instead of the connection object avoids that
without touching `scg-common.psm1`'s logic. The practical difference is one extra
silent login/logout round-trip per tool (3 total instead of 1) — you still only type
your password once.

`Invoke-AuditRunnerTool` and `Invoke-VmsaEnvironmentReportTool` both gained
`-SharedVcAddress`/`-SharedCredential` parameters for this; when both are supplied they
skip their own interactive address/credential prompts. `Invoke-KisaEsxAuditTool`
already took `-Server`/`-Credential` parameters, so no change was needed there beyond
passing them through. The old standalone `Show-SecurityHardeningMenu`, `Show-VmsaMenu`,
and `Invoke-KisaEsxAudit` wrapper functions were removed from the launcher since their
paths are now reached only through the consolidated flow (running `audit_runner`,
`audit-reporter`, `vmsa_environment_report`, or the KISA tool completely standalone is
no longer exposed from the main menu — say the word if you'd like any of those kept as
separate menu options too).

### E — VMSA download + CVE lookup combined

Main-menu option "VMSA Full List Download + CVE Lookup" is now labeled
"(Internet connection required — takes a long time)" and calls a new function,
`Invoke-VmsaDownloadAndCveLookup`: it runs `Invoke-VmsaDownloaderTool`, finds the
newest `VMSA_CVE_List_*.csv` it just produced in the `vmsa` output folder, and feeds
that straight into `Invoke-VmsaCveLookupTool -CveListCsv <that file>`. If the
downloader didn't produce a matching CSV, it stops with an error instead of guessing.

### F — English console text (scope and what's intentionally left in Korean)

All menus, `Read-Host`/`Get-Credential` prompts, and `Write-Host`/`Write-Warning`/
`Write-Error`/`Write-Verbose`/`Write-Log`/`throw` messages that appear on the console
while running any of the 14 tools or the launcher itself were translated to English.
This included the entire new launcher/menu section (hand-written in English from the
start) and every wrapper progress-message helper each tool defines for itself
(`Write-VCFOpsStep`/`Write-VCFOpsSubStep`/`Write-VCFOpsStepDone` for VCF Operations,
`Write-Log`/`Write-Section` for KISA, and so on) — not just direct `Write-Host` calls,
since several tools route their console output through their own small logging
wrapper functions.

**Deliberately left in Korean** (disclosed, not missed):
- The **KISA per-control finding descriptions** — about 100 `Add-Result` calls
  covering HV-01 through HV-25 (e.g. "기본 관리자 계정 변경", "비밀번호 복잡성 설정")
  and the corresponding HTML report content `New-KisaHtmlReport` generates. These are
  the actual audit *findings*, not console UI text, and translating ~100
  security-control descriptions accurately is a substantially larger, separate task.
- The **HTML/CSV/Excel report bodies** produced by `Invoke-OperationsReportTool` (VCF
  Operations — column headers, section titles, embedded JavaScript labels) and by
  `Invoke-Vcf9NvmeTieringTool` (the NVMe tiering analysis report, including its
  interactive JS controls). Same reasoning: these are report *content*, not the
  console screen, and are a much larger volume of text (mostly HTML/CSS/JS embedded in
  PowerShell here-strings) than the console UI.
- Inline **code comments** throughout the file (documentation for future maintainers,
  e.g. the VCF Operations `statKey` mapping notes) — these are never displayed at
  runtime and carry no user-facing risk, so translating them wasn't necessary to meet
  "no language problems while running the scripts."

If you'd like a follow-up pass on either of the two report-body items or the KISA
finding descriptions, let me know and I can scope that as its own task — it's larger
than this change set (the KISA descriptions alone are ~100 short phrases, and the two
report bodies are several hundred lines of embedded HTML/JS each).

### Updated main menu

```
  [1] VCF 9 Upgrade (Pre-check / NVMe Tiering Analysis)           (vcf_9_upgrade)
  [2] VCF Operations Report                                       (Operations)
  [3] vCenter Security Suite: Hardening Audit + VMSA Version Check + KISA Audit
                                                                  (single vCenter login)
  [4] vCenter Daily Comprehensive Report                          (vcenter)
  [5] VMSA Full List Download + CVE Lookup  (Internet connection required - takes a long time)
  [6] Regenerate Security Hardening Report (existing logs, no vCenter needed)
  [0] Exit
```

Option `[6]` is unchanged in behavior from before (`Invoke-AuditReporterTool` with no
override — it still prompts you to pick a folder) — it's kept as an escape hatch for
regenerating a report without re-running a live audit or connecting to vCenter.

### Re-verification after this delivery

Re-ran both checks used for the original merge (see "What I could not verify" below)
against the updated file: **zero parse errors**, **zero `exit` statements**, **288
functions total, 25 of them top-level with no unintended name collisions** (the new
`ConvertTo-MaskedAuditName` helper is nested identically in 5 places, verified safe the
same way as the pre-existing duplicated helpers). Also swept the whole file
programmatically for any remaining Korean text next to a console-output cmdlet
(`Write-Host`, `Write-Warning`, `Write-Error`, `Write-Verbose`, `Write-Log`, custom
`Write-*` wrappers, `Read-Host`, `Get-Credential`, `throw`) — that sweep caught several
messages the first translation pass missed (a handful of `throw` error messages, and
progress messages routed through each tool's own `Write-VCFOpsStep`/`Write-VCFOpsSubStep`/
`Write-VCFOpsStepDone`/`Write-Verbose` wrapper functions rather than `Write-Host`
directly) — those are now translated too, and a second sweep confirms zero
console-facing Korean text remains anywhere in the file.

---

## Original full inline merge (previous delivery)

### What changed

The previous `allinonevmw.ps1` was a thin menu that spawned each tool as a **separate
child script** (`& $Path`, with a `Push-Location` into that tool's own folder first).

The new `allinonevmw.ps1` (attached) contains **all tool logic inlined as PowerShell
functions in the same file** — no more child-process calls for the 10 tools listed
below. Each tool's original script became one `Invoke-*Tool` function; each tool's
own helper modules were inlined as nested functions inside that same wrapper (see
"Collision handling" below for why this is safe).

| Menu item | Old script | New function |
|---|---|---|
| VCF9 pre-check | `vcf_9_upgrade/vcf9-precheck-toolkit_v2.ps1` | `Invoke-Vcf9PrecheckToolkitTool` |
| VCF9 NVMe tiering | `vcf_9_upgrade/vcf9-nvme-tiering-analysis.ps1` | `Invoke-Vcf9NvmeTieringTool` |
| VCF Operations report | `Operations/New-VCFOpsReport.ps1` (+ 11 modules) | `Invoke-OperationsReportTool` |
| Security hardening audit run | `security-hardening/vmware-tools/audit_runner.ps1` | `Invoke-AuditRunnerTool` |
| (called internally by audit_runner) | `.../audit-all.ps1` | `Invoke-AuditAllTool` |
| (called internally by audit-all) | `.../audit-vm-8.ps1` | `Invoke-AuditVm8Tool` |
| (called internally by audit-all) | `.../audit-esxi-8.ps1` | `Invoke-AuditEsxi8Tool` |
| (called internally by audit-all) | `.../audit-vcenter-8.ps1` | `Invoke-AuditVcenter8Tool` |
| Security hardening report generation | `security-hardening/audit-reporter.ps1` | `Invoke-AuditReporterTool` |
| vCenter daily report | `vcenter/Get_VC_DailyReport.ps1` | `Invoke-VCenterDailyReportTool` |
| VMSA list download | `vmsa/vmsa_fulllist_downloader.ps1` | `Invoke-VmsaDownloaderTool` |
| VMSA CVE lookup | `vmsa/vmsa_cve_lookup.ps1` | `Invoke-VmsaCveLookupTool` |
| VMSA environment check | `vmsa/vmsa_environment_report.ps1` | `Invoke-VmsaEnvironmentReportTool` |
| KISA audit | `kisa_esx/invoke-vSpherekisaaudit.ps1` | `Invoke-KisaEsxAuditTool` |

**Explicitly out of scope (per your earlier answer):** `security-hardening/vmware-tools/
remediate-esxi-8.ps1`, `remediate-vcenter-8.ps1`, `remediate-vm-8.ps1`. These are
untouched and still run standalone from their current location. They still `Import-
Module "$PSScriptRoot\scg-common.psm1"`, so **`scg-common.psm1` must stay in
`security-hardening/vmware-tools/`** — do not delete or move it.

### Repo layout changes required

Two **data** folders/files that lived under a tool's own subfolder had to move to the
repo root, because the merged script's `$PSScriptRoot` is now the repo root (not each
tool's old folder), and these two are looked up relative to the running script:

```
infra_assessment/
 ├─ allinonevmw.ps1                                              <- replace with the new file
 ├─ hcl/                                                          <- MOVE from vcf_9_upgrade/hcl/
 │   ├─ CPU_All_Models_Single_Sheet.csv
 │   ├─ IO Devices_vcf_9_0.csv / _vcf_9_1.csv
 │   ├─ Systems _ Servers_vcf_9_0.csv / _vcf_9_1.csv
 │   └─ vSAN I_O Controller_vcf_9_0.csv / _vcf_9_1.csv
 ├─ vmware-vsphere-security-configuration-guide-8-controls.csv    <- MOVE from security-hardening/
 └─ output/                                                       <- NEW, auto-created at runtime
     ├─ vcf_9_upgrade/      (vSphere_Inventory_*, compatibility_*, performance_*, nvme_tiering_*, *.zip)
     ├─ Operations/         (output/, snapshots/)
     ├─ security-hardening/ (Audit_Report_*, Output_*, cached_credential.xml)
     ├─ vcenter/            (DailyReport_*)
     ├─ vmsa/               (VMSA_*.csv/json/html, CVE_Lookup_*, VMSA_By_Category_*, VMSA_Excel_*)
     └─ kisa_esx/           (output_esxi/)
```

I copied both (the 7 HCL CSVs and the SCG controls CSV) into this delivery so you have
them ready to drop in — I couldn't push to your GitHub repo directly (no connector is
connected in this session), so please move them into place yourself. Everything else
(the original `vcf_9_upgrade/`, `Operations/`, `security-hardening/`, `vcenter/`,
`vmsa/`, `kisa_esx/` folders and their `.ps1`/`.psm1` files) is no longer read by the
new launcher and can stay as historical reference or be deleted — **except**
`security-hardening/vmware-tools/scg-common.psm1`, which the 3 excluded remediate
scripts still need in place.

`output/` itself doesn't need to be created ahead of time — every tool creates its own
subfolder on first run.

### Collision handling (why this is safe to merge into one file)

Four of the audit scripts (`audit-all`, `audit-esxi-8`, `audit-vcenter-8`,
`audit-vm-8`) each carried **byte-identical copies** of the same 5 helper functions
(`Log-Message`, `Accept-EULA`, `Do-Pause`, `Check-vCenter`, `Check-Hosts`) plus their
own `Import-Module scg-common.psm1` (5 more functions: `Write-Log`, `Show-EULA`,
`Wait-UserInput`, `Test-vCenterConnection`, `Test-HostsExist`). The VMSA downloader and
environment-report scripts also share 5 helper-function *names*, but 3 of those 5 have
genuinely **different logic** between the two files (verified by diff, not just by
name).

Rather than deduplicating or renaming any of this — which would have meant editing
logic I didn't write and couldn't test — each tool's entire original script became one
self-contained function, and every one of the above helpers stays **nested inside its
own tool's wrapper function**. PowerShell scopes nested function definitions to their
parent, so `Log-Message` inside `Invoke-AuditVm8Tool` and `Log-Message` inside
`Invoke-AuditEsxi8Tool` are two completely separate functions that never see each
other — exactly like when they ran as separate processes before. I verified this with
PowerShell's own parser (not just a text search): 25 top-level functions, all
uniquely named, and every duplicate name resolves to a different enclosing top-level
function.

The only real code changes beyond wrapping were:
- `audit-all`'s three `& "$PSScriptRoot\audit-vm-8.ps1" ...` (etc.) calls became
  direct calls to `Invoke-AuditVm8Tool` / `Invoke-AuditEsxi8Tool` /
  `Invoke-AuditVcenter8Tool` (now sibling functions in the same file).
- `audit_runner`'s `& "$PSScriptRoot\audit-all.ps1" ...` became a direct call to
  `Invoke-AuditAllTool`.
- `vmsa_environment_report`'s "run the downloader script if the JSON cache is
  missing" logic became a direct call to `Invoke-VmsaDownloaderTool` instead of
  locating and executing a sibling `.ps1` file.
- Every `exit` / `Exit` statement (39 of them, all inside try/catch error branches)
  became `return`, since `exit` would otherwise terminate the whole launcher process,
  not just that one menu operation. I found every one of these with PowerShell's own
  parser (not a text search), including ones the original author capitalized
  differently, so this should be exhaustive.
- Every output-writing path built from `$PSScriptRoot` (or, for `Get_VC_DailyReport`
  and the KISA script, a `.\`-relative default) now points at
  `output\<tool-folder>\...` instead. The two genuinely **data-lookup** paths (the HCL
  folder, the SCG controls CSV) were deliberately left as `$PSScriptRoot`-relative,
  since they resolve correctly once the data itself moves to the repo root with the
  script.
- All 11 `Operations\Modules\*.psm1` files and (four separate copies of)
  `scg-common.psm1` had their `Import-Module`/`Export-ModuleMember` lines stripped and
  their function bodies pasted in place — they no longer need to exist as separate
  module files for the launcher to work (though I left the originals on disk; nothing
  deletes them).

### What I could not verify

I don't have a real vCenter/ESXi environment, PowerCLI, or PowerShell itself for this
review (only a Linux sandbox) — so I validated this with PowerShell 7's own **language
parser** (downloaded a portable copy specifically to check this): the merged file
parses with **zero syntax errors**, has **zero remaining `exit` statements**, and has
**no accidental function collisions at the top level**. What I could not do is actually
run any of the 10 tools against live infrastructure. Before relying on this in
production, I'd suggest a dry run of at least the `-Mock` path for VCF Operations
(`Invoke-OperationsReportTool -Mock`) and one low-risk tool (e.g. VMSA list download,
which only needs internet access) against a real environment first.

## Files in this delivery

- `allinonevmw.ps1` — the fully inlined launcher, now with menus `[1]`, `[3]`, and `[5]`
  all running their process(es) automatically with no submenu, hostname/IP masking, a
  consolidated vCenter security suite (host-first prompt), an English console, the two
  VMSA cache files relocated to the repo root, fixed-name (no timestamp) VMSA summary
  CSVs, an optional combined Excel workbook alongside every tool's CSV output, real
  NVD CVE descriptions (from `CVE_Lookup_Cache.json`) in the VMSA Version Check HTML
  report, and per-category/version Critical/High/Medium/Low severity counts in that
  same report's "Detected Versions" table (15,442 lines)
- `hcl/` — the 7 HCL CSVs, to move to the repo root
- `vmware-vsphere-security-configuration-guide-8-controls.csv` — to move to the repo root
- `pptx-reports/` — the new standalone Python PowerPoint-summary tool: `generate_security_decks.py`,
  `deck_style.py`, `tests/make_sample_data.py`, and its own `README.md` (not called by, and does
  not modify, `allinonevmw.ps1`)
- `CHANGE-NOTES.md` — this file
- `README.md` — Korean-language usage guide

**Optional:** to get the Excel workbook companions (item 2 above), install the
`ImportExcel` PowerShell module once (`Install-Module ImportExcel -Scope CurrentUser`).
Without it, every tool still works exactly as before — CSV output only.
