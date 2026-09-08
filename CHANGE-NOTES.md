# allinonevmw.ps1 — full inline merge (change notes)

## What changed

The previous `allinonevmw.ps1` was a thin menu that spawned each tool as a **separate
child script** (`& $Path`, with a `Push-Location` into that tool's own folder first).

The new `allinonevmw.ps1` (attached) contains **all tool logic inlined as PowerShell
functions in the same file** — no more child-process calls for the 10 tools listed
below. Each tool's original script became one `Invoke-*Tool` function; each tool's
own helper modules were inlined as nested functions inside that same wrapper (see
"Collision handling" below for why this is safe).

| Menu item | Old script | New function |
|---|---|---|
| VCF9 사전점검 | `vcf_9_upgrade/vcf9-precheck-toolkit_v2.ps1` | `Invoke-Vcf9PrecheckToolkitTool` |
| VCF9 NVMe 티어링 | `vcf_9_upgrade/vcf9-nvme-tiering-analysis.ps1` | `Invoke-Vcf9NvmeTieringTool` |
| VCF Operations 리포트 | `Operations/New-VCFOpsReport.ps1` (+ 11 modules) | `Invoke-OperationsReportTool` |
| 보안 감사 실행 | `security-hardening/vmware-tools/audit_runner.ps1` | `Invoke-AuditRunnerTool` |
| (audit_runner이 내부 호출) | `.../audit-all.ps1` | `Invoke-AuditAllTool` |
| (audit-all이 내부 호출) | `.../audit-vm-8.ps1` | `Invoke-AuditVm8Tool` |
| (audit-all이 내부 호출) | `.../audit-esxi-8.ps1` | `Invoke-AuditEsxi8Tool` |
| (audit-all이 내부 호출) | `.../audit-vcenter-8.ps1` | `Invoke-AuditVcenter8Tool` |
| 보안 감사 리포트 생성 | `security-hardening/audit-reporter.ps1` | `Invoke-AuditReporterTool` |
| vCenter 일일 리포트 | `vcenter/Get_VC_DailyReport.ps1` | `Invoke-VCenterDailyReportTool` |
| VMSA 목록 다운로드 | `vmsa/vmsa_fulllist_downloader.ps1` | `Invoke-VmsaDownloaderTool` |
| VMSA CVE 조회 | `vmsa/vmsa_cve_lookup.ps1` | `Invoke-VmsaCveLookupTool` |
| VMSA 환경 점검 | `vmsa/vmsa_environment_report.ps1` | `Invoke-VmsaEnvironmentReportTool` |
| KISA 점검 | `kisa_esx/invoke-vSpherekisaaudit.ps1` | `Invoke-KisaEsxAuditTool` |

**Explicitly out of scope (per your earlier answer):** `security-hardening/vmware-tools/
remediate-esxi-8.ps1`, `remediate-vcenter-8.ps1`, `remediate-vm-8.ps1`. These are
untouched and still run standalone from their current location. They still `Import-
Module "$PSScriptRoot\scg-common.psm1"`, so **`scg-common.psm1` must stay in
`security-hardening/vmware-tools/`** — do not delete or move it.

## Repo layout changes required

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

## Collision handling (why this is safe to merge into one file)

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

## What I could not verify

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

- `allinonevmw.ps1` — the new, fully inlined launcher (~15,300 lines)
- `hcl/` — the 7 HCL CSVs, to move to the repo root
- `vmware-vsphere-security-configuration-guide-8-controls.csv` — to move to the repo root
- `CHANGE-NOTES.md` — this file
