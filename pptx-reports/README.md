# Security Summary PPTX Generator (Python)

Standalone Python tool that turns the CSV results of `allinonevmw.ps1`'s
menu `[3]` (vCenter Security Suite: Hardening Audit + VMSA Version Check +
KISA Audit) into three separate, C-level-oriented PowerPoint decks:

| Output file | Source data |
|---|---|
| `KISA_Security_Summary_<timestamp>.pptx` | `kisa_virtualization_report_*.csv` |
| `Security_Compliance_Guide_Summary_<timestamp>.pptx` | `audit_report_summary.csv` + `audit_report_details.csv` |
| `VMSA_Version_Mapping_Summary_<timestamp>.pptx` | `VMSA_Environment_Match_*.csv` |

This is fully independent of `allinonevmw.ps1` - it only reads the CSV files
that tool already writes under its `output\` folder. It does not call the
PowerShell toolkit, and the toolkit does not call it either.

## Design

- Bright/light color tone: white/near-white slide backgrounds with colored
  accents only on small elements (KPI card top-bars, badges, chart series) -
  never a full-slide saturated fill.
- Colors are taken directly from `allinonevmw.ps1`'s own embedded HTML
  report CSS (VMSA's navy/severity palette, the hardening audit report's
  pass/fail/info palette, the KISA report's status colors), so the decks
  read as the same product family as the HTML reports.
- Compact shapes and a dense layout: KPI cards, progress-bar gauges,
  "executive summary" / "observation" callout bars, and dense per-row-colored
  tables (up to ~14 rows per slide) are used instead of a slide-per-finding
  wall of text, so each deck stays short enough for a C-level readout.
- Each deck: cover (KPIs + one-paragraph executive summary + a breakdown
  table/gauges) -> overview (chart + breakdown table + an observation
  callout) -> paginated findings table(s) -> a highlights/remediation page ->
  closing recommendations.
- The VMSA deck's cover slide includes a "Severity Breakdown by Detected
  Category / Version" table - one row per detected `MatchedAgainst` target
  (e.g. `vCenter 8.0.2`, `ESXi 8.0.1`), with Critical/High/Medium/Low advisory
  counts for that specific target. This mirrors the same per-category/version
  severity columns added to the VMSA Version Check HTML report's "Detected
  Versions" table in `allinonevmw.ps1`, so the two stay consistent. If more
  than 7 targets are detected, only the top 7 (by matched-advisory count) are
  shown, with a "(top 7 of N)" note - the full per-advisory detail is still on
  the "Matched Advisories" pages later in the deck.

## Requirements

```
pip install python-pptx
```

(No Microsoft Office / PowerPoint installation is required - `python-pptx`
writes the `.pptx` XML directly, so this also runs on Linux/macOS.)

## Usage

Point at the toolkit's `output\` folder and let it auto-discover the most
recent result file(s) for each deck:

```bash
python generate_security_decks.py --input-folder /path/to/output --output-dir /path/to/reports
```

Or pass specific files explicitly (useful for a specific point-in-time
result rather than "whatever is newest"):

```bash
python generate_security_decks.py \
    --kisa-csv output/kisa_esx/output_esxi/kisa_virtualization_report_20260910-0900.csv \
    --scg-summary-csv output/security-hardening/Audit_Report_20260910-0900/audit_report_summary.csv \
    --scg-details-csv output/security-hardening/Audit_Report_20260910-0900/audit_report_details.csv \
    --vmsa-csv output/vmsa/vmsa_environment/VMSA_Environment_Match_20260910-0900.csv \
    --output-dir ./reports
```

Only the decks whose required input file(s) are found are built - the
others print a one-line warning to stderr and are skipped, so this works
fine if you've only run part of menu `[3]`.

Useful options:

- `--only kisa,scg,vmsa` - build a subset (comma-separated).
- `--max-rows-per-slide N` - rows per findings-table slide (default 14).
- `--top-n N` - cap on how many findings/advisories are shown, worst-first
  (default 60) - keeps very large result sets from producing an
  excessively long deck.

## Files

- `generate_security_decks.py` - CLI entry point and the 3 deck builders.
- `deck_style.py` - shared visual-style helpers (palette, KPI cards,
  progress gauges, callout bars, tables, charts). No CLI of its own.
- `tests/make_sample_data.py` - generates larger synthetic CSVs (multiple
  hosts/objects/advisories) under `tests/sample_data/`, useful for trying
  the generator out or for regression-checking a change to the script:
  `python tests/make_sample_data.py && python generate_security_decks.py --input-folder tests/sample_data --output-dir tests/output`.
