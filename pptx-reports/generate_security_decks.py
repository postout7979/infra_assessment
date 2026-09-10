#!/usr/bin/env python3
"""
generate_security_decks.py

Builds three separate, C-level-oriented PowerPoint decks from the CSV
outputs produced by allinonevmw.ps1's menu [3] (vCenter Security Suite:
Hardening Audit + VMSA Version Check + KISA Audit):

  1. KISA_Security_Summary_<timestamp>.pptx
       <- kisa_virtualization_report_*.csv          (output\\kisa_esx\\output_esxi\\)
  2. Security_Compliance_Guide_Summary_<timestamp>.pptx
       <- audit_report_summary.csv + audit_report_details.csv
                                                      (output\\security-hardening\\Audit_Report_*\\)
  3. VMSA_Version_Mapping_Summary_<timestamp>.pptx
       <- VMSA_Environment_Match_*.csv               (output\\vmsa\\vmsa_environment\\)

Design goals (per request): a bright/light color tone matching the toolkit's
own HTML reports, compact shapes (no oversized boxes), a dense/tightly
arranged layout, and content organized for a short executive read rather
than a raw data dump. See deck_style.py for the shared visual language.

This script is fully standalone from allinonevmw.ps1 - it only reads the
CSV files that tool already produces, and does not modify or depend on the
PowerShell toolkit in any other way. It requires the `python-pptx` package
(pip install python-pptx).

USAGE
-----
Auto-discover the most recent result files under a folder (typically the
toolkit's `output\\` folder, or its parent) and build whichever of the 3
decks it can find source data for:

    python generate_security_decks.py --input-folder /path/to/output --output-dir /path/to/reports

Or point at specific files explicitly (any subset - only the decks with
their required input(s) supplied are built):

    python generate_security_decks.py \\
        --kisa-csv output/kisa_esx/output_esxi/kisa_virtualization_report_20260101-1200.csv \\
        --scg-summary-csv output/security-hardening/Audit_Report_20260101-1200/audit_report_summary.csv \\
        --scg-details-csv output/security-hardening/Audit_Report_20260101-1200/audit_report_details.csv \\
        --vmsa-csv output/vmsa/vmsa_environment/VMSA_Environment_Match_20260101-1200.csv \\
        --output-dir ./reports

Limit to a subset of decks with --only (comma-separated: kisa,scg,vmsa).
"""

from __future__ import annotations

import argparse
import csv
import re
import sys
from collections import Counter, defaultdict
from datetime import datetime
from pathlib import Path

from pptx.util import Inches, Pt
from pptx.enum.text import PP_ALIGN, MSO_ANCHOR

import deck_style as ds

MAX_ROWS_PER_SLIDE_DEFAULT = 14
TOP_N_DEFAULT = 60


# ==========================================================================
# Generic helpers
# ==========================================================================
def load_csv(path: Path):
    with open(path, newline="", encoding="utf-8-sig") as f:
        return list(csv.DictReader(f))


def find_latest(root: Path, pattern: str):
    matches = [p for p in root.rglob(pattern) if p.is_file()]
    if not matches:
        return None
    return max(matches, key=lambda p: p.stat().st_mtime)


def find_latest_scg(root: Path):
    candidates = [p for p in root.rglob("audit_report_details.csv") if p.is_file()]
    if not candidates:
        return None, None
    latest = max(candidates, key=lambda p: p.stat().st_mtime)
    summary = latest.parent / "audit_report_summary.csv"
    return latest, (summary if summary.exists() else None)


def pct(part, whole):
    if not whole:
        return 0.0
    return round(100.0 * part / whole, 1)


def clip(text, n):
    text = "" if text is None else str(text)
    text = re.sub(r"\s+", " ", text).strip()
    return text if len(text) <= n else text[: n - 1].rstrip() + "…"


def timestamp_tag():
    return datetime.now().strftime("%Y%m%d-%H%M")


def add_content_footer(slide, source_label, page_no, total_pages):
    ds.add_footer(slide, f"Source: {source_label}  |  Generated {datetime.now():%Y-%m-%d %H:%M}",
                  page_no, total_pages)


# ==========================================================================
# 1) KISA deck  (chrome in Korean, matching the KISA HTML report's language)
# ==========================================================================
KISA_IMPORTANCE_ORDER = {"상": 0, "중": 1, "하": 2}
KISA_STATUS_RANK = {"FAIL": 5, "ERROR": 4, "WARN": 3, "MANUAL": 2, "PASS": 0}
KISA_IMPORTANCE_BADGE = {
    "상": (ds.P["crit_bg"], ds.P["crit_fg"]),
    "중": (ds.P["med_bg"], ds.P["med_fg"]),
    "하": (ds.P["low_bg"], ds.P["low_fg"]),
}


def build_kisa_deck(rows, source_label, max_rows_per_slide, top_n):
    prs = ds.new_presentation()
    total = len(rows)
    hosts = sorted({r.get("HostName", "") for r in rows})
    status_counter = Counter((r.get("Status") or "").upper() for r in rows)
    n_pass = status_counter.get("PASS", 0)
    n_fail = status_counter.get("FAIL", 0)
    n_warn = status_counter.get("WARN", 0)
    n_manual = status_counter.get("MANUAL", 0)
    n_error = status_counter.get("ERROR", 0)
    pass_rate = pct(n_pass, total)

    # Aggregate by check code (across all hosts) once, up front - used by
    # both the overview slide's "observation" callout and the findings
    # table slides below.
    by_code = defaultdict(list)
    for r in rows:
        by_code[r.get("Code", "")].append(r)
    agg = []
    for code, items in by_code.items():
        title0 = items[0].get("Title", "")
        importance = items[0].get("Importance", "")
        n = len(items)
        n_p = sum(1 for r in items if (r.get("Status") or "").upper() == "PASS")
        n_f = sum(1 for r in items if (r.get("Status") or "").upper() == "FAIL")
        n_other = n - n_p - n_f
        rate = pct(n_p, n)
        agg.append({
            "code": code, "title": title0, "importance": importance,
            "hosts": n, "pass": n_p, "fail": n_f, "other": n_other, "rate": rate,
        })
    agg.sort(key=lambda a: (KISA_IMPORTANCE_ORDER.get(a["importance"], 9), -a["fail"], a["rate"]))

    # ---- Slide 1: Cover ----
    slide = ds.add_blank_slide(prs)
    meta = (f"생성일: {datetime.now():%Y-%m-%d %H:%M}\n"
            f"대상 호스트: {len(hosts)}개\n"
            f"점검 항목: 총 {total}건 (HV-01~HV-25)")
    ds.add_header_band(
        slide, "VSPHERE SECURITY ASSESSMENT",
        "KISA 가상화(vSphere) 보안 점검 결과 요약",
        "행정·공공기관 가상화 시스템 보안 점검 기준(HV-01~HV-25) 기반 하드닝 점검 결과",
        meta,
    )
    ds.add_kpi_row(
        slide, ds.MARGIN, Inches(1.55), ds.CONTENT_W, Inches(1.35),
        [
            {"label": "전체 점검 항목", "value": total, "color": ds.P["navy"]},
            {"label": "정상 (PASS)", "value": n_pass, "color": ds.P["k_pass"], "sub": f"{pass_rate}%"},
            {"label": "취약 (FAIL)", "value": n_fail, "color": ds.P["k_fail"]},
            {"label": "주의 (WARN/수동확인)", "value": n_warn + n_manual + n_error, "color": ds.P["k_warn"]},
            {"label": "대상 호스트", "value": len(hosts), "color": ds.P["accent"]},
        ],
    )
    n_critical_fail_codes = len({r.get("Code") for r in rows
                                  if r.get("Importance") == "상" and (r.get("Status") or "").upper() == "FAIL"})
    summary_sentence = (
        f"전체 {total}건 중 {n_pass}건이 정상(PASS)으로 확인되어 준수율은 {pass_rate}%입니다. "
        f"중요도 '상' 항목 중 취약(FAIL) 코드는 {n_critical_fail_codes}개로, 최우선 조치가 필요합니다."
    )
    ds.add_insight_bar(slide, ds.MARGIN, Inches(3.10), ds.CONTENT_W, Inches(1.05),
                        "핵심 요약", summary_sentence, color=ds.P["navy"])
    gauge_y = Inches(4.35)
    ds.add_text(slide, ds.MARGIN, gauge_y, ds.CONTENT_W, Inches(0.24), "중요도별 준수율", size=11.5, bold=True, color=ds.P["text"])
    gy = gauge_y + Inches(0.34)
    for imp, gcolor in (("상", ds.P["k_fail"]), ("중", ds.P["k_warn"]), ("하", ds.P["k_pass"])):
        sub = [r for r in rows if r.get("Importance") == imp]
        if not sub:
            continue
        s_pass = sum(1 for r in sub if (r.get("Status") or "").upper() == "PASS")
        ds.add_progress_bar(slide, ds.MARGIN, gy, ds.CONTENT_W, Inches(0.36),
                             f"중요도 '{imp}' ({len(sub)}건)", pct(s_pass, len(sub)), gcolor)
        gy += Inches(0.42)
    add_content_footer(slide, source_label, 1, "N")

    # ---- Slide 2: Overview (donut + importance breakdown table) ----
    slide = ds.add_blank_slide(prs)
    content_y = ds.add_page_header(slide, "점검 결과 개요", "상태별 분포 및 중요도별 준수 현황")
    donut_w, donut_h = Inches(4.6), Inches(4.1)
    labels = ["PASS", "FAIL", "WARN", "MANUAL", "ERROR"]
    vals = [n_pass, n_fail, n_warn, n_manual, n_error]
    labels_f, vals_f = [], []
    colors = []
    color_map = {"PASS": ds.P["k_pass"], "FAIL": ds.P["k_fail"], "WARN": ds.P["k_warn"],
                 "MANUAL": ds.P["k_manual"], "ERROR": ds.P["k_error"]}
    for l, v in zip(labels, vals):
        if v > 0:
            labels_f.append(l)
            vals_f.append(v)
            colors.append(color_map[l])
    if vals_f:
        ds.add_donut_chart(slide, ds.MARGIN, content_y, donut_w, donut_h, labels_f, vals_f, colors)

    # importance breakdown table
    imp_rows = []
    for imp in ("상", "중", "하"):
        sub = [r for r in rows if r.get("Importance") == imp]
        if not sub:
            continue
        s_total = len(sub)
        s_pass = sum(1 for r in sub if (r.get("Status") or "").upper() == "PASS")
        s_fail = sum(1 for r in sub if (r.get("Status") or "").upper() == "FAIL")
        imp_rows.append([imp, s_total, s_pass, s_fail, f"{pct(s_pass, s_total)}%"])
    tbl_x = ds.MARGIN + donut_w + Inches(0.35)
    tbl_w = ds.SLIDE_W - ds.MARGIN - tbl_x
    ds.add_text(slide, tbl_x, content_y, tbl_w, Inches(0.26), "중요도별 준수 현황", size=12, bold=True, color=ds.P["text"])
    if imp_rows:
        ds.add_table(
            slide, tbl_x, content_y + Inches(0.34), tbl_w, Inches(1.7),
            ["중요도", "항목 수", "PASS", "FAIL", "준수율"], imp_rows,
            col_widths=[1, 1, 1, 1, 1.2], font_size=11, badge_col=0,
            badge_fn=lambda v: KISA_IMPORTANCE_BADGE.get(v, (ds.P["default_bg"], ds.P["default_fg"])),
        )
    # host summary mini-table below
    if len(hosts) > 1:
        host_rows = []
        for h in hosts:
            sub = [r for r in rows if r.get("HostName") == h]
            s_total = len(sub)
            s_fail = sum(1 for r in sub if (r.get("Status") or "").upper() == "FAIL")
            s_pass = sum(1 for r in sub if (r.get("Status") or "").upper() == "PASS")
            host_rows.append((h, s_total, s_pass, s_fail, pct(s_pass, s_total)))
        host_rows.sort(key=lambda r: r[4])
        disp_rows = [[h, t, p, f, f"{r}%"] for (h, t, p, f, r) in host_rows[:5]]
        ds.add_text(slide, tbl_x, content_y + Inches(2.2), tbl_w, Inches(0.26),
                    "준수율 낮은 호스트 Top 5", size=12, bold=True, color=ds.P["text"])
        ds.add_table(
            slide, tbl_x, content_y + Inches(2.54), tbl_w, Inches(1.5),
            ["호스트", "항목 수", "PASS", "FAIL", "준수율"], disp_rows,
            col_widths=[1.6, 1, 1, 1, 1.2], font_size=10,
        )
    worst_code = max(agg, key=lambda a: a["fail"], default=None) if agg else None
    insight_y = Inches(5.35)
    if worst_code and worst_code["fail"] > 0:
        note = (f"가장 많은 호스트에서 FAIL이 발생한 항목은 '{worst_code['code']} - {worst_code['title']}'"
                f"({worst_code['fail']}/{worst_code['hosts']} 호스트)입니다. 동일 코드가 여러 호스트에서 "
                f"반복되면 표준 이미지/템플릿 수준의 일괄 조치를 검토하세요.")
        ds.add_insight_bar(slide, ds.MARGIN, insight_y, ds.CONTENT_W, Inches(1.1), "관찰 사항", note, color=ds.P["navy"])
    add_content_footer(slide, source_label, 2, "N")

    # ---- Slide(s) 3+: Findings aggregated by check code ----
    findings = [a for a in agg if a["fail"] > 0 or a["other"] > 0][:top_n]
    if not findings:
        findings = agg[:top_n]

    table_rows = [
        [a["code"], clip(a["title"], 42), a["importance"], a["hosts"], a["pass"],
         a["fail"], a["other"], f"{a['rate']}%"]
        for a in findings
    ]
    pages = ds.paginate(table_rows, max_rows_per_slide)
    for pi, page_rows in enumerate(pages, start=1):
        slide = ds.add_blank_slide(prs)
        subtitle = f"호스트 전반에서 취약/주의 항목이 있는 점검 코드 ({pi}/{len(pages)} 페이지)"
        content_y = ds.add_page_header(slide, "취약/주의 항목 상세 (점검 코드 기준 집계)", subtitle)
        ds.add_table(
            slide, ds.MARGIN, content_y, ds.CONTENT_W, ds.SLIDE_H - content_y - Inches(0.55),
            ["코드", "점검 항목", "중요도", "대상", "PASS", "FAIL", "기타", "준수율"], page_rows,
            col_widths=[1.0, 4.6, 0.9, 0.8, 0.8, 0.8, 0.8, 1.0], font_size=10,
            badge_col=2, badge_fn=lambda v: KISA_IMPORTANCE_BADGE.get(v, (ds.P["default_bg"], ds.P["default_fg"])),
        )
        add_content_footer(slide, source_label, "-", "-")

    # ---- Closing: recommendations ----
    slide = ds.add_blank_slide(prs)
    content_y = ds.add_page_header(slide, "권고 사항 및 후속 조치", "우선순위에 따른 조치 제안")
    card_w = (ds.CONTENT_W - Inches(0.3) * 2) / 3
    card_h = ds.bullet_card_height(3)
    bullets_1 = [
        "중요도 '상'이면서 FAIL인 항목을 최우선으로 조치합니다.",
        f"현재 해당 대상 항목: {sum(1 for a in agg if a['importance']=='상' and a['fail']>0)}개 점검 코드.",
        "조치 완료 후 재점검을 실행해 준수 여부를 확인하세요.",
    ]
    bullets_2 = [
        "중요도 '중', '하' FAIL 항목은 다음 점검 주기 전까지 순차적으로 조치합니다.",
        "동일 코드가 다수 호스트에서 반복되면 표준 이미지/템플릿 수준에서 일괄 반영을 검토하세요.",
    ]
    bullets_3 = [
        "자동 점검이 불가능한 MANUAL 항목은 담당자가 수동으로 확인 후 결과를 기록합니다.",
        "ERROR 항목은 점검 스크립트 실행 조건(권한/접속 등)을 먼저 확인하세요.",
        f"전체 준수율: {pass_rate}% (목표: 지속적 개선)",
    ]
    ds.add_bullet_card(slide, ds.MARGIN, content_y, card_w, card_h, "1) 즉시 조치 (중요도 상 + FAIL)", bullets_1, color=ds.P["k_fail"])
    ds.add_bullet_card(slide, ds.MARGIN + card_w + Inches(0.3), content_y, card_w, card_h, "2) 순차 조치 (중요도 중/하)", bullets_2, color=ds.P["k_warn"])
    ds.add_bullet_card(slide, ds.MARGIN + 2 * (card_w + Inches(0.3)), content_y, card_w, card_h, "3) 수동 확인 필요 (MANUAL/ERROR)", bullets_3, color=ds.P["k_manual"])

    total_hosts = len(hosts)
    closing_note = (
        f"이 요약본은 {source_label} 파일을 기준으로 자동 생성되었습니다. 조치 진행 상황은 다음 정기 점검 "
        f"실행 시(메뉴 [3] vCenter Security Suite) 자동으로 갱신되는 결과와 비교해 추적하는 것을 권장합니다. "
        f"(대상 호스트 {total_hosts}개, 전체 준수율 {pass_rate}%)"
    )
    ds.add_insight_bar(slide, ds.MARGIN, content_y + card_h + Inches(0.3), ds.CONTENT_W, Inches(1.15),
                        "다음 단계", closing_note, color=ds.P["navy"])
    add_content_footer(slide, source_label, "N", "N")

    # fix up page numbers now that slide count is final
    _renumber_footers(prs, skip_first=1)
    return prs


# ==========================================================================
# 2) Security Compliance Guide deck (English chrome, matches audit-reporter HTML)
# ==========================================================================
PRIORITY_ORDER = {"P0": 0, "P1": 1, "P2": 2, "ADVANCED": 3}


def _priority_key(p):
    return PRIORITY_ORDER.get((p or "").upper(), 9)


def build_scg_deck(summary_rows, detail_rows, source_label, max_rows_per_slide, top_n):
    prs = ds.new_presentation()

    s_total = sum(int(r.get("Total") or 0) for r in summary_rows)
    s_pass = sum(int(r.get("Pass") or 0) for r in summary_rows)
    s_fail = sum(int(r.get("Fail") or 0) for r in summary_rows)
    s_info = sum(int(r.get("Info") or 0) for r in summary_rows)
    overall_rate = pct(s_pass, s_total)

    fails = [r for r in detail_rows if (r.get("Status") or "").upper() == "FAIL"]
    prio_counter = Counter((r.get("Priority") or "Advanced").strip().upper() or "ADVANCED" for r in fails)

    # ---- Slide 1: Cover ----
    slide = ds.add_blank_slide(prs)
    objects = sorted({r.get("Object", "") for r in summary_rows})
    meta = (f"Generated: {datetime.now():%Y-%m-%d %H:%M}\n"
            f"Objects assessed: {len(objects)}\n"
            f"Baseline: VMware vSphere Security Configuration Guide")
    ds.add_header_band(
        slide, "SECURITY COMPLIANCE",
        "vSphere Security Compliance Guide",
        "Hardening Audit Summary - executive overview of checks against the VMware Security Configuration Guide",
        meta, color1=ds.P["slate"], color2=ds.P["slate2"],
    )
    ds.add_kpi_row(
        slide, ds.MARGIN, Inches(1.55), ds.CONTENT_W, Inches(1.35),
        [
            {"label": "Total Checks", "value": s_total, "color": ds.P["accent"]},
            {"label": "Pass", "value": s_pass, "color": ds.P["pass_fg"], "sub": f"{overall_rate}%"},
            {"label": "Fail", "value": s_fail, "color": ds.P["fail_fg"]},
            {"label": "Info", "value": s_info, "color": ds.P["info_fg"]},
            {"label": "P0 Critical Gaps", "value": prio_counter.get("P0", 0), "color": ds.P["crit_fg"]},
        ],
    )
    summary_sentence = (
        f"Across {len(objects)} assessed object(s), {s_pass} of {s_total} checks passed ({overall_rate}%). "
        f"{prio_counter.get('P0', 0)} finding(s) are rated P0 (critical priority) and should be remediated "
        f"before the next audit cycle; {prio_counter.get('P1', 0)} are P1."
    )
    ds.add_insight_bar(slide, ds.MARGIN, Inches(3.10), ds.CONTENT_W, Inches(1.05),
                        "Executive Summary", summary_sentence, color=ds.P["slate"])
    gauge_y = Inches(4.35)
    ds.add_text(slide, ds.MARGIN, gauge_y, ds.CONTENT_W, Inches(0.24), "Pass Rate by Object Type", size=11.5, bold=True, color=ds.P["text"])
    gy = gauge_y + Inches(0.34)
    for otype, gcolor in (("vCenter", ds.P["navy"]), ("ESXi", ds.P["accent"]), ("VM", ds.P["info_fg"])):
        sub = [r for r in summary_rows if r.get("Type") == otype]
        if not sub:
            continue
        t_total = sum(int(r.get("Total") or 0) for r in sub)
        t_pass = sum(int(r.get("Pass") or 0) for r in sub)
        ds.add_progress_bar(slide, ds.MARGIN, gy, ds.CONTENT_W, Inches(0.36),
                             f"{otype} ({len(sub)} object(s))", pct(t_pass, t_total), gcolor)
        gy += Inches(0.42)
    add_content_footer(slide, source_label, 1, "N")

    # ---- Slide 2: Overview ----
    slide = ds.add_blank_slide(prs)
    content_y = ds.add_page_header(slide, "Compliance Overview", "Pass rate by object and open-finding priority mix")
    chart_w, chart_h = Inches(6.6), Inches(4.1)
    cats = [f"{r.get('Type','')}: {r.get('Object','')}" for r in summary_rows]
    rates = [float(str(r.get("PassRate", "0")).replace("%", "") or 0) for r in summary_rows]
    if cats:
        ds.add_bar_chart(slide, ds.MARGIN, content_y, chart_w, chart_h, cats, "Pass Rate %", rates,
                          bar_color=ds.P["accent"], min_scale=0, max_scale=100)

    tbl_x = ds.MARGIN + chart_w + Inches(0.35)
    tbl_w = ds.SLIDE_W - ds.MARGIN - tbl_x
    ds.add_text(slide, tbl_x, content_y, tbl_w, Inches(0.26), "Open Findings by Priority", size=12, bold=True, color=ds.P["text"])
    prio_rows = []
    for p in ("P0", "P1", "P2", "ADVANCED"):
        c = prio_counter.get(p, 0)
        if c:
            prio_rows.append([p.title() if p != "P0" else "P0", c])
    if prio_rows:
        ds.add_table(
            slide, tbl_x, content_y + Inches(0.34), tbl_w, Inches(1.9),
            ["Priority", "Fail Count"], prio_rows, col_widths=[1.4, 1],
            font_size=11, badge_col=0,
            badge_fn=lambda v: ds.PRIORITY_COLORS.get(str(v).upper(), (ds.P["default_bg"], ds.P["default_fg"])),
        )
    ds.add_text(slide, tbl_x, content_y + Inches(2.5), tbl_w, Inches(1.4),
                "P0 items represent the highest-risk configuration gaps and should be "
                "remediated first; see the priority findings and remediation pages that follow.",
                size=10, color=ds.P["muted"], line_spacing=1.25)
    worst_obj = min(summary_rows, key=lambda r: float(str(r.get("PassRate", "0")).replace("%", "") or 0), default=None)
    if worst_obj:
        note = (f"The lowest pass rate is {worst_obj.get('PassRate','')} on {worst_obj.get('Type','')}: "
                f"{worst_obj.get('Object','')} ({worst_obj.get('Fail','0')} failed check(s)). "
                f"Review this object first when planning remediation work.")
        ds.add_insight_bar(slide, ds.MARGIN, Inches(5.35), ds.CONTENT_W, Inches(1.1), "Observation", note, color=ds.P["slate"])
    add_content_footer(slide, source_label, 2, "N")

    # ---- Slide(s) 3+: Priority findings table ----
    fails_sorted = sorted(fails, key=lambda r: (_priority_key(r.get("Priority")), r.get("Type", ""), r.get("Object", "")))
    fails_sorted = fails_sorted[:top_n]
    table_rows = [
        [r.get("SCG ID", ""), clip(r.get("SCG Title", "") or r.get("Message", ""), 40),
         (r.get("Priority") or "Advanced"), r.get("Type", ""), r.get("Object", ""), clip(r.get("Baseline", ""), 16)]
        for r in fails_sorted
    ]
    pages = ds.paginate(table_rows, max_rows_per_slide)
    for pi, page_rows in enumerate(pages, start=1):
        slide = ds.add_blank_slide(prs)
        content_y = ds.add_page_header(slide, "Priority Findings (Failed Controls)",
                                        f"Sorted by remediation priority - P0 first  ({pi}/{len(pages)})")
        ds.add_table(
            slide, ds.MARGIN, content_y, ds.CONTENT_W, ds.SLIDE_H - content_y - Inches(0.55),
            ["SCG ID", "Title", "Priority", "Type", "Object", "Baseline"], page_rows,
            col_widths=[1.0, 4.6, 1.0, 1.0, 1.2, 1.4], font_size=10,
            badge_col=2, badge_fn=lambda v: ds.PRIORITY_COLORS.get(str(v).upper(), (ds.P["default_bg"], ds.P["default_fg"])),
        )
        add_content_footer(slide, source_label, "-", "-")

    # ---- Remediation highlights (top P0 items, one card per distinct SCG ID) ----
    p0_pool = [r for r in fails_sorted if (r.get("Priority") or "").upper() == "P0"]
    seen_scg_ids = set()
    p0_items = []
    for r in p0_pool:
        sid = r.get("SCG ID", "")
        if sid in seen_scg_ids:
            continue
        seen_scg_ids.add(sid)
        p0_items.append(r)
        if len(p0_items) == 3:
            break
    if p0_items:
        slide = ds.add_blank_slide(prs)
        content_y = ds.add_page_header(slide, "Remediation Highlights", "Distinct P0 (critical priority) findings and suggested remediation")
        card_w = (ds.CONTENT_W - Inches(0.3) * (len(p0_items) - 1)) / len(p0_items)
        card_bullets = []
        for r in p0_items:
            affected = [x for x in p0_pool if x.get("SCG ID") == r.get("SCG ID")]
            bullets = [
                f"Affected: {len(affected)} object(s), e.g. {r.get('Type','')} / {r.get('Object','')}",
                f"Finding: {clip(r.get('Message',''), 80)}",
                f"Remediation: {clip(r.get('Remediation',''), 90)}",
            ]
            if r.get("DISA STIG"):
                bullets.append(f"DISA STIG: {r.get('DISA STIG')}")
            if r.get("PCI DSS 4.0"):
                bullets.append(f"PCI DSS 4.0: {r.get('PCI DSS 4.0')}")
            card_bullets.append(bullets)
        card_h = max(ds.bullet_card_height(len(b), bullet_size=9.5) for b in card_bullets)
        for i, (r, bullets) in enumerate(zip(p0_items, card_bullets)):
            cx = ds.MARGIN + i * (card_w + Inches(0.3))
            ds.add_bullet_card(slide, cx, content_y, card_w, card_h,
                                f"{r.get('SCG ID','')} - {clip(r.get('SCG Title',''), 34)}",
                                bullets, color=ds.P["crit_fg"], title_size=11, bullet_size=9.5)
        remaining_p0 = len({x.get("SCG ID") for x in p0_pool}) - len(p0_items)
        note = (f"{len(p0_pool)} P0 finding(s) span {len({x.get('SCG ID') for x in p0_pool})} distinct control(s). "
                + (f"{remaining_p0} additional P0 control(s) are not shown here - see the Priority Findings pages for the full list."
                   if remaining_p0 > 0 else "All distinct P0 controls are shown above."))
        ds.add_insight_bar(slide, ds.MARGIN, content_y + card_h + Inches(0.3), ds.CONTENT_W, Inches(1.0),
                            "Coverage Note", note, color=ds.P["crit_fg"])
        add_content_footer(slide, source_label, "-", "-")

    # ---- Closing ----
    slide = ds.add_blank_slide(prs)
    content_y = ds.add_page_header(slide, "Recommendations & Next Steps")
    card_w = (ds.CONTENT_W - Inches(0.3) * 2) / 3
    bullets_1 = [
        f"{prio_counter.get('P0', 0)} critical (P0) findings require immediate remediation.",
        "Assign owners per object type (vCenter / ESXi / VM) and track to closure.",
    ]
    bullets_2 = [
        f"{prio_counter.get('P1', 0)} P1 and {prio_counter.get('P2', 0)} P2 findings can follow in the next maintenance window.",
        "Group by SCG ID to batch similar fixes across objects.",
    ]
    bullets_3 = [
        f"Current overall pass rate is {overall_rate}%.",
        "Re-run the hardening audit after remediation to confirm improvement and refresh this report.",
    ]
    card_h = max(ds.bullet_card_height(len(b)) for b in (bullets_1, bullets_2, bullets_3))
    ds.add_bullet_card(slide, ds.MARGIN, content_y, card_w, card_h, "1) Remediate P0 Gaps", bullets_1, color=ds.P["crit_fg"])
    ds.add_bullet_card(slide, ds.MARGIN + card_w + Inches(0.3), content_y, card_w, card_h, "2) Schedule P1/P2", bullets_2, color=ds.P["high_fg"])
    ds.add_bullet_card(slide, ds.MARGIN + 2 * (card_w + Inches(0.3)), content_y, card_w, card_h, "3) Re-Baseline", bullets_3, color=ds.P["accent"])

    closing_note = (
        f"This summary was generated from {source_label}. Track remediation progress by comparing it against "
        f"the results produced the next time menu [3] (vCenter Security Suite) is run "
        f"({len(objects)} object(s) assessed, overall pass rate {overall_rate}%)."
    )
    ds.add_insight_bar(slide, ds.MARGIN, content_y + card_h + Inches(0.3), ds.CONTENT_W, Inches(1.15),
                        "Next Steps", closing_note, color=ds.P["slate"])
    add_content_footer(slide, source_label, "N", "N")

    _renumber_footers(prs, skip_first=1)
    return prs


# ==========================================================================
# 3) VMSA Version Mapping deck (English chrome, matches VMSA HTML)
# ==========================================================================
SEVERITY_ORDER = {"CRITICAL": 0, "IMPORTANT": 1, "HIGH": 1, "MODERATE": 2, "MEDIUM": 2, "LOW": 3}


def _sev_key(sev):
    return SEVERITY_ORDER.get((sev or "").upper(), 9)


def _sev_badge(sev):
    return ds.SEVERITY_COLORS.get((sev or "").lower(), (ds.P["default_bg"], ds.P["default_fg"]))


# Same 4-bucket normalization the allinonevmw.ps1 VMSA Version Check HTML
# report uses for its per-category/version severity-count columns (see
# Get-SeverityBadgeClass there) - kept in sync so the PPTX cover slide's
# breakdown table reads the same way as the HTML report's.
def _sev_bucket_name(sev):
    s = (sev or "").strip().lower()
    if s == "critical":
        return "Critical"
    if s in ("important", "high"):
        return "High"
    if s in ("moderate", "medium"):
        return "Medium"
    if s == "low":
        return "Low"
    return None


CVE_DESC_RE = re.compile(r"(CVE-\d{4}-\d{4,7})\s*\[Description=([^\]]*)\]")


def build_vmsa_deck(rows, source_label, max_rows_per_slide, top_n):
    prs = ds.new_presentation()

    def cve_count(r):
        raw = r.get("CVEs", "") or ""
        return len([c for c in re.split(r"[,;\s]+", raw) if c.strip()])

    total_adv = len(rows)
    unique_cves = set()
    for r in rows:
        raw = r.get("CVEs", "") or ""
        for c in re.split(r"[,;\s]+", raw):
            c = c.strip()
            if c:
                unique_cves.add(c)
    sev_counter = Counter((r.get("Severity") or "Unknown").strip() for r in rows)

    # ---- Slide 1: Cover ----
    slide = ds.add_blank_slide(prs)
    targets = sorted({r.get("MatchedAgainst", "") for r in rows})
    meta = (f"Generated: {datetime.now():%Y-%m-%d %H:%M}\n"
            f"Environment targets: {len(targets)}\n"
            f"Source: VMware Security Advisories (VMSA)")
    ds.add_header_band(
        slide, "PATCH & VULNERABILITY MANAGEMENT",
        "VMSA Advisory & Version Mapping Summary",
        "Environment-matched VMware Security Advisories for the assessed vCenter/ESXi versions",
        meta,
    )
    crit = sev_counter.get("Critical", 0)
    important = sev_counter.get("Important", 0) + sev_counter.get("High", 0)
    ds.add_kpi_row(
        slide, ds.MARGIN, Inches(1.55), ds.CONTENT_W, Inches(1.35),
        [
            {"label": "Advisories Matched", "value": total_adv, "color": ds.P["navy"]},
            {"label": "Critical", "value": crit, "color": ds.P["crit_fg"]},
            {"label": "Important / High", "value": important, "color": ds.P["high_fg"]},
            {"label": "Unique CVEs", "value": len(unique_cves), "color": ds.P["accent"]},
            {"label": "Environment Targets", "value": len(targets), "color": ds.P["muted"]},
        ],
    )
    summary_sentence = (
        f"{total_adv} VMSA advisories match this environment's assessed versions, covering {len(unique_cves)} "
        f"unique CVE(s). {crit} are Critical and {important} are Important/High severity - "
        f"these should be prioritized for the next patch cycle."
    )
    ds.add_insight_bar(slide, ds.MARGIN, Inches(3.10), ds.CONTENT_W, Inches(1.05),
                        "Executive Summary", summary_sentence, color=ds.P["navy"])

    # Severity breakdown per detected category/version (mirrors the same
    # breakdown added to the "Detected Versions" table in the VMSA Version
    # Check HTML report) - one row per distinct MatchedAgainst target,
    # showing how many matched advisories fall into each of the same 4
    # severity buckets used everywhere else in this deck.
    target_order, target_category, target_counts = [], {}, {}
    for r in rows:
        key = r.get("MatchedAgainst", "") or "(unknown)"
        if key not in target_counts:
            target_order.append(key)
            target_category[key] = r.get("Category", "")
            target_counts[key] = {"Critical": 0, "High": 0, "Medium": 0, "Low": 0}
        bucket = _sev_bucket_name(r.get("Severity"))
        if bucket:
            target_counts[key][bucket] += 1
    target_order.sort(key=lambda k: sum(target_counts[k].values()), reverse=True)

    breakdown_y = Inches(4.35)
    max_targets_shown = 7
    shown_targets = target_order[:max_targets_shown]
    subtitle = "Severity Breakdown by Detected Category / Version"
    if len(target_order) > max_targets_shown:
        subtitle += f"  (top {max_targets_shown} of {len(target_order)}, by advisory count)"
    ds.add_text(slide, ds.MARGIN, breakdown_y, ds.CONTENT_W, Inches(0.24), subtitle, size=11.5, bold=True, color=ds.P["text"])
    breakdown_table_rows = [
        [target_category.get(k, ""), k, target_counts[k]["Critical"], target_counts[k]["High"],
         target_counts[k]["Medium"], target_counts[k]["Low"]]
        for k in shown_targets
    ]
    sev_col_colors = {
        2: lambda v: (ds.P["crit_bg"], ds.P["crit_fg"]),
        3: lambda v: (ds.P["high_bg"], ds.P["high_fg"]),
        4: lambda v: (ds.P["med_bg"], ds.P["med_fg"]),
        5: lambda v: (ds.P["low_bg"], ds.P["low_fg"]),
    }
    table_y = breakdown_y + Inches(0.32)
    table_h = ds.SLIDE_H - Inches(0.55) - table_y
    if breakdown_table_rows:
        ds.add_table(
            slide, ds.MARGIN, table_y, ds.CONTENT_W, table_h,
            ["Category", "Version", "Critical", "High", "Medium", "Low"], breakdown_table_rows,
            col_widths=[1.3, 2.6, 1, 1, 1, 1], font_size=10.5,
            badge_cols=sev_col_colors, zero_muted_cols=[2, 3, 4, 5],
        )
    add_content_footer(slide, source_label, 1, "N")

    # ---- Slide 2: Overview ----
    slide = ds.add_blank_slide(prs)
    content_y = ds.add_page_header(slide, "Advisory Overview", "Severity distribution across matched advisories")
    donut_w, donut_h = Inches(4.6), Inches(4.1)
    order = ["Critical", "Important", "High", "Moderate", "Medium", "Low"]
    labels_f, vals_f, colors = [], [], []
    seen = set()
    for lab in order:
        v = sev_counter.get(lab, 0)
        if v and lab not in seen:
            labels_f.append(lab)
            vals_f.append(v)
            colors.append(_sev_badge(lab)[1])
            seen.add(lab)
    for lab, v in sev_counter.items():
        if lab not in seen and v:
            labels_f.append(lab)
            vals_f.append(v)
            colors.append(ds.P["default_fg"])
    if vals_f:
        ds.add_donut_chart(slide, ds.MARGIN, content_y, donut_w, donut_h, labels_f, vals_f, colors)

    tbl_x = ds.MARGIN + donut_w + Inches(0.35)
    tbl_w = ds.SLIDE_W - ds.MARGIN - tbl_x
    ds.add_text(slide, tbl_x, content_y, tbl_w, Inches(0.26), "Advisories by Environment Target", size=12, bold=True, color=ds.P["text"])
    tgt_counter = Counter(r.get("MatchedAgainst", "") for r in rows)
    tgt_rows = [[t, c] for t, c in sorted(tgt_counter.items(), key=lambda kv: -kv[1])[:6]]
    if tgt_rows:
        ds.add_table(
            slide, tbl_x, content_y + Inches(0.34), tbl_w, Inches(2.6),
            ["Target", "Advisories"], tgt_rows, col_widths=[2.4, 1], font_size=10.5,
        )
    if tgt_rows:
        top_target, top_target_count = tgt_rows[0]
        note = (f"'{top_target}' has the most matched advisories ({top_target_count}), making it the priority "
                f"target for the next patch/upgrade cycle. See the Matched Advisories pages that follow for detail.")
        ds.add_insight_bar(slide, ds.MARGIN, Inches(5.35), ds.CONTENT_W, Inches(1.1), "Observation", note, color=ds.P["navy"])
    add_content_footer(slide, source_label, 2, "N")

    # ---- Slide(s) 3+: Critical/Important advisory table ----
    def cvss_val(r):
        try:
            return float(r.get("CVSS") or 0)
        except ValueError:
            return 0.0

    prioritized = sorted(rows, key=lambda r: (_sev_key(r.get("Severity")), -cvss_val(r)))
    prioritized = prioritized[:top_n]
    table_rows = [
        [r.get("AdvisoryID", ""), clip(r.get("Title", ""), 34), (r.get("Severity") or ""),
         r.get("CVSS", ""), r.get("Published", ""), clip(r.get("MatchedAgainst", ""), 20)]
        for r in prioritized
    ]
    pages = ds.paginate(table_rows, max_rows_per_slide)
    for pi, page_rows in enumerate(pages, start=1):
        slide = ds.add_blank_slide(prs)
        content_y = ds.add_page_header(slide, "Matched Advisories", f"Sorted by severity, then CVSS  ({pi}/{len(pages)})")
        ds.add_table(
            slide, ds.MARGIN, content_y, ds.CONTENT_W, ds.SLIDE_H - content_y - Inches(0.55),
            ["Advisory ID", "Title", "Severity", "CVSS", "Published", "Environment Target"], page_rows,
            col_widths=[1.1, 3.6, 1.0, 0.7, 1.0, 1.8], font_size=10,
            badge_col=2, badge_fn=_sev_badge,
        )
        add_content_footer(slide, source_label, "-", "-")

    # ---- CVE highlights (from CveLookupInfo, if present) ----
    highlight_items = []
    for r in prioritized:
        info = r.get("CveLookupInfo", "") or ""
        m = CVE_DESC_RE.search(info)
        if m:
            highlight_items.append((r, m.group(1), m.group(2)))
        if len(highlight_items) >= 3:
            break
    if highlight_items:
        slide = ds.add_blank_slide(prs)
        content_y = ds.add_page_header(slide, "CVE Highlights", "Top matched CVEs with NVD lookup detail (from CVE_Lookup_Cache.json)")
        card_w = (ds.CONTENT_W - Inches(0.3) * (len(highlight_items) - 1)) / len(highlight_items)
        card_bullets = []
        for r, cve_id, desc in highlight_items:
            card_bullets.append([
                f"Advisory: {r.get('AdvisoryID','')} ({r.get('Severity','')}, CVSS {r.get('CVSS','')})",
                clip(desc, 200),
            ])
        card_h = max(ds.bullet_card_height(len(b), bullet_size=10.5, max_h=Inches(3.4)) for b in card_bullets)
        for i, ((r, cve_id, desc), bullets) in enumerate(zip(highlight_items, card_bullets)):
            cx = ds.MARGIN + i * (card_w + Inches(0.3))
            ds.add_bullet_card(slide, cx, content_y, card_w, card_h, cve_id, bullets,
                                color=_sev_badge(r.get("Severity"))[1], title_size=12, bullet_size=10.5)
        note = ("CVE descriptions above come from the repo-root CVE_Lookup_Cache.json cache. Run menu [5] "
                "(VMSA Full List Download + CVE Lookup) to refresh this cache before regenerating this deck.")
        ds.add_insight_bar(slide, ds.MARGIN, content_y + card_h + Inches(0.3), ds.CONTENT_W, Inches(1.0),
                            "Data Source", note, color=ds.P["navy"])
        add_content_footer(slide, source_label, "-", "-")

    # ---- Closing ----
    slide = ds.add_blank_slide(prs)
    content_y = ds.add_page_header(slide, "Patch Priority Recommendations")
    card_w = (ds.CONTENT_W - Inches(0.3) * 2) / 3
    bullets_1 = [
        f"{crit} Critical-severity advisories affect this environment.",
        "Plan emergency or next-available maintenance windows for affected vCenter/ESXi hosts.",
    ]
    bullets_2 = [
        f"{important} Important/High advisories should be scheduled into the next regular patch cycle.",
        "Group by environment target to minimize the number of maintenance windows needed.",
    ]
    bullets_3 = [
        "Re-run menu [5] (VMSA Full List Download + CVE Lookup) periodically to keep",
        "VMSA_FullList_Data.json and CVE_Lookup_Cache.json current, then re-generate this deck.",
    ]
    card_h = max(ds.bullet_card_height(len(b)) for b in (bullets_1, bullets_2, bullets_3))
    ds.add_bullet_card(slide, ds.MARGIN, content_y, card_w, card_h, "1) Patch Critical First", bullets_1, color=ds.P["crit_fg"])
    ds.add_bullet_card(slide, ds.MARGIN + card_w + Inches(0.3), content_y, card_w, card_h, "2) Track Important/High", bullets_2, color=ds.P["high_fg"])
    ds.add_bullet_card(slide, ds.MARGIN + 2 * (card_w + Inches(0.3)), content_y, card_w, card_h, "3) Keep Advisory Data Fresh", bullets_3, color=ds.P["accent"])

    closing_note = (
        f"This summary was generated from {source_label}. {total_adv} advisories were matched against "
        f"{len(targets)} environment target(s); re-generate this deck after each menu [3]/[5] run to keep it current."
    )
    ds.add_insight_bar(slide, ds.MARGIN, content_y + card_h + Inches(0.3), ds.CONTENT_W, Inches(1.15),
                        "Next Steps", closing_note, color=ds.P["navy"])
    add_content_footer(slide, source_label, "N", "N")

    _renumber_footers(prs, skip_first=1)
    return prs


# ==========================================================================
# Footer page-numbering fixup
# ==========================================================================
def _renumber_footers(prs, skip_first=1):
    """Slides were built with page markers of '-' or 'N' as placeholders
    because the final slide count wasn't known yet; walk the finished deck
    and rewrite the footer's page-number textbox (always the last shape
    add_footer created on a slide that called it) with real 'i / total'."""
    total = len(prs.slides)
    for idx, slide in enumerate(prs.slides, start=1):
        # The footer page-number textbox is identifiable as the last
        # textbox whose text matches one of our placeholder patterns.
        for shape in slide.shapes:
            if not shape.has_text_frame:
                continue
            text = shape.text_frame.text
            if re.fullmatch(r"(-|\d+|N) / (-|\d+|N)", text):
                shape.text_frame.paragraphs[0].runs[0].text = f"{idx} / {total}"


# ==========================================================================
# CLI
# ==========================================================================
def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--input-folder", type=Path, default=None,
                     help="Root folder to search for the 3 known result-file patterns (e.g. the toolkit's output\\ folder). "
                          "Skipped for any deck whose file(s) are given explicitly below.")
    ap.add_argument("--kisa-csv", type=Path, default=None, help="Path to kisa_virtualization_report_*.csv")
    ap.add_argument("--scg-summary-csv", type=Path, default=None, help="Path to audit_report_summary.csv")
    ap.add_argument("--scg-details-csv", type=Path, default=None, help="Path to audit_report_details.csv")
    ap.add_argument("--vmsa-csv", type=Path, default=None, help="Path to VMSA_Environment_Match_*.csv")
    ap.add_argument("--output-dir", type=Path, default=None, help="Where to write the .pptx files (default: --input-folder, or cwd)")
    ap.add_argument("--only", type=str, default="kisa,scg,vmsa", help="Comma-separated subset to build: kisa,scg,vmsa (default: all)")
    ap.add_argument("--max-rows-per-slide", type=int, default=MAX_ROWS_PER_SLIDE_DEFAULT)
    ap.add_argument("--top-n", type=int, default=TOP_N_DEFAULT, help="Cap on rows shown in each findings table (worst-first)")
    args = ap.parse_args()

    wanted = {s.strip().lower() for s in args.only.split(",") if s.strip()}
    root = args.input_folder
    out_dir = args.output_dir or root or Path.cwd()
    out_dir.mkdir(parents=True, exist_ok=True)
    tag = timestamp_tag()

    built = []

    # ---- KISA ----
    if "kisa" in wanted:
        kisa_path = args.kisa_csv
        if kisa_path is None and root is not None:
            kisa_path = find_latest(root, "kisa_virtualization_report_*.csv")
        if kisa_path is None:
            print("[kisa] SKIPPED - no kisa_virtualization_report_*.csv found (pass --kisa-csv or --input-folder).", file=sys.stderr)
        else:
            rows = load_csv(kisa_path)
            if not rows:
                print(f"[kisa] SKIPPED - {kisa_path} has no data rows.", file=sys.stderr)
            else:
                prs = build_kisa_deck(rows, kisa_path.name, args.max_rows_per_slide, args.top_n)
                out_path = out_dir / f"KISA_Security_Summary_{tag}.pptx"
                prs.save(out_path)
                built.append(out_path)
                print(f"[kisa] wrote {out_path} ({len(prs.slides)} slides, {len(rows)} source rows)")

    # ---- SCG ----
    if "scg" in wanted:
        details_path = args.scg_details_csv
        summary_path = args.scg_summary_csv
        if details_path is None and root is not None:
            details_path, auto_summary = find_latest_scg(root)
            if summary_path is None:
                summary_path = auto_summary
        if details_path is None or summary_path is None:
            print("[scg] SKIPPED - need both audit_report_summary.csv and audit_report_details.csv "
                  "(pass --scg-summary-csv/--scg-details-csv or --input-folder).", file=sys.stderr)
        else:
            summary_rows = load_csv(summary_path)
            detail_rows = load_csv(details_path)
            if not summary_rows and not detail_rows:
                print(f"[scg] SKIPPED - {summary_path} / {details_path} have no data rows.", file=sys.stderr)
            else:
                label = f"{summary_path.parent.name}"
                prs = build_scg_deck(summary_rows, detail_rows, label, args.max_rows_per_slide, args.top_n)
                out_path = out_dir / f"Security_Compliance_Guide_Summary_{tag}.pptx"
                prs.save(out_path)
                built.append(out_path)
                print(f"[scg] wrote {out_path} ({len(prs.slides)} slides, "
                      f"{len(summary_rows)} summary rows, {len(detail_rows)} detail rows)")

    # ---- VMSA ----
    if "vmsa" in wanted:
        vmsa_path = args.vmsa_csv
        if vmsa_path is None and root is not None:
            vmsa_path = find_latest(root, "VMSA_Environment_Match_*.csv")
        if vmsa_path is None:
            print("[vmsa] SKIPPED - no VMSA_Environment_Match_*.csv found (pass --vmsa-csv or --input-folder).", file=sys.stderr)
        else:
            rows = load_csv(vmsa_path)
            if not rows:
                print(f"[vmsa] SKIPPED - {vmsa_path} has no data rows.", file=sys.stderr)
            else:
                prs = build_vmsa_deck(rows, vmsa_path.name, args.max_rows_per_slide, args.top_n)
                out_path = out_dir / f"VMSA_Version_Mapping_Summary_{tag}.pptx"
                prs.save(out_path)
                built.append(out_path)
                print(f"[vmsa] wrote {out_path} ({len(prs.slides)} slides, {len(rows)} source rows)")

    if not built:
        print("No decks were built - check the warnings above.", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()
