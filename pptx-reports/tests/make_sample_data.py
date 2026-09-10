#!/usr/bin/env python3
"""Generates larger, more realistic synthetic CSVs (multi-host / multi-object /
multi-advisory) than the tiny 3-4 row fixtures used for Task D, so the new
Python deck generator's pagination, sorting, and charts can be exercised
properly before delivery. Output goes under tests/sample_data/."""
import csv
import random
from pathlib import Path

random.seed(42)
OUT = Path(__file__).parent / "sample_data"

# ---- KISA ----
kisa_dir = OUT / "kisa_esx" / "output_esxi"
kisa_dir.mkdir(parents=True, exist_ok=True)
codes = [
    ("HV-01", "관리자 계정 변경", "상"), ("HV-02", "패스워드 복잡도", "상"),
    ("HV-03", "계정 잠금 임계값", "중"), ("HV-04", "불필요 서비스 제거", "중"),
    ("HV-05", "로그 서버 연동", "상"), ("HV-06", "NTP 서버 설정", "중"),
    ("HV-07", "SSH 접속 제한", "상"), ("HV-08", "관리 포트 제한", "중"),
    ("HV-09", "스냅샷 보관 주기", "하"), ("HV-10", "가상 스위치 보안 정책", "상"),
    ("HV-11", "vMotion 암호화", "중"), ("HV-12", "TLS 버전 강제", "상"),
    ("HV-13", "인증서 유효기간", "하"), ("HV-14", "로그 보관 기간", "중"),
    ("HV-15", "관리 네트워크 분리", "상"),
]
hosts = [f"esxi{i:02d}" for i in range(1, 7)]
rows = []
for h in hosts:
    for code, title, imp in codes:
        r = random.random()
        if imp == "상":
            status = "PASS" if r > 0.4 else "FAIL"
        elif imp == "중":
            status = "PASS" if r > 0.3 else random.choice(["FAIL", "WARN", "MANUAL"])
        else:
            status = "PASS" if r > 0.2 else random.choice(["WARN", "MANUAL", "ERROR"])
        detail = "정상" if status == "PASS" else f"{title} 항목 조치 필요"
        rows.append([h, code, title, imp, status, detail])
with open(kisa_dir / "kisa_virtualization_report_20260910-0900.csv", "w", newline="", encoding="utf-8-sig") as f:
    w = csv.writer(f)
    w.writerow(["HostName", "Code", "Title", "Importance", "Status", "Detail"])
    w.writerows(rows)

# ---- Security Compliance Guide ----
scg_dir = OUT / "security-hardening" / "Audit_Report_20260910-0900"
scg_dir.mkdir(parents=True, exist_ok=True)
objects = [("vCenter", "vc01"), ("ESXi", "esxi01"), ("ESXi", "esxi02"), ("ESXi", "esxi03"),
           ("VM", "vm-web01"), ("VM", "vm-db01"), ("VM", "vm-app01")]
summary_rows = []
detail_rows = []
scg_controls = [
    ("SCG-001", "P0", "NTP Configuration", "NTP not configured consistently", "vc01-ntp-fix"),
    ("SCG-002", "P0", "Centralized Log Forwarding", "Syslog forwarding disabled", "Enable-Syslog"),
    ("SCG-010", "P1", "Snapshot Age", "Snapshot older than 7 days", "Remove-Snapshot"),
    ("SCG-014", "P1", "Lockdown Mode", "Lockdown mode not enabled", "Enable-LockdownMode"),
    ("SCG-022", "P2", "DCUI Timeout", "DCUI timeout above recommended value", "Set-DcuiTimeOut"),
    ("SCG-031", "P2", "SSH Service Policy", "SSH service set to start/stop with host", "Set-SshPolicy"),
    ("SCG-040", "Advanced", "VM Console Copy/Paste", "Copy/paste enabled on VM", "Disable-CopyPaste"),
]
for otype, oname in objects:
    n_ctrl = random.randint(18, 30)
    fails = random.sample(scg_controls, k=random.randint(1, 4))
    n_fail = len(fails)
    n_info = random.randint(0, 2)
    n_pass = n_ctrl - n_fail - n_info
    rate = round(100.0 * n_pass / n_ctrl, 0)
    summary_rows.append([otype, oname, n_pass, n_fail, n_info, n_ctrl, f"{int(rate)}%"])
    for scg_id, prio, title, msg, remediation in fails:
        detail_rows.append([otype, oname, "FAIL", msg, scg_id, prio, title, "default",
                             f"STIG-{random.randint(1,60)}", f"PCI-{random.randint(1,12)}", remediation])
    for _ in range(n_info):
        detail_rows.append([otype, oname, "INFO", "Manual verification recommended", "", "", "", "", "", "", ""])

with open(scg_dir / "audit_report_summary.csv", "w", newline="", encoding="utf-8-sig") as f:
    w = csv.writer(f)
    w.writerow(["Type", "Object", "Pass", "Fail", "Info", "Total", "PassRate"])
    w.writerows(summary_rows)
with open(scg_dir / "audit_report_details.csv", "w", newline="", encoding="utf-8-sig") as f:
    w = csv.writer(f)
    w.writerow(["Type", "Object", "Status", "Message", "SCG ID", "Priority", "SCG Title",
                "Baseline", "DISA STIG", "PCI DSS 4.0", "Remediation"])
    w.writerows(detail_rows)

# ---- VMSA ----
vmsa_dir = OUT / "vmsa" / "vmsa_environment"
vmsa_dir.mkdir(parents=True, exist_ok=True)
severities = ["Critical", "Important", "Moderate", "Low"]
targets = ["vCenter 8.0.2", "ESXi 8.0.2", "ESXi 8.0.1", "vCenter 7.0.3"]
vmsa_rows = []
descs = [
    "Out-of-bounds write vulnerability in the VMX process",
    "Authentication bypass in vCenter Server plugin",
    "Heap overflow in USB controller",
    "SQL injection in vCenter Server database interface",
    "Local privilege escalation via VMware Tools",
]
for i in range(1, 23):
    sev = random.choices(severities, weights=[3, 5, 6, 4])[0]
    cvss = {"Critical": round(random.uniform(9.0, 10.0), 1), "Important": round(random.uniform(7.0, 8.9), 1),
            "Moderate": round(random.uniform(4.0, 6.9), 1), "Low": round(random.uniform(1.0, 3.9), 1)}[sev]
    cve = f"CVE-2025-{20000+i}"
    desc = random.choice(descs)
    lookup = f"{cve} [Description={desc}]" if random.random() > 0.3 else ""
    target = random.choice(targets)
    category = "vCenter" if target.startswith("vCenter") else "ESX"  # Category always matches its target, like the real tool's output
    vmsa_rows.append([
        i, target, category, "Direct",
        f"VMSA-2025-{i:04d}", f"VMware {random.choice(['vCenter Server','ESXi'])} update addresses {sev.lower()} issue",
        sev, cvss, f"2025-{random.randint(1,9):02d}-{random.randint(1,28):02d}", cve,
        "8.0.3", "", "", "https://www.vmware.com/security/advisories/", lookup,
    ])
with open(vmsa_dir / "VMSA_Environment_Match_20260910-0900.csv", "w", newline="", encoding="utf-8-sig") as f:
    w = csv.writer(f)
    w.writerow(["No", "MatchedAgainst", "Category", "MatchType", "AdvisoryID", "Title", "Severity", "CVSS",
                "Published", "CVEs", "MatchedFixVersions", "MatchedRowsDetail", "PossibleBundleRowsDetail",
                "Link", "CveLookupInfo"])
    w.writerows(vmsa_rows)

print("Sample data written under", OUT)
