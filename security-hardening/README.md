# vSphere Audit Reporter

기존에 수집된 vSphere 보안 감사(security hardening audit) 로그(txt)를 읽어서, 보기 좋은 HTML 리포트와 CSV, (가능한 경우) Excel 파일로 정리해 주는 PowerShell 스크립트입니다. `auditreporter.ps1` 스크립트 하나로 동작하며, vCenter 접속이나 Office(Excel/PowerPoint) 설치 없이도 실행됩니다.

## 주요 특징

- **vCenter 접속 불필요**: 각 로그 파일 첫 줄의 배너 문구만으로 대상 종류를 자동 판별합니다.
  - `VMware vCenter ...` 포함 → **vCenter**
  - `VMware ESX Host ...` 포함 → **ESXi**
  - `VMware Virtual Machine ...` 포함 → **VM**
  - 위 세 가지에 해당하지 않는 txt 파일은 인식 불가로 건너뛰고 경고만 출력합니다.
- **대상 이름 자동 추출**: 로그 내부의 `Audit of <이름> started` 줄에서 이름을 우선 추출하고, 없으면 파일명을 사용합니다.
- **오브젝트별 PASS / FAIL / INFO 집계**: 리포트 목록과 상세 화면 모두에서 상태별 개수를 바로 확인할 수 있습니다.
- **상태별로 구분된 상세 보기**: 오브젝트를 클릭하면 FAIL / PASS / INFO 탭으로 나뉘어 표시되며(FAIL이 있으면 기본으로 FAIL 탭이 열림), 각 탭 옆에 개수가 함께 표시됩니다.
- **검색 및 타입 필터**: 상단 검색창으로 오브젝트 이름을 검색하고, vCenter / ESXi / VM 버튼으로 타입별로 필터링할 수 있습니다.
- **HTML + CSV + Excel(선택) 동시 생성**: 브라우저용 HTML 리포트 외에 요약/상세 CSV 파일이 항상 함께 생성됩니다. `ImportExcel` PowerShell 모듈이 설치되어 있으면 Excel(xlsx) 파일도 자동으로 생성되고, 모듈이 없으면 Excel 생성 단계만 건너뛰고 HTML/CSV는 정상적으로 생성됩니다(스크립트 실행이 중단되지 않습니다).
- **VMware Security Configuration Guide(SCG) 매칭(선택)**: 스크립트와 같은 위치에 공식 SCG "controls" CSV를 두면, 각 점검 항목을 해당 공식 컨트롤(SCG ID, 우선순위, 제목, 권장 기준값, DISA STIG/PCI DSS 매핑, 원격 조치 명령)과 자동으로 매칭해 HTML/CSV/Excel 모두에 반영합니다. 파일이 없으면 이 단계는 조용히 건너뛰고 기존과 동일하게 동작합니다.

## 사전 준비물

- Windows PowerShell (5.1 이상) 또는 PowerShell 7 이상
- 감사 로그 txt 파일이 모여 있는 폴더 (아래 "로그 폴더 준비" 참고)
- (선택) Excel 파일까지 생성하려면 `ImportExcel` 모듈이 필요합니다. 설치되어 있지 않아도 HTML/CSV 생성에는 영향이 없습니다.

  ```powershell
  Install-Module ImportExcel -Scope CurrentUser
  ```

vCenter 접속 정보나 VCF.PowerCLI 같은 모듈은 필요하지 않습니다.

## SCG(Security Configuration Guide) 컨트롤 매칭 (선택)

Broadcom/VMware가 배포하는 **vSphere Security Configuration Guide 8 "controls" CSV**를 `auditreporter.ps1`과 같은 폴더에 두면, 실행 시 자동으로 인식되어 각 점검 항목을 공식 컨트롤 번호와 매칭합니다.

```
audit\
├── auditreporter.ps1
├── vmware-vsphere-security-configuration-guide-8-controls.csv   <- 여기에 두면 자동 인식
└── 2026-02-10_logs\
    └── ...
```

- **파일명은 상관없습니다.** 스크립트는 폴더 내 모든 `*.csv` 파일의 첫 줄(헤더)을 확인해서 `SCG ID`와 `Configuration Parameter` 컬럼이 모두 있는 CSV를 자동으로 찾아 사용합니다. 해당하는 CSV가 없으면 이 기능은 건너뛰고 나머지는 기존과 동일하게 동작합니다(실행이 중단되지 않습니다).
- 매칭에 성공하면 HTML 상세 로그의 각 줄 오른쪽에 `SCG ID · 우선순위` 배지(pill)가 표시되며, 마우스를 올리면 컨트롤 제목/권장 기준값/DISA STIG/PCI DSS 4.0 매핑/원격 조치(Remediation) 명령을 툴팁으로 확인할 수 있습니다. CSV/Excel의 상세 데이터에는 `SCG ID`, `Priority`, `SCG Title`, `Baseline`, `DISA STIG`, `PCI DSS 4.0`, `Remediation` 7개 컬럼이 추가됩니다.
- **매칭률은 100%가 아닙니다.** 실제 감사 로그 기준 약 **69%**(로그 항목 기준)가 매칭되며, 나머지는 아래와 같은 이유로 매칭되지 않을 수 있습니다.
  - VLAN 기본값, VM 하드웨어 버전, NTP 서비스 상태 등 SCG 컨트롤 목록 자체에 대응 항목이 없는 점검
  - `[INFO]` 배너/메타 문구(유틸리티 버전, 감사 시작 시각 등) 등 애초에 보안 컨트롤과 무관한 줄
  - 로그 문구가 SCG CSV의 `Configuration Parameter` 값과 정확히 일치하지 않는 일부 항목(스크립트 내부에 수작업으로 검증한 보조 매핑 테이블을 추가해 매칭률을 높였지만, 모든 문구를 커버하지는 못합니다)
- SCG CSV가 없어도 HTML/CSV/Excel은 기존과 완전히 동일한 형식(추가 컬럼 없음)으로 생성됩니다.

## 로그 폴더 준비

`auditreporter.ps1`이 있는 위치를 기준으로, 그 아래에 감사 로그(txt)들이 들어 있는 하위 폴더를 하나 준비합니다.

```
audit\
├── auditreporter.ps1
└── 2026-02-10_logs\          <- 이 폴더를 스크립트 실행 시 선택
    ├── vc.vks.lab.txt        (vCenter)
    ├── fu01.vks.lab.txt      (ESXi)
    ├── fu02.vks.lab.txt      (ESXi)
    ├── fu03.vks.lab.txt      (ESXi)
    ├── avi.txt               (VM)
    ├── avi_svc_controller01.txt   (VM)
    └── avicontroller01.txt        (VM)
```

각 txt 파일은 `[PASS]`, `[FAIL]`, `[INFO]`, `[WARNING]`, `[ERROR]` 형태의 상태 태그가 포함된 감사 로그 형식이어야 합니다(`WARNING`은 `INFO`로, `ERROR`는 `FAIL`로 집계됩니다).

## 실행 방법

1. `auditreporter.ps1`을 원하는 위치(예: `C:\powercli\audit\`)에 둡니다.
2. PowerShell에서 스크립트를 실행합니다.

   ```powershell
   cd C:\powercli\audit
   .\auditreporter.ps1
   ```

3. 감사 로그가 들어 있는 하위 폴더 번호를 선택합니다.
4. 로그 분류 및 분석이 끝나면, 스크립트가 있는 위치에 결과 폴더가 자동으로 생성되고 리포트가 저장됩니다.

## 결과물

스크립트를 실행한 위치에 아래와 같은 폴더가 생성됩니다.

```
audit\
└── Output_20260228_143000\
    ├── audit_report.html
    ├── audit_report_summary.csv
    ├── audit_report_details.csv
    └── audit_report.xlsx        (ImportExcel 모듈이 설치된 경우에만 생성)
```

- 폴더명은 `Output_yyyyMMdd_HHmmss` 형식으로, 실행할 때마다 새로 생성되어 이전 결과를 덮어쓰지 않습니다.
- `audit_report.html`은 브라우저로 열어서 바로 확인할 수 있으며, 인터넷 연결 없이도 동작하는 단일 HTML 파일입니다(첨부된 `audit_report.html`이 실제 실행 결과 예시입니다).
- `audit_report_summary.csv`: 오브젝트별 Type / Pass / Fail / Info / Total / PassRate 요약.
- `audit_report_details.csv`: 모든 개별 점검 항목(Type / Object / Status / Message)을 한 줄씩 기록한 상세 목록. SCG controls CSV가 인식된 경우 `SCG ID` / `Priority` / `SCG Title` / `Baseline` / `DISA STIG` / `PCI DSS 4.0` / `Remediation` 7개 컬럼이 추가로 붙습니다(인식되지 않으면 기존과 동일한 4개 컬럼만 생성).
- `audit_report.xlsx`: `ImportExcel` 모듈이 설치되어 있을 때만 생성되며, `Summary` / `Details` 두 개의 시트로 위 CSV 내용과 동일한 데이터를 담습니다. 모듈이 없으면 이 파일은 생성되지 않고, 콘솔에 건너뛰었다는 안내만 출력됩니다.
- 스크립트 실행이 끝나면 결과 폴더가 자동으로 열립니다.

## HTML 리포트 사용법

- 상단 대시보드에서 전체 Total / PASS / FAIL / INFO 건수와 Pass Rate를 확인합니다.
- 검색창에 오브젝트 이름 일부를 입력하면 실시간으로 필터링됩니다.
- `All` / `vCenter` / `ESXi` / `VM` 버튼으로 타입별로만 볼 수 있습니다.
- 각 오브젝트 행의 `Details` 버튼(또는 행 클릭)을 누르면 상세 로그가 열리며, `FAIL (n)` / `PASS (n)` / `INFO (n)` 탭을 눌러 상태별로 전환할 수 있습니다.
- 상단 대시보드 아래에는 SCG controls CSV 인식 여부와 매칭 건수가 표시됩니다(예: `SCG Controls: vmware-vsphere-security-configuration-guide-8-controls.csv (156 controls) — 996 check(s) matched to an official control`). 매칭된 상세 로그 줄에는 오른쪽에 `SCG ID · 우선순위` 배지가 표시되며, 마우스를 올리면 상세 정보(툴팁)를 볼 수 있습니다.

## 문제 해결

| 증상 | 원인 / 조치 |
|---|---|
| `No .txt log files found in the selected folder.` | 선택한 폴더에 `.txt` 로그 파일이 없습니다. 폴더 경로를 확인하세요. |
| `Skipped (unrecognized audit type): <파일명>` | 해당 txt 파일 첫 5줄에서 `VMware vCenter` / `ESX Host` / `Virtual Machine` 문구를 찾지 못했습니다. 원본 감사 유틸리티가 생성한 로그 형식인지 확인하세요. |
| 오브젝트 이름이 예상과 다르게 나옴 | 로그 내부에 `Audit of <이름> started` 줄이 없으면 파일명(확장자 제외)을 이름으로 사용합니다. |
| `! ImportExcel module not found. Skipping Excel export.` | `ImportExcel` 모듈이 설치되어 있지 않습니다. HTML/CSV는 정상적으로 생성됩니다. Excel까지 필요하면 `Install-Module ImportExcel -Scope CurrentUser`로 설치 후 다시 실행하세요. |
| `No SCG controls CSV found next to the script. Skipping SCG enrichment.` | 스크립트와 같은 폴더에서 `SCG ID` / `Configuration Parameter` 헤더를 가진 CSV를 찾지 못했습니다. 공식 SCG controls CSV를 스크립트와 같은 폴더에 두었는지 확인하세요. 이 CSV가 없어도 HTML/CSV/Excel은 정상적으로 생성됩니다(추가 컬럼만 생략). |

## 변경 이력 (요약)

- 스크립트와 같은 폴더의 VMware Security Configuration Guide(SCG) controls CSV를 자동 인식하여, HTML/CSV/Excel 상세 결과에 공식 컨트롤(SCG ID, 우선순위, 제목, 권장 기준값, DISA STIG/PCI DSS 매핑, 원격 조치 명령) 매칭 정보 추가 — CSV가 없으면 자동으로 건너뛰고 기존과 동일하게 동작
- 결과물에 CSV(요약/상세) 및 Excel(xlsx, `ImportExcel` 모듈 설치 시) 출력 추가 — Excel 모듈이 없으면 자동으로 건너뛰고 HTML/CSV만 생성
- HTML 리포트 UI를 대시보드 형태로 개편, 오브젝트별 PASS/FAIL/INFO 수치 표시 및 상태별 탭 상세 보기 추가
- vCenter 접속 로직 제거 → 로그 파일 배너 문구로 자동 판별하는 방식으로 전환
- 결과 저장 위치를 로그 폴더가 아닌 스크립트 실행 위치의 신규 폴더로 변경
- JSON 결과 파일 생성 제거
