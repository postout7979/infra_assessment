# vSphere Audit Reporter

기존에 수집된 vSphere 보안 감사(security hardening audit) 로그(txt)를 읽어서, 보기 좋은 HTML 리포트 한 장으로 정리해 주는 PowerShell 스크립트입니다. `auditreporter.ps1` 스크립트 하나로 동작하며, vCenter 접속이나 Office(Excel/PowerPoint) 설치 없이도 실행됩니다.

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
- **결과는 HTML 리포트 하나**: 별도 JSON, Excel, PowerPoint 파일은 생성하지 않습니다.

## 사전 준비물

- Windows PowerShell (5.1 이상) 또는 PowerShell 7 이상
- 감사 로그 txt 파일이 모여 있는 폴더 (아래 "로그 폴더 준비" 참고)

별도의 PowerShell 모듈(VCF.PowerCLI 등)이나 vCenter 로그인 정보는 필요하지 않습니다.

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
└── AuditReport_20260228_143000\
    └── audit_report.html
```

- 폴더명은 `AuditReport_yyyyMMdd_HHmmss` 형식으로, 실행할 때마다 새로 생성되어 이전 결과를 덮어쓰지 않습니다.
- `audit_report.html`은 브라우저로 열어서 바로 확인할 수 있으며, 인터넷 연결 없이도 동작하는 단일 HTML 파일입니다(첨부된 `audit_report.html`이 실제 실행 결과 예시입니다).
- 스크립트 실행이 끝나면 결과 폴더가 자동으로 열립니다.

## HTML 리포트 사용법

- 상단 대시보드에서 전체 Total / PASS / FAIL / INFO 건수와 Pass Rate를 확인합니다.
- 검색창에 오브젝트 이름 일부를 입력하면 실시간으로 필터링됩니다.
- `All` / `vCenter` / `ESXi` / `VM` 버튼으로 타입별로만 볼 수 있습니다.
- 각 오브젝트 행의 `Details` 버튼(또는 행 클릭)을 누르면 상세 로그가 열리며, `FAIL (n)` / `PASS (n)` / `INFO (n)` 탭을 눌러 상태별로 전환할 수 있습니다.

## 문제 해결

| 증상 | 원인 / 조치 |
|---|---|
| `No .txt log files found in the selected folder.` | 선택한 폴더에 `.txt` 로그 파일이 없습니다. 폴더 경로를 확인하세요. |
| `Skipped (unrecognized audit type): <파일명>` | 해당 txt 파일 첫 5줄에서 `VMware vCenter` / `ESX Host` / `Virtual Machine` 문구를 찾지 못했습니다. 원본 감사 유틸리티가 생성한 로그 형식인지 확인하세요. |
| 오브젝트 이름이 예상과 다르게 나옴 | 로그 내부에 `Audit of <이름> started` 줄이 없으면 파일명(확장자 제외)을 이름으로 사용합니다. |

## 변경 이력 (요약)

- HTML 리포트 UI를 대시보드 형태로 개편, 오브젝트별 PASS/FAIL/INFO 수치 표시 및 상태별 탭 상세 보기 추가
- vCenter 접속 로직 제거 → 로그 파일 배너 문구로 자동 판별하는 방식으로 전환
- 결과 저장 위치를 로그 폴더가 아닌 스크립트 실행 위치의 신규 폴더로 변경
- JSON 결과 파일 생성 제거
- (검토 후 제거됨) Excel / PowerPoint 결과물 생성 기능
