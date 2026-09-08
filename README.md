# allinonevmw.ps1 사용법

`postout7979/infra_assessment` 저장소의 VMware/VCF 인프라 점검 도구들을 하나의 메뉴에서
실행할 수 있도록 통합한 올인원 런처 스크립트입니다. 원래 각 폴더(`vcf_9_upgrade`,
`Operations`, `security-hardening`, `vcenter`, `vmsa`, `kisa_esx`)에 흩어져 있던 스크립트
로직이 전부 이 파일 하나에 함수로 인라인되어 있어서, 실행 시 별도 하위 스크립트를 호출하지
않습니다.

## 1. 사전 준비물

- **PowerShell 7.0 이상** (`#Requires -Version 7.0`)
- **인터넷 연결** — 최초 실행 시 `VMware.PowerCLI` 모듈이 없으면 자동 설치를 시도합니다
  (PSGallery 접근 필요). 인터넷이 차단된 폐쇄망이라면, 인터넷이 되는 PC에서 PowerCLI ZIP을
  내려받아 오프라인으로 설치해야 하며, 스크립트가 이 경우 안내 메시지를 출력합니다.
- **(선택) ImportExcel 모듈** — 설치돼 있으면 각 도구가 CSV 결과와 함께 통합 엑셀
  워크북(.xlsx)도 자동으로 하나 더 생성합니다. 설치되어 있지 않아도 CSV 출력에는 전혀 영향이
  없습니다.
  ```powershell
  Install-Module ImportExcel -Scope CurrentUser
  ```
- 메뉴 `[5]` (VMSA 전체 목록 다운로드 + CVE 조회)는 실행 중 인터넷 연결이 계속 필요합니다
  (VMSA 공지사항/NVD CVE 정보를 온라인으로 조회하기 때문).

## 2. 폴더 구성 (최초 1회 설정)

이 스크립트는 저장소 루트에 있어야 하며, 아래 2가지 항목을 원래 있던 하위 폴더에서 루트로
옮겨야 합니다.

```
infra_assessment\                      <- git clone https://github.com/postout7979/infra_assessment
 ├─ allinonevmw.ps1                    <- 이 스크립트
 ├─ hcl\                               <- (이동) vcf_9_upgrade\hcl\ 에서 이동
 ├─ vmware-vsphere-security-configuration-guide-8-controls.csv   <- (이동) security-hardening\ 에서 이동
 ├─ VMSA_FullList_Data.json           <- 메뉴 [5] 실행 시 여기 자동 생성/갱신 (누적 캐시 파일,
 │                                        output\ 폴더 정리와 무관하게 항상 유지됨)
 ├─ CVE_Lookup_Cache.json             <- 메뉴 [5] 실행 시 여기 자동 생성/갱신 (누적 캐시 파일,
 │                                        output\ 폴더 정리와 무관하게 항상 유지됨)
 └─ output\                            <- 실행 결과가 저장되는 폴더 (자동 생성됨)
     ├─ vcf_9_upgrade\
     ├─ Operations\
     ├─ security-hardening\
     ├─ vcenter\
     ├─ vmsa\
     └─ kisa_esx\
```

`hcl\` 폴더와 `vmware-vsphere-security-configuration-guide-8-controls.csv`는 이번 전달
zip에 함께 포함되어 있으니, 위 위치에 그대로 복사해 넣으면 됩니다.

기존 저장소 폴더(`vcf_9_upgrade`, `Operations`, `security-hardening`, `vcenter`, `vmsa`,
`kisa_esx`)는 실행 시 더 이상 필요하지 않습니다. 다만 `security-hardening\vmware-tools\
scg-common.psm1`은 이 병합 범위에서 제외된 `remediate-esxi-8.ps1` / `remediate-vcenter-8.ps1`
/ `remediate-vm-8.ps1` 3개 스크립트가 여전히 참조하므로 원래 위치에 그대로 남겨둬야 합니다.

저장소를 다른 경로에 두고 싶다면, 환경 변수 `VMWTOOLS_INFRA_PATH`에 그 루트 경로를 지정하면
됩니다.

## 3. 실행 방법

```powershell
.\allinonevmw.ps1
```

최초 실행 시 실행 정책 오류가 나면:

```powershell
Set-ExecutionPolicy -Scope CurrentUser RemoteSigned
```

GitHub에서 ZIP으로 내려받은 경우, Windows가 파일을 "인터넷에서 다운로드됨"으로 표시해
"디지털 서명이 되어 있지 않습니다" 오류가 날 수 있습니다. 스크립트가 시작 시 자동으로
`Unblock-File`을 실행하지만, 그래도 오류가 계속되면 아래 명령을 수동으로 실행하세요.

```powershell
Get-ChildItem -Path . -Recurse | Unblock-File
```

## 4. 메인 메뉴 구성

```
  [1] VCF 9 Upgrade (Pre-check / NVMe Tiering Analysis)           (vcf_9_upgrade)
  [2] VCF Operations Report                                       (Operations)
  [3] vCenter Security Suite: Hardening Audit + VMSA Version Check + KISA Audit
                                                                  (single vCenter login)
  [4] vCenter Daily Comprehensive Report                          (vcenter)
  [5] VMSA Full List Download + CVE Lookup  (Internet connection required - takes a long time)

  [0] Exit
```

### [1] VCF 9 Upgrade (사전 점검 / NVMe 티어링 분석)

인벤토리 수집 + HCL 호환성 점검이 끝나면, 별도 확인 없이 곧바로 NVMe 메모리 티어링 분석까지
자동으로 이어서 실행됩니다(하위 메뉴 없이 한 번에 진행). NVMe 분석만 단독으로 돌리거나
인벤토리/HCL 점검만 따로 실행하고 싶다면, 이 메뉴 진입 후 나오는 하위 옵션에서 개별 선택도
가능합니다.

- 결과: `output\vcf_9_upgrade\vSphere_Inventory_<타임스탬프>\`,
  `output\vcf_9_upgrade\compatibility_<타임스탬프>\`,
  `output\vcf_9_upgrade\nvme_tiering_<타임스탬프>\` 등
- CSV 옆에 ImportExcel이 설치돼 있으면 `Compatibility_Summary.xlsx`,
  `NVMe_Tiering_Report_<타임스탬프>.xlsx` 등 통합 엑셀 파일도 함께 생성됩니다.

### [2] VCF Operations Report

VCF Operations(Aria Operations) API를 통한 인벤토리/성능 리포트를 생성합니다.
`output\Operations\` 아래에 결과가 저장됩니다.

### [3] vCenter Security Suite (통합 보안 점검)

vCenter 주소를 먼저 입력받고, 그 다음 계정/암호를 한 번만 입력받아 아래 3개 점검을
하위 메뉴 없이 순서대로 자동 실행합니다.

1. 보안 하드닝 감사 실행 → 리포트 생성까지 자동 연계
2. VMSA 버전 점검(설치된 vCenter/ESXi 버전 기준 해당 VMSA 취약점 매칭)
3. KISA 가상화 보안 점검(HV-01 ~ HV-25)

콘솔/로그에 표시되는 모든 호스트명·IP는 마스킹 처리됩니다(예: `10.20.30.40` →
`***.***.***.40`, `host.corp.local` → `host.***.***`). 실제 vCenter/ESXi API 호출은
마스킹되지 않은 실제 이름으로 정상 수행되며, 화면 출력과 파일명만 마스킹됩니다.

- 결과: `output\security-hardening\`, `output\vmsa\` (버전 점검 CSV/HTML),
  `output\kisa_esx\output_esxi\`

### [4] vCenter Daily Comprehensive Report

vCenter 하나 또는 여러 대(쉼표로 구분 입력 가능)에 대한 일일 종합 리포트를 생성합니다.
입력을 비워두면 실행 중 별도로 물어봅니다.

- 결과: `output\vcenter\DailyReport_<날짜>\` (CSV, HTML, 그리고 ImportExcel이 설치돼
  있으면 `DailyReport_Summary_<날짜>.xlsx`)

### [5] VMSA 전체 목록 다운로드 + CVE 조회

인터넷 연결이 필요하며 시간이 오래 걸릴 수 있습니다. VMSA 공지사항 전체를 내려받은 뒤,
그 결과에서 발견된 CVE 목록을 이어서 자동으로 상세 조회합니다.

- `VMSA_FullList_Data.json`, `CVE_Lookup_Cache.json`은 저장소 루트에 누적 캐시로
  저장됩니다. 이미 파일이 있으면 기존 내용은 그대로 두고 새로 추가된 항목만 갱신합니다.
- `VMSA_All_Advisories.csv`, `VMSA_CVE_List.csv`는 날짜가 붙지 않는 고정 파일명이며,
  실행할 때마다 같은 이름으로 덮어써집니다(이 두 파일 자체는 캐시가 아니라 매번 새로
  생성되는 요약 결과입니다).
- 그 외 결과(HTML 리포트, 카테고리별 CSV/엑셀 폴더 등)는 `output\vmsa\` 아래 그대로
  생성됩니다.
- ImportExcel이 설치돼 있으면 `VMSA_FullList_Report.xlsx`(요약 CSV 통합)도 함께
  생성됩니다.

## 5. 자주 나오는 안내/오류 메시지

- **"VMware.PowerCLI module not found"** — 자동 설치를 시도합니다. 인터넷이 안 되는
  환경이면 화면에 나오는 안내에 따라 오프라인 설치용 ZIP을 준비해야 합니다.
- **인증서 경고** — PowerCLI 인증서 유효성 검사는 기본적으로 무시(Ignore)하도록 설정되어
  있어 자체 서명 인증서를 쓰는 vCenter/ESXi에도 별도 설정 없이 접속됩니다.
- **엑셀 파일이 안 생긴다** — ImportExcel 모듈이 설치되어 있는지 확인하세요
  (`Get-Module -ListAvailable -Name ImportExcel`). 미설치 시 CSV만 생성되는 것이
  정상 동작입니다.

## 6. 결과물 위치 요약

| 메뉴 | 결과 폴더 |
|---|---|
| [1] VCF 9 Upgrade | `output\vcf_9_upgrade\` |
| [2] VCF Operations Report | `output\Operations\` |
| [3] vCenter Security Suite | `output\security-hardening\`, `output\vmsa\`, `output\kisa_esx\` |
| [4] vCenter Daily Report | `output\vcenter\` |
| [5] VMSA 다운로드 + CVE 조회 | 저장소 루트(캐시 2개) + `output\vmsa\` (그 외 전부) |

자세한 변경 이력은 함께 전달된 `CHANGE-NOTES.md`(영문)를 참고하세요.
