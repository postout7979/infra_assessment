# all-in-one-vmw.ps1

이 저장소(`infra_assessment`) 안의 5개 폴더에 흩어져 있는 PowerShell 스크립트들을 하나의 메뉴에서 골라 실행하는 통합 런처입니다. 런처 자체는 수집/분석 로직을 갖지 않고 각 폴더의 원본 `.ps1`을 그대로 호출합니다.

## 설치 / 배치

`all-in-one-vmw.ps1`을 이 저장소의 **루트**(5개 폴더와 같은 위치)에 두세요.

```
git clone 혹은 ZIP 다운로드 후 스크립트 실행
1) Windows에서 실행 시, git 명령어 도구를 다운로드한 다음 git bash로 먼저 git clone으로 복제 후, Powershell windows로 실행해야 디지털 서명 문제가 발생하지 않습니다.
- git git clone https://github.com/postout7979/infra_assessment

2) ZIP 압축파일을 다운로드 후, 해제한 경우에는 다음 커맨드를 해당 경로에서 실행합니다.
Get-ChildItem -Path . -Recurse | Unblock-File


infra_assessment\                      <- git clone https://github.com/postout7979/infra_assessment
 ├─ all-in-one-vmw.ps1                 <- 이 파일
 ├─ vcf_9_upgrade\
 ├─ Operations\
 ├─ security-hardening\
 ├─ vcenter\
 └─ vmsa\
```

저장소 루트가 아닌 다른 위치에서 실행하고 싶다면, 실행 전에 환경변수 `VMWTOOLS_INFRA_PATH`에 저장소 루트 경로를 지정하세요.
- 저장소 경로를 아래와 같이 해당하는 경로를 환경 변수로 추가

```powershell
$env:VMWTOOLS_INFRA_PATH = "C:\repos\infra_assessment"
```

## 실행

```powershell
cd C:\repos\infra_assessment
Set-ExecutionPolicy -Scope CurrentUser RemoteSigned   # 최초 1회, 필요한 경우만
.\all-in-one-vmw.ps1
```

## 메뉴 구성

| 메뉴 | 대상 폴더 | 원본 스크립트 | 비고 |
|---|---|---|---|
| **[1]** VCF 9 업그레이드 | `vcf_9_upgrade\` | `vcf9-precheck-toolkit_v2.ps1` / `vcf9-nvme-tiering-analysis.ps1` | 하위 메뉴에서 선택. (1) 사전점검 통합 스크립트는 실행하면 스크립트 자체 내부 메뉴(1~4)가 그대로 뜨고, vCenter 계정과 `hcl\` 폴더의 HCL CSV 4종이 필요합니다. (2) NVMe 티어링 분석은 (1)의 메뉴 2에서 만들어진 인벤토리 폴더 경로를 입력받아 실행합니다 |
| **[2]** VCF Operations 리포트 | `Operations\` | `New-VCFOpsReport.ps1` | 하위 메뉴에서 Mock 미리보기 또는 실제 연동(Host URL·계정) 선택. 비밀번호는 원본 스크립트가 실행 중 안전하게 별도로 입력받습니다 |
| **[3]** 보안 하드닝 감사 | `security-hardening\` | `vmware-tools\audit_runner.ps1` / `audit-reporter.ps1` | 하위 메뉴에서 선택. (1) 신규 감사 실행(vCenter/ESXi/VM 접속), (2) 기존 로그 폴더로 리포트 생성 |
| **[4]** vCenter 일일 리포트 | `vcenter\` | `Get_VC_DailyReport.ps1` | vCenter 주소를 미리 입력하거나, 비워두면 실행 중 원본 스크립트가 물어봅니다 |
| **[5]** VMSA 취약점 관리 | `vmsa\` | `vmsa_fulllist_downloader.ps1` / `vmsa_cve_lookup.ps1` | 하위 메뉴에서 선택. (1) 전체 목록 다운로드, (2) CVE 상세 조회(CSV 경로 입력 필요) |
| **[U]** | - | - | 이 저장소를 `git pull`로 업데이트 (git clone된 경우만) |

각 스크립트는 원본이 요구하는 사전 준비물(PowerCLI 모듈, vCenter 읽기전용 계정, HCL CSV, ImportExcel 모듈 등)을 그대로 필요로 합니다 — 자세한 내용은 각 하위 폴더의 readme를 참고하세요.

## 참고

- Windows PowerShell 5.1 이상 (PowerShell 7 `pwsh`도 가능) 환경 기준으로 원본 스크립트들이 작성되어 있습니다.
- 자식 스크립트 실행 중 오류가 나도 런처(메뉴)는 죽지 않고 메뉴로 돌아옵니다.
- 실행 위치는 각 스크립트가 있는 폴더로 자동 이동(Push-Location) 후 실행하므로, 상대 경로로 파일을 찾는 원본 스크립트(예: `hcl\` 폴더, SCG CSV 등)도 문제없이 동작합니다.
