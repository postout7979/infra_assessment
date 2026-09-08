# allinonevmw.ps1

이 저장소(`infra_assessment`) 안의 6개 폴더에 흩어져 있는 PowerShell 스크립트들을 하나의 메뉴에서 골라 실행하는 통합 런처입니다. 런처 자체는 수집/분석 로직을 갖지 않고 각 폴더의 원본 `.ps1`을 그대로 호출합니다.

## 설치 / 배치

`allinonevmw.ps1`을 이 저장소의 **루트**(각 폴더와 같은 위치)에 두세요.

1) Windows에서 실행 시, git 명령어 도구를 다운로드한 다음 git bash로 먼저 git clone으로 복제 후, Powershell windows로 실행해야 디지털 서명 문제가 발생하지 않습니다.
```
git clone https://github.com/postout7979/infra_assessment
```

2) ZIP 압축파일을 다운로드 후, 해제한 경우에는 다음 커맨드를 해당 경로에서 실행합니다.
```powershell
Get-ChildItem -Path . -Recurse | Unblock-File
```
(참고: `allinonevmw.ps1`은 실행할 때마다 저장소 폴더 전체에 대해 이 Unblock-File을 자동으로도 한 번 수행합니다. 그래도 "is not digitally signed" 에러가 나면 위 명령을 수동으로 한 번 더 실행하세요.)

```
infra_assessment\                      <- git clone https://github.com/postout7979/infra_assessment
 ├─ allinonevmw.ps1                    <- 이 파일
 ├─ vcf_9_upgrade\
 ├─ Operations\
 ├─ security-hardening\
 ├─ vcenter\
 ├─ vmsa\
 └─ kisa_esx\
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
.\allinonevmw.ps1
```

## 메뉴 구성

| 메뉴 | 대상 폴더 | 원본 스크립트 | 비고 |
|---|---|---|---|
| **[1]** VCF 9 업그레이드 | `vcf_9_upgrade\` | `vcf9-precheck-toolkit_v2.ps1` / `vcf9-nvme-tiering-analysis.ps1` | 하위 메뉴에서 선택. (1) 사전점검 통합 스크립트는 실행하면 스크립트 자체 내부 메뉴(1~4)가 그대로 뜨고, vCenter 계정과 `hcl\` 폴더의 HCL CSV 4종이 필요합니다. (2) NVMe 티어링 분석은 `vcf_9_upgrade\` 폴더 안의 `vSphere_Inventory_*` 폴더 목록을 보여주고 번호로 선택하게 합니다(목록에 없으면 직접 경로 입력 가능) |
| **[2]** VCF Operations 리포트 | `Operations\` | `New-VCFOpsReport.ps1` | 항상 실제 VCF Operations 연동으로 실행합니다(Mock 미리보기 없음). 호스트 주소는 `https://` 없이 입력하면 자동으로 붙여서 전달합니다(예: `vcfops.corp.local` 입력 → `https://vcfops.corp.local`). 비밀번호는 원본 스크립트가 실행 중 안전하게 별도로 입력받습니다 |
| **[3]** 보안 하드닝 감사 | `security-hardening\` | `vmware-tools\audit_runner.ps1` / `audit-reporter.ps1` | 하위 메뉴에서 선택. (1) 신규 감사 실행(vCenter/ESXi/VM 접속), (2) 기존 로그 폴더로 리포트 생성 |
| **[4]** vCenter 일일 리포트 | `vcenter\` | `Get_VC_DailyReport.ps1` | vCenter 주소를 미리 입력하거나, 비워두면 실행 중 원본 스크립트가 물어봅니다 |
| **[5]** VMSA 취약점 관리 | `vmsa\` | `vmsa_fulllist_downloader.ps1` / `vmsa_cve_lookup.ps1` / `vmsa_environment_report.ps1` | 하위 메뉴에서 선택. (1) 전체 목록 다운로드, (2) CVE 상세 조회(CSV 경로 입력 필요), (3) 버전 확인 조회(vCenter연결) — vCenter에 접속해 vCenter/ESXi 실제 버전을 읽어와 VMSA와 자동 매칭(주소/계정/비밀번호는 실행 중 원본 스크립트가 안전하게 물어봄) |
| **[6]** KISA 가상화 취약점 점검 | `kisa_esx\` | `invoke-vSpherekisaaudit.ps1` | KISA 주요정보통신기반시설 가상화 장비 점검 항목(HV-01~HV-25)을 PowerCLI로 원격 점검. 대상 서버 주소만 입력하면 되고, 계정 정보는 입력하지 않으면 원본 스크립트가 실행 중 안전하게 물어봅니다. ESXi 호스트 root 계정이 vCenter 계정과 다르면 별도 입력 가능, 인증서 오류 무시 여부/결과 저장 폴더/스냅샷 경과일 임계값도 선택 입력 |

각 스크립트는 원본이 요구하는 사전 준비물(PowerCLI 모듈, vCenter 읽기전용 계정, HCL CSV, ImportExcel 모듈 등)을 그대로 필요로 합니다 — 자세한 내용은 각 하위 폴더의 readme를 참고하세요.

## 참고

- Windows PowerShell 5.1 이상 (PowerShell 7 `pwsh`도 가능) 환경 기준으로 원본 스크립트들이 작성되어 있습니다.
- 자식 스크립트 실행 중 오류가 나도 런처(메뉴)는 죽지 않고 메뉴로 돌아옵니다.
- 실행 위치는 각 스크립트가 있는 폴더로 자동 이동(Push-Location) 후 실행하므로, 상대 경로로 파일을 찾는 원본 스크립트(예: `hcl\` 폴더, SCG CSV 등)도 문제없이 동작합니다.
- 런처 시작 시 저장소 폴더 전체에 `Unblock-File`을 자동으로 실행해, GitHub ZIP 다운로드로 생긴 "인터넷에서 받은 파일" 차단을 미리 해제합니다.
