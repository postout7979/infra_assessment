# Get_VC_DailyReport.ps1

vCenter 종합 인벤토리/성능/스토리지/VM 상세 리포트 생성 스크립트입니다.
VCF Operations 없이 **PowerCLI만으로** 동작하며, 실행하면 vCenter 로그인 정보를 받아
11개 섹션짜리 리포트를 CSV + HTML로 생성합니다.

## 요구사항

- Windows PowerShell 5.1 이상 (PowerShell 7에서도 동작)
- VMware PowerCLI 모듈 설치 및 vCenter 접근 권한
- 리포트를 생성할 대상 vCenter에 로그인 가능한 계정

## 사용법

### 대화형 실행 (파라미터 없이)

```powershell
.\Get_VC_DailyReport.ps1
```

실행하면 vCenter 서버 주소와 계정을 순서대로 물어봅니다.

### 파라미터를 지정해서 실행

```powershell
.\Get_VC_DailyReport.ps1 `
    -VCenterServer "vc-seoul01.corp.local" `
    -VCenterCredential (Get-Credential) `
    -DaysBack 1 `
    -SnapshotAgeDays 7 `
    -OutputFolder ".\Report_2026Q3"
```

여러 vCenter를 한 번에 조회하려면 쉼표로 구분한 배열을 넘기면 됩니다.

```powershell
.\Get_VC_DailyReport.ps1 -VCenterServer "vc01.corp.local","vc02.corp.local"
```

### 파라미터 설명

| 파라미터 | 필수 | 기본값 | 설명 |
|---|---|---|---|
| `-VCenterServer` | 아니오 (없으면 실행 중 입력받음) | - | vCenter 서버 주소. 여러 개면 문자열 배열 |
| `-VCenterCredential` | 아니오 (없으면 실행 중 입력받음) | - | vCenter 로그인 계정(PSCredential) |
| `-DaysBack` | 아니오 | `1` | 성능 지표를 조회할 기간(일). 예: 1이면 최근 1일 평균 |
| `-SnapshotAgeDays` | 아니오 | `7` | 이 일수보다 오래된 스냅샷을 "오래된 스냅샷"으로 판정 |
| `-OutputFolder` | 아니오 | `.\DailyReport_yyyyMMdd_HHmm` (실행 시각 기준 자동 생성) | 결과 CSV/HTML을 저장할 폴더 |

## 수집 항목 (11개 섹션)

1. **인벤토리 요약** — Datacenter/Cluster/Host/VM(전원 On/Off) 수, 전체 및 클러스터별 Total Core/메모리
2. **성능 요약** — 전체 평균 CPU/메모리 사용률, 클러스터별 CPU/메모리 사용률(진행바), Top3 호스트(CPU 사용률/메모리 사용률/CPU Ready %)
3. **스토리지 요약** — 공유 데이터스토어(로컬 제외) 용량/사용량/잔여량
4. **VM 성능 Top5** — vCPU 사용률, vCPU Ready %, vMEM 사용률, 가상 디스크 Write/Read Latency 기준 각각 상위 5개
5. **오래된 스냅샷** — `-SnapshotAgeDays`보다 오래된 스냅샷 보유 VM 목록(개수/보존기간/용량)
6. **가상장치 연결 VM** — ISO 등 CD/DVD가 마운트되어 있는 VM 목록
7. **VM 인벤토리** — VM별 호스트/클러스터/vCPU/CPU 토폴로지/메모리/가상 디스크(디스크별 행 분리, Thin/Thick 표기)
8. **VM 분포도** — Guest OS별, VMware Tools 상태/버전별, 가상 하드웨어 버전별, vCPU(4개 단위)/vMEM(8GB 단위) 구간별, Thin/Thick 디스크 수량 분포
9. **공유(Multi-writer) 가상 디스크 사용 VM**
10. **RDM(Raw Device Mapping) 연결 VM**
11. **VM 성능 분포 요약** — CPU 사용률/CPU Ready/메모리 사용률/디스크 Latency를 정상·주의·경고 3단계로 분류한 비율

추가로 **라이센스 키 수집**(vCenter + ESXi 호스트, HTML에는 포함되지 않고 CSV로만 출력)도 함께 진행됩니다.

## 출력 파일

`-OutputFolder`로 지정한 폴더(기본값은 실행할 때마다 `DailyReport_yyyyMMdd_HHmm` 형식으로 새로 생성)에
다음 파일들이 생성됩니다. (`yyyyMMdd`는 실행한 날짜)

| 파일명 | 내용 |
|---|---|
| `01_InventoryOverall_*.csv` | 전체 인벤토리 요약 |
| `01_InventoryPerCluster_*.csv` | 클러스터별 인벤토리 |
| `02_PerfPerCluster_*.csv` | 클러스터별 성능 |
| `02_Top3CpuHosts_*.csv` / `02_Top3MemHosts_*.csv` / `02_Top3ReadyHosts_*.csv` | CPU/메모리/CPU Ready 상위 호스트 |
| `03_SharedDatastores_*.csv` | 공유 데이터스토어 용량 |
| `04_Top5Vm*.csv` (5개) | VM 성능 Top5 리스트들 |
| `05_OldSnapshots_*.csv` | 오래된 스냅샷 |
| `06_ConnectedDevices_*.csv` | 가상장치 연결 VM |
| `07_VmInventory_*.csv` | VM 전체 인벤토리 |
| `08_DistBy*.csv` (6개) | VM 분포도 |
| `09_SharedDisks_*.csv` | 공유 가상 디스크 |
| `10_RdmDisks_*.csv` | RDM 디스크 |
| `11_PerfDistribution_*.csv` | 성능 분포 요약 |
| `LicenseKeys_*.csv` | vCenter/ESXi 라이센스 키 (HTML에는 미포함) |
| `VCenterReport_*.html` | 위 내용을 종합한 HTML 리포트(1~11번 섹션, 라이센스 제외) |
| `EmailReport_*.html` | 위와 같은 내용을 이메일 본문에 붙여넣기 좋은 형태(표 기반 레이아웃, 인라인 스타일)로 재구성한 버전. Outlook/Gmail 등에서 깨지지 않도록 CSS 변수·flexbox·그라데이션을 쓰지 않음 |

빈 결과(예: 오래된 스냅샷이 하나도 없음)는 해당 CSV 생성을 건너뛰고 경고만 표시합니다 — 정상 동작입니다.

## 호스트명 마스킹

리포트 전체(HTML의 모든 표, 라이센스 CSV 포함)에서 ESXi 호스트 이름은 다음 규칙으로 가려서 표시됩니다.

- **FQDN인 경우**: 짧은 이름(첫 번째 라벨)은 그대로 두고, 도메인 부분만 `vcf.local`로 교체
  - 예: `esxi01.corp.local` → `esxi01.vcf.local`
  - 이미 `vcf.local`이면 그대로 둠
- **IP 주소인 경우**: 앞 3개 옥텟은 자릿수와 무관하게 각각 `*`로, 마지막 옥텟만 그대로 표시
  - 예: `192.168.10.101` → `*.*.*.101`
- 도메인 없는 짧은 이름은 그대로 표시
- vCenter 서버 자체의 이름도 동일한 FQDN 규칙(도메인만 `vcf.local`로 교체)이 리포트/이메일 표시에 적용됩니다. 단, 실제 vCenter 접속(로그인)에는 원본 주소가 그대로 사용됩니다 — 마스킹은 화면/파일에 보이는 표시용일 뿐입니다.

## 참고 / 제약사항

- **가상 디스크 Latency**(`virtualDisk.totalReadLatency.average`/`totalWriteLatency.average`)는 vCenter 기본 통계 수집 레벨에서 **realtime 전용** 카운터라, 켜져 있는(Powered On) VM에서만 값이 나옵니다. 또한 VM당 값이 아니라 가상 디스크(인스턴스)별로 나오므로, 디스크가 여러 개인 VM은 그중 최댓값을 대표값으로 사용합니다.
- **공유 데이터스토어** 판별 기준은 "2대 이상의 호스트에서 보이는 데이터스토어"입니다. 환경에 따라 기준이 다르면 스크립트 내 `Get-StorageSummaryReport` 함수를 조정하세요.
- **공유 가상 디스크** 판별은 VMDK의 Multi-writer 공유 설정 여부로 합니다.
- **CPU Ready %**는 `cpu.ready.summation`(ms)을 백분율로 환산한 값이며, 환산 시 가정하는 샘플링 인터벌은 스크립트 상단의 `$Script:ReadyIntervalSeconds` (기본 20초)입니다. 환경의 실제 히스토리컬 롤업 간격과 다르면 이 값을 조정하세요.
- 임계치(정상/주의/경고 기준)는 스크립트 상단 `$Script:Threshold`에서 조정할 수 있습니다.

## 문제 해결

- **"인수 형식이 일치하지 않습니다" 류의 에러가 나는 경우**: 스크립트 실행 중 예상치 못한 에러가 나면, Main 전체가 try/catch로 감싸져 있어 예외 타입/메시지/발생 위치/스택트레이스를 화면에 출력합니다. 그 내용을 그대로 확인하면 어느 줄에서 실패했는지 알 수 있습니다.
- **라이센스 CSV가 비어 있거나 경고가 뜨는 경우**: vCenter 라이센스 조회 권한이 없거나, 해당 vCenter API 버전에서 `LicenseAssignmentManager`를 지원하지 않는 경우일 수 있습니다. 나머지 섹션(1~11번)에는 영향이 없습니다.
- **특정 섹션이 비어 있는 경우**: 해당 vSphere 버전/라이선스에서 관련 Get-Stat 메트릭이 없을 수 있습니다. `Get-StatType -Entity <객체>`로 사용 가능한 메트릭을 확인하세요.
