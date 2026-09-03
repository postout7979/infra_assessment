# VCF 9 사전 점검 통합 스크립트

`vcf9-precheck-toolkit.ps1` 하나로 인벤토리 수집, HCL 호환성 검사, 성능 리포트 생성을 모두 수행합니다.
실행하면 아래 메뉴가 표시됩니다.

| 메뉴 | 동작 |
|---|---|
| **[1]** | vCenter 접속 → 인벤토리 수집 → 생성된 폴더의 CSV를 바로 읽어 HCL 호환성 검사까지 자동 연속 실행 |
| **[2]** | vCenter 접속 → 인벤토리 수집만 실행 (CSV만 생성, HCL 검사는 나중에) |
| **[3]** | 메뉴 [2]에서 생성된 인벤토리 폴더명(또는 경로)을 입력받아 HCL 호환성 검사만 독립 실행 |
| **[4]** | 메뉴 [2]에서 생성된 인벤토리 폴더명(또는 경로)을 입력받아 성능 리포트(HTML)만 독립 생성 |

> 이전에는 `vcf9-precheck-script-cs.ps1`(인벤토리 수집)과 `vcf9-hcl-check.ps1`(HCL 검사)이 별도 스크립트였지만,
> 이제 `vcf9-precheck-toolkit.ps1` 하나로 통합되어 메뉴로 선택해 실행합니다.

---

## 1. 사전 준비사항

| 항목 | 내용 |
|---|---|
| PowerShell | Windows PowerShell 5.1 이상 (PowerShell 7도 가능) |
| VMware.PowerCLI 모듈 | 없으면 스크립트가 **자동 설치**를 시도합니다 (메뉴 1, 2 실행 시). 인터넷이 안 되는 폐쇄망이면 [7. 폐쇄망(오프라인) 환경 안내](#7-폐쇄망오프라인-환경-안내) 참고. 메뉴 3(HCL 검사만 실행)은 vCenter 접속이 없으므로 PowerCLI가 없어도 동작합니다 |
| vCenter 접속 계정 | 메뉴 1, 2 실행 시 필요. 클러스터/호스트 정보를 읽을 수 있는 권한 (읽기 전용 계정이면 충분) |
| HCL 비교용 CSV 4종 | VMware Compatibility Guide에서 내려받은 아래 4개 파일 (메뉴 1, 3 실행 시 필요) |

**HCL CSV 4종:**
- **CPU 정보** (`CPU_All_Models_*.csv`): 헤더 없는 6컬럼(Vendor, Series, Model, Cores, Freq, TDP) 형식, CPU Series별 지원 ESXi 버전
- **IO Devices**: NIC / RAID / HBA 등 I/O 장치별 지원 ESXi 버전
- **Systems / Servers**: 서버 벤더·모델별 지원 CPU Series, GPU, ESXi 버전
- **vSAN I/O Controller**: vSAN용 스토리지 컨트롤러 지원 목록

> **파일 종류 식별:** 파일명이 아니라 **CSV 안의 컬럼(헤더)** 으로 자동 판별합니다. 파일명을 바꿔도 상관없습니다. (CPU 파일만 예외적으로 파일명에 `CPU_All_Models` 포함 여부 또는 헤더 없는 6컬럼 Vendor/Series 패턴으로 판별)
>
> **ESXi 버전 구분:** 파일명에 `9_0` 또는 `9.0`이 포함되면 **9.0 전용**, `9_1` 또는 `9.1`이 포함되면 **9.1 전용**으로 인식합니다. 버전 표시가 없으면 9.0/9.1 공통 데이터로 처리합니다.
>
> 예) `IO_Devices_9_0.csv` → 9.0 전용 / `IO_Devices_9_1.csv` → 9.1 전용 / `IO_Devices.csv` → 공통

---

## 2. 파일 배치

```
C:\powercli\
 ├─ vcf9-precheck-toolkit.ps1
 └─ hcl\                              ← HCL CSV 4종을 여기에 위치
     ├─ CPU_All_Models_9_1.csv        (9.0/9.1 공통 또는 버전별 지정 가능)
     ├─ IO_Devices_9_0.csv
     ├─ IO_Devices_9_1.csv
     ├─ Systems_Servers_9_0.csv
     ├─ Systems_Servers_9_1.csv
     ├─ vSAN_IO_Controller_9_0.csv
     └─ vSAN_IO_Controller_9_1.csv
```

- `hcl` 폴더명은 대소문자 무관 (`hcl` / `HCL` / `Hcl` 모두 인식)
- 버전별로 파일이 나뉘어 있지 않아도 동작합니다 (그 경우 9.0/9.1 공통 데이터로 처리)
- 다른 위치에 두고 싶다면 스크립트 내부의 `-HCLPath` 값을 직접 지정할 수 있습니다 (기본은 스크립트 위치의 `hcl` 폴더 자동 사용)

---

## 3. 실행 방법

```powershell
.\vcf9-precheck-toolkit.ps1
```

실행하면 메뉴가 표시되고, 번호(1/2/3/4)를 입력하면 해당 동작이 수행됩니다.

### [메뉴 1] 인벤토리 수집 + HCL 호환성 검사 자동 연속 실행

1. vCenter 주소/계정 입력 프롬프트가 표시됩니다.
2. 아래 [4. 인벤토리 수집 단계]의 12단계를 수행하며 `vSphere_Inventory_YYYYMMDD_HHMM` 폴더를 생성합니다.
3. 수집이 끝나면 별도 명령 실행 없이 **자동으로** 그 폴더의 CSV를 읽어 HCL 호환성 검사를 수행하고, `compatibility_YYYYMMDD_HHMM` 폴더에 결과를 저장합니다.
4. 두 폴더(`vSphere_Inventory_...`, `compatibility_...`)가 모두 생성되면, 이 둘을 하나로 묶은 압축 파일(`VCF9_Precheck_YYYYMMDD_HHMM.zip`)을 스크립트가 있는 위치에 추가로 생성합니다. **원본 폴더 두 개는 삭제되지 않고 그대로 남아 있습니다** — 압축 파일은 원본에 더해지는 사본입니다.

### [메뉴 2] 인벤토리 수집만 실행

- 메뉴 1과 동일하게 vCenter에 접속해 12단계 수집을 수행하지만, HCL 검사는 수행하지 않고 `vSphere_Inventory_YYYYMMDD_HHMM` 폴더만 생성합니다.
- 완료 메시지에 생성된 폴더 경로가 표시되며, 나중에 메뉴 3 또는 4에서 이 폴더명을 입력해 HCL 검사 또는 성능 리포트를 실행할 수 있습니다.

### [메뉴 3] 기존 인벤토리 폴더 지정 → HCL 호환성 검사만 실행

- vCenter 접속 없이, 메뉴 2(또는 메뉴 1)에서 이미 생성된 인벤토리 폴더를 대상으로 HCL 검사만 독립 실행합니다.
- 폴더명만 입력해도(전체 경로가 아니어도) 스크립트가 위치한 폴더 기준으로 자동 탐색합니다. 예: `vSphere_Inventory_20260827_0930` 입력 시 `.\vSphere_Inventory_20260827_0930` 경로를 자동으로 찾습니다.
- 전체 경로를 입력해도 그대로 사용됩니다. 예: `C:\powercli\vSphere_Inventory_20260827_0930`

### [메뉴 4] 기존 인벤토리 폴더 지정 → 성능 리포트만 생성

- vCenter 접속 없이, 메뉴 2(또는 메뉴 1)에서 이미 생성된 인벤토리 폴더의 CSV(`Hosts_Perf.csv`, `Hosts_Hardware.csv`, `VMs_Status.csv`, `Datastores.csv`, `Clusters.csv`)를 읽어 성능 리포트 HTML을 생성합니다.
- 폴더명 입력 방식은 메뉴 3과 동일합니다 (폴더명만 입력해도 스크립트 위치 기준으로 자동 탐색).
- `Hosts_Perf.csv`가 없으면 실행이 중단됩니다. 나머지 파일은 없어도 해당 항목만 건너뛰고 계속 진행됩니다.

---

## 4. 인벤토리 수집 단계 (메뉴 1, 2 공통, 총 12단계)

| 단계 | 내용 | 생성 파일 |
|---|---|---|
| 0 | PowerCLI 설치 확인/자동 설치, vCenter 연결 | - |
| 1 | 클러스터 정보 수집 | `Clusters.csv` |
| 2 | 호스트 성능/하드웨어 수집 (CPU 모델·벤더·소켓·코어, CPU Ready, CPU/Mem 사용률, 라이선스 키 포함) | `Hosts_Perf.csv`, `Hosts_Hardware.csv` |
| 3 | VM 상태/디스크/VMTools 수집 (CPU Ready/Costop 포함) | `VMs_Status.csv`, `Special_Disks(RDM_Shared_Thick).csv` |
| 4 | 스토리지/LUN 매핑 | `Datastores.csv` |
| 5 | 가상 스위치/VDS 정보 수집 | `Virtual_Switches.csv` |
| 6 | ESXCLI 캐시 구성 (드라이버/펌웨어 조회용) | - |
| 7 | 물리 NIC 정보 수집 | `Physical_NICs.csv` |
| 8 | FC HBA 정보 수집 | `HBA_Cards.csv` (FC HBA 없으면 미생성) |
| 9 | RAID 컨트롤러 정보 수집 | `RAID_Controllers.csv` |
| 10 | **ESX Memory Page 수집** (NVMe 메모리 티어링 평가용) | `ESX_Memory_Page.csv` |
| 11 | vCenter 연결 해제 | - |
| 12 | 완료 메시지 출력 (메뉴 1이면 이어서 HCL 검사 자동 실행) | - |

모든 파일은 **`vSphere_Inventory_YYYYMMDD_HHMM`** 폴더에 저장됩니다 (ZIP 압축 없이 폴더 그대로 보존).

---

## 5. HCL 호환성 검사 (메뉴 1, 3 공통)

### 입력 파일 (인벤토리 폴더 안에 있어야 함)

| 파일 | 필수 여부 |
|---|---|
| `Hosts_Hardware.csv` | **필수** (없으면 실행 중단) |
| `Physical_NICs.csv` | 선택 (없으면 NIC 검사 건너뜀) |
| `HBA_Cards.csv` | 선택 |
| `RAID_Controllers.csv` | 선택 |

### 출력 결과

스크립트 위치에 **`compatibility_YYYYMMDD_HHMM`** 폴더가 자동 생성되고 그 안에 저장됩니다.

```
C:\powercli\
 └─ compatibility_20260827_1430\       ← 실행 시 자동 생성
     ├─ Compatibility_Report.html
     ├─ Compatibility_Cluster_<클러스터명>.html
     ├─ Compatibility_Server.csv
     ├─ Compatibility_CPU.csv
     ├─ Compatibility_NIC.csv
     └─ Compatibility_StorageController.csv
```

### CSV 컬럼 설명

| 컬럼 | 내용 |
|---|---|
| `Detected` | vCenter에서 수집된 실제 하드웨어 정보 |
| `HCL_Match` | 가장 유사도가 높은 HCL 항목 (MISMATCH여도 항상 표시) |
| `Match_Score(%)` | 유사도 점수 (0~100%). 50% 이상이면 OK |
| `ESXi_9.0` / `ESXi_9.1` | ESXi 9.0 / 9.1 각각의 판정 결과 (`OK` / `MISMATCH`) |
| `Note` | 지원 버전, 수동 확인 안내 등 상세 정보 |

**Server CSV 추가 컬럼** (물리 코어 산정):

| 컬럼 | 내용 |
|---|---|
| `CPU_Sockets` | 물리 소켓 수 |
| `CoresPerSocket_Actual` | 실제 소켓당 코어 수 |
| `CoresPerSocket_Eff` | 산정에 사용된 소켓당 코어 수 (실제가 16 미만이면 16으로 상향) |
| `Total_Cores_Eff` | 산정 기준 총 코어 수 (`CPU_Sockets × CoresPerSocket_Eff`) |

### 항목별 매칭 방식

| 항목 | 매칭 방식 |
|---|---|
| **Server** | 제조사+모델명 토큰 유사도 (숫자 포함 토큰에 가중치 3배) |
| **CPU** | 세부 SKU가 아닌 **모델 시리즈(세대)** 단위 판정. Intel: SKU 앞 2자리, AMD: 첫/끝자리로 세대 구분 |
| **NIC** | IO Devices HCL 중 `Device Type = Network` 항목과 모델명 유사도 |
| **Storage Controller** | IO Devices HCL(Network 제외) + vSAN I/O Controller HCL 모두 비교. vSAN 지원 여부는 Note에 별도 표기 |

> 모든 매칭은 ESXi 9.0 HCL과 9.1 HCL에 대해 **각각 독립적으로** 수행됩니다.

---

## 6. ESX Memory Page (ESX_Memory_Page.csv)

NVMe 메모리 티어링 구성 검토를 위한 호스트별 메모리 페이지 정보입니다.

| 컬럼 | 내용 |
|---|---|
| `Allocated_Mem_GB` | 전체 물리 메모리 |
| `Consumed_Mem_GB` / `Mem_Usage_Pct` | 소비 메모리 및 사용률 |
| `Active_Mem_GB` / `Active_Pct_of_Consumed` | 활성(Hot) 메모리 및 소비 대비 비율 |
| `Cold_Mem_GB` / `Cold_Pct_of_Consumed` | 콜드 메모리 (= Consumed − Active) 및 비율 |
| `NVMe_Tiering_Candidate` | `Cold ≥ 1GB` 이고 `Cold 비율 ≥ 20%`이면 `Yes` — NVMe 티어링 검토 대상 |
| `Stat_Source` | `Realtime` 또는 `QuickStats` (데이터 신뢰도 확인용) |

---

## 7. HTML 리포트 구조

### `Compatibility_Report.html` (메인 요약)

1. **상단 드롭다운 네비게이션** — 페이지 최상단에서 클러스터를 선택하면 해당 클러스터 상세 페이지로 바로 이동
2. **전체 호스트 호환성 현황** — ESXi 9.0 / 9.1 각각의 100% 일치 호스트 수, 불일치 호스트 수, 물리 코어 합계를 둥근 카드로 표시
3. **클러스터별 호환성 현황** — 클러스터별 미니 카드 (100% 일치/불일치 호스트 수 + 코어 합계). **클러스터명 클릭 시 상세 파일 열림**
4. **Part별 항목 수 요약** — Server/CPU/NIC/Storage_Controller별 총 개수 및 9.0/9.1 일치율 테이블

### `Compatibility_Cluster_<클러스터명>.html` (클러스터별 상세)

- 상단에 다른 클러스터로 바로 이동하는 드롭다운과, `Compatibility_Report.html`로 돌아가는 **Home 버튼**을 제공
- Server → CPU → NIC → Storage_Controller 순서로 상세 표 표시
- 행 배경색: 흰색(둘 다 OK) / 노란색(한쪽만 OK) / 빨간색(둘 다 MISMATCH)
- Server 섹션에는 소켓/코어 산정 컬럼 추가 표시

> 모든 HTML 파일이 같은 폴더 안에 있어야 클러스터 링크가 정상 동작합니다 (상대 경로 방식).

### `Performance_Report.html` (성능 리포트 메인 요약, 메뉴 4)

1. **상단 드롭다운 네비게이션** — Compatibility_Report.html과 동일하게, 클러스터를 선택하면 해당 클러스터 성능 상세 페이지로 바로 이동
2. **전체 요약 카드** — 전체 호스트 수(연결됨 포함), 평균 CPU/메모리 사용률, 전체 VM 수(켜짐/꺼짐), 데이터스토어 총 용량/사용량/여유공간
3. **클러스터별 성능 테이블** — 클러스터별 호스트 수, VM 수(켜짐/꺼짐), 평균 CPU/메모리 사용률, 데이터스토어 용량/사용량/여유공간. 클러스터명 클릭 시 상세 페이지로 이동 (CPU/메모리 사용률 80% 이상은 빨간색, 60% 이상은 주황색으로 강조)
4. **CPU 사용률 상위 10개 호스트**, **메모리 사용률 상위 10개 호스트**, **CPU Ready% 상위 10개 VM** 테이블
5. **여유 공간 15% 미만 데이터스토어** 경고 테이블 (해당 데이터스토어가 있는 경우에만 표시)

### `Performance_Cluster_<클러스터명>.html` (클러스터별 성능 상세, 메뉴 4)

- 상단에 다른 클러스터로 바로 이동하는 드롭다운과, `Performance_Report.html`로 돌아가는 **Home 버튼**을 제공
- **Hosts** 표: 호스트명, 상태, ESXi 버전, CPU/메모리 사용률, CPU Ready%, 총 메모리, 벤더/모델 (CPU 사용률 기준 내림차순 정렬)
- **Virtual Machines** 표: VM명, 전원 상태, 호스트, NumCPU, 메모리, CPU 사용량(MHz), CPU Ready%/Costop%, 소비 메모리, VMTools 상태 (CPU Ready% 기준 내림차순 정렬)
- **Datastores** 표: 데이터스토어명, 타입, 용량/사용량/여유공간, 여유율, 평균 IOPS (여유율 오름차순 정렬, 15% 미만은 빨간색 강조)

---

## 8. 폐쇄망(오프라인) 환경 안내

인터넷이 안 되는 서버에서 메뉴 1 또는 2를 실행하면 PowerCLI 자동 설치가 실패하고 안내 메시지가 출력됩니다. (메뉴 3, 4는 PowerCLI가 필요 없으므로 영향 없음)
공식 가이드: [Install PowerCLI Offline (Broadcom TechDocs)](https://techdocs.broadcom.com/us/en/vmware-cis/vcf/power-cli/latest/powercli/installing-vmware-vsphere-powercli/install-powercli-offline.html)

**오프라인 설치 절차**

**[1단계]** 인터넷이 되는 PC에서 PowerCLI ZIP 파일 내려받기
→ [Broadcom Developer Portal](https://developer.broadcom.com/tools/vmware-powercli/latest/)에서 내려받아 폐쇄망 서버로 전송

**[2단계]** 폐쇄망 서버에서 설치 위치 확인
```powershell
$env:PSModulePath
```
출력된 경로 중 하나에 ZIP 내용을 압축 해제 (예: `C:\Program Files\WindowsPowerShell\Modules`)

**[3단계]** 복사된 파일 차단 해제 (Windows 필수)
```powershell
Get-ChildItem -Path 'C:\Program Files\WindowsPowerShell\Modules\VMware*' -Recurse | Unblock-File
```

**[4단계]** 설치 확인
```powershell
Get-Module VMware* -ListAvailable
```

**[5단계]** 로컬 스크립트 실행 허용 (필요 시)
```powershell
Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope CurrentUser
```

---

## 9. 자주 발생하는 문제

| 증상 | 원인 / 해결 방법 |
|---|---|
| `Cannot complete login due to an incorrect user name or password` | 계정/비밀번호 오류. SSO 계정 형식(`user@vsphere.local`)인지, 비밀번호 만료/계정 잠김 여부 확인 |
| 메뉴 3, 4에서 폴더를 찾지 못함 | 폴더명만 입력한 경우 스크립트와 같은 위치에 있어야 자동 인식됩니다. 다른 위치에 있다면 전체 경로를 입력하세요 |
| 메뉴 1, 3 실행 시 `[ERROR] HCL data folder not found` | 스크립트 위치에 `hcl` 폴더가 없습니다. `hcl` 폴더를 만들고 HCL CSV를 넣으세요 |
| `ESXi_9.0`은 OK인데 `ESXi_9.1`은 MISMATCH (또는 반대) | 정상 동작입니다. 해당 장비가 한쪽 버전 HCL에만 등록돼 있다는 의미입니다 |
| `HBA_Cards.csv`가 생성되지 않음 | 정상입니다. FC HBA가 없는 환경에서는 파일이 생성되지 않습니다 |
| `License_Key`가 `*****`로 마스킹됨 | 접속 계정에 `Global.Licenses` 권한이 없는 경우입니다. 전체 키가 필요하면 해당 권한이 있는 계정으로 재실행하세요 |
| 메뉴 1 실행 중 인벤토리 수집은 성공했는데 HCL 검사에서 실패 | 인벤토리 폴더 자체는 남아있으므로, 메뉴 3에서 그 폴더명을 입력해 HCL 검사만 재시도할 수 있습니다 |

---

## 10. 한계 / 주의사항

- 호환성 판정은 **모델명/시리즈 기반 best-effort 유사도 매칭**이며, VMware 공식 Compatibility Guide 조회를 완전히 대체하지 않습니다.
- CPU 세대 판정 시 Intel Xeon Gold 6300번대처럼 여러 마이크로아키텍처가 같은 번호대를 공유하는 경우 정확한 구분이 어려울 수 있습니다.
- `ESX_Memory_Page.csv`의 `NVMe_Tiering_Candidate = Yes`는 1차 스크리닝 기준(`Cold ≥ 1GB, Cold 비율 ≥ 20%`)이며, 실제 NVMe 티어링 적용 여부는 추가 검토가 필요합니다.
- 모든 메뉴는 읽기 전용 조회만 수행하며, vCenter/ESXi 설정을 변경하지 않습니다.
