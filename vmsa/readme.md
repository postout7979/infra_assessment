
# VMSA 취약점 관리 툴킷

VMware(Broadcom) 보안 권고(VMSA) 정보를 수집하고, CVE 상세 정보를 조회하기 위한 PowerShell 스크립트 모음입니다.

> 두 스크립트 모두 Windows PowerShell 5.1 기준으로 작성되었습니다. 한글이 포함된 출력(HTML/콘솔)이 깨지지 않도록 각 `.ps1` 파일은 UTF-8 BOM으로 저장되어 있어야 하며, 편집 시에도 이 인코딩을 유지해야 합니다.

## 스크립트 구성

| 파일 | 실행 환경 | 역할 |
|------|-----------|------|
| `VMSA_FullList_Downloader.ps1` | 인터넷 PC | 메인 수집 스크립트. 전체 VMSA 목록을 페이지 단위로 수집하고 CSV/JSON/HTML 생성 |
| `VMSA_CVE_Lookup.ps1` | 인터넷 PC | 위 스크립트가 만든 CVE 목록을 입력받아 NVD에서 상세 정보를 조회, 검색 가능한 CSV/HTML 생성 |

기본 사용 순서는 **`VMSA_FullList_Downloader.ps1` 실행 → (필요 시) 그 결과 CVE 목록으로 `VMSA_CVE_Lookup.ps1` 실행**입니다.

---

## `VMSA_FullList_Downloader.ps1` (메인 수집 스크립트 - 인터넷 PC)

Broadcom 보안 권고 전체 목록(`https://support.broadcom.com/web/ecx/security-advisory`)을 API로 직접 페이징하며 수집하고, 신규 어드바이저리만 상세 페이지를 크롤링하는 **증분(incremental) 수집기**입니다.

### 사용법

```powershell
.\VMSA_FullList_Downloader.ps1                          # 전체 페이지
.\VMSA_FullList_Downloader.ps1 -StartPage 1 -EndPage 2   # 최신 2페이지(약 40건)만
.\VMSA_FullList_Downloader.ps1 -StartPage 5 -EndPage 5   # 5페이지만
.\VMSA_FullList_Downloader.ps1 -PageSize 50 -EndPage 3   # 페이지당 50건, 앞 3페이지만
.\VMSA_FullList_Downloader.ps1 -ForceRefreshAll          # 캐시 무시하고 전체 재수집
```

### 주요 파라미터

| 파라미터 | 기본값 | 설명 |
|---|---|---|
| `-Segment` | `VC` | Broadcom 사이트의 세그먼트 필터 (VMware Cloud) |
| `-PageSize` | `20` | 목록 API 한 페이지당 항목 수 |
| `-StartPage` / `-EndPage` | `1` / `0` | 가져올 페이지 범위 (1부터 시작, `EndPage=0`은 마지막 페이지까지) |
| `-DelayMsBetweenListPages` | `400` | 목록 페이지 호출 간 대기시간(ms) |
| `-DelayMsBetweenDetailPages` | `300` | 상세 페이지 호출 간 대기시간(ms) |
| `-ForceRefreshAll` | - | JSON 캐시를 무시하고 모든 어드바이저리를 다시 크롤링 |

### 동작 방식

1. 목록 API를 페이지 단위로 호출해 전체 어드바이저리 목록(현재 약 340건)을 수집합니다.
2. `VMSA_FullList_Data.json`(고정 파일명)을 먼저 읽어 이미 알고 있는 AdvisoryID는 건너뛰고, **새로 발견된 어드바이저리만** 상세 페이지를 열어 CVSS, Response Matrix, 각 CVE 설명을 가져옵니다. NVD 등 외부 CVE 조회는 하지 않으므로 조회 속도 제한이 없습니다.
3. Response Matrix 추출은 여러 단계 폴백을 거칩니다: 표준 `<table>` → "Fixed Version" 문구 주변 텍스트 → 오래된 어드바이저리의 ASCII `<pre>` 표 → `data-label` 기반 반응형 표 → 그마저도 없으면 페이지 전체 텍스트에서 "제품명 ... 버전" 패턴을 찾는 최후 수단까지 순서대로 시도합니다.
4. "Product | Component | Version" 형태의 3단 행(예: VMware Cloud Foundation 번들에서 "vCenter Server"가 실제 영향받는 컴포넌트인 경우)을 인식해서, Product/Component 텍스트로 분류하되 버전은 정확한 컬럼에서 가져옵니다. 버전 칸에 컴포넌트명 등 버전이 아닌 값이 남으면 자동으로 "N/A"로 정규화되어 목록을 오염시키지 않습니다.
5. "Synopsis" 요약 문단이 표 형태 마크업 안에 있어 가짜 매트릭스 행으로 잘못 캡처되는 경우를 걸러냅니다.
6. VMware의 최신(2026년~) "ESXi" → "ESX" 표기 변경도 함께 인식합니다 (`\bESXi?\b`).

### 생성 파일

| 파일 | 설명 |
|---|---|
| `VMSA_All_Advisories_<timestamp>.csv` | 전체 어드바이저리 목록 (스냅샷, 매 실행마다 새로 생성) |
| `VMSA_CVE_List_<timestamp>.csv` | 고유 CVE 목록 (설명 없이 CVE ID + 관련 AdvisoryID만) - `VMSA_CVE_Lookup.ps1`의 입력으로 사용 |
| `VMSA_FullList_Data.json` | 누적 전체 데이터 (고정 파일명, 매 실행 시 갱신되는 캐시) |
| `VMSA_Report_<timestamp>.html` | 아래 참고 |
| `VMSA_By_Category_<timestamp>/VMSA_<카테고리>.csv` | 아래 참고 |

### HTML 리포트 (`VMSA_Report_<timestamp>.html`)

- 영문 UI, Product 드롭다운 → 해당 제품에서 발견된 **정확한 버전 전체를 체크박스 목록**으로 표시 (메이저 버전만이 아닌 실제 버전 문자열, 예: "8.0 U3", "7.0.3").
- 목록 맨 위 **ALL** 체크박스가 기본 선택 상태이며, 이 상태에서는 해당 제품의 모든 버전이 표시됩니다. 특정 버전을 체크하면 ALL은 자동 해제되고, 여러 버전을 동시에 선택하는 멀티 선택이 가능합니다. 선택을 모두 해제하면 다시 ALL로 자동 복귀합니다.
- 상단에 심각도(Critical/Important/Moderate/Low)별 전체 건수 요약이 표시되며, Product/Version을 선택하면 그 선택 결과 기준으로 심각도별 건수가 함께 갱신됩니다.
- 조건에 맞는 어드바이저리는 아코디언(`<details>`) 형태로 접힌 채 나열되며, 클릭하거나 Expand All/Collapse All 버튼으로 펼쳐서 Response Matrix 전체를 표(제목줄 포함)로 확인할 수 있습니다.

### 카테고리별 CSV (`VMSA_By_Category_<timestamp>/`)

Response Matrix의 Product(+Component) 텍스트를 기준으로 아래 8개 고정 카테고리 폴더/파일이 매 실행마다 생성됩니다 (0건이어도 생성):

```
ESX, vCenter, VMware Cloud Foundation, VMware vSphere Foundation,
Operations, Automation, NSX, Tools
```

각 CSV의 첫 번째 컬럼은 해당 카테고리 기준 영향 버전이며, 하나의 어드바이저리가 여러 카테고리에 동시에 포함될 수 있습니다.

---

## `VMSA_CVE_Lookup.ps1` (CVE 상세 조회 - 인터넷 PC)

`VMSA_FullList_Downloader.ps1`이 만든 `VMSA_CVE_List_<timestamp>.csv`(또는 "CVE" 컬럼이 있는 임의의 CSV)를 입력받아, 각 CVE를 NVD(국가 취약점 데이터베이스)에서 조회해 설명/CVSS/심각도/참고 링크를 CSV와 검색 가능한 HTML로 만들어줍니다.

### 사용법

```powershell
.\VMSA_CVE_Lookup.ps1 -CveListCsv .\VMSA_CVE_List_20260828-1529.csv
.\VMSA_CVE_Lookup.ps1 -CveListCsv .\VMSA_CVE_List_20260828-1529.csv -NvdApiKey "xxxxxxxx-...."
.\VMSA_CVE_Lookup.ps1 -CveListCsv .\VMSA_CVE_List_20260828-1529.csv -ForceRefreshAll
```

### 주요 파라미터

| 파라미터 | 기본값 | 설명 |
|---|---|---|
| `-CveListCsv` | (필수) | "CVE" 컬럼을 포함한 입력 CSV 경로 |
| `-NvdApiKey` | 없음 | NVD API 키 (있으면 요청 속도 제한 완화) |
| `-DelayMs` | `0` (자동) | 요청 간 대기시간 - 키 없으면 6200ms, 있으면 650ms 자동 적용 |
| `-ForceRefreshAll` | - | 캐시를 무시하고 모든 CVE를 다시 조회 |

### 동작 방식

- 조회 결과는 `CVE_Lookup_Cache.json`(고정 파일명)에 캐싱되어, 이미 조회된 CVE는 재실행 시 다시 조회하지 않습니다.
- 네트워크 순단 등으로 조회에 실패한 CVE는 캐시에 저장하지 않아 **다음 실행 시 자동으로 재시도**됩니다 (캐시에 실패가 영구히 박히는 문제 방지).
- 연속 HTTPS 요청 중 발생할 수 있는 "underlying connection was closed" 오류에 대비해 재시도(백오프) 로직이 포함되어 있습니다.

### 생성 파일

| 파일 | 설명 |
|---|---|
| `CVE_Lookup_Results_<timestamp>.csv` | CVE별 설명/CVSS/심각도/공개일/참고링크/관련 AdvisoryID |
| `CVE_Lookup_<timestamp>.html` | 검색창에 CVE ID(전체 또는 일부)를 입력하면 즉시 필터링되는 조회 화면 |
| `CVE_Lookup_Cache.json` | 조회 결과 누적 캐시 (고정 파일명) |

---

## 공통 참고 사항

- **캐시 파일명 규칙**: `VMSA_FullList_Data.json`, `CVE_Lookup_Cache.json`처럼 이름에 날짜가 없는 파일은 누적 캐시이며 재실행 시마다 갱신됩니다. 반면 CSV/HTML은 실행할 때마다 타임스탬프가 붙어 새로 생성되므로, 이전 실행 결과가 덮어써지지 않습니다.
- **인코딩**: 한글 등 비ASCII 문자가 깨지지 않으려면 `.ps1` 파일이 UTF-8 BOM으로 저장되어 있어야 합니다 (Windows PowerShell 5.1은 BOM이 없으면 시스템 코드페이지로 잘못 해석할 수 있습니다).
- **PowerShell 버전**: Windows PowerShell 5.1 기준으로 검증되었습니다. `pwsh`(PowerShell 7+)에서도 대부분 동작하지만 별도로 검증하지는 않았습니다.

## HTML output
<img width="2146" height="1183" alt="image" src="https://github.com/user-attachments/assets/6432d84f-7ba2-4f59-84e9-0a9f0b7e8ce3" />

## CSV output
<img width="1896" height="847" alt="image" src="https://github.com/user-attachments/assets/6e111ab6-37dd-4b4b-85b5-1e22314fe6da" />


