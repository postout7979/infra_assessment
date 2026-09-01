# VCF Operations 가상화 인프라 운영 현황 리포트 생성기 (PowerShell / HTML 전용)

Python 버전(`vcf_ops_report/`)을 PowerShell로 변환한 버전입니다. **PPTX는 이 버전에서
다루지 않으며, HTML 리포트만 생성**합니다. REST API(`Invoke-RestMethod`) 방식을 그대로
유지했습니다.

## ⚠️ 실행 환경에 대한 중요 안내

이 코드는 **이 환경에 PowerShell 실행기가 없어 직접 실행 테스트를 하지 못했습니다**
(인터넷 접근이 제한되어 PowerShell 설치 파일도 받을 수 없었습니다). 문법/here-string
종료 토큰/괄호 균형/함수명 일치 등을 한 줄씩 수동으로 정밀 검토했지만, Python 버전처럼
실제 실행 후 시각적으로 QA한 결과물은 아닙니다. **받으신 후 아래 순서로 먼저 가볍게
검증해보시는 걸 권장드립니다.**

```powershell
# 1) PowerShell 버전 확인 (7.0 이상 권장)
$PSVersionTable.PSVersion

# 2) 모듈이 정상적으로 파싱/로드되는지만 빠르게 확인
Get-ChildItem .\Modules\*.psm1 | ForEach-Object {
    [System.Management.Automation.Language.Parser]::ParseFile($_.FullName, [ref]$null, [ref]$errors)
    if ($errors) { Write-Host "$($_.Name): 문법 오류 있음" -ForegroundColor Red; $errors }
    else { Write-Host "$($_.Name): OK" -ForegroundColor Green }
}

# 3) Mock 데이터로 실제 생성 테스트
.\New-VCFOpsReport.ps1 -Mock -CustomerName "테스트"
```

문제가 발견되면 알려주시면 바로 고쳐드리겠습니다.

**Excel/PDF 출력은 특히 더 미검증입니다.** ImportExcel 모듈의 차트 관련 파라미터,
Edge/Chrome headless PDF 변환은 공개 문서/예제를 근거로 작성했지만 실제 실행을 못 해봤습니다.
실패해도 HTML(+CSV)은 항상 정상 생성되도록 폴백을 넣어뒀으니, 안 되면 경고 메시지와
함께 알려주세요.

## 빠른 시작 (Mock 데이터)

```powershell
.\New-VCFOpsReport.ps1 -Mock -CustomerName "고객사명"
```

`./output/` 폴더에 `vcfops_report_YYYYMMDD_HHMM.html` 이 생성됩니다.

## 실제 VCF Operations 연동

```powershell
.\New-VCFOpsReport.ps1 -HostUrl https://vcfops.corp.local -Username admin `
    -CustomerName "ABC손해보험" -ScopeLabel "vCenter: vc-seoul01" -SkipCertCheck
```

비밀번호를 `-Password`로 지정하지 않으면 실행 중 `Read-Host -AsSecureString` 으로
안전하게 입력받습니다. 환경변수(`VCFOPS_HOST`, `VCFOPS_USERNAME`, `VCFOPS_PASSWORD`,
`VCFOPS_AUTH_SOURCE`, `VCFOPS_CUSTOMER_NAME`, `VCFOPS_SCOPE_LABEL`)로도 전달할 수 있습니다.

대규모 환경에서는 먼저 `-MaxVMs 50` 으로 범위를 제한해 테스트하세요.

## 이메일(SMTP) 발송

```powershell
.\New-VCFOpsReport.ps1 -CustomerName "고객사명" -SendEmail `
    -SmtpServer smtp.corp.local -SmtpFrom "vcfops-report@corp.local" `
    -SmtpTo "manager@corp.local","sales@corp.local"
```

생성된 HTML/Excel(또는 CSV를 zip으로 묶은 것)/PDF를 첨부해서 발송합니다.
`Send-MailMessage`는 마이크로소프트가 폐기 예정으로 지정한 cmdlet이라
`System.Net.Mail.SmtpClient`(.NET)를 직접 사용했습니다.

- 인증이 필요 없는 내부 릴레이면 `-SmtpUsername` 없이 서버/발신자/수신자만 지정하면 됩니다.
- `-SmtpUsername`을 주고 비밀번호를 안 주면 실행 중 안전하게 입력받습니다.
- 환경변수로도 지정 가능: `VCFOPS_SMTP_SERVER`/`PORT`/`FROM`/`TO`/`USERNAME`/`PASSWORD`
- 기본은 SSL/TLS 사용(`-SmtpNoSsl`로 끌 수 있음)

### HTML을 첨부 대신 메일 본문에 바로 삽입 (`-EmailHtmlInBody`)

```powershell
.\New-VCFOpsReport.ps1 -CustomerName "고객사명" -SendEmail -EmailHtmlInBody `
    -SmtpServer smtp.corp.local -SmtpFrom "vcfops-report@corp.local" `
    -SmtpTo "manager@corp.local","sales@corp.local"
```

`-EmailHtmlInBody`를 지정하면 HTML 리포트를 첨부파일이 아니라 **메일 본문 자체**로 삽입해서
보냅니다(수신자가 메일을 열자마자 바로 확인 가능). Excel/PDF/CSV(zip)는 이 옵션과 무관하게
기존처럼 첨부로 함께 발송됩니다. `-EmailHtmlInBody`를 지정하지 않으면 기존과 동일하게 HTML도
첨부파일로 발송됩니다.

⚠️ Outlook 데스크톱 앱은 자체 렌더링 엔진(Word 기반)을 사용해 CSS flexbox/grid,
`position:sticky` 내비게이션, 외부 폰트(`<link>`), `<script>`(테이블 검색 필터) 등
일부가 첨부 방식과 다르게 보이거나 동작하지 않을 수 있습니다(카드/표/색상 등 핵심 내용은
정상 표시됩니다). 웹 메일(Gmail 등)이나 모바일 메일 앱에서는 대체로 잘 보입니다. 완전히
동일한 모습이 중요하면 기존 첨부 방식(`-EmailHtmlInBody` 미지정)을 사용하세요.

## 리소스 현황: VM Power On/Off 수량

"가상머신" 카드에 전체 수량 아래로 켜짐/꺼짐 대수가 함께 표시됩니다
(VM 인벤토리 properties의 `summary|runtime|powerState`로 판별, "Powered On" 기준).

## 출력 파일: HTML(웹용 + 이메일용) + Excel(또는 CSV) + PDF

```powershell
.\New-VCFOpsReport.ps1 -Mock -CustomerName "고객사명"              # HTML(웹용+이메일용) + Excel(또는 CSV) + PDF 모두 생성
.\New-VCFOpsReport.ps1 -Mock -CustomerName "고객사명" -SkipData    # Excel/CSV 생성 건너뛰기
.\New-VCFOpsReport.ps1 -Mock -CustomerName "고객사명" -SkipPdf     # PDF 변환 건너뛰기
```

### HTML 리포트 2종 (웹용 1개 + 이메일용 1개)

HTML 리포트는 실행할 때마다 항상 2개가 함께 생성됩니다(별도 옵션 없음):

- `vcfops_report_타임스탬프.html` — 브라우저/PDF 변환용 웹 버전. `<style>` 블록,
  flexbox/grid, sticky 내비게이션, 검색창(JS), 외부 폰트를 사용한 모던 대시보드입니다.
- `vcfops_report_타임스탬프_email.html` — **이메일용** 버전(`Modules/VCFOpsEmailHtmlReport.psm1`).
  `<style>`/`<script>`/외부 리소스를 전혀 사용하지 않고 `<table>` + 인라인 `style` 속성만으로
  동일한 데이터를 렌더링합니다. Outlook 등 데스크톱 메일 클라이언트(자체 렌더링 엔진 사용)에
  그대로 붙여넣거나 첨부해도 레이아웃이 깨지지 않도록 만든 버전입니다. `-SendEmail -EmailHtmlInBody`
  옵션을 쓰면 이 파일이 자동으로 메일 본문에 삽입됩니다(위 "이메일(SMTP) 발송" 참고).
  카드/막대그래프 대신 데이터 테이블 위주로 구성되어 있어 웹 버전보다 다소 밋밋하지만,
  어떤 메일 클라이언트에서도 안정적으로 보입니다.
  ⚠️ VM 대수가 매우 많은 환경에서는 이 파일 용량이 커질 수 있습니다(예: VM 수백 대 기준
  수백 KB). Gmail 웹은 HTML 이메일 본문이 약 102KB를 넘으면 메일을 자동으로 잘라
  "메일 전체 보기" 링크로 표시하는 것으로 알려져 있으니, 너무 커지면 본문 삽입 대신
  첨부(`-EmailHtmlInBody` 미지정) 방식을 권장합니다.
  - 색상 팔레트: 사내에서 참고용으로 공유된 이메일 리포트 예시와 동일한 톤으로
    맞춰져 있습니다 — 상단 배너 진한 인디고(`#3730a3`), 테이블 헤더 진한 네이비
    (`#1c2130` 배경 + 흰 글자), 본문 행은 흰색/연회색(`#f6f8fb`) 교차 줄무늬,
    섹션 제목 좌측 강조 바(`#4f46e5`), 테두리 `#dde1e8`. 위험/주의/정상 상태
    배지는 기존 웹 리포트와 동일한 의미색(빨강/주황/초록 계열)을 그대로 유지합니다.
    (`Modules/VCFOpsEmailHtmlReport.psm1` 상단의 `$Script:EC` 해시테이블에서
    색상값을 한 곳에서 관리합니다.)

### Excel (1개 파일, 여러 시트) — 안 되면 자동으로 CSV 다중 파일로 폴백

[ImportExcel](https://github.com/dfinke/ImportExcel) 모듈이 설치되어 있으면
`vcfops_report_타임스탬프.xlsx` **하나**에 인벤토리수량/성능요약/데이터스토어/클러스터/
ESXi호스트/VM Top 3종/스냅샷/VM인벤토리/VM디스크/VM성능/VM분포 4종 — 총 16개 시트가
생성됩니다. 클러스터·데이터스토어·Guest OS 분포 시트에는 **네이티브 Excel 차트도 함께
생성**됩니다(시도해보고 실패하면 차트 없이 데이터만 정상적으로 들어갑니다).

```powershell
Install-Module ImportExcel -Scope CurrentUser    # 최초 1회만 설치 (Excel 프로그램 설치 불필요)
```

모듈이 없으면 경고만 출력하고 기존처럼 `./output/csv_타임스탬프/` 에 데이터셋별 CSV
여러 개로 자동 폴백합니다 — 별도 설정 없이도 항상 결과물은 나옵니다.

### PDF

HTML 리포트를 Windows에 기본 내장된 **Microsoft Edge의 headless 모드**로 PDF
변환합니다(Edge가 없으면 Chrome을 찾아 시도). 둘 다 없는 환경이면 경고만 남기고
PDF 없이 HTML/Excel/CSV는 정상적으로 생성됩니다 — 추가 설치가 필요 없는 방식을
우선 사용했습니다.

### 콘솔 진행률

실행 중 `[2/6] 데이터 수집 중...` 형식으로 단계가 표시되고, 그 아래 `- 클러스터
성능 통계 조회 중...` 같은 세부 진행 내역도 함께 출력됩니다(`-Verbose` 없이도
기본으로 보입니다).

## 비교(N일 전) 옵션

```powershell
.\New-VCFOpsReport.ps1 -CompareDays 30   # 30일 전과 비교
.\New-VCFOpsReport.ps1                    # -CompareDays 미입력/0 -> 비교 없이 현재값만 출력
```

- `-CompareDays`를 입력하지 않거나 0이거나, 그 시점 데이터가 없는 경우(보존기간 초과 등)
  **자동으로 비교 없이 현재값만 표시**합니다(경고만 콘솔에 남습니다).
- **Executive Summary / 클러스터별 성능**: VCF Operations의 실제 시계열 API로 해당 시점을
  직접 조회합니다. 한 번도 그 시점에 실행한 적이 없어도 정확합니다.
- **리소스 현황(수량) / VM 인벤토리 요약(OS·Tools·HW·vCPU 분포)**: 시계열 API가 없어
  로컬 캐시(`./snapshots/`)로만 비교 가능합니다. **처음 실행 시에는 비교할 과거 캐시가
  없어 "비교 없음"으로 나오고, 주기적으로 실행해서 캐시가 쌓여야 비교가 채워집니다.**

## 리포트 구성 (이번 개편 반영)

- Executive Summary / 리소스 현황: vCenter 수량 추가
- 클러스터별 성능: 비교 활성 시 카드별로 증감 표시
- **데이터스토어 현황**: 클러스터명 + 현재/이전 용량 + 증감(용량·사용량)을 검색 가능한
  테이블로 표시 (`StatKeysDatastore` 가 미확인이라 0으로 보이면 아래 안내 참고)
- **가상디스크 레이턴시 Top10**: 데이터스토어 컬럼이 VM 인벤토리(properties)에서 가져온
  실제 데이터스토어명으로 채워집니다 (이전엔 N/A로만 표시됨)
- **ESXi 호스트 / VM Top 리스트**: 각각 지표별(CPU 사용률 / MEM 사용률 / CPU 경합률,
  vCPU 사용률 / CPU 경합 Ready / 디스크 레이턴시) 독립적인 Top10 테이블 3개로 분리해
  세로로 배치됩니다 (호스트·VM 모두 인기 지표가 다를 수 있어 통합 랭킹 대신 분리)
- **VM 인벤토리 요약**: 개별 VM 리스트가 아니라 Guest OS / VMware Tools 버전 /
  Virtual HW버전 / vCPU 구간(4개 이하·5~8·9~16·17~32·33개 이상)별 수량 분포 카드
  (2열 배치)
- **VM 성능정보 요약**: 개별 VM 리스트가 아니라 CPU 사용률 / CPU 경합(Ready) / MEM
  사용률 / 가상디스크 레이턴시 4개 지표의 정상·주의·위험 등급별 VM 수량(등급 기준
  수치 범위 함께 표시)

## vCenter 수량 관련 참고

`Get-VCenterCount`(`Modules/VCFOpsCollector.psm1`)는 `/suite-api/api/adapters`
응답에서 VMWARE 어댑터 인스턴스 수를 vCenter 수량으로 집계합니다. 응답 구조가
환경별로 다를 수 있어 실패 시 0으로 표시되고 경고가 출력됩니다 — 이 경우
`Invoke-VCFOpsApi -Method GET -Path "/suite-api/api/adapters"` 를 직접 호출해
실제 응답 구조를 확인 후 알려주시면 정확히 고쳐드리겠습니다.

## 인벤토리 수량 비교 방식 (vSphere World 리소스 기반)

- **vCenter / 데이터센터 / 클러스터 / ESXi 호스트 / VM 수량 전부**: 인프라 전체를
  대표하는 단일 리소스인 **"vSphere World"**에서 `summary|total_number_vcenters`,
  `summary|total_number_datacenters`, `summary|total_number_clusters`,
  `summary|total_number_hosts`, `summary|total_number_vms` 키로 N일 전 시점을
  직접 조회합니다 (조회 윈도우 12시간). 클러스터별로 합산하는 방식이 아니라
  공식적으로 확인된 단일 리소스 조회 방식입니다.
  (참고: https://www.brockpeterson.com/post/pulling-vsphere-world-metrics-from-vcf-operations)
- 동작하면 카드에 **"(실측)"** 표시가 뜹니다. World 리소스를 못 찾거나 해당 시점
  데이터가 없으면 자동으로 캐시 비교로 폴백됩니다.
- `Test-StatKeys.ps1` 실행 시 vSphere World 리소스를 자동으로 탐색해서 위 5개 키의
  실제 수집 여부를 보여줍니다.

## ESXi 호스트명 마스킹 (도메인/IP 비식별화)

리포트에 표시되는 ESXi 호스트 식별자(호스트 Top 리스트, VM 인벤토리/Top 리스트의
Host 컬럼 — HTML/Excel/CSV 전부 동일 적용)는 실제 API 값을 그대로 쓰지 않고
`Modules/VCFOpsCollector.psm1`의 `Protect-VCFOpsHostIdentifier` 함수를 거쳐
아래처럼 자동 마스킹됩니다(외부/타사에 리포트를 공유할 때 사내 도메인·IP 노출 방지 목적):

- **FQDN**: 호스트명은 유지하고 도메인 부분만 `vcf.local`로 치환
  예) `esx01.corp.local` → `esx01.vcf.local`
- **IPv4 주소**: 앞 3개 옥텟을 `***`로 마스킹, 마지막 옥텟만 유지
  예) `192.168.10.55` → `***.***.***.55`
- 도메인이 없는 짧은 이름(예: `esx-prd1-01`)은 그대로 표시됩니다.

이 마스킹은 리소스 인벤토리를 조회한 직후(호스트명 매핑 생성 시점) 한 곳에서 적용되어
이후 모든 화면·파일에 자동으로 반영됩니다. `-Mock` 데이터는 애초에 도메인/IP가 없는
짧은 이름을 사용하므로 마스킹 전후 차이가 보이지 않습니다(정상 동작).
도메인/마스킹 규칙을 바꾸고 싶으면 `Protect-VCFOpsHostIdentifier` 함수만 수정하면 됩니다.

## 데이터스토어 현황 관련 참고

- **용량/사용량 키**: 확인 완료 — `capacity|total_capacity` / `capacity|used_space` /
  `capacity|available_space` (서로 교차검증됨: 총량 − 사용량 = 가용량).
- **로컬 데이터스토어 제외**: properties의 `summary|isLocal` 값이 `true`인 데이터스토어는
  목록에서 제외하도록 했습니다(`Modules/VCFOpsCollector.psm1`의 `Get-DatastoreInfoWithDelta`).
  ⚠️ 이 키 이름은 아직 미확인 추정값입니다 — `Test-VmProperties.ps1 -ResourceKind Datastore`
  로 실제 키를 확인해서 보내주시면 정확히 맞추겠습니다. 키가 틀려도 단순히 "전부 안 제외됨"
  으로만 동작해서 에러는 나지 않습니다.
- **동일 UUID 중복 제거**: properties의 `summary|url`(vSphere 표준 객체모델의 UUID가
  포함된 URL, 예: `ds:///vmfs/volumes/<UUID>/`)이 같은 값이면 같은 물리 데이터스토어로
  보고 처음 한 번만 표시합니다(여러 vCenter/리소스로 중복 검출되는 경우 대비). ⚠️ 이 키도
  미확인 추정값입니다 — 틀리면 단순히 "중복 제거가 안 일어남"으로만 동작합니다.
- **클러스터명 매핑**: 클러스터 -> 데이터스토어 관계를 `Get-VCFOpsChildren`(클러스터 기준
  CHILD 조회)으로 가져오는데, 실제 관계 방향이 이와 다르면(예: 데이터센터 하위로만 연결)
  클러스터명이 비어있을 수 있습니다.

## 진단 스크립트 (statKey / property 키가 환경과 안 맞을 때)

```powershell
.\Test-StatKeys.ps1 -HostUrl $env:VCFOPS_HOST -Username admin -SkipCertCheck
.\Test-VmProperties.ps1 -HostUrl $env:VCFOPS_HOST -Username admin -SkipCertCheck
.\Test-VmProperties.ps1 -ResourceKind Datastore -SkipCertCheck    # 데이터스토어 properties(isLocal 등) 확인
```

각각 클러스터/호스트/VM의 실제 통계 키, VM(또는 `-ResourceKind`로 지정한 다른 리소스)의
실제 property 키를 뽑아서 보여줍니다. 결과를 보내주시면 `VCFOpsStatKeys.psm1`을
추측 없이 정확하게 맞춰드립니다.

## ⚠️ statKey/property 검증 필수

Python 버전과 동일하게, statKey/property 이름은 환경별로 다를 수 있습니다.
`Modules/VCFOpsStatKeys.psm1` 한 곳에서 관리하므로, 다르면 이 파일만 수정하면 됩니다.
검증 방법은 Python 버전 README 3번 항목과 동일합니다.

```text
GET /suite-api/api/adapterkinds/VMWARE/resourcekinds/{ResourceKind}/statkeys
GET /suite-api/api/resources/{resourceId}/stats
GET /suite-api/api/resources/{resourceId}/properties
```

## 디렉터리 구조

```
New-VCFOpsReport.ps1            메인 진입점 (CLI)

Modules/
  VCFOpsTheme.psm1               디자인 토큰(파스텔 팔레트) + 임계치 + 숫자 포맷 헬퍼
  VCFOpsStatKeys.psm1            statKey/property 매핑 (환경별 조정 지점)
  VCFOpsApiClient.psm1           VCF Operations REST API 클라이언트 (Invoke-RestMethod 기반)
  VCFOpsSnapshotCache.psm1       인벤토리 수량 주간 비교용 로컬 JSON 캐시
  VCFOpsCollector.psm1           API -> 리포트 데이터 변환 (수집 오케스트레이션)
  VCFOpsMockData.psm1            샘플 데이터 생성기 (-Mock)
  VCFOpsHtmlReport.psm1          HTML 리포트 렌더러 - 웹용 (모던/파스텔 대시보드)
  VCFOpsEmailHtmlReport.psm1     HTML 리포트 렌더러 - 이메일용 (CSS/JS 없이 테이블+인라인 style)
  VCFOpsCsvExport.psm1           CSV 다중 파일 출력 (Excel 사용 불가 시 폴백)
  VCFOpsExcelExport.psm1         Excel(.xlsx, 다중 시트 + 차트) 출력 - ImportExcel 모듈 기반
  VCFOpsPdfExport.psm1           HTML -> PDF 변환 (Edge/Chrome headless)
  VCFOpsEmailExport.psm1         SMTP 이메일 발송 (System.Net.Mail 기반)
  VCFOpsProgress.psm1            콘솔 진행률("[n/총] 메시지") 표시 헬퍼
```

Python 버전의 `config.py`에 대응하는 별도 설정 파일은 두지 않았습니다. PowerShell에서는
`param()` 기본값 + 환경변수로 충분히 대응되고, 디자인/임계치/통계키 조정은
`VCFOpsTheme.psm1`/`VCFOpsStatKeys.psm1` 두 곳에서 하시면 됩니다.

## Python 버전과의 차이점

| 항목 | Python 버전 | PowerShell 버전 |
|---|---|---|
| 출력 형식 | HTML + PPTX | **HTML만** |
| HTTP 클라이언트 | `requests` | `Invoke-RestMethod` |
| 동시성 | `ThreadPoolExecutor` | 순차 처리 (대규모 환경은 아래 참고) |
| 데이터 모델 | `dataclass` | `[PSCustomObject]` |

### 대규모 환경 성능 가속 (선택)

VM properties 조회처럼 리소스 1건당 API 1회 호출이 필요한 구간은 PowerShell 7+의
`ForEach-Object -Parallel` 로 가속할 수 있습니다. 예를 들어
`Modules/VCFOpsCollector.psm1`의 `Get-VmInventoryFromApi` 내부 속성 조회 루프를
아래처럼 바꾸면 동시 처리가 가능합니다 (단, 모듈 함수를 병렬 러너블 스크립트 블록에서
쓰려면 `-ThrottleLimit`과 함께 `Import-Module`을 각 병렬 스레드에서 다시 해줘야 합니다):

```powershell
$propsMap = $VmList | ForEach-Object -Parallel {
    Import-Module $using:ModulesPath\VCFOpsApiClient.psm1 -Force
    @{ Id = $_.identifier; Props = (Get-VCFOpsProperties -ResourceId $_.identifier) }
} -ThrottleLimit 10
```

기본 제공 코드는 안정성을 위해 순차 처리로 두었습니다.

## 실행 테스트 이력 (이메일용 HTML 추가 시 함께 발견/수정한 기존 버그)

이메일용 HTML(`VCFOpsEmailHtmlReport.psm1`)을 추가하면서 실제 PowerShell 7 환경에서
`-Mock` 실행 + 목(mock) API 서버를 띄운 `Invoke-VCFOpsCollection` 실행 + 헤드리스
브라우저 스크린샷까지 검증했고, 그 과정에서 기존 코드에 있던 버그 2가지를 함께 고쳤습니다.

- **"비교 기준일 (N일 전)" 표시 오류**: `Modules/VCFOpsHtmlReport.psm1`의
  `Get-CompareDaysLabel`에서 `"$days일 전"`처럼 변수 뒤에 한글을 바로 붙여 쓰면
  PowerShell이 `한글도 포함해 "$days일" 전체를 하나의 변수명으로 해석`해버려
  (해당 변수가 없으므로 빈 값) 웹 리포트의 비교 기준일이 항상 "( 전)"으로만
  표시되던 문제가 있었습니다. `${days}일 전`처럼 중괄호로 변수명을 명시해 수정했고,
  이메일용 렌더러에도 동일한 패턴이 있어 같이 고쳤습니다.
- **Mock 데이터의 Thick 디스크 목록이 항상 비어 있던 문제**: 웹/이메일 리포트 모두
  디스크를 "Thin/Thick"으로 나눌 때 `ProvisioningKind` 필드를 보는데,
  `VCFOpsMockData.psm1`은 `Provisioning`(예: "Thick Eager Zeroed")만 채우고
  `ProvisioningKind`는 채우지 않아 `-Mock`으로 실행하면 "Thick 프로비저닝 디스크
  목록" 섹션이 항상 "없습니다"로만 나왔습니다. 실제 API 연동 시에는 영향 없는
  Mock 전용 버그였지만, 데모/테스트 시 혼동을 줄 수 있어 함께 수정했습니다.

## 알려진 제약 사항

- PPTX 생성은 포함되어 있지 않습니다. 필요하시면 Python 버전의 `--format pptx`를
  계속 사용하시거나, 하이브리드(수집/HTML은 PowerShell, PPTX 생성만 Python 호출)로
  연결하는 방법을 도와드릴 수 있습니다.
- Windows PowerShell 5.1에서는 `Invoke-RestMethod -SkipCertificateCheck` 가 없어
  자체서명 인증서 환경에서 별도 인증서 콜백 설정이 필요합니다. **PowerShell 7+(pwsh)
  사용을 권장**합니다.
- `-Mock` 실행과, 목(mock) API 서버를 이용한 `Invoke-VCFOpsCollection`(실제 API
  연동 경로) 흐름은 PowerShell 7 환경에서 직접 실행해 검증했습니다. 다만 실제
  VCF Operations 서버를 대상으로 한 연동 테스트는 이 환경에서 할 수 없어 아직
  거치지 못했으므로, statKey/property 값은 여전히 `Test-StatKeys.ps1` /
  `Test-VmProperties.ps1`로 사용자 환경에서 검증하시는 것을 권장합니다.
