# VCFOpsProgress.psm1
# -----------------------------------------------------------------------------
# 콘솔에 "[n/총단계] 메시지" 형식으로 진행률을 표시하는 단순 헬퍼.
# Write-Progress(진행률 바)는 호스트/리다이렉션 환경에 따라 표시가 들쭉날쭉해서,
# 어떤 콘솔/로그 환경에서도 동일하게 보이는 텍스트 기반 방식을 사용합니다.
# -----------------------------------------------------------------------------

$Script:StepCurrent = 0
$Script:StepTotal = 0

function Initialize-VCFOpsProgress {
    [CmdletBinding()]
    param([int]$Total)
    $Script:StepCurrent = 0
    $Script:StepTotal = $Total
}

function Write-VCFOpsStep {
    # 상위 단계 ("[2/6] HTML 리포트 생성 중...")
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$Message, [switch]$NoIncrement)
    if (-not $NoIncrement) { $Script:StepCurrent++ }
    $prefix = if ($Script:StepTotal -gt 0) { "[$($Script:StepCurrent)/$($Script:StepTotal)]" } else { "[*]" }
    Write-Host "$prefix $Message" -ForegroundColor Cyan
}

function Write-VCFOpsSubStep {
    # 하위 진행 내역 (들여쓰기, 회색) - 단계 번호 증가 없음
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$Message)
    Write-Host "    - $Message" -ForegroundColor DarkGray
}

function Write-VCFOpsStepDone {
    [CmdletBinding()]
    param([string]$Message = "완료")
    Write-Host "    ✓ $Message" -ForegroundColor Green
}

Export-ModuleMember -Function Initialize-VCFOpsProgress, Write-VCFOpsStep, Write-VCFOpsSubStep, Write-VCFOpsStepDone
