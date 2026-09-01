# VCFOpsStatKeys.psm1
# -----------------------------------------------------------------------------
# VCF Operations (Aria Operations / vRealize Operations) suite-api statKey 매핑
#
# [중요] statKey/property 이름은 vCenter Adapter 버전, 설치된 Management Pack,
# VCF Operations 버전에 따라 달라질 수 있습니다. 아래 값은 vSphere(VMWARE) 어댑터
# 환경에서 가장 보편적으로 쓰이는 기본값이며, 실제 연동 전 반드시 사용자 환경에서
# 검증하세요.
#
# 검증 방법(suite-api):
#   GET /suite-api/api/adapterkinds/VMWARE/resourcekinds/{ResourceKind}/statkeys
#   GET /suite-api/api/resources/{resourceId}/stats
#   GET /suite-api/api/resources/{resourceId}/properties
#
# 키가 환경과 다르면 이 파일만 수정하면 되고, 나머지 스크립트는 변경할 필요가 없습니다.
# -----------------------------------------------------------------------------

$ResourceKind = @{
    datacenter = "Datacenter"
    cluster    = "ClusterComputeResource"
    host       = "HostSystem"
    vm         = "VirtualMachine"
    datastore  = "Datastore"
}

$AdapterKindVMware = "VMWARE"

$StatKeysCluster = @{
    cpu_usage_pct       = "cpu|capacity_usagepct_average"   # 확인됨: usagemhz_average/capacity_provisioned 와 일치
    cpu_capacity_mhz    = "cpu|capacity_provisioned"        # 확인됨
    cpu_contention_pct  = "cpu|capacity_contentionPct"      # 확인됨
    mem_usage_pct       = "mem|usage_average"               # 확인됨
    mem_capacity_kb     = "mem|host_provisioned"            # 확인됨 (consumed_average와 교차검증 일치)
    storage_used_gb     = "diskspace|used"                  # 확인됨 (※ _average 접미사 없음)
    storage_total_gb    = "diskspace|total_capacity"        # 확인됨
    storage_latency_ms  = "disk|totalLatency_average"       # 확인됨 (namespace가 datastore가 아니라 disk)
}

# Datastore 리소스 레벨 statKey.
# 확인됨 - 실제 환경에서 capacity|total_capacity / capacity|used_space / capacity|available_space
# 세 값이 (총량 - 사용량 = 가용량) 으로 정확히 교차검증되었습니다.
# (이전에 추정했던 "diskspace|total_capacity"는 Datastore에 존재하지 않았고,
#  "diskspace|used"는 존재해도 값이 부정확했습니다.)
$StatKeysDatastore = @{
    capacity_gb = "capacity|total_capacity"
    used_gb     = "capacity|used_space"
    free_gb     = "capacity|available_space"
}

# Datastore property 키.
# ⚠️ 미확인 - "summary|isLocal" 로 추정(다른 summary|* 키들과 동일한 네이밍 패턴).
#    uuid_url은 vSphere 표준 객체모델의 summary.url(예: "ds:///vmfs/volumes/<UUID>/")에
#    UUID가 포함되어 있어, 같은 물리 데이터스토어가 여러 vCenter/리소스로 중복 발견되는
#    경우를 식별하는 키로 추정했습니다. 정확한 값은 Test-VmProperties.ps1 -ResourceKind
#    Datastore 로 확인 가능합니다.
$PropertyKeysDatastore = @{
    is_local = "summary|isLocal"
    uuid_url = "summary|url"
}

# "vSphere World" 리소스(인프라 전체를 대표하는 단일 객체) 레벨 statKey.
# 출처: https://www.brockpeterson.com/post/pulling-vsphere-world-metrics-from-vcf-operations
# 클러스터/호스트/VM 등 인벤토리 "수량"의 시계열 비교는 이 객체 하나에서 직접 조회합니다
# (클러스터별로 합산하는 방식이 아님 - 더 정확하고 공식적으로 확인된 방법).
$StatKeysWorld = @{
    vcenter_count    = "summary|total_number_vcenters"
    datacenter_count = "summary|total_number_datacenters"
    cluster_count    = "summary|total_number_clusters"
    host_count       = "summary|total_number_hosts"
    vm_count         = "summary|total_number_vms"
}

$StatKeysHost = @{
    cpu_usage_pct      = "cpu|usage_average"         # 확인됨
    mem_usage_pct      = "mem|usage_average"         # 확인됨
    cpu_contention_pct = "cpu|max_cpu_ready"         # 확인됨 (호스트엔 contentionPct 키가 없어 ready% 로 대체)
    mem_contention_pct = "mem|host_contentionPct"    # 확인됨
}

$StatKeysVM = @{
    cpu_usage_pct          = "cpu|usage_average"        # 확인됨
    cpu_ready_pct          = "cpu|readyPct"             # 확인됨 (※ _average 접미사 없음)
    mem_usage_pct          = "mem|usage_average"        # 확인됨
    mem_active_kb          = "mem|active_average"       # 확인됨
    disk_latency_ms        = "virtualDisk:Aggregate of all instances|totalLatency"               # 확인됨
    disk_read_latency_ms   = "virtualDisk:Aggregate of all instances|totalReadLatency_average"    # 확인됨
    disk_write_latency_ms  = "virtualDisk:Aggregate of all instances|totalWriteLatency_average"   # 확인됨
    disk_read_iops         = "virtualDisk:Aggregate of all instances|numberReadAveraged_average"  # 확인됨 (read+write 합산해서 IOPS로 사용)
    disk_write_iops        = "virtualDisk:Aggregate of all instances|numberWriteAveraged_average" # 확인됨
    net_throughput_kbps    = "net|usage_average"        # 확인됨 (throughput_usage_average는 존재하지 않았음)
}

$PropertyKeysVM = @{
    guest_os                    = "config|guestFullName"            # 확인됨
    hw_version                  = "config|version"                  # 확인됨 (실제 데이터로 검증, vmx-15 등 반환)
    vmtools_version              = "summary|guest|toolsVersion"       # 확인됨 (12.4.5)
    vmtools_status               = "summary|guest|toolsRunningStatus" # 확인됨 ("Guest Tools Running")
    vmtools_version_status      = "summary|guest|toolsVersionStatus2" # 확인됨 (※ 끝에 "2" 붙음, "Guest Tools Unmanaged")
    power_state                 = "summary|runtime|powerState"        # 확인됨 ("Powered On")
    vcpu_num                    = "config|hardware|numCpu"            # 확인됨
    vmem_kb                      = "config|hardware|memoryKB"          # 확인됨 (※ MB가 아니라 KB, 단위 변환 수정 필요)
}

# 디스크는 "config|hardware|disk{N}|..." 형태가 아니라
# "virtualDisk:scsi0:0|..." (SCSI 컨트롤러:유닛 표기) 형태로 확인되었습니다.
$DiskPropertySuffix = @{
    capacity_gb    = "configuredGB"        # 확인됨 (※ 이미 GB 단위, 추가 변환 불필요)
    provisioning   = "provisioning_type"   # 확인됨 (문자열, 예: "Thin Provision")
    datastore      = "datastore"           # 확인됨
    label          = "label"               # 확인됨 (예: "Hard disk 1")
    shared         = "shared"              # ⚠️ 미확인 - 이 VM은 공유디스크가 없어 예시가 없었음. 없으면 false로 처리됨(공유 아닌 디스크엔 정상 동작)
}

# 스냅샷은 "summary|snapshot|*" 가 아니라 "diskspace|snapshot|*" 형태였습니다.
$PropertyKeysSnapshot = @{
    snapshot_age_days = "diskspace|snapshot|snapshotAge"   # 확인됨 (값이 -1이면 스냅샷 없음, 0 이상이면 보존일수)
}
# 스냅샷 용량은 property가 아니라 stat(시계열)으로 확인되었습니다 ("diskspace|snapshot", VM stats).
$StatKeySnapshotSizeGb = "diskspace|snapshot"

Export-ModuleMember -Variable ResourceKind, AdapterKindVMware, StatKeysCluster, StatKeysDatastore, StatKeysHost, StatKeysVM, StatKeysWorld, `
    PropertyKeysVM, PropertyKeysSnapshot, PropertyKeysDatastore, DiskPropertySuffix, StatKeySnapshotSizeGb
