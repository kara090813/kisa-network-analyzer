# -*- coding: utf-8 -*-
"""
rules/kisa_rules.py
KISA 네트워크 장비 보안 점검 룰셋 정의 (완전판)

KISA 가이드 기반 보안 룰들의 정의만 포함
logical_check_function은 checks_kisa.py에서 import
"""

# 공통 클래스들을 loader에서 import
from .loader import RuleCategory, ConfigContext, LogicalCondition, SecurityRule, parse_config_context
# ==================== KISA 룰셋 정의 ====================

# checks_kisa.py에서 logical_check_function들 import
from .checks_kisa import (
    check_basic_password_usage,
    check_password_complexity,
    check_password_encryption,
    check_vty_access_control,
    check_session_timeout,
    check_security_patch_management,
    check_snmp_service_status,
    check_snmp_security,
    check_snmp_acl_configuration,
    check_snmp_community_permissions,
    check_tftp_service_status,
    check_anti_spoofing_filtering,
    check_ddos_protection,
    check_unused_interface_shutdown,
    check_user_privilege_levels,
    check_ssh_protocol_usage,
    check_auxiliary_port_security,
    check_login_banner_message,
    check_remote_log_server,
    check_logging_buffer_size,
    check_logging_policy_configuration,
    check_ntp_server_configuration,
    check_timestamp_logging,
    check_tcp_keepalive_service,
    check_finger_service_status,
    check_web_service_security,
    check_small_services_status,
    check_bootp_service_status,
    check_cdp_service_status,
    check_directed_broadcast_status,
    check_source_routing_status,
    check_proxy_arp_status,
    check_icmp_services_status,
    check_identd_service_status,
    check_domain_lookup_status,
    check_pad_service_status,
    check_mask_reply_status,
    check_switch_hub_security
)

KISA_RULES = {
    # ======================= 계정 관리 =======================
    
    "N-01": SecurityRule(
        rule_id="N-01",
        title="기본 패스워드 변경",
        description="기본 패스워드를 변경하지 않고 사용하는지 점검",
        severity="상",
        category=RuleCategory.ACCOUNT_MANAGEMENT,
        patterns=[
            r"enable\s+password\s+(cisco|admin|password|123|1234|default)",
            r"username\s+\w+\s+password\s+(cisco|admin|password|123|1234|default)",
        ],
        negative_patterns=[
            r"enable\s+secret\s+\$1\$",
            r"service\s+password-encryption"
        ],
        device_types=["Cisco", "Alteon", "Passport", "Juniper", "Piolink"],
        recommendation="enable secret 명령어를 사용하여 암호화된 패스워드 설정 필요",
        reference="KISA 가이드 N-01 (상) 1.1 패스워드 설정",
        logical_check_function=check_basic_password_usage,
    ),
    
    "N-02": SecurityRule(
        rule_id="N-02",
        title="패스워드 복잡성 설정",
        description="패스워드 복잡성 정책이 적용되어 있는지 점검",
        severity="상",
        category=RuleCategory.ACCOUNT_MANAGEMENT,
        patterns=[
            r"enable\s+password\s+\w{1,7}$",
            r"username\s+\w+\s+password\s+\w{1,7}$"
        ],
        negative_patterns=[
            r"security\s+passwords\s+min-length\s+[8-9]|[1-9][0-9]",
            r"enable\s+secret\s+.{8,}"
        ],
        device_types=["Cisco", "Alteon", "Passport", "Juniper", "Piolink"],
        recommendation="최소 8자 이상의 복잡한 패스워드 설정 및 복잡성 정책 적용",
        reference="KISA 가이드 N-02 (상) 1.2 패스워드 복잡성 설정",
        logical_check_function=check_password_complexity,
    ),
    
    "N-03": SecurityRule(
        rule_id="N-03",
        title="암호화된 패스워드 사용",
        description="패스워드 암호화 설정이 적용되어 있는지 점검",
        severity="상",
        category=RuleCategory.ACCOUNT_MANAGEMENT,
        patterns=[
            r"enable\s+password\s+[^$0-9]",
            r"username\s+\w+\s+password\s+[^$0-9]"
        ],
        negative_patterns=[
            r"enable\s+secret",
            r"username\s+\w+\s+secret",
            r"service\s+password-encryption"
        ],
        device_types=["Cisco", "Juniper"],
        recommendation="enable secret 및 service password-encryption 설정 적용",
        reference="KISA 가이드 N-03 (상) 1.3 암호화된 패스워드 사용",
        logical_check_function=check_password_encryption,
    ),
    
    "N-04": SecurityRule(
        rule_id="N-04",
        title="VTY 접근 제한 설정", 
        description="VTY 라인에 접근 제한 ACL이 설정되어 있는지 점검",
        severity="상",
        category=RuleCategory.ACCESS_MANAGEMENT,
        patterns=[
            r"line\s+vty.*(?:\n(?!.*access-class).*)*"
        ],
        negative_patterns=[
            r"line\s+vty.*\n.*access-class\s+\d+\s+in"
        ],
        device_types=["Cisco", "Alteon", "Passport", "Juniper", "Piolink"],
        recommendation="VTY 라인에 특정 IP 주소만 접근 가능하도록 ACL 설정",
        reference="KISA 가이드 N-04 (상) 2.1 VTY 접근(ACL) 설정",
        logical_check_function=check_vty_access_control,
    ),
    
    "N-05": SecurityRule(
        rule_id="N-05",
        title="Session Timeout 설정",
        description="Session Timeout이 적절히 설정되어 있는지 점검",
        severity="상",
        category=RuleCategory.ACCESS_MANAGEMENT,
        patterns=[
            r"exec-timeout\s+0\s+0",
            r"exec-timeout\s+[6-9][0-9]|[1-9][0-9]{2,}"
        ],
        negative_patterns=[
            r"exec-timeout\s+[1-5]\s+0"
        ],
        device_types=["Cisco", "Alteon", "Juniper", "Piolink"],
        recommendation="Session Timeout을 5분 이하로 설정",
        reference="KISA 가이드 N-05 (상) 2.2 Session Timeout 설정",
        logical_check_function=check_session_timeout,
    ),
    
    "N-06": SecurityRule(
        rule_id="N-06",
        title="최신 보안 패치 및 벤더 권고사항 적용",
        description="패치 적용 정책에 따라 주기적인 패치를 하고 있는지 점검",
        severity="상",
        category=RuleCategory.PATCH_MANAGEMENT,
        patterns=[
            r"show\s+version"  # 버전 확인을 위한 패턴
        ],
        negative_patterns=[],
        device_types=["Cisco", "Alteon", "Passport", "Juniper", "Piolink"],
        recommendation="장비 별 제공하는 최신 취약점 정보를 파악 후 최신 패치 및 업그레이드를 수행",
        reference="KISA 가이드 N-06 (상) 3.1 최신 보안 패치 및 벤더 권고사항 적용",
        logical_check_function=check_security_patch_management,
    ),
    
    "N-07": SecurityRule(
        rule_id="N-07",
        title="SNMP 서비스 확인",
        description="네트워크 장비의 SNMP 서비스를 사용하지 않는 경우 비활성화 상태인지 점검",
        severity="상",
        category=RuleCategory.FUNCTION_MANAGEMENT,
        patterns=[
            r"snmp-server"
        ],
        negative_patterns=[
            r"no\s+snmp-server"
        ],
        device_types=["Cisco", "Alteon", "Passport", "Juniper", "Piolink"],
        recommendation="SNMP 서비스를 사용하지 않는 경우 비활성화하고, 사용하는 경우 SNMPv3 사용 권고",
        reference="KISA 가이드 N-07 (상) 5.1 SNMP 서비스 확인",
        logical_check_function=check_snmp_service_status,
    ),
    
    "N-08": SecurityRule(
        rule_id="N-08",
        title="SNMP Community String 복잡성",
        description="기본 또는 단순한 SNMP Community String 사용 여부 점검",
        severity="상",
        category=RuleCategory.FUNCTION_MANAGEMENT,
        patterns=[
            r"snmp-server\s+community\s+(public|private)"
        ],
        negative_patterns=[
            r"snmp-server\s+community\s+[a-zA-Z0-9_-]{8,}"
        ],
        device_types=["Cisco", "Alteon", "Passport", "Juniper", "Piolink"],
        recommendation="Public, Private 외 유추하기 어려운 복잡한 Community String 설정",
        reference="KISA 가이드 N-08 (상) 5.2 SNMP community string 복잡성 설정",
        logical_check_function=check_snmp_security,
    ),
    
    "N-09": SecurityRule(
        rule_id="N-09",
        title="SNMP ACL 설정",
        description="SNMP 서비스 사용 시 ACL을 설정하여 접근 IP를 제한하였는지 점검",
        severity="상",
        category=RuleCategory.FUNCTION_MANAGEMENT,
        patterns=[
            r"snmp-server\s+community\s+\w+\s+RO(?!\s+\d+)",
            r"snmp-server\s+community\s+\w+\s+RW(?!\s+\d+)"
        ],
        negative_patterns=[
            r"snmp-server\s+community\s+\w+\s+RO\s+\d+",
            r"snmp-server\s+community\s+\w+\s+RW\s+\d+"
        ],
        device_types=["Cisco", "Alteon", "Passport", "Juniper", "Piolink"],
        recommendation="SNMP 접근에 대한 ACL(Access list) 설정",
        reference="KISA 가이드 N-09 (상) 5.3 SNMP ACL 설정",
        logical_check_function=check_snmp_acl_configuration,
    ),
    
    "N-10": SecurityRule(
        rule_id="N-10",
        title="SNMP 커뮤니티 권한 설정",
        description="SNMP 커뮤니티에 반드시 필요하지 않은 쓰기 권한을 허용하는지 점검",
        severity="상",
        category=RuleCategory.FUNCTION_MANAGEMENT,
        patterns=[
            r"snmp-server\s+community\s+\w+\s+RW"
        ],
        negative_patterns=[
            r"snmp-server\s+community\s+\w+\s+RO"
        ],
        device_types=["Cisco", "Alteon", "Passport", "Juniper", "Piolink"],
        recommendation="SNMP Community String 권한 설정 (RW 권한 삭제 권고)",
        reference="KISA 가이드 N-10 (상) 5.4 SNMP 커뮤니티 권한 설정",
        logical_check_function=check_snmp_community_permissions,
    ),
    
    "N-11": SecurityRule(
        rule_id="N-11",
        title="TFTP 서비스 차단",
        description="불필요한 TFTP 서비스가 구동되어 있는지 점검",
        severity="상",
        category=RuleCategory.FUNCTION_MANAGEMENT,
        patterns=[
            r"service\s+tftp"
        ],
        negative_patterns=[
            r"no\s+service\s+tftp"
        ],
        device_types=["Cisco"],
        recommendation="네트워크 장비의 불필요한 TFTP 서비스를 비활성화 설정",
        reference="KISA 가이드 N-11 (상) 5.5 TFTP 서비스 차단",
        logical_check_function=check_tftp_service_status,
    ),
    
    "N-12": SecurityRule(
        rule_id="N-12",
        title="Spoofing 방지 필터링 적용 또는 보안장비 사용",
        description="사설 네트워크, 루프백 등 특수 용도 IP 주소를 스푸핑 방지 필터링으로 차단하는지 점검",
        severity="상",
        category=RuleCategory.FUNCTION_MANAGEMENT,
        patterns=[
            r"interface.*(?:\n(?!.*ip\s+access-group.*in).*)*"
        ],
        negative_patterns=[
            r"access-list\s+\d+\s+deny\s+ip\s+10\.0\.0\.0\s+0\.255\.255\.255\s+any",
            r"access-list\s+\d+\s+deny\s+ip\s+127\.0\.0\.0\s+0\.255\.255\.255\s+any"
        ],
        device_types=["Cisco", "Juniper"],
        recommendation="경계 라우터 또는 보안장비에서 스푸핑 방지 필터링 적용",
        reference="KISA 가이드 N-12 (상) 5.6 Spoofing 방지 필터링 적용 또는 보안장비 사용",
        logical_check_function=check_anti_spoofing_filtering,
    ),
    
    "N-13": SecurityRule(
        rule_id="N-13",
        title="DDoS 공격 방어 설정 또는 DDoS 장비 사용",
        description="DDoS 공격 방어 설정을 적용하거나 DDoS 대응장비를 사용하는지 점검",
        severity="상",
        category=RuleCategory.FUNCTION_MANAGEMENT,
        patterns=[],
        negative_patterns=[
            r"ip\s+tcp\s+intercept",
            r"rate-limit"
        ],
        device_types=["Cisco", "Juniper"],
        recommendation="DDoS 공격 방어 설정 점검",
        reference="KISA 가이드 N-13 (상) 5.7 DDoS 공격 방어 설정 또는 DDoS 장비 사용",
        logical_check_function=check_ddos_protection,
    ),
    
    "N-14": SecurityRule(
        rule_id="N-14",
        title="사용하지 않는 인터페이스의 Shutdown 설정",
        description="사용하지 않는 인터페이스가 비활성화 상태인지 점검",
        severity="상",
        category=RuleCategory.FUNCTION_MANAGEMENT,
        patterns=[
            r"interface\s+\w+.*(?:\n(?!.*shutdown).*)*(?=interface|\Z)"
        ],
        negative_patterns=[
            r"interface\s+\w+.*\n.*shutdown"
        ],
        device_types=["Cisco", "Alteon", "Juniper", "Piolink"],
        recommendation="네트워크 장비에서 사용하지 않는 모든 인터페이스를 비활성화 설정",
        reference="KISA 가이드 N-14 (상) 5.8 사용하지 않는 인터페이스의 Shutdown 설정",
        logical_check_function=check_unused_interface_shutdown,
    ),
    
    "N-15": SecurityRule(
        rule_id="N-15",
        title="사용자·명령어별 권한 수준 설정",
        description="사용자의 업무에 따라 계정 별로 장비 관리 권한을 차등 부여하고 있는지 점검",
        severity="중",
        category=RuleCategory.ACCOUNT_MANAGEMENT,
        patterns=[
            r"username\s+\w+\s+privilege\s+15"
        ],
        negative_patterns=[
            r"username\s+\w+\s+privilege\s+[1-9](?!5)",
            r"privilege\s+exec\s+level\s+[1-9]"
        ],
        device_types=["Cisco", "Alteon", "Juniper", "Piolink"],
        recommendation="업무에 맞게 계정 별 권한 차등(관리자 권한 최소화) 부여",
        reference="KISA 가이드 N-15 (중) 1.4 사용자·명령어별 권한 수준 설정",
        logical_check_function=check_user_privilege_levels,
    ),
    
    "N-16": SecurityRule(
        rule_id="N-16",
        title="VTY 안전한 프로토콜 사용",
        description="VTY 접속 시 암호화 프로토콜(SSH) 사용 여부 점검",
        severity="중",
        category=RuleCategory.ACCESS_MANAGEMENT,
        patterns=[
            r"transport\s+input\s+telnet",
            r"transport\s+input\s+all"
        ],
        negative_patterns=[
            r"transport\s+input\s+ssh",
            r"ip\s+ssh\s+version\s+2"
        ],
        device_types=["Cisco", "Alteon", "Juniper", "Piolink"],
        recommendation="VTY 라인에서 SSH만 허용하도록 설정",
        reference="KISA 가이드 N-16 (중) 2.3 VTY 접속 시 안전한 프로토콜 사용",
        logical_check_function=check_ssh_protocol_usage,
    ),
    
    "N-17": SecurityRule(
        rule_id="N-17",
        title="불필요한 보조 입·출력 포트 사용 금지",
        description="사용하지 않는 보조(AUX) 포트 및 콘솔 점검",
        severity="중",
        category=RuleCategory.ACCESS_MANAGEMENT,
        patterns=[
            r"line\s+aux\s+0(?:\n(?!.*no\s+exec).*)*",
            r"line\s+aux\s+0(?:\n(?!.*transport\s+input\s+none).*)*"
        ],
        negative_patterns=[
            r"line\s+aux\s+0\n.*no\s+exec",
            r"line\s+aux\s+0\n.*transport\s+input\s+none"
        ],
        device_types=["Cisco", "Juniper"],
        recommendation="불필요한 포트 및 인터페이스 사용 제한 또는 비활성화",
        reference="KISA 가이드 N-17 (중) 2.4 불필요한 보조 입·출력 포트 사용 금지",
        logical_check_function=check_auxiliary_port_security,
    ),
    
    "N-18": SecurityRule(
        rule_id="N-18",
        title="로그온 시 경고 메시지 설정",
        description="터미널 접속 화면에 비인가자의 불법 접근에 대한 경고 메시지를 표시하도록 설정되어 있는지 점검",
        severity="중",
        category=RuleCategory.ACCESS_MANAGEMENT,
        patterns=[],
        negative_patterns=[
            r"banner\s+motd",
            r"banner\s+login"
        ],
        device_types=["Cisco", "Alteon", "Juniper"],
        recommendation="네트워크 장비 접속 시 경고 메시지 설정",
        reference="KISA 가이드 N-18 (중) 2.5 로그온 시 경고 메시지 설정",
        logical_check_function=check_login_banner_message,
    ),
    
    "N-19": SecurityRule(
        rule_id="N-19",
        title="원격 로그서버 사용",
        description="네트워크 장비의 로그를 별도의 원격 로그 서버에 보관하도록 설정하였는지를 점검",
        severity="하",
        category=RuleCategory.LOG_MANAGEMENT,
        patterns=[],
        negative_patterns=[
            r"logging\s+\d+\.\d+\.\d+\.\d+"
        ],
        device_types=["Cisco", "Alteon", "Juniper", "Piolink"],
        recommendation="Syslog 등을 이용하여 로그 저장 설정",
        reference="KISA 가이드 N-19 (하) 4.1 원격 로그서버 사용",
        logical_check_function=check_remote_log_server,
    ),
    
    "N-20": SecurityRule(
        rule_id="N-20",
        title="로깅 버퍼 크기 설정",
        description="버퍼 메모리의 크기를 어느 정도로 설정하고 있는지 점검",
        severity="중",
        category=RuleCategory.LOG_MANAGEMENT,
        patterns=[
            r"logging\s+buffered\s+[1-9]\d{3}(?![0-9])"  # 16000 미만
        ],
        negative_patterns=[
            r"logging\s+buffered\s+(?:1[6-9]\d{3}|[2-9]\d{4}|\d{6,})"  # 16000 이상
        ],
        device_types=["Cisco", "Piolink"],
        recommendation="로그에 대한 정보를 확인하여 장비 성능을 고려한 최대 버퍼 크기를 설정",
        reference="KISA 가이드 N-20 (중) 4.2 로깅 버퍼 크기 설정",
        logical_check_function=check_logging_buffer_size,
    ),
    
    "N-21": SecurityRule(
        rule_id="N-21",
        title="정책에 따른 로깅 설정",
        description="정책에 따른 로깅 설정이 이루어지고 있는지 점검",
        severity="중",
        category=RuleCategory.LOG_MANAGEMENT,
        patterns=[],
        negative_patterns=[
            r"logging\s+on",
            r"logging\s+buffered"
        ],
        device_types=["Cisco", "Juniper"],
        recommendation="로그 기록 정책을 수립하고 정책에 따른 로깅 설정",
        reference="KISA 가이드 N-21 (중) 4.3 정책에 따른 로깅 설정",
        logical_check_function=check_logging_policy_configuration,
    ),
    
    "N-22": SecurityRule(
        rule_id="N-22",
        title="NTP 서버 연동",
        description="네트워크 장비의 NTP 서버 연동 설정 적용 여부 점검",
        severity="중",
        category=RuleCategory.LOG_MANAGEMENT,
        patterns=[],
        negative_patterns=[
            r"ntp\s+server\s+\d+\.\d+\.\d+\.\d+"
        ],
        device_types=["Cisco", "Alteon", "Juniper"],
        recommendation="NTP 사용 시 신뢰할 수 있는 서버로 설정",
        reference="KISA 가이드 N-22 (중) 4.4 NTP 서버 연동",
        logical_check_function=check_ntp_server_configuration,
    ),
    
    "N-23": SecurityRule(
        rule_id="N-23",
        title="timestamp 로그 설정",
        description="네트워크 장비 설정 중 timestamp를 설정하여 로그 시간을 기록할 수 있게 하였는지 점검",
        severity="하",
        category=RuleCategory.LOG_MANAGEMENT,
        patterns=[],
        negative_patterns=[
            r"service\s+timestamps\s+log\s+datetime"
        ],
        device_types=["Cisco"],
        recommendation="로그에 시간 정보가 기록될 수 있도록 timestamp 로그 설정",
        reference="KISA 가이드 N-23 (하) 4.5 timestamp 로그 설정",
        logical_check_function=check_timestamp_logging,
    ),
    
    "N-24": SecurityRule(
        rule_id="N-24",
        title="TCP Keepalive 서비스 설정",
        description="TCP Keepalive 서비스를 사용하는지 점검",
        severity="중",
        category=RuleCategory.FUNCTION_MANAGEMENT,
        patterns=[],
        negative_patterns=[
            r"service\s+tcp-keepalives-in",
            r"service\s+tcp-keepalives-out"
        ],
        device_types=["Cisco"],
        recommendation="네트워크 장비에서 TCP Keepalive 서비스를 사용하도록 설정",
        reference="KISA 가이드 N-24 (중) 5.9 TCP Keepalive 서비스 설정",
        logical_check_function=check_tcp_keepalive_service,
    ),
    
    "N-25": SecurityRule(
        rule_id="N-25",
        title="Finger 서비스 차단",
        description="Finger 서비스를 차단하는지 점검",
        severity="중",
        category=RuleCategory.FUNCTION_MANAGEMENT,
        patterns=[
            r"service\s+finger",
            r"ip\s+finger"
        ],
        negative_patterns=[
            r"no\s+service\s+finger",
            r"no\s+ip\s+finger"
        ],
        device_types=["Cisco", "Juniper"],
        recommendation="각 장비별 Finger 서비스 제한 설정",
        reference="KISA 가이드 N-25 (중) 5.10 Finger 서비스 차단",
        logical_check_function=check_finger_service_status,
    ),
    
    "N-26": SecurityRule(
        rule_id="N-26",
        title="웹 서비스 차단",
        description="불필요한 웹 서비스를 비활성화하거나 특정 IP만 접근을 허용하는지 점검",
        severity="중",
        category=RuleCategory.FUNCTION_MANAGEMENT,
        patterns=[
            r"ip\s+http\s+server",
            r"ip\s+http\s+secure-server"
        ],
        negative_patterns=[
            r"no\s+ip\s+http\s+server",
            r"no\s+ip\s+http\s+secure-server"
        ],
        device_types=["Cisco", "Juniper", "Alteon", "Piolink"],
        recommendation="HTTP 서비스 차단 또는 HTTP 서버를 관리하는 관리자 접속 IP 설정",
        reference="KISA 가이드 N-26 (중) 5.11 웹 서비스 차단",
        logical_check_function=check_web_service_security,
    ),
    
    "N-27": SecurityRule(
        rule_id="N-27",
        title="TCP/UDP Small 서비스 차단",
        description="TCP/UDP Small 서비스가 제한되어 있는지 점검",
        severity="중",
        category=RuleCategory.FUNCTION_MANAGEMENT,
        patterns=[
            r"service\s+tcp-small-servers",
            r"service\s+udp-small-servers"
        ],
        negative_patterns=[
            r"no\s+service\s+tcp-small-servers",
            r"no\s+service\s+udp-small-servers"
        ],
        device_types=["Cisco"],
        recommendation="TCP/UDP Small Service 제한 설정",
        reference="KISA 가이드 N-27 (중) 5.12 TCP/UDP Small 서비스 차단",
        logical_check_function=check_small_services_status,
    ),
    
    "N-28": SecurityRule(
        rule_id="N-28",
        title="Bootp 서비스 차단",
        description="Bootp 서비스의 차단 여부 점검",
        severity="중",
        category=RuleCategory.FUNCTION_MANAGEMENT,
        patterns=[
            r"ip\s+bootp\s+server"
        ],
        negative_patterns=[
            r"no\s+ip\s+bootp\s+server",
            r"ip\s+dhcp\s+bootp\s+ignore"
        ],
        device_types=["Cisco", "Alteon", "Juniper"],
        recommendation="각 장비별 Bootp 서비스 제한 설정",
        reference="KISA 가이드 N-28 (중) 5.13 Bootp 서비스 차단",
        logical_check_function=check_bootp_service_status,
    ),
    
    "N-29": SecurityRule(
        rule_id="N-29",
        title="CDP 서비스 차단",
        description="CDP 서비스를 차단하는지 점검",
        severity="중",
        category=RuleCategory.FUNCTION_MANAGEMENT,
        patterns=[
            r"cdp\s+run"
        ],
        negative_patterns=[
            r"no\s+cdp\s+run"
        ],
        device_types=["Cisco"],
        recommendation="각 장비별 CDP 서비스 제한 설정",
        reference="KISA 가이드 N-29 (중) 5.14 CDP 서비스 차단",
        logical_check_function=check_cdp_service_status,
    ),
    
    "N-30": SecurityRule(
        rule_id="N-30",
        title="Directed-broadcast 차단",
        description="Directed-broadcast를 차단하는지 점검",
        severity="중",
        category=RuleCategory.FUNCTION_MANAGEMENT,
        patterns=[
            r"ip\s+directed-broadcast"
        ],
        negative_patterns=[
            r"no\s+ip\s+directed-broadcast"
        ],
        device_types=["Cisco", "Alteon", "Passport"],
        recommendation="각 장치별로 Directed Broadcasts 제한 설정",
        reference="KISA 가이드 N-30 (중) 5.15 Directed-broadcast 차단",
        logical_check_function=check_directed_broadcast_status,
    ),
    
    "N-31": SecurityRule(
        rule_id="N-31",
        title="Source 라우팅 차단",
        description="source routing를 차단하는지 점검",
        severity="중",
        category=RuleCategory.FUNCTION_MANAGEMENT,
        patterns=[
            r"ip\s+source-route"
        ],
        negative_patterns=[
            r"no\s+ip\s+source-route"
        ],
        device_types=["Cisco", "Juniper"],
        recommendation="각 인터페이스에서 ip source route 차단 설정",
        reference="KISA 가이드 N-31 (중) 5.16 Source 라우팅 차단",
        logical_check_function=check_source_routing_status,
    ),
    
    "N-32": SecurityRule(
        rule_id="N-32",
        title="Proxy ARP 차단",
        description="Proxy ARP를 차단하는지 점검",
        severity="중",
        category=RuleCategory.FUNCTION_MANAGEMENT,
        patterns=[
            r"ip\s+proxy-arp"
        ],
        negative_patterns=[
            r"no\s+ip\s+proxy-arp"
        ],
        device_types=["Cisco", "Juniper"],
        recommendation="각 인터페이스에서 Proxy ARP 비활성화 설정",
        reference="KISA 가이드 N-32 (중) 5.17 Proxy ARP 차단",
        logical_check_function=check_proxy_arp_status,
    ),
    
    "N-33": SecurityRule(
        rule_id="N-33",
        title="ICMP unreachable, Redirect 차단",
        description="ICMP unreachable, ICMP redirect를 차단하는지 점검",
        severity="중",
        category=RuleCategory.FUNCTION_MANAGEMENT,
        patterns=[
            r"ip\s+unreachables",
            r"ip\s+redirects"
        ],
        negative_patterns=[
            r"no\s+ip\s+unreachables",
            r"no\s+ip\s+redirects"
        ],
        device_types=["Cisco", "Juniper"],
        recommendation="각 인터페이스에서 ICMP Unreachables, ICMP Redirects 비활성화",
        reference="KISA 가이드 N-33 (중) 5.18 ICMP unreachable, Redirect 차단",
        logical_check_function=check_icmp_services_status,
    ),
    
    "N-34": SecurityRule(
        rule_id="N-34",
        title="identd 서비스 차단",
        description="identd 서비스를 차단하는지 점검",
        severity="중",
        category=RuleCategory.FUNCTION_MANAGEMENT,
        patterns=[
            r"ip\s+identd"
        ],
        negative_patterns=[
            r"no\s+ip\s+identd"
        ],
        device_types=["Cisco"],
        recommendation="idnetd 서비스 비활성화",
        reference="KISA 가이드 N-34 (중) 5.19 identd 서비스 차단",
        logical_check_function=check_identd_service_status,
    ),
    
    "N-35": SecurityRule(
        rule_id="N-35",
        title="Domain lookup 차단",
        description="Domain Lookup를 차단하는지 점검",
        severity="중",
        category=RuleCategory.FUNCTION_MANAGEMENT,
        patterns=[
            r"ip\s+domain.lookup"
        ],
        negative_patterns=[
            r"no\s+ip\s+domain.lookup"
        ],
        device_types=["Cisco"],
        recommendation="Domain Lookup 비활성화",
        reference="KISA 가이드 N-35 (중) 5.20 Domain lookup 차단",
        logical_check_function=check_domain_lookup_status,
    ),
    
    "N-36": SecurityRule(
        rule_id="N-36",
        title="PAD 차단",
        description="PAD 서비스를 차단하는지 점검",
        severity="중",
        category=RuleCategory.FUNCTION_MANAGEMENT,
        patterns=[
            r"service\s+pad"
        ],
        negative_patterns=[
            r"no\s+service\s+pad"
        ],
        device_types=["Cisco"],
        recommendation="PAD 서비스 비활성화",
        reference="KISA 가이드 N-36 (중) 5.21 PAD 차단",
        logical_check_function=check_pad_service_status,
    ),
    
    "N-37": SecurityRule(
        rule_id="N-37",
        title="mask-reply 차단",
        description="mask-reply를 차단하는지 점검",
        severity="중",
        category=RuleCategory.FUNCTION_MANAGEMENT,
        patterns=[
            r"ip\s+mask-reply"
        ],
        negative_patterns=[
            r"no\s+ip\s+mask-reply"
        ],
        device_types=["Cisco"],
        recommendation="각 인터페이스에서 mask-reply 비활성화",
        reference="KISA 가이드 N-37 (중) 5.22 mask-reply 차단",
        logical_check_function=check_mask_reply_status,
    ),
    
    "N-38": SecurityRule(
        rule_id="N-38",
        title="스위치, 허브 보안 강화",
        description="스위치나 허브에서 포트 보안, SPAN 설정이 적용되고 있는지 점검",
        severity="하",
        category=RuleCategory.FUNCTION_MANAGEMENT,
        patterns=[],
        negative_patterns=[
            r"switchport\s+port-security",
            r"monitor\s+session"
        ],
        device_types=["Cisco", "Alteon", "Juniper", "Piolink"],
        recommendation="장비별 보안 위협에 관한 대책 설정 적용(포트 보안, SPAN 설정)",
        reference="KISA 가이드 N-38 (하) 5.23 스위치, 허브 보안 강화",
        logical_check_function=check_switch_hub_security,
    ),
}

# 기존 호환성을 위한 별칭
COMPLETE_ENHANCED_KISA_RULES = KISA_RULES
KISA_SECURITY_RULES = KISA_RULES
ENHANCED_KISA_SECURITY_RULES = KISA_RULES