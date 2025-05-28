# -*- coding: utf-8 -*-
"""
rules/security_rules.py
KISA 네트워크 장비 보안 점검 룰셋 정의 (38개 전체 룰셋)

KISA 가이드 기반 네트워크 장비 취약점 탐지 규칙들을 정의
"""

import re
from dataclasses import dataclass
from typing import List, Dict, Pattern, Callable, Optional
from enum import Enum


class RuleCategory(Enum):
    """룰 카테고리"""
    ACCOUNT_MANAGEMENT = "계정 관리"
    ACCESS_MANAGEMENT = "접근 관리"
    PATCH_MANAGEMENT = "패치 관리"
    LOG_MANAGEMENT = "로그 관리"
    FUNCTION_MANAGEMENT = "기능 관리"


@dataclass
class SecurityRule:
    """보안 룰 정의"""
    rule_id: str
    title: str
    description: str
    severity: str  # 상/중/하
    category: RuleCategory
    patterns: List[str]  # 탐지할 패턴들 (정규식)
    negative_patterns: List[str]  # 양호한 상태를 나타내는 패턴들
    device_types: List[str]  # 적용 가능한 장비 타입
    recommendation: str
    reference: str
    check_function: Optional[Callable] = None  # 커스텀 체크 함수
    
    def __post_init__(self):
        """패턴들을 컴파일된 정규식으로 변환"""
        self.compiled_patterns = [re.compile(pattern, re.IGNORECASE) for pattern in self.patterns]
        self.compiled_negative_patterns = [re.compile(pattern, re.IGNORECASE) for pattern in self.negative_patterns]


# KISA 가이드 기반 보안 룰셋 정의 (38개 전체)
KISA_SECURITY_RULES = {
    # ======================= 계정 관리 =======================
    
    # N-01: 패스워드 설정 (기본 패스워드 변경)
    "N-01": SecurityRule(
        rule_id="N-01",
        title="기본 패스워드 변경",
        description="기본 패스워드를 변경하지 않고 사용하는지 점검",
        severity="상",
        category=RuleCategory.ACCOUNT_MANAGEMENT,
        patterns=[
            r"enable\s+password\s+(cisco|admin|password|123|1234|default)",
            r"username\s+\w+\s+password\s+(cisco|admin|password|123|1234|default)",
            r"password\s+(cisco|admin|password|123|1234|default)",
            r"community\s+(public|private)\s*$",
            r"admpw\s+(admin|password|default)"
        ],
        negative_patterns=[
            r"enable\s+secret\s+\$1\$",
            r"username\s+\w+\s+secret\s+\$1\$",
            r"no\s+password",
            r"service\s+password-encryption"
        ],
        device_types=["Cisco", "Alteon", "Passport", "Juniper", "Piolink"],
        recommendation="enable secret 명령어를 사용하여 암호화된 패스워드 설정 필요",
        reference="KISA 가이드 N-01 (상) 1.1 패스워드 설정"
    ),
    
    # N-02: 패스워드 복잡성 설정
    "N-02": SecurityRule(
        rule_id="N-02",
        title="패스워드 복잡성 설정",
        description="패스워드 복잡성 정책이 적용되어 있는지 점검",
        severity="상",
        category=RuleCategory.ACCOUNT_MANAGEMENT,
        patterns=[
            r"enable\s+password\s+\w{1,7}$",  # 8자 미만 패스워드
            r"username\s+\w+\s+password\s+\w{1,7}$",
            r"password\s+\w{1,7}$"
        ],
        negative_patterns=[
            r"security\s+passwords\s+min-length\s+[8-9]|[1-9][0-9]",
            r"enable\s+secret\s+.{8,}",
            r"username\s+\w+\s+secret\s+.{8,}"
        ],
        device_types=["Cisco", "Alteon", "Passport", "Juniper", "Piolink"],
        recommendation="최소 8자 이상의 복잡한 패스워드 설정 및 복잡성 정책 적용",
        reference="KISA 가이드 N-02 (상) 1.2 패스워드 복잡성 설정"
    ),
    
    # N-03: 암호화된 패스워드 사용
    "N-03": SecurityRule(
        rule_id="N-03",
        title="암호화된 패스워드 사용",
        description="패스워드 암호화 설정이 적용되어 있는지 점검",
        severity="상",
        category=RuleCategory.ACCOUNT_MANAGEMENT,
        patterns=[
            r"enable\s+password\s+[^$0-9]",  # password 사용 (암호화되지 않음)
            r"username\s+\w+\s+password\s+[^$0-9]",
            r"no\s+service\s+password-encryption"
        ],
        negative_patterns=[
            r"enable\s+secret",
            r"username\s+\w+\s+secret",
            r"service\s+password-encryption",
            r"enable\s+password\s+7\s+\w+",  # Type 7 암호화
            r"username\s+\w+\s+password\s+7\s+\w+"
        ],
        device_types=["Cisco", "Juniper"],
        recommendation="enable secret 및 service password-encryption 설정 적용",
        reference="KISA 가이드 N-03 (상) 1.3 암호화된 패스워드 사용"
    ),
    
    # N-15: 사용자·명령어별 권한 수준 설정
    "N-15": SecurityRule(
        rule_id="N-15",
        title="사용자·명령어별 권한 수준 설정",
        description="업무에 따라 계정 별로 장비 관리 권한을 차등 부여하고 있는지 점검",
        severity="중",
        category=RuleCategory.ACCOUNT_MANAGEMENT,
        patterns=[
            r"username\s+\w+\s+privilege\s+15",  # 모든 사용자가 최고 권한
        ],
        negative_patterns=[
            r"username\s+\w+\s+privilege\s+[1-9](\s|$)",  # 차등 권한 설정
            r"privilege\s+exec\s+level\s+[1-9]",
        ],
        device_types=["Cisco", "Alteon", "Juniper", "Piolink"],
        recommendation="업무에 맞게 계정 별 권한 차등(관리자 권한 최소화) 부여",
        reference="KISA 가이드 N-15 (중) 1.4 사용자·명령어별 권한 수준 설정"
    ),

    # ======================= 접근 관리 =======================
    
    # N-04: VTY 접근(ACL) 설정
    "N-04": SecurityRule(
        rule_id="N-04",
        title="VTY 접근 제한 설정",
        description="VTY 라인에 접근 제한 ACL이 설정되어 있는지 점검",
        severity="상",
        category=RuleCategory.ACCESS_MANAGEMENT,
        patterns=[
            r"line\s+vty.*(?:\n(?!.*access-class).*)*",  # VTY 라인에 access-class 없음
        ],
        negative_patterns=[
            r"line\s+vty.*\n.*access-class\s+\d+\s+in",
            r"firewall\s+filter.*input",
            r"access-policy.*enable"
        ],
        device_types=["Cisco", "Alteon", "Passport", "Juniper", "Piolink"],
        recommendation="VTY 라인에 특정 IP 주소만 접근 가능하도록 ACL 설정",
        reference="KISA 가이드 N-04 (상) 2.1 VTY 접근(ACL) 설정"
    ),
    
    # N-05: Session Timeout 설정
    "N-05": SecurityRule(
        rule_id="N-05",
        title="Session Timeout 설정",
        description="Session Timeout이 적절히 설정되어 있는지 점검",
        severity="상",
        category=RuleCategory.ACCESS_MANAGEMENT,
        patterns=[
            r"exec-timeout\s+0\s+0",  # 무제한 timeout
            r"exec-timeout\s+[6-9][0-9]|[1-9][0-9]{2,}",  # 60분 이상 timeout
            r"no\s+exec-timeout"
        ],
        negative_patterns=[
            r"exec-timeout\s+[1-5]\s+0",  # 5분 이하 설정
            r"idle-timeout\s+[1-5]"
        ],
        device_types=["Cisco", "Alteon", "Juniper", "Piolink"],
        recommendation="Session Timeout을 5분 이하로 설정",
        reference="KISA 가이드 N-05 (상) 2.2 Session Timeout 설정"
    ),
    
    # N-16: VTY 접속 시 안전한 프로토콜 사용
    "N-16": SecurityRule(
        rule_id="N-16",
        title="VTY 안전한 프로토콜 사용",
        description="VTY 접속 시 암호화 프로토콜(SSH) 사용 여부 점검",
        severity="중",
        category=RuleCategory.ACCESS_MANAGEMENT,
        patterns=[
            r"transport\s+input\s+telnet",
            r"transport\s+input\s+all",
        ],
        negative_patterns=[
            r"transport\s+input\s+ssh",
            r"no\s+telnet",
            r"ip\s+ssh\s+version\s+2"
        ],
        device_types=["Cisco", "Alteon", "Juniper", "Piolink"],
        recommendation="VTY 라인에서 SSH만 허용하도록 설정",
        reference="KISA 가이드 N-16 (중) 2.3 VTY 접속 시 안전한 프로토콜 사용"
    ),
    
    # N-17: 불필요한 보조 입·출력 포트 사용 금지
    "N-17": SecurityRule(
        rule_id="N-17",
        title="불필요한 보조 입·출력 포트 사용 금지",
        description="사용하지 않는 보조(AUX) 포트 및 콘솔이 비활성화되어 있는지 점검",
        severity="중",
        category=RuleCategory.ACCESS_MANAGEMENT,
        patterns=[
            r"line\s+aux\s+0(?:\n(?!.*no\s+exec)(?!.*transport\s+input\s+none).*)*",
        ],
        negative_patterns=[
            r"line\s+aux\s+0.*\n.*no\s+exec",
            r"line\s+aux\s+0.*\n.*transport\s+input\s+none",
        ],
        device_types=["Cisco", "Juniper"],
        recommendation="불필요한 포트 및 인터페이스 사용 제한 또는 비활성화",
        reference="KISA 가이드 N-17 (중) 2.4 불필요한 보조 입·출력 포트 사용 금지"
    ),
    
    # N-18: 로그온 시 경고 메시지 설정
    "N-18": SecurityRule(
        rule_id="N-18",
        title="로그온 시 경고 메시지 설정",
        description="터미널 접속 화면에 비인가자의 불법 접근에 대한 경고 메시지를 표시하도록 설정되어 있는지 점검",
        severity="중",
        category=RuleCategory.ACCESS_MANAGEMENT,
        patterns=[],  # 경고 메시지가 없는 경우를 탐지하기 어려우므로 빈 패턴
        negative_patterns=[
            r"banner\s+motd",
            r"banner\s+login",
            r"banner\s+exec",
        ],
        device_types=["Cisco", "Alteon", "Juniper"],
        recommendation="네트워크 장비 접속 시 경고 메시지 설정",
        reference="KISA 가이드 N-18 (중) 2.5 로그온 시 경고 메시지 설정"
    ),

    # ======================= 패치 관리 =======================
    
    # N-06: 최신 보안 패치 및 벤더 권고사항 적용
    "N-06": SecurityRule(
        rule_id="N-06",
        title="최신 보안 패치 및 벤더 권고사항 적용",
        description="패치 적용 정책에 따라 주기적인 패치를 하고 있는지 점검",
        severity="상",
        category=RuleCategory.PATCH_MANAGEMENT,
        patterns=[
            r"version\s+1[0-1]\.",  # 오래된 버전 탐지
            # 이 룰은 주로 수동 점검이 필요하므로 패턴으로 완전히 자동화하기 어려움
        ],
        negative_patterns=[
            r"version\s+1[5-9]\.",  # 비교적 최신 버전
        ],
        device_types=["Cisco", "Juniper", "Alteon", "Passport", "Piolink"],
        recommendation="장비 별 제공하는 최신 취약점 정보를 파악 후 최신 패치 및 업그레이드를 수행",
        reference="KISA 가이드 N-06 (상) 3.1 최신 보안 패치 및 벤더 권고사항 적용"
    ),

    # ======================= 로그 관리 =======================
    
    # N-19: 원격 로그서버 사용
    "N-19": SecurityRule(
        rule_id="N-19",
        title="원격 로그서버 사용",
        description="네트워크 장비의 로그를 별도의 원격 로그 서버에 보관하도록 설정하였는지를 점검",
        severity="하",
        category=RuleCategory.LOG_MANAGEMENT,
        patterns=[],  # 로그 서버 설정이 없는 경우
        negative_patterns=[
            r"logging\s+\d+\.\d+\.\d+\.\d+",
            r"syslog\s+host",
        ],
        device_types=["Cisco", "Alteon", "Juniper", "Piolink"],
        recommendation="Syslog 등을 이용하여 로그 저장 설정",
        reference="KISA 가이드 N-19 (하) 4.1 원격 로그서버 사용"
    ),
    
    # N-20: 로깅 버퍼 크기 설정
    "N-20": SecurityRule(
        rule_id="N-20",
        title="로깅 버퍼 크기 설정",
        description="버퍼 메모리의 크기를 어느 정도로 설정하고 있는지 점검",
        severity="중",
        category=RuleCategory.LOG_MANAGEMENT,
        patterns=[
            r"logging\s+buffered\s+[1-9]\d{0,2}$",  # 1000 미만의 작은 버퍼
        ],
        negative_patterns=[
            r"logging\s+buffered\s+[1-6][0-9]{4}",  # 16KB~64KB 적정 크기
        ],
        device_types=["Cisco", "Piolink"],
        recommendation="로그에 대한 정보를 확인하여 장비 성능을 고려한 최대 버퍼 크기를 설정",
        reference="KISA 가이드 N-20 (중) 4.2 로깅 버퍼 크기 설정"
    ),
    
    # N-21: 정책에 따른 로깅 설정
    "N-21": SecurityRule(
        rule_id="N-21",
        title="정책에 따른 로깅 설정",
        description="정책에 따른 로깅 설정이 이루어지고 있는지 점검",
        severity="중",
        category=RuleCategory.LOG_MANAGEMENT,
        patterns=[],  # 로깅 설정이 부족한 경우
        negative_patterns=[
            r"logging\s+on",
            r"logging\s+buffered",
            r"service\s+timestamps",
        ],
        device_types=["Cisco", "Juniper"],
        recommendation="로그 기록 정책을 수립하고 정책에 따른 로깅 설정",
        reference="KISA 가이드 N-21 (중) 4.3 정책에 따른 로깅 설정"
    ),
    
    # N-22: NTP 서버 연동
    "N-22": SecurityRule(
        rule_id="N-22",
        title="NTP 서버 연동",
        description="네트워크 장비의 NTP 서버 연동 설정 적용 여부 점검",
        severity="중",
        category=RuleCategory.LOG_MANAGEMENT,
        patterns=[],  # NTP 설정이 없는 경우
        negative_patterns=[
            r"ntp\s+server\s+\d+\.\d+\.\d+\.\d+",
        ],
        device_types=["Cisco", "Alteon", "Juniper"],
        recommendation="NTP 사용 시 신뢰할 수 있는 서버로 설정",
        reference="KISA 가이드 N-22 (중) 4.4 NTP 서버 연동"
    ),
    
    # N-23: timestamp 로그 설정
    "N-23": SecurityRule(
        rule_id="N-23",
        title="timestamp 로그 설정",
        description="네트워크 장비 설정 중 timestamp를 설정하여 로그 시간을 기록할 수 있게 하였는지 점검",
        severity="하",
        category=RuleCategory.LOG_MANAGEMENT,
        patterns=[],  # timestamp 설정이 없는 경우
        negative_patterns=[
            r"service\s+timestamps\s+log\s+datetime",
            r"service\s+timestamps\s+debug\s+datetime",
        ],
        device_types=["Cisco"],
        recommendation="로그에 시간 정보가 기록될 수 있도록 timestamp 로그 설정",
        reference="KISA 가이드 N-23 (하) 4.5 timestamp 로그 설정"
    ),

    # ======================= 기능 관리 =======================
    
    # N-07: SNMP 서비스 확인
    "N-07": SecurityRule(
        rule_id="N-07",
        title="SNMP 서비스 차단",
        description="불필요한 SNMP 서비스가 활성화되어 있는지 점검",
        severity="상",
        category=RuleCategory.FUNCTION_MANAGEMENT,
        patterns=[
            r"snmp-server\s+community",
            r"snmp\s+community",
            r"snmp.*enable",
            r"snmp.*read-only",
            r"snmp.*read-write"
        ],
        negative_patterns=[
            r"no\s+snmp-server",
            r"snmp.*disable",
            r"snmp.*access.*disabled"
        ],
        device_types=["Cisco", "Alteon", "Passport", "Juniper", "Piolink"],
        recommendation="SNMP 서비스를 사용하지 않는 경우 비활성화, 사용 시 SNMPv3 권고",
        reference="KISA 가이드 N-07 (상) 5.1 SNMP 서비스 확인"
    ),
    
    # N-08: SNMP community string 복잡성 설정
    "N-08": SecurityRule(
        rule_id="N-08",
        title="SNMP Community String 복잡성",
        description="기본 또는 단순한 SNMP Community String 사용 여부 점검",
        severity="상",
        category=RuleCategory.FUNCTION_MANAGEMENT,
        patterns=[
            r"snmp-server\s+community\s+(public|private)",
            r"snmp\s+community\s+(public|private)",
            r"community\s+(public|private)",
            r"snmp-server\s+community\s+\w{1,4}\s",  # 너무 짧은 커뮤니티 스트링
            r"rcomm\s+(public|private)",
            r"wcomm\s+(public|private)"
        ],
        negative_patterns=[
            r"snmp-server\s+community\s+[a-zA-Z0-9_-]{8,}",
            r"no\s+snmp-server\s+community\s+(public|private)"
        ],
        device_types=["Cisco", "Alteon", "Passport", "Juniper", "Piolink"],
        recommendation="Public, Private 외 유추하기 어려운 복잡한 Community String 설정",
        reference="KISA 가이드 N-08 (상) 5.2 SNMP community string 복잡성 설정"
    ),
    
    # N-09: SNMP ACL 설정
    "N-09": SecurityRule(
        rule_id="N-09",
        title="SNMP ACL 설정",
        description="SNMP 서비스 사용 시 네트워크 장비 ACL(Access list)을 설정하여 SNMP 접속 대상 호스트를 지정하여 접근이 가능한 IP를 제한하였는지 점검",
        severity="상",
        category=RuleCategory.FUNCTION_MANAGEMENT,
        patterns=[
            r"snmp-server\s+community\s+\w+\s+RO$",  # ACL 없는 SNMP
            r"snmp-server\s+community\s+\w+\s+RW$",
        ],
        negative_patterns=[
            r"snmp-server\s+community\s+\w+\s+RO\s+\d+",  # ACL 적용된 SNMP
            r"snmp-server\s+community\s+\w+\s+RW\s+\d+",
        ],
        device_types=["Cisco", "Alteon", "Passport", "Juniper", "Piolink"],
        recommendation="SNMP 접근에 대한 ACL(Access list) 설정",
        reference="KISA 가이드 N-09 (상) 5.3 SNMP ACL 설정"
    ),
    
    # N-10: SNMP 커뮤니티 권한 설정
    "N-10": SecurityRule(
        rule_id="N-10",
        title="SNMP 커뮤니티 권한 설정",
        description="SNMP 커뮤니티에 반드시 필요하지 않은 쓰기 권한을 허용하는지 점검",
        severity="상",
        category=RuleCategory.FUNCTION_MANAGEMENT,
        patterns=[
            r"snmp-server\s+community\s+\w+\s+RW",
        ],
        negative_patterns=[
            r"snmp-server\s+community\s+\w+\s+RO",
        ],
        device_types=["Cisco", "Alteon", "Passport", "Juniper", "Piolink"],
        recommendation="SNMP Community String 권한 설정 (RW 권한 삭제 권고)",
        reference="KISA 가이드 N-10 (상) 5.4 SNMP 커뮤니티 권한 설정"
    ),
    
    # N-11: TFTP 서비스 차단
    "N-11": SecurityRule(
        rule_id="N-11",
        title="TFTP 서비스 차단",
        description="불필요한 TFTP 서비스가 활성화되어 있는지 점검",
        severity="상",
        category=RuleCategory.FUNCTION_MANAGEMENT,
        patterns=[
            r"service\s+tftp",
            r"tftp-server",
            r"ip\s+tftp"
        ],
        negative_patterns=[
            r"no\s+service\s+tftp",
            r"no\s+tftp-server",
            r"no\s+ip\s+tftp"
        ],
        device_types=["Cisco"],
        recommendation="불필요한 TFTP 서비스 비활성화 설정",
        reference="KISA 가이드 N-11 (상) 5.5 TFTP 서비스 차단"
    ),
    
    # N-12: Spoofing 방지 필터링 적용
    "N-12": SecurityRule(
        rule_id="N-12",
        title="Spoofing 방지 필터링 적용",
        description="사설 네트워크, 루프백 등 특수 용도로 배정하여 라우팅이 불가능한 IP 주소를 스푸핑 방지 필터링을 적용하여 차단하는지 점검",
        severity="상",
        category=RuleCategory.FUNCTION_MANAGEMENT,
        patterns=[],  # 스푸핑 방지 필터가 없는 경우
        negative_patterns=[
            r"access-list\s+\d+\s+deny\s+ip\s+10\.0\.0\.0\s+0\.255\.255\.255",
            r"access-list\s+\d+\s+deny\s+ip\s+192\.168\.0\.0\s+0\.0\.255\.255",
            r"access-list\s+\d+\s+deny\s+ip\s+172\.16\.0\.0\s+0\.15\.255\.255",
        ],
        device_types=["Cisco", "Juniper"],
        recommendation="경계 라우터 또는 보안장비에서 스푸핑 방지 필터링 적용",
        reference="KISA 가이드 N-12 (상) 5.6 Spoofing 방지 필터링 적용"
    ),
    
    # N-13: DDoS 공격 방어 설정
    "N-13": SecurityRule(
        rule_id="N-13",
        title="DDoS 공격 방어 설정",
        description="DDoS 공격 방어 설정을 적용하거나 DDoS 대응장비를 사용하는지 점검",
        severity="상",
        category=RuleCategory.FUNCTION_MANAGEMENT,
        patterns=[],  # DDoS 방어 설정이 없는 경우
        negative_patterns=[
            r"ip\s+tcp\s+intercept",
            r"rate\s+limit",
        ],
        device_types=["Cisco", "Juniper"],
        recommendation="DDoS 공격 방어 설정 점검",
        reference="KISA 가이드 N-13 (상) 5.7 DDoS 공격 방어 설정"
    ),
    
    # N-14: 사용하지 않는 인터페이스의 Shutdown 설정
    "N-14": SecurityRule(
        rule_id="N-14",
        title="사용하지 않는 인터페이스의 Shutdown 설정",
        description="사용하지 않는 인터페이스가 비활성화 상태인지 점검",
        severity="상",
        category=RuleCategory.FUNCTION_MANAGEMENT,
        patterns=[
            r"interface\s+\w+.*(?:\n(?!.*shutdown).*)*(?=interface|\Z)",  # shutdown이 없는 인터페이스
        ],
        negative_patterns=[
            r"interface\s+\w+.*\n.*shutdown",
        ],
        device_types=["Cisco", "Alteon", "Juniper", "Piolink"],
        recommendation="네트워크 장비에서 사용하지 않는 모든 인터페이스를 비활성화 설정",
        reference="KISA 가이드 N-14 (상) 5.8 사용하지 않는 인터페이스의 Shutdown 설정"
    ),
    
    # N-24: TCP Keepalive 서비스 설정
    "N-24": SecurityRule(
        rule_id="N-24",
        title="TCP Keepalive 서비스 설정",
        description="TCP Keepalive 서비스를 사용하는지 점검",
        severity="중",
        category=RuleCategory.FUNCTION_MANAGEMENT,
        patterns=[],  # TCP Keepalive 설정이 없는 경우
        negative_patterns=[
            r"service\s+tcp-keepalives-in",
            r"service\s+tcp-keepalives-out",
        ],
        device_types=["Cisco"],
        recommendation="네트워크 장비에서 TCP Keepalive 서비스를 사용하도록 설정",
        reference="KISA 가이드 N-24 (중) 5.9 TCP Keepalive 서비스 설정"
    ),
    
    # N-25: Finger 서비스 차단
    "N-25": SecurityRule(
        rule_id="N-25",
        title="Finger 서비스 차단",
        description="Finger 서비스가 활성화되어 있는지 점검",
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
        recommendation="Finger 서비스 비활성화",
        reference="KISA 가이드 N-25 (중) 5.10 Finger 서비스 차단"
    ),
    
    # N-26: 웹 서비스 차단
    "N-26": SecurityRule(
        rule_id="N-26",
        title="웹 서비스 차단",
        description="불필요한 웹 서비스가 활성화되어 있는지 점검",
        severity="중",
        category=RuleCategory.FUNCTION_MANAGEMENT,
        patterns=[
            r"ip\s+http\s+server",
            r"ip\s+http\s+secure-server",
            r"web-management.*enable",
            r"https.*enable",
            r"http.*enable"
        ],
        negative_patterns=[
            r"no\s+ip\s+http\s+server",
            r"no\s+ip\s+http\s+secure-server",
            r"web-management.*disable",
            r"https.*disable",
            r"http.*disable"
        ],
        device_types=["Cisco", "Juniper", "Radware", "Piolink"],
        recommendation="불필요한 웹 서비스 비활성화 또는 허용된 IP에서만 접근 설정",
        reference="KISA 가이드 N-26 (중) 5.11 웹 서비스 차단"
    ),
    
    # N-27: TCP/UDP Small 서비스 차단
    "N-27": SecurityRule(
        rule_id="N-27",
        title="TCP/UDP Small 서비스 차단",
        description="TCP/UDP Small 서비스가 활성화되어 있는지 점검",
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
        recommendation="TCP/UDP Small 서비스 비활성화",
        reference="KISA 가이드 N-27 (중) 5.12 TCP/UDP Small 서비스 차단"
    ),
    
    # N-28: Bootp 서비스 차단
    "N-28": SecurityRule(
        rule_id="N-28",
        title="Bootp 서비스 차단",
        description="Bootp 서비스의 차단 여부 점검",
        severity="중",
        category=RuleCategory.FUNCTION_MANAGEMENT,
        patterns=[
            r"service\s+bootp",
            r"ip\s+bootp\s+server",
        ],
        negative_patterns=[
            r"no\s+ip\s+bootp\s+server",
            r"ip\s+dhcp\s+bootp\s+ignore",
        ],
        device_types=["Cisco", "Alteon", "Juniper"],
        recommendation="각 장비별 Bootp 서비스 제한 설정",
        reference="KISA 가이드 N-28 (중) 5.13 Bootp 서비스 차단"
    ),
    
    # N-29: CDP 서비스 차단
    "N-29": SecurityRule(
        rule_id="N-29",
        title="CDP 서비스 차단",
        description="CDP 서비스가 활성화되어 있는지 점검",
        severity="중",
        category=RuleCategory.FUNCTION_MANAGEMENT,
        patterns=[
            r"cdp\s+run",
            r"cdp\s+enable"
        ],
        negative_patterns=[
            r"no\s+cdp\s+run",
            r"no\s+cdp\s+enable"
        ],
        device_types=["Cisco"],
        recommendation="CDP 서비스 비활성화",
        reference="KISA 가이드 N-29 (중) 5.14 CDP 서비스 차단"
    ),
    
    # N-30: Directed-broadcast 차단
    "N-30": SecurityRule(
        rule_id="N-30",
        title="Directed-broadcast 차단",
        description="Directed-broadcast를 차단하는지 점검",
        severity="중",
        category=RuleCategory.FUNCTION_MANAGEMENT,
        patterns=[
            r"ip\s+directed-broadcast",
        ],
        negative_patterns=[
            r"no\s+ip\s+directed-broadcast",
        ],
        device_types=["Cisco", "Alteon", "Passport"],
        recommendation="각 장치별로 Directed Broadcasts 제한 설정",
        reference="KISA 가이드 N-30 (중) 5.15 Directed-broadcast 차단"
    ),
    
    # N-31: Source 라우팅 차단
    "N-31": SecurityRule(
        rule_id="N-31",
        title="Source 라우팅 차단",
        description="IP Source 라우팅이 활성화되어 있는지 점검",
        severity="중",
        category=RuleCategory.FUNCTION_MANAGEMENT,
        patterns=[
            r"ip\s+source-route"
        ],
        negative_patterns=[
            r"no\s+ip\s+source-route",
            r"no-source-route"
        ],
        device_types=["Cisco", "Juniper"],
        recommendation="IP Source 라우팅 비활성화",
        reference="KISA 가이드 N-31 (중) 5.16 Source 라우팅 차단"
    ),
    
    # N-32: Proxy ARP 차단
    "N-32": SecurityRule(
        rule_id="N-32",
        title="Proxy ARP 차단",
        description="Proxy ARP를 차단하는지 점검",
        severity="중",
        category=RuleCategory.FUNCTION_MANAGEMENT,
        patterns=[
            r"ip\s+proxy-arp",
        ],
        negative_patterns=[
            r"no\s+ip\s+proxy-arp",
        ],
        device_types=["Cisco", "Juniper"],
        recommendation="각 인터페이스에서 Proxy ARP 비활성화 설정",
        reference="KISA 가이드 N-32 (중) 5.17 Proxy ARP 차단"
    ),
    
    # N-33: ICMP unreachable, Redirect 차단
    "N-33": SecurityRule(
        rule_id="N-33",
        title="ICMP unreachable, Redirect 차단",
        description="ICMP unreachable, ICMP redirect를 차단하는지 점검",
        severity="중",
        category=RuleCategory.FUNCTION_MANAGEMENT,
        patterns=[
            r"ip\s+unreachables",
            r"ip\s+redirects",
        ],
        negative_patterns=[
            r"no\s+ip\s+unreachables",
            r"no\s+ip\s+redirects",
        ],
        device_types=["Cisco", "Juniper"],
        recommendation="각 인터페이스에서 ICMP Unreachables, ICMP Redirects 비활성화",
        reference="KISA 가이드 N-33 (중) 5.18 ICMP unreachable, Redirect 차단"
    ),
    
    # N-34: identd 서비스 차단
    "N-34": SecurityRule(
        rule_id="N-34",
        title="identd 서비스 차단",
        description="identd 서비스를 차단하는지 점검",
        severity="중",
        category=RuleCategory.FUNCTION_MANAGEMENT,
        patterns=[
            r"ip\s+identd",
        ],
        negative_patterns=[
            r"no\s+ip\s+identd",
        ],
        device_types=["Cisco"],
        recommendation="idnetd 서비스 비활성화",
        reference="KISA 가이드 N-34 (중) 5.19 identd 서비스 차단"
    ),
    
    # N-35: Domain lookup 차단
    "N-35": SecurityRule(
        rule_id="N-35",
        title="Domain Lookup 차단",
        description="불필요한 Domain Lookup이 활성화되어 있는지 점검",
        severity="중",
        category=RuleCategory.FUNCTION_MANAGEMENT,
        patterns=[
            r"ip\s+domain[-\s]lookup",
        ],
        negative_patterns=[
            r"no\s+ip\s+domain[-\s]lookup",
            r"no\s+ip\s+domain-lookup"
        ],
        device_types=["Cisco"],
        recommendation="Domain Lookup 비활성화",
        reference="KISA 가이드 N-35 (중) 5.20 Domain lookup 차단"
    ),
    
    # N-36: PAD 차단
    "N-36": SecurityRule(
        rule_id="N-36",
        title="PAD 차단",
        description="PAD 서비스를 차단하는지 점검",
        severity="중",
        category=RuleCategory.FUNCTION_MANAGEMENT,
        patterns=[
            r"service\s+pad",
        ],
        negative_patterns=[
            r"no\s+service\s+pad",
        ],
        device_types=["Cisco"],
        recommendation="PAD 서비스 비활성화",
        reference="KISA 가이드 N-36 (중) 5.21 PAD 차단"
    ),
    
    # N-37: mask-reply 차단
    "N-37": SecurityRule(
        rule_id="N-37",
        title="mask-reply 차단",
        description="mask-reply를 차단하는지 점검",
        severity="중",
        category=RuleCategory.FUNCTION_MANAGEMENT,
        patterns=[
            r"ip\s+mask-reply",
        ],
        negative_patterns=[
            r"no\s+ip\s+mask-reply",
        ],
        device_types=["Cisco"],
        recommendation="각 인터페이스에서 mask-reply 비활성화",
        reference="KISA 가이드 N-37 (중) 5.22 mask-reply 차단"
    ),
    
    # N-38: 스위치, 허브 보안 강화
    "N-38": SecurityRule(
        rule_id="N-38",
        title="스위치, 허브 보안 강화",
        description="스위치나 허브에서 포트 보안, SPAN 설정이 적용되고 있는지 점검",
        severity="하",
        category=RuleCategory.FUNCTION_MANAGEMENT,
        patterns=[],  # 포트 보안 설정이 없는 경우
        negative_patterns=[
            r"switchport\s+port-security",
            r"monitor\s+session",
        ],
        device_types=["Cisco"],
        recommendation="장비별 보안 위협에 관한 대책 설정 적용(포트 보안, SPAN 설정)",
        reference="KISA 가이드 N-38 (하) 5.23 스위치, 허브 보안 강화"
    ),
}


def get_all_rules() -> Dict[str, SecurityRule]:
    """모든 보안 룰 반환"""
    return KISA_SECURITY_RULES


def get_rules_by_device_type(device_type: str) -> Dict[str, SecurityRule]:
    """특정 장비 타입에 적용 가능한 룰들만 반환"""
    return {
        rule_id: rule for rule_id, rule in KISA_SECURITY_RULES.items()
        if device_type in rule.device_types
    }


def get_rules_by_severity(severity: str) -> Dict[str, SecurityRule]:
    """특정 심각도의 룰들만 반환"""
    return {
        rule_id: rule for rule_id, rule in KISA_SECURITY_RULES.items()
        if rule.severity == severity
    }


def get_rules_by_category(category: RuleCategory) -> Dict[str, SecurityRule]:
    """특정 카테고리의 룰들만 반환"""
    return {
        rule_id: rule for rule_id, rule in KISA_SECURITY_RULES.items()
        if rule.category == category
    }


def get_rule_by_id(rule_id: str) -> Optional[SecurityRule]:
    """특정 룰 ID로 룰 반환"""
    return KISA_SECURITY_RULES.get(rule_id)