# -*- coding: utf-8 -*-
"""
rules/security_rules.py
KISA 네트워크 장비 보안 점검 룰셋 정의

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


# KISA 가이드 기반 보안 룰셋 정의
SECURITY_RULES = {
    # N-01: 패스워드 설정 (기본 패스워드 변경)
    "N-01": SecurityRule(
        rule_id="N-01",
        title="기본 패스워드 변경",
        description="기본 패스워드를 변경하지 않고 사용하는지 점검",
        severity="상",
        category=RuleCategory.ACCOUNT_MANAGEMENT,
        patterns=[
            r"enable\s+password\s+(cisco|admin|password|123|1234)",
            r"username\s+\w+\s+password\s+(cisco|admin|password|123|1234)",
            r"password\s+(cisco|admin|password|123|1234|default)",
            r"community\s+(public|private)\s*$",
            r"admpw\s+(admin|password|default)"
        ],
        negative_patterns=[
            r"enable\s+secret\s+\w+",
            r"username\s+\w+\s+secret\s+\w+",
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
            r"enable\s+password\s+\w{1,4}$",  # 짧은 패스워드
            r"username\s+\w+\s+password\s+\w{1,4}$",
            r"password\s+\w{1,4}$"
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
            r"enable\s+password\s+[^0-9]",  # password 사용 (암호화되지 않음)
            r"username\s+\w+\s+password\s+[^0-9]",
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
    
    # N-04: VTY 접근(ACL) 설정
    "N-04": SecurityRule(
        rule_id="N-04",
        title="VTY 접근 제한 설정",
        description="VTY 라인에 접근 제한 ACL이 설정되어 있는지 점검",
        severity="상",
        category=RuleCategory.ACCESS_MANAGEMENT,
        patterns=[
            r"line\s+vty.*\n(?:(?!access-class).*\n)*$",  # VTY 라인에 access-class 없음
            r"line\s+vty\s+\d+\s+\d+\s*$"  # VTY 라인만 있고 ACL 없음
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
            r"line\s+(?:con|vty|aux).*\n(?:(?!exec-timeout).*\n)*$",  # timeout 설정 없음
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
            r"line\s+vty.*\n(?:(?!transport\s+input\s+ssh).*\n)*$"
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
    
    # N-35: Domain lookup 차단
    "N-35": SecurityRule(
        rule_id="N-35",
        title="Domain Lookup 차단",
        description="불필요한 Domain Lookup이 활성화되어 있는지 점검",
        severity="중",
        category=RuleCategory.FUNCTION_MANAGEMENT,
        patterns=[
            r"ip\s+domain[-\s]lookup",
            r"^(?!.*no\s+ip\s+domain).*ip\s+domain"
        ],
        negative_patterns=[
            r"no\s+ip\s+domain[-\s]lookup",
            r"no\s+ip\s+domain-lookup"
        ],
        device_types=["Cisco"],
        recommendation="Domain Lookup 비활성화",
        reference="KISA 가이드 N-35 (중) 5.20 Domain lookup 차단"
    )
}


def get_all_rules() -> Dict[str, SecurityRule]:
    """모든 보안 룰 반환"""
    return SECURITY_RULES


def get_rules_by_device_type(device_type: str) -> Dict[str, SecurityRule]:
    """특정 장비 타입에 적용 가능한 룰들만 반환"""
    return {
        rule_id: rule for rule_id, rule in SECURITY_RULES.items()
        if device_type in rule.device_types
    }


def get_rules_by_severity(severity: str) -> Dict[str, SecurityRule]:
    """특정 심각도의 룰들만 반환"""
    return {
        rule_id: rule for rule_id, rule in SECURITY_RULES.items()
        if rule.severity == severity
    }


def get_rules_by_category(category: RuleCategory) -> Dict[str, SecurityRule]:
    """특정 카테고리의 룰들만 반환"""
    return {
        rule_id: rule for rule_id, rule in SECURITY_RULES.items()
        if rule.category == category
    }


def get_rule_by_id(rule_id: str) -> Optional[SecurityRule]:
    """특정 룰 ID로 룰 반환"""
    return SECURITY_RULES.get(rule_id)
