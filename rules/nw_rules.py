# -*- coding: utf-8 -*-
"""
rules/nw_rules.py
NW 네트워크 장비 보안 점검 룰셋 정의

NW 가이드 기반 보안 룰들의 정의만 포함
logical_check_function은 checks_nw.py에서 import
"""

import re
from dataclasses import dataclass, field
from typing import List, Dict, Pattern, Callable, Optional, Any, Tuple
from enum import Enum

# 기존 KISA 룰셋의 구조 재사용
from .kisa_rules import RuleCategory, ConfigContext, LogicalCondition, SecurityRule

# checks_nw.py에서 logical_check_function들 import
from .checks_nw import (
    check_nw_01,
    check_nw_02,
    check_nw_03,
    check_nw_04,
    check_nw_05,
    check_nw_06,
    check_nw_07,  # ← 추가 필요
    check_nw_08,
    check_nw_09,  # ← 추가 필요
    check_nw_11,
    check_nw_12,  # ← 추가 필요
    check_nw_13,  # ← 추가 필요
    check_nw_14,
    check_nw_15,  # ← 추가 필요
    check_nw_16,
    check_nw_17,
    check_nw_18,
    check_nw_19,
    check_nw_20,  # ← 추가 필요
    check_nw_21,
    check_nw_22,  # ← 추가 필요
    check_nw_23,
    check_nw_24,  # ← 추가 필요
    check_nw_25,  # ← 추가 필요
    check_nw_26,  # ← 추가 필요
    check_nw_27,  # ← 추가 필요
    check_nw_28,  # ← 추가 필요
    check_nw_29,  # ← 추가 필요
    check_nw_30,  # ← 추가 필요
    check_nw_31,  # ← 추가 필요
    check_nw_32,  # ← 추가 필요
    check_nw_33,
    check_nw_34,  # ← 추가 필요
    check_nw_35,  # ← 추가 필요
    check_nw_36,  # ← 추가 필요
    check_nw_37,  # ← 추가 필요
    check_nw_38,
    check_nw_39,  # ← 추가 필요
    check_nw_40,
    check_nw_41,
    check_nw_42
)

NW_RULES = {
    # ======================= 계정 관리 =======================
    
    "NW-01": SecurityRule(
        rule_id="NW-01",
        title="비밀번호 설정",
        description="장비 출고 시 설정된 기본 관리자 계정과 비밀번호를 변경하지 않고 그대로 사용할 경우 비인가자의 체계 접근을 허용할 위험성이 있다",
        severity="상",
        category=RuleCategory.ACCOUNT_MANAGEMENT,
        patterns=[
            # 더 정확한 패턴
            r"enable\s+password\s+(?:0\s+)?(cisco|admin|password|123|1234|default|switch|router)\s*$",
            r"username\s+\w+\s+password\s+(?:0\s+)?(cisco|admin|password|123|1234|default|switch|router)\s*$",
            r"username\s+(admin|cisco|root|guest)\s+password\s+",
        ],
        negative_patterns=[
            r"enable\s+secret\s+[45]\s+\$",  # Type 4,5 암호화
            r"service\s+password-encryption",
            r"username\s+\w+\s+secret\s+",
            r"username\s+\w+\s+password\s+[57]\s+",  # 암호화된 패스워드
        ],
        device_types=["Cisco", "Alteon", "Passport", "Juniper", "Piolink", "HP", "Dasan", "Netgear", "Radware"],
        recommendation="기본 패스워드를 강력한 패스워드로 변경하고 enable secret 명령어 사용",
        reference="NW 가이드 NW-01 (상) 비밀번호 설정",
        logical_check_function=check_nw_01,
    ),
    
    "NW-02": SecurityRule(
        rule_id="NW-02",
        title="비밀번호 복잡성 설정",
        description="취약한 비밀번호를 사용하는 경우 추측이나 도구에 의한 비밀번호 해킹으로 비인가자의 체계 접근을 허용할 위험성이 있다",
        severity="상",
        category=RuleCategory.ACCOUNT_MANAGEMENT,
        patterns=[
            # 평문 패스워드만 탐지
            r"enable\s+password\s+(?:0\s+)?\w{1,7}\s*$",
            r"username\s+\w+\s+password\s+(?:0\s+)?\w{1,7}\s*$",
        ],
        negative_patterns=[
            r"security\s+passwords\s+min-length",
            r"username\s+\w+\s+secret",  # secret 사용시 제외
            r"service\s+password-encryption",  # 암호화 서비스 사용시
            r"username\s+\w+\s+password\s+[57]\s+",  # 이미 암호화된 경우
        ],
        device_types=["Cisco", "Piolink", "Alcatel"],
        recommendation="패스워드 복잡성 정책 설정 및 최소 8자 이상의 복잡한 패스워드 사용",
        reference="NW 가이드 NW-02 (상) 비밀번호 복잡성 설정",
        logical_check_function=check_nw_02,
    ),
    
    "NW-03": SecurityRule(
        rule_id="NW-03",
        title="암호화된 비밀번호 사용",
        description="계정 비밀번호 암호화 기능이 설정되어 있지 않을 경우, 비인가자가 네트워크 터미널에 접근하여 장비 내에 존재하는 모든 계정의 비밀번호를 획득할 수 있는 위험이 있다",
        severity="상",
        category=RuleCategory.ACCOUNT_MANAGEMENT,
        patterns=[
            r"enable\s+password\s+[^$0-9]",
            r"username\s+\w+\s+password\s+[^$0-9]"
        ],
        negative_patterns=[
            r"enable\s+secret",
            r"username\s+\w+\s+secret",
            r"service\s+password-encryption",
            r"root\s+authentication\s+.*encrypted-password"
        ],
        device_types=["Cisco", "Juniper", "HP", "Alcatel", "Dasan", "Alteon", "Piolink"],
        recommendation="enable secret 사용, Password-Encryption 서비스 활성화 및 암호화된 비밀번호 사용",
        reference="NW 가이드 NW-03 (상) 암호화된 비밀번호 사용",
        logical_check_function=check_nw_03,
    ),
    
    # ======================= 접근 관리 =======================
    
    "NW-04": SecurityRule(
        rule_id="NW-04",
        title="사용자·명령어별 권한 수준 설정",
        description="다수의 계정을 생성할 때 계정별로 권한 수준을 동일하게 설정하면 비인가자에 의한 네트워크 설정 변경, 삭제의 위험성이 있다",
        severity="중",
        category=RuleCategory.ACCESS_MANAGEMENT,
        patterns=[
            r"username\s+\w+\s+privilege\s+15",
            r"username\s+\w+\s+.*privilege\s+15",
        ],
        negative_patterns=[
            r"username\s+\w+\s+privilege\s+[1-9]$",
            r"username\s+\w+\s+privilege\s+1[0-4]$"
        ],
        device_types=["Cisco", "Radware", "Juniper", "HP", "Alcatel", "Piolink", "Extreme", "Dasan"],
        recommendation="사용자별 권한 수준을 차등 적용하고 명령어별 권한 수준 지정",
        reference="NW 가이드 NW-04 (중) 사용자·명령어별 권한 수준 설정",
        logical_check_function=check_nw_04,
    ),
    
    "NW-05": SecurityRule(
        rule_id="NW-05",
        title="VTY 접근(ACL) 설정",
        description="지정된 IP에서만 네트워크 장비에 접근하도록 설정되어 있지 않을 경우 네트워크를 통한 침해행위의 위험성이 높다",
        severity="상",
        category=RuleCategory.ACCESS_MANAGEMENT,
        patterns=[
            # VTY 라인에 access-class가 없는 경우만
            r"line\s+vty\s+\d+(?:\s+\d+)?(?:\n(?!.*access-class).*)*?(?=line|\Z)",
        ],
        negative_patterns=[
            r"line\s+vty.*\n(?:.*\n)*?\s*access-class\s+\d+\s+in",
            r"transport\s+input\s+none",  # 접속 자체를 차단한 경우
        ],
        device_types=["Cisco", "Radware", "Passport", "Juniper", "Piolink", "HP", "Dasan", "Alcatel"],
        recommendation="네트워크 장비에 접근 가능한 관리자 IP를 설정하여 VTY 서비스 미사용 시 설정 불필요",
        reference="NW 가이드 NW-05 (상) VTY 접근(ACL) 설정",
        logical_check_function=check_nw_05,
    ),
    
    "NW-06": SecurityRule(
        rule_id="NW-06",
        title="Session Timeout 설정",
        description="Session Timeout 정책이 적용되지 않았거나 설정 시간이 너무 긴 경우, 비인가자가 네트워크 장비 터미널에 접속된 컴퓨터를 통해 네트워크 장비의 정책 변경 및 삭제 등의 행위를 할 수 있는 위험이 존재한다",
        severity="상",
        category=RuleCategory.ACCESS_MANAGEMENT,
        patterns=[
            r"exec-timeout\s+0\s+0",
            r"exec-timeout\s+[6-9][0-9]|[1-9][0-9]{2,}"
        ],
        negative_patterns=[
            r"exec-timeout\s+[1-5]\s+0"
        ],
        device_types=["Cisco", "Radware", "Juniper", "Piolink", "HP", "Alcatel", "Dasan"],
        recommendation="미사용 시 5분 이내에 자동으로 연결을 종료하도록 Session Timeout 시간을 설정한다",
        reference="NW 가이드 NW-06 (상) Session Timeout 설정",
        logical_check_function=check_nw_06,
    ),
    
    "NW-07": SecurityRule(
        rule_id="NW-07",
        title="VTY 접속 시 안전한 프로토콜 사용",
        description="평문 프로토콜(telnet)을 이용하여 네트워크 장비에 접근할 경우, 네트워크 스니핑 공격으로 관리자 계정 정보가 비인가자에게 유출될 수 있다",
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
        device_types=["Cisco", "Radware", "Juniper", "Piolink", "HP", "Alcatel", "Extreme", "Dasan"],
        recommendation="네트워크 장비에서 암호화 통신인 암호화 방식의 원격접속 서비스(SSH 등)를 활용한다",
        reference="NW 가이드 NW-07 (중) VTY 접속 시 안전한 프로토콜 사용",
        logical_check_function = check_nw_07,
    ),
    
    # ======================= 기능 관리 =======================
    
    "NW-08": SecurityRule(
        rule_id="NW-08",
        title="불필요한 보조 입출력 포트 사용 금지",
        description="불필요한 포트 및 인터페이스가 활성화되어 있으면, 비인가자가 네트워크 장비에 접근할 수 있는 위험이 존재한다",
        severity="중",
        category=RuleCategory.FUNCTION_MANAGEMENT,
        patterns=[
            r"interface\s+\w+.*(?:\n(?!.*shutdown).*)*(?=interface|\Z)"
        ],
        negative_patterns=[
            r"interface\s+\w+.*\n.*shutdown"
        ],
        device_types=["Cisco", "Juniper", "HP", "Dasan", "Alcatel", "Piolink"],
        recommendation="불필요한 포트 및 인터페이스의 사용을 제한하거나 비활성화한다",
        reference="NW 가이드 NW-08 (중) 불필요한 보조 입출력 포트 사용 금지",
        logical_check_function=check_nw_08,
    ),
    
    "NW-09": SecurityRule(
        rule_id="NW-09",
        title="로그온 시 경고 메시지 설정",
        description="터미널 접근 시 경고 메시지가 표시되지 않을 경우, 비인가자가 법 위반에 대한 경각심을 느끼지 않게 되어 더 많은 공격을 시도할 수 있는 원인이 된다",
        severity="중",
        category=RuleCategory.FUNCTION_MANAGEMENT,
        patterns=[],
        negative_patterns=[
            r"banner\s+(motd|login|exec)",
            r"message\s+text"
        ],
        device_types=["Cisco", "Radware", "Juniper", "Piolink", "HP", "Alcatel", "Dasan"],
        recommendation="네트워크 장비 접속 시 경고 메시지가 출력되도록 설정한다",
        reference="NW 가이드 NW-09 (중) 로그온 시 경고 메시지 설정",
        logical_check_function = check_nw_09,
    ),
    
    "NW-10": SecurityRule(
        rule_id="NW-10",
        title="네트워크 장비 펌웨어 최신화 관리",
        description="최신 펌웨어를 유지하지 않으면 알려진 취약점에 노출될 수 있다",
        severity="상",
        category=RuleCategory.PATCH_MANAGEMENT,
        patterns=[],
        negative_patterns=[],
        device_types=["Cisco", "Juniper", "HP", "Alteon", "Alcatel", "Piolink", "Extreme", "Dasan"],
        recommendation="시스템 영향성을 고려하여 검토 후 버전 업그레이드를 시행한다",
        reference="NW 가이드 NW-10 (상) 네트워크 장비 펌웨어 최신화 관리",
    ),
    
    # ======================= 로그 관리 =======================
    
    "NW-11": SecurityRule(
        rule_id="NW-11",
        title="원격 로그서버 사용",
        description="침해사고 발생 시 이벤트 로그를 확인할 수 없으면 침해경로 및 내용에 대한 사후 분석이 제한된다",
        severity="중",
        category=RuleCategory.LOG_MANAGEMENT,
        patterns=[],
        negative_patterns=[
            r"logging\s+\d+\.\d+\.\d+\.\d+",
            r"syslog\s+host",
            r"logging\s+server"
        ],
        device_types=["Cisco", "Radware", "Juniper", "Piolink", "HP", "Alcatel", "Extreme", "Dasan"],
        recommendation="로그저장 서버를 설정한다",
        reference="NW 가이드 NW-11 (중) 원격 로그서버 사용",
        logical_check_function=check_nw_11,
    ),
    
    "NW-12": SecurityRule(
        rule_id="NW-12",
        title="로깅 버퍼 크기 설정",
        description="버퍼 메모리의 용량을 초과하는 로그가 저장될 경우 로그 정보를 잃게 되어 침해사고 발생 시 침해경로 및 내용에 대한 사후 분석이 제한된다",
        severity="중",
        category=RuleCategory.LOG_MANAGEMENT,
        patterns=[
            r"logging\s+buffered\s+[0-9]{1,4}$",  # 작은 버퍼 크기
        ],
        negative_patterns=[
            r"logging\s+buffered\s+1[6-9][0-9]{3}",  # 16000 이상
            r"logging\s+buffered\s+[2-9][0-9]{4}",   # 20000 이상
        ],
        device_types=["Cisco", "Piolink", "HP", "Alcatel"],
        recommendation="로그저장 장치의 크기를 고려하여 버퍼 크기를 설정하고 2년 이상 보관한다",
        reference="NW 가이드 NW-12 (중) 로깅 버퍼 크기 설정",
        logical_check_function = check_nw_12,
    ),
    
    "NW-13": SecurityRule(
        rule_id="NW-13",
        title="정책에 따른 로깅 설정",
        description="로깅 설정이 되어있지 않을 경우 침입 규명이 어려우며, 법적 대응을 위한 충분한 근거를 사용할 수 없다",
        severity="중",
        category=RuleCategory.LOG_MANAGEMENT,
        patterns=[],
        negative_patterns=[
            r"logging\s+on",
            r"logging\s+enable",
            r"log\s+messages"
        ],
        device_types=["Cisco", "Juniper", "Piolink"],
        recommendation="로그 기록 정책을 수립하고 정책에 따른 로깅 설정을 한다",
        reference="NW 가이드 NW-13 (중) 정책에 따른 로깅 설정",
        logical_check_function = check_nw_13,
    ),
    
    "NW-14": SecurityRule(
        rule_id="NW-14",
        title="NTP 서버 연동",
        description="시스템 간 시간 동기화가 안 되면 보안사고 및 장애 발생 시 로그에 대한 신뢰도 확보가 미흡하게 된다",
        severity="중",
        category=RuleCategory.LOG_MANAGEMENT,
        patterns=[],
        negative_patterns=[
            r"ntp\s+server\s+\d+\.\d+\.\d+\.\d+",
            r"sntp\s+server",
            r"clock\s+timezone"
        ],
        device_types=["Cisco", "Radware", "Juniper", "HP", "Alcatel", "Piolink", "Extreme", "Dasan"],
        recommendation="NTP 서버를 활용하여 장비 간의 시간 동기화를 유지한다",
        reference="NW 가이드 NW-14 (중) NTP 서버 연동",
        logical_check_function=check_nw_14,
    ),
    
    "NW-15": SecurityRule(
        rule_id="NW-15",
        title="Timestamp 로그 설정",
        description="네트워크 장비에 timestamp를 설정하지 않을 경우, 로그에 시간이 기록되지 않아 공격 및 침입시도에 관한 정보를 정확히 분석할 수 없고 로그 기록에 대한 신뢰성을 잃게 된다",
        severity="중",
        category=RuleCategory.LOG_MANAGEMENT,
        patterns=[],
        negative_patterns=[
            r"service\s+timestamps",
            r"timestamp\s+log"
        ],
        device_types=["Cisco", "HP", "Alcatel", "Piolink", "Extreme", "Dasan"],
        recommendation="Timestamp 로그를 설정한다",
        reference="NW 가이드 NW-15 (중) Timestamp 로그 설정",
        logical_check_function = check_nw_15,
    ),
    
    # ======================= SNMP 관리 =======================
    
    "NW-16": SecurityRule(
        rule_id="NW-16",
        title="SNMP 서비스 확인",
        description="불필요한 SNMP 서비스를 비활성화하지 않으면 비인가자가 네트워크 정보를 획득하거나 장비를 임의로 제어할 수 있는 취약점이 발생한다",
        severity="중",
        category=RuleCategory.FUNCTION_MANAGEMENT,
        patterns=[
            r"snmp-server\s+enable",
            r"snmp\s+enable"
        ],
        negative_patterns=[
            r"no\s+snmp-server",
            r"snmp\s+disable"
        ],
        device_types=["Cisco", "Radware", "Juniper", "Piolink", "HP", "Alcatel", "Extreme", "Dasan"],
        recommendation="사용하지 않는 SNMP 서비스는 비활성화한다",
        reference="NW 가이드 NW-16 (중) SNMP 서비스 확인",
        logical_check_function=check_nw_16,
    ),
    
    "NW-17": SecurityRule(
        rule_id="NW-17",
        title="SNMP community string 복잡성 설정",
        description="SNMP는 네트워크상에서 장비를 관리하기 위한 프로토콜로 SNMP Community String이라는 일종의 key 값을 통해 장비 상호 간 인증한다. 이러한 SNMP Community String은 장비 출하 시 기본으로 설정되어 있거나 유추 가능한 값으로 설정되어 있을 경우 공격자가 네트워크 정보를 획득하거나 장비를 임의로 제어할 수 있는 취약점이 발생한다",
        severity="중",
        category=RuleCategory.FUNCTION_MANAGEMENT,
        patterns=[
            r"snmp-server\s+community\s+(public|private)"
        ],
        negative_patterns=[
            r"snmp-server\s+community\s+[a-zA-Z0-9_-]{8,}"
        ],
        device_types=["Cisco", "Radware", "Passport", "Juniper", "Piolink", "Alcatel"],
        recommendation="SNMP Community String을 네트워크 장비와 관리 콘솔 간에 인증하기 위한 일종의 key 값으로 비밀번호에 준하여 설정한다",
        reference="NW 가이드 NW-17 (중) SNMP community string 복잡성 설정",
        logical_check_function=check_nw_17,
    ),
    
    "NW-18": SecurityRule(
        rule_id="NW-18",
        title="SNMP ACL 설정",
        description="비인가자의 SNMP 접근을 차단하지 않을 경우, 공격자가 Community String 추측 공격 후 MIB 정보를 수집하여 라우팅 정보를 변경하거나 터널링 설정을 하여 내부망에 침투할 수 있는 위험이 존재한다",
        severity="중",
        category=RuleCategory.FUNCTION_MANAGEMENT,
        patterns=[
            r"snmp-server\s+community\s+\w+(?!\s+\d+)"
        ],
        negative_patterns=[
            r"snmp-server\s+community\s+\w+\s+\d+",
            r"snmp\s+community\s+\w+\s+authorization"
        ],
        device_types=["Cisco", "Passport", "Juniper", "Piolink", "HP", "Alteon", "Alcatel", "Extreme", "Dasan"],
        recommendation="SNMP 접근에 대한 ACL(Access Control list)을 설정한다",
        reference="NW 가이드 NW-18 (중) SNMP ACL 설정",
        logical_check_function=check_nw_18,
    ),
    
    "NW-19": SecurityRule(
        rule_id="NW-19",
        title="SNMP 커뮤니티 권한 설정",
        description="SNMP 커뮤니티 권한이 불필요하게 RW로 설정되어 있으면, 공격자가 Community String 추측 공격을 통해 Community String을 탈취했을 시 SNMP를 이용하여 네트워크 설정 정보를 변경하여 내부망 침투가 가능해진다",
        severity="중",
        category=RuleCategory.FUNCTION_MANAGEMENT,
        patterns=[
            r"snmp-server\s+community\s+\w+\s+rw",
            r"snmp\s+community\s+\w+.*rw"
        ],
        negative_patterns=[
            r"snmp-server\s+community\s+\w+\s+ro",
            r"snmp\s+community\s+\w+.*read-only"
        ],
        device_types=["Cisco", "Juniper", "Passport", "Alteon", "Piolink", "HP", "Extreme", "Dasan"],
        recommendation="SNMP Community String에 RO(Read-Only) 권한을 적용한다",
        reference="NW 가이드 NW-19 (중) SNMP 커뮤니티 권한 설정",
        logical_check_function=check_nw_19,
    ),
    
    "NW-20": SecurityRule(
        rule_id="NW-20",
        title="TFTP 서비스 차단",
        description="TFTP 서비스는 인증절차 없이 누구나 사용이 가능한 서비스로 공격자가 TFTP를 통해 악성 코드가 삽입된 파일을 올려 사용자에게 배포할 수 있고, 네트워크 설정 파일이나 중요한 내부 정보를 유출할 수 있다",
        severity="중",
        category=RuleCategory.FUNCTION_MANAGEMENT,
        patterns=[
            r"tftp\s+server",
            r"service\s+tftp"
        ],
        negative_patterns=[
            r"no\s+service\s+tftp",
            r"no\s+tftp\s+server"
        ],
        device_types=["Cisco"],
        recommendation="네트워크 장비의 TFTP 서비스가 비활성화되도록 설정한다(필요시에만 활성화)",
        reference="NW 가이드 NW-20 (중) TFTP 서비스 차단",
        logical_check_function = check_nw_20,
    ),
    
    # ======================= 보안 방어 =======================
    
    "NW-21": SecurityRule(
        rule_id="NW-21",
        title="Spoofing 방지 필터링 적용 또는 보안장비 사용",
        description="IP 스푸핑 기반 DoS 공격 트래픽이 네트워크 장비의 한계용량을 초과하는 경우 정상적인 서비스가 불가능해 된다",
        severity="중",
        category=RuleCategory.FUNCTION_MANAGEMENT,
        patterns=[
            # 패턴 기반 검사는 논리 검사로 대체
        ],
        negative_patterns=[
            # 기본적인 스푸핑 방지 설정들
            r"access-list\s+\d+\s+deny\s+ip\s+(?:host\s+)?0\.0\.0\.0",
            r"access-list\s+\d+\s+deny\s+ip\s+10\.0\.0\.0\s+0\.255\.255\.255",
            r"access-list\s+\d+\s+deny\s+ip\s+172\.1[6-9]\.0\.0",
            r"access-list\s+\d+\s+deny\s+ip\s+172\.2[0-9]\.0\.0",
            r"access-list\s+\d+\s+deny\s+ip\s+172\.3[0-1]\.0\.0",
            r"access-list\s+\d+\s+deny\s+ip\s+192\.168\.0\.0\s+0\.0\.255\.255",
            r"access-list\s+\d+\s+deny\s+ip\s+127\.0\.0\.0\s+0\.255\.255\.255",
            r"access-list\s+\d+\s+deny\s+ip\s+22[4-9]\.",
            r"access-list\s+\d+\s+deny\s+ip\s+23[0-9]\.",
        ],
        device_types=["Cisco", "Juniper"],
        recommendation="IP spoofing 공격 방지를 위해서 루프백, 브로드캐스트 주소, 멀티캐스트 주소를 가진 패킷은 차단해야 한다",
        reference="NW 가이드 NW-21 (중) Spoofing 방지 필터링 적용 또는 보안장비 사용",
        logical_check_function=check_nw_21,
    ),
    
    "NW-22": SecurityRule(
        rule_id="NW-22",
        title="DDoS 공격 방어 설정 또는 DDoS 대응 장비 사용",
        description="DDoS 공격으로 인해 시스템 리소스가 과도하게 소모되어 속도가 느려지거나 심한 서비가 손상될 수 있다",
        severity="중",
        category=RuleCategory.FUNCTION_MANAGEMENT,
        patterns=[],
        negative_patterns=[
            r"rate-limiting",
            r"tcp\s+intercept",
            r"access-control\s+list"
        ],
        device_types=["Cisco", "Juniper"],
        recommendation="DDoS 공격 대응 설정을 한다",
        reference="NW 가이드 NW-22 (중) DDoS 공격 방어 설정 또는 DDoS 대응 장비 사용",
        logical_check_function = check_nw_22,
    ),
    
    "NW-23": SecurityRule(
        rule_id="NW-23",
        title="사용하지 않는 인터페이스의 Shutdown 설정",
        description="사용하지 않은 포트의 인터페이스를 Shutdown 하지 않을 경우, 물리적인 내부 접근을 통해 비인가자의 불법적인 네트워크 접근이 가능하게 되며 이로 인해 네트워크 정보 유출 및 네트워크 손상이 발생할 수 있다",
        severity="중",
        category=RuleCategory.FUNCTION_MANAGEMENT,
        patterns=[
            r"interface\s+\w+.*(?:\n(?!.*shutdown).*)*(?=interface|\Z)"
        ],
        negative_patterns=[
            r"interface\s+\w+.*\n.*shutdown"
        ],
        device_types=["Cisco", "Radware", "Juniper", "Piolink", "HP", "Alcatel", "Extreme", "Dasan"],
        recommendation="네트워크 장비에서 사용하지 않는 모든 인터페이스를 비활성화하도록 설정한다",
        reference="NW 가이드 NW-23 (중) 사용하지 않는 인터페이스의 Shutdown 설정",
        logical_check_function=check_nw_23,
    ),
    
    "NW-24": SecurityRule(
        rule_id="NW-24",
        title="TCP keepalive 서비스 설정",
        description="유휴 TCP 세션은 무단 접근 및 하이재킹 공격에 취약하다",
        severity="중",
        category=RuleCategory.FUNCTION_MANAGEMENT,
        patterns=[],
        negative_patterns=[
            r"service\s+tcp-keepalives-in"
        ],
        device_types=["Cisco"],
        recommendation="사용되지 않은 터미널 삭제 및 원격에서의 동일한 터미널 접속을 방지하기 위해 TCP keepalive 서비스를 사용한다",
        reference="NW 가이드 NW-24 (중) TCP keepalive 서비스 설정",
        logical_check_function = check_nw_24,
    ),
    
    # ======================= 불필요한 서비스 차단 =======================
    
    "NW-25": SecurityRule(
        rule_id="NW-25",
        title="Finger 서비스 차단",
        description="Finger 서비스를 사용하여 네트워크 장비에 로그인한 계정 ID, 접속 IP 등 정보가 노출될 위험성이 있다",
        severity="중",
        category=RuleCategory.FUNCTION_MANAGEMENT,
        patterns=[
            r"service\s+finger"
        ],
        negative_patterns=[
            r"no\s+service\s+finger",
            r"no\s+ip\s+finger"
        ],
        device_types=["Cisco", "Juniper"],
        recommendation="finger 서비스는 임의의 사용자가 장비에 접속한 유저명, IP 등 민감한 정보를 얻을 수 있으므로 제거한다",
        reference="NW 가이드 NW-25 (중) Finger 서비스 차단",
        logical_check_function = check_nw_25,
    ),
    
    "NW-26": SecurityRule(
        rule_id="NW-26",
        title="웹 서비스 차단",
        description="허용된 IP만 웹 관리자 에이전트 접속을 가능하게 ACL을 적용하지 않을 경우, 공격자는 알려진 웹 취약점(SQL 인젝션, 커맨드 인젝션 등)이나 자동화된 비밀번호 대입 공격을 통하여 네트워크 장비의 관리자 권한을 획득할 수 있다",
        severity="중",
        category=RuleCategory.FUNCTION_MANAGEMENT,
        patterns=[
            r"ip\s+http\s+server"
        ],
        negative_patterns=[
            r"no\s+ip\s+http\s+server",
            r"no\s+ip\s+http\s+secure-server"
        ],
        device_types=["Cisco", "Radware", "Juniper", "Piolink", "HP", "Alcatel"],
        recommendation="관리상 불필요한 웹서비스를 제거한다",
        reference="NW 가이드 NW-26 (중) 웹 서비스 차단",
        logical_check_function = check_nw_26,
    ),
    
    "NW-27": SecurityRule(
        rule_id="NW-27",
        title="TCP/UDP Small 서비스 차단",
        description="TCP/UDP Small 서비스를 차단하지 않을 경우, DoS 공격의 대상이 될 수 있다",
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
        recommendation="DoS 공격에 악용될 수 있는 서비스(echo, discard, daytime, chargen)를 제거한다",
        reference="NW 가이드 NW-27 (중) TCP/UDP Small 서비스 차단",
        logical_check_function = check_nw_27,
    ),
    
    "NW-28": SecurityRule(
        rule_id="NW-28",
        title="Bootp 서비스 차단",
        description="Bootp 서비스를 차단하지 않을 경우, 다른 라우터 상의 OS 자본에 접속하여 OS 소프트웨어 복사본을 다운로드할 수 있다",
        severity="중",
        category=RuleCategory.FUNCTION_MANAGEMENT,
        patterns=[
            r"ip\s+bootp\s+server"
        ],
        negative_patterns=[
            r"no\s+ip\s+bootp\s+server",
            r"ip\s+dhcp\s+bootp\s+ignore"
        ],
        device_types=["Cisco", "Radware", "Juniper"],
        recommendation="장비별 Bootp 서비스 제한 설정을 한다",
        reference="NW 가이드 NW-28 (중) Bootp 서비스 차단",
        logical_check_function = check_nw_28,
    ),
    
    "NW-29": SecurityRule(
        rule_id="NW-29",
        title="CDP 서비스 차단",
        description="보안이 검증되지 않은 서비스로, 비인가자가 다른 Cisco 장비의 정보를 획득할 수 있으며, Routing Protocol Attack을 통해 네트워크 장비의 서비스 기부 공격을 할 수 있다",
        severity="중",
        category=RuleCategory.FUNCTION_MANAGEMENT,
        patterns=[
            r"cdp\s+run"
        ],
        negative_patterns=[
            r"no\s+cdp\s+run",
            r"no\s+cdp\s+enable"
        ],
        device_types=["Cisco"],
        recommendation="Cisco 전용 프로토콜로 Neighbor 장비들의 정보를 획득할 수 있는 CDP를 사용하지 않는다",
        reference="NW 가이드 NW-29 (중) CDP 서비스 차단",
        logical_check_function = check_nw_29,
    ),
    
    "NW-30": SecurityRule(
        rule_id="NW-30",
        title="Directed-broadcast 차단",
        description="IP Directed-Broadcast를 차단하여 smurf 공격 등을 방지",
        severity="중",
        category=RuleCategory.FUNCTION_MANAGEMENT,
        patterns=[
            r"ip\s+directed-broadcast"
        ],
        negative_patterns=[
            r"no\s+ip\s+directed-broadcast"
        ],
        device_types=["Cisco", "Juniper", "Radware", "Passport", "Alcatel"],
        recommendation="각 인터페이스에서 no ip directed-broadcast 설정",
        reference="NW 가이드 NW-30 (중) Directed-broadcast 차단",
        logical_check_function = check_nw_30,
    ),

    "NW-31": SecurityRule(
        rule_id="NW-31",
        title="Source 라우팅 차단",
        description="공격자가 source routing된 패킷을 네트워크에 반송할 수 있는 경우 차단",
        severity="중",
        category=RuleCategory.FUNCTION_MANAGEMENT,
        patterns=[
            r"ip\s+source-route"
        ],
        negative_patterns=[
            r"no\s+ip\s+source-route"
        ],
        device_types=["Cisco", "Juniper"],
        recommendation="각 인터페이스에서 no ip source-route 설정",
        reference="NW 가이드 NW-31 (중) Source 라우팅 차단",
        logical_check_function = check_nw_31,
    ),

    "NW-32": SecurityRule(
        rule_id="NW-32",
        title="Proxy ARP 차단",
        description="Proxy ARP를 차단하여 악의적인 사용자가 보낸 가짜 IP와 MAC 정보 보관 방지",
        severity="중",
        category=RuleCategory.FUNCTION_MANAGEMENT,
        patterns=[
            r"ip\s+proxy-arp"
        ],
        negative_patterns=[
            r"no\s+ip\s+proxy-arp"
        ],
        device_types=["Cisco", "Juniper", "Piolink", "Alcatel"],
        recommendation="각 인터페이스에서 no ip proxy-arp 설정",
        reference="NW 가이드 NW-32 (중) Proxy ARP 차단",
        logical_check_function = check_nw_32,
    ),

    "NW-33": SecurityRule(
        rule_id="NW-33",
        title="ICMP unreachable, Redirect 차단",
        description="ICMP unreachable을 차단하여 시스템의 현재 운영되고 있는 상태 정보가 노출되는 것을 방지",
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
        recommendation="각 인터페이스에서 no ip unreachables, no ip redirects 설정",
        reference="NW 가이드 NW-33 (중) ICMP unreachable, Redirect 차단",
        logical_check_function=check_nw_33,
    ),

    "NW-34": SecurityRule(
        rule_id="NW-34",
        title="identd 서비스 차단",
        description="identd 서비스는 TCP 세션의 사용자 식별이 가능하여 비인가자에게 사용자 정보가 노출될 수 있음",
        severity="중",
        category=RuleCategory.FUNCTION_MANAGEMENT,
        patterns=[
            r"ip\s+identd"
        ],
        negative_patterns=[
            r"no\s+ip\s+identd"
        ],
        device_types=["Cisco"],
        recommendation="no ip identd 설정으로 identd 서비스 비활성화",
        reference="NW 가이드 NW-34 (중) identd 서비스 차단",
        logical_check_function = check_nw_34,
    ),

    "NW-35": SecurityRule(
        rule_id="NW-35",
        title="Domain lookup 차단",
        description="Domain lookup 기능은 의부명령어에 대한 질의를 도메인 또는 전체 네트워크로 전송하여 네트워크 정보가 노출될 수 있음",
        severity="중",
        category=RuleCategory.FUNCTION_MANAGEMENT,
        patterns=[
            r"ip\s+domain-lookup"
        ],
        negative_patterns=[
            r"no\s+ip\s+domain-lookup"
        ],
        device_types=["Cisco"],
        recommendation="no ip domain-lookup 설정으로 Domain lookup 기능 비활성화",
        reference="NW 가이드 NW-35 (중) Domain lookup 차단",
        logical_check_function = check_nw_35,
    ),

    "NW-36": SecurityRule(
        rule_id="NW-36",
        title="PAD 차단",
        description="PAD와 같이 불필요한 서비스를 차단하지 않을 경우 잠재적인 위험점 및 공격에 노출될 수 있음",
        severity="중",
        category=RuleCategory.FUNCTION_MANAGEMENT,
        patterns=[
            r"service\s+pad"
        ],
        negative_patterns=[
            r"no\s+service\s+pad"
        ],
        device_types=["Cisco"],
        recommendation="no service pad 설정으로 PAD 서비스 비활성화",
        reference="NW 가이드 NW-36 (중) PAD 차단",
        logical_check_function = check_nw_36,
    ),

    "NW-37": SecurityRule(
        rule_id="NW-37",
        title="mask-reply 차단",
        description="mask-reply를 차단하지 않을 경우 비인가자에게 내부 서브 네트워크의 서브넷 마스크 정보가 노출될 수 있음",
        severity="중",
        category=RuleCategory.FUNCTION_MANAGEMENT,
        patterns=[
            r"ip\s+mask-reply"
        ],
        negative_patterns=[
            r"no\s+ip\s+mask-reply"
        ],
        device_types=["Cisco"],
        recommendation="각 인터페이스에서 no ip mask-reply 설정",
        reference="NW 가이드 NW-37 (중) mask-reply 차단",
        logical_check_function = check_nw_37,
    ),

    "NW-38": SecurityRule(
        rule_id="NW-38",
        title="스위치, 허브 보안 강화",
        description="포트 보안을 설정하지 않을 경우 동일 네트워크 내에서 MAC flooding, ARP spoofing 공격으로 비인가자에게 패킷 정보가 제공될 수 있음",
        severity="중",
        category=RuleCategory.FUNCTION_MANAGEMENT,
        patterns=[
            # 스위치포트 액세스 모드인데 포트 시큐리티가 없는 경우
            r"interface\s+\S+\s*\n(?=.*switchport\s+mode\s+access)(?!.*port-security)",
        ],
        negative_patterns=[
            r"switchport\s+port-security",
            r"switchport\s+mode\s+trunk",  # 트렁크 포트는 제외
            r"switchport\s+voice\s+vlan",  # 음성 VLAN은 제외
        ],
        device_types=["Cisco", "스위치"],
        recommendation="스위치 포트 보안 설정(switchport port-security) 적용",
        reference="NW 가이드 NW-38 (중) 스위치, 허브 보안 강화",
        logical_check_function=check_nw_38,
    ),

    "NW-39": SecurityRule(
        rule_id="NW-39",
        title="환경설정 원격 로딩",
        description="네트워크 장비에서 재공하는 환경설정 정보를 원격으로 로딩하는 기능은 악의적인 웹 위험점 공격이나 장비 정보가 노출될 위험성이 있음",
        severity="중",
        category=RuleCategory.FUNCTION_MANAGEMENT,
        patterns=[
            r"service\s+config",
            r"boot\s+network",
            r"boot\s+host"
        ],
        negative_patterns=[
            r"no\s+service\s+config",
            r"no\s+boot\s+network",
            r"no\s+boot\s+host"
        ],
        device_types=["Cisco"],
        recommendation="환경설정 원격 로딩 기능을 일반적으로 사용하지 않으므로 제거",
        reference="NW 가이드 NW-39 (중) 환경설정 원격 로딩",
        logical_check_function = check_nw_39,
    ),

    "NW-40": SecurityRule(
        rule_id="NW-40",
        title="동적 라우팅 프로토콜 인증 여부",
        description="동적 라우팅 프로토콜을 사용할 때 안전한 인증절차가 구현되지 않을 경우 비인가가 비인가 단말로 네트워크 효율을 조작하여 가용성을 침해할 수 있음",
        severity="중",
        category=RuleCategory.FUNCTION_MANAGEMENT,
        patterns=[
            r"router\s+(ospf|rip|eigrp|bgp)"
        ],
        negative_patterns=[
            r"authentication\s+message-digest",
            r"ip\s+ospf\s+message-digest-key"
        ],
        device_types=["Cisco", "HP", "Alteon", "Alcatel", "Piolink", "Extreme", "Dasan", "한드림넷"],
        recommendation="동적 라우팅 프로토콜에서 MD5 또는 다른 인증 방식 설정",
        reference="NW 가이드 NW-40 (중) 동적 라우팅 프로토콜 인증 여부",
        logical_check_function=check_nw_40,
    ),

    "NW-41": SecurityRule(
        rule_id="NW-41",
        title="네트워크 장비 백업 관리",
        description="장애, 가동중지, 위험점, 해킹 등으로 인한 세계/장비 중단에 대비해 백업을 시행하고, 안전하게 보관해야 한다",
        severity="중",
        category=RuleCategory.PATCH_MANAGEMENT,
        patterns=[],
        negative_patterns=[],
        device_types=["All"],
        recommendation="백업 방법 및 절차가 수립되어 있는지 확인하고, 중요자료의 경우 물리적 피해에도 백업자료가 안전할 수 있도록 떨어진 장소에 보관해야 한다",
        reference="NW 가이드 NW-41 (중) 네트워크 장비 백업 관리",
        logical_check_function=check_nw_41,
    ),

    "NW-42": SecurityRule(
        rule_id="NW-42",
        title="무선랜 통제대책 수립",
        description="무선 LAN은 유선 LAN보다 비인가 단말을 통한 침몰하지 않는 통신 데이터 도청, 악의적 접근에 취약하다",
        severity="상",
        category=RuleCategory.ACCESS_MANAGEMENT,
        patterns=[
            r"wireless\s+security\s+wep",
            r"encryption\s+wep"
        ],
        negative_patterns=[
            r"encryption\s+wpa2",
            r"authentication\s+wpa2"
        ],
        device_types=["Cisco", "무선장비"],
        recommendation="무선 LAN 접근 시 보호 대책(인증 서버, WIPS)을 강구하고, 무선 구간을 보호한다",
        reference="NW 가이드 NW-42 (상) 무선랜 통제대책 수립",
        logical_check_function=check_nw_42,
    ),
}

# 기존 호환성을 위한 별칭
COMPLETE_ENHANCED_NW_RULES = NW_RULES
NW_SECURITY_RULES = NW_RULES
ENHANCED_NW_SECURITY_RULES = NW_RULES