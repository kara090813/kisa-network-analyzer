# -*- coding: utf-8 -*-
"""
rules/cis_rules.py
CIS Cisco IOS 12 Benchmark v4.0.0 보안 점검 룰셋 정의

CIS 가이드 기반 보안 룰들의 정의만 포함
logical_check_function은 checks_cis.py에서 import
"""

import re
from dataclasses import dataclass, field
from typing import List, Dict, Pattern, Callable, Optional, Any, Tuple
from enum import Enum

# KISA 룰셋에서 공통 클래스들 import
from .loader import (
    RuleCategory, ConfigContext, LogicalCondition, SecurityRule,
    parse_config_context
)


# ==================== CIS 룰셋 정의 ====================

# checks_cis.py에서 logical_check_function들 import
from .checks_cis import (
    check_cis_1_1_1,
    check_cis_1_1_2,
    check_cis_1_1_3,
    check_cis_1_1_4,
    check_cis_1_1_5,
    check_cis_1_1_6,
    check_cis_1_1_7,
    check_cis_1_1_8,
    check_cis_1_1_9,
    check_cis_1_1_10,
    check_cis_1_1_11,
    check_cis_2_1_1_1_1,
    check_cis_2_1_1_1_2,
    check_cis_2_1_1_1_3,
    check_cis_2_1_1_1_4,
    check_cis_2_1_1_1_5,
    check_cis_2_1_1_2,
    check_cis_2_1_2,
    check_cis_2_1_3,
    check_cis_2_1_4,
    check_cis_2_1_5,
    check_cis_2_1_6,
    check_cis_2_1_7,
    check_cis_2_1_8,
    check_cis_1_2_1,
    check_cis_1_2_4,
    check_cis_1_2_5,
    check_cis_1_3_1,
    check_cis_1_3_2,
    check_cis_1_3_3,
    check_cis_1_5_1,
    check_cis_1_5_6,
    check_cis_1_5_7,
    check_cis_2_2_2,
    check_cis_2_2_4,
    check_cis_2_2_7,
    check_cis_2_3_1_2,
    check_cis_2_3_1_3,
    check_cis_2_3_2,
    check_cis_2_4_1,
    check_cis_2_4_2,
    check_cis_3_1_2,
    check_cis_3_1_4,
    check_cis_3_2_1,
    check_cis_3_2_2,
    check_cis_3_3_1_1,
    check_cis_3_3_1_2,
    check_cis_3_3_1_3,
    check_cis_3_3_1_4,
    check_cis_3_3_1_5,
    check_cis_3_3_1_6,
    check_cis_3_3_1_7,
    check_cis_3_3_1_8,
    check_cis_3_3_1_9,
    check_cis_3_3_2_1,
    check_cis_3_3_2_2,
    check_cis_3_3_3_1,
    check_cis_3_3_3_2,
    check_cis_3_3_3_3,
    check_cis_3_3_3_4,
    check_cis_3_3_3_5,
    check_cis_3_3_4_1,
)

CIS_RULES = {
    # ======================= 1.1 Local Authentication, Authorization and Accounting (AAA) Rules =======================
    
    "CIS-1.1.1": SecurityRule(
        rule_id="CIS-1.1.1",
        title="Enable 'aaa new-model'",
        description="이 명령어는 AAA 접근 제어 시스템을 활성화합니다.",
        severity="상",
        category=RuleCategory.ACCOUNT_MANAGEMENT,
        patterns=[
            r"^(?!.*aaa\s+new-model).*$"  # aaa new-model이 없는 경우
        ],
        negative_patterns=[
            r"aaa\s+new-model"
        ],
        device_types=["Cisco"],
        recommendation="AAA 서비스를 활성화하기 위해 'aaa new-model' 명령어를 설정하세요",
        reference="CIS Cisco IOS 12 Benchmark v4.0.0 - 1.1.1 (Scored) Level 1",
        logical_check_function=check_cis_1_1_1,
        vulnerability_examples={
            "Cisco": [
                "! 설정에 aaa new-model이 없는 경우",
                "hostname(config)# show running-config | incl aaa new-model",
                "! (결과 없음)"
            ]
        },
        safe_examples={
            "Cisco": [
                "aaa new-model",
                "!"
            ]
        }
    ),
    
    "CIS-1.1.2": SecurityRule(
        rule_id="CIS-1.1.2",
        title="Enable 'aaa authentication login'",
        description="로그인 시 AAA 인증을 설정합니다.",
        severity="상",
        category=RuleCategory.ACCOUNT_MANAGEMENT,
        patterns=[
            r"^(?!.*aaa\s+authentication\s+login).*$"  # aaa authentication login이 없는 경우
        ],
        negative_patterns=[
            r"aaa\s+authentication\s+login\s+(default|[\w-]+)\s+"
        ],
        device_types=["Cisco"],
        recommendation="로그인 인증을 위해 'aaa authentication login default method1 [method2]' 명령어를 설정하세요",
        reference="CIS Cisco IOS 12 Benchmark v4.0.0 - 1.1.2 (Scored) Level 1",
        logical_check_function=check_cis_1_1_2,
        vulnerability_examples={
            "Cisco": [
                "! AAA 인증 로그인 설정이 없는 경우",
                "hostname# show run | incl aaa authentication login",
                "! (결과 없음)"
            ]
        },
        safe_examples={
            "Cisco": [
                "aaa authentication login default group tacacs+ local",
                "aaa authentication login CONSOLE local"
            ]
        }
    ),
    
    "CIS-1.1.3": SecurityRule(
        rule_id="CIS-1.1.3",
        title="Enable 'aaa authentication enable default'",
        description="enable 명령어 사용 시 특권 EXEC 모드에 접근하는 사용자를 인증합니다.",
        severity="상",
        category=RuleCategory.ACCOUNT_MANAGEMENT,
        patterns=[
            r"^(?!.*aaa\s+authentication\s+enable).*$"  # aaa authentication enable이 없는 경우
        ],
        negative_patterns=[
            r"aaa\s+authentication\s+enable\s+default\s+"
        ],
        device_types=["Cisco"],
        recommendation="특권 모드 인증을 위해 'aaa authentication enable default method1 enable' 명령어를 설정하세요",
        reference="CIS Cisco IOS 12 Benchmark v4.0.0 - 1.1.3 (Scored) Level 1",
        logical_check_function=check_cis_1_1_3,
        vulnerability_examples={
            "Cisco": [
                "! enable 인증 설정이 없는 경우",
                "hostname# show running-config | incl aaa authentication enable",
                "! (결과 없음)"
            ]
        },
        safe_examples={
            "Cisco": [
                "aaa authentication enable default group tacacs+ enable",
                "aaa authentication enable default local enable"
            ]
        }
    ),
    
    "CIS-1.1.4": SecurityRule(
        rule_id="CIS-1.1.4",
        title="Set 'login authentication for 'line con 0'",
        description="콘솔 포트를 통해 라우터나 스위치에 접근하는 사용자를 인증합니다.",
        severity="상",
        category=RuleCategory.ACCESS_MANAGEMENT,
        patterns=[
            r"line\s+con\s+0.*(?:\n(?!.*login\s+authentication).*)*"
        ],
        negative_patterns=[
            r"line\s+con\s+0.*\n.*login\s+authentication\s+(default|[\w-]+)"
        ],
        device_types=["Cisco"],
        recommendation="콘솔 라인에 'login authentication default' 또는 명명된 AAA 인증 목록을 설정하세요",
        reference="CIS Cisco IOS 12 Benchmark v4.0.0 - 1.1.4 (Scored) Level 1",
        logical_check_function=check_cis_1_1_4,
        vulnerability_examples={
            "Cisco": [
                "line con 0",
                " password cisco",
                " login",
                "! (login authentication 설정 없음)"
            ]
        },
        safe_examples={
            "Cisco": [
                "line con 0",
                " login authentication default",
                " exec-timeout 5 0"
            ]
        }
    ),
    
    "CIS-1.1.5": SecurityRule(
        rule_id="CIS-1.1.5",
        title="Set 'login authentication for 'line tty'",
        description="TTY 포트를 통해 라우터나 스위치에 접근하는 사용자를 인증합니다.",
        severity="상",
        category=RuleCategory.ACCESS_MANAGEMENT,
        patterns=[
            r"line\s+tty.*(?:\n(?!.*login\s+authentication).*)*"
        ],
        negative_patterns=[
            r"line\s+tty.*\n.*login\s+authentication\s+(default|[\w-]+)"
        ],
        device_types=["Cisco"],
        recommendation="TTY 라인에 'login authentication default' 또는 명명된 AAA 인증 목록을 설정하세요",
        reference="CIS Cisco IOS 12 Benchmark v4.0.0 - 1.1.5 (Scored) Level 1",
        logical_check_function=check_cis_1_1_5,
        vulnerability_examples={
            "Cisco": [
                "line tty 1 4",
                " password cisco",
                " login",
                "! (login authentication 설정 없음)"
            ]
        },
        safe_examples={
            "Cisco": [
                "line tty 1 4",
                " login authentication default",
                " exec-timeout 5 0"
            ]
        }
    ),
    
    "CIS-1.1.6": SecurityRule(
        rule_id="CIS-1.1.6",
        title="Set 'login authentication for 'line vty'",
        description="VTY 포트를 통해 원격으로 라우터나 스위치에 접근하는 사용자를 인증합니다.",
        severity="상",
        category=RuleCategory.ACCESS_MANAGEMENT,
        patterns=[
            r"line\s+vty.*(?:\n(?!.*login\s+authentication).*)*"
        ],
        negative_patterns=[
            r"line\s+vty.*\n.*login\s+authentication\s+(default|[\w-]+)"
        ],
        device_types=["Cisco"],
        recommendation="VTY 라인에 'login authentication default' 또는 명명된 AAA 인증 목록을 설정하세요",
        reference="CIS Cisco IOS 12 Benchmark v4.0.0 - 1.1.6 (Scored) Level 1",
        logical_check_function=check_cis_1_1_6,
        vulnerability_examples={
            "Cisco": [
                "line vty 0 4",
                " password cisco",
                " login",
                "! (login authentication 설정 없음)"
            ]
        },
        safe_examples={
            "Cisco": [
                "line vty 0 4",
                " login authentication default",
                " transport input ssh",
                " access-class 10 in"
            ]
        }
    ),
    
    "CIS-1.1.7": SecurityRule(
        rule_id="CIS-1.1.7",
        title="Set 'aaa accounting' to log all privileged use commands using 'commands 15'",
        description="지정된 권한 레벨의 모든 명령어에 대한 계정 추적을 실행합니다.",
        severity="중",
        category=RuleCategory.LOG_MANAGEMENT,
        patterns=[
            r"^(?!.*aaa\s+accounting\s+commands\s+15).*$"
        ],
        negative_patterns=[
            r"aaa\s+accounting\s+commands\s+15\s+"
        ],
        device_types=["Cisco"],
        recommendation="권한 명령어 추적을 위해 'aaa accounting commands 15 default start-stop group tacacs+' 명령어를 설정하세요",
        reference="CIS Cisco IOS 12 Benchmark v4.0.0 - 1.1.7 (Scored) Level 2",
        logical_check_function=check_cis_1_1_7,
        vulnerability_examples={
            "Cisco": [
                "! AAA accounting commands 15 설정이 없는 경우",
                "hostname# sh run | incl aaa accounting commands",
                "! (결과 없음)"
            ]
        },
        safe_examples={
            "Cisco": [
                "aaa accounting commands 15 default start-stop group tacacs+",
                "aaa accounting commands 15 default start-stop group radius"
            ]
        }
    ),
    
    "CIS-1.1.8": SecurityRule(
        rule_id="CIS-1.1.8",
        title="Set 'aaa accounting connection'",
        description="네트워크 접근 서버로부터의 모든 아웃바운드 연결에 대한 정보를 제공합니다.",
        severity="중",
        category=RuleCategory.LOG_MANAGEMENT,
        patterns=[
            r"^(?!.*aaa\s+accounting\s+connection).*$"
        ],
        negative_patterns=[
            r"aaa\s+accounting\s+connection\s+"
        ],
        device_types=["Cisco"],
        recommendation="연결 추적을 위해 'aaa accounting connection default start-stop group tacacs+' 명령어를 설정하세요",
        reference="CIS Cisco IOS 12 Benchmark v4.0.0 - 1.1.8 (Scored) Level 2",
        logical_check_function=check_cis_1_1_8,
        vulnerability_examples={
            "Cisco": [
                "! AAA accounting connection 설정이 없는 경우",
                "hostname# sh run | incl aaa accounting connection",
                "! (결과 없음)"
            ]
        },
        safe_examples={
            "Cisco": [
                "aaa accounting connection default start-stop group tacacs+",
                "aaa accounting connection default start-stop group radius"
            ]
        }
    ),
    
    "CIS-1.1.9": SecurityRule(
        rule_id="CIS-1.1.9",
        title="Set 'aaa accounting exec'",
        description="EXEC 셸 세션에 대한 계정 추적을 실행합니다.",
        severity="중",
        category=RuleCategory.LOG_MANAGEMENT,
        patterns=[
            r"^(?!.*aaa\s+accounting\s+exec).*$"
        ],
        negative_patterns=[
            r"aaa\s+accounting\s+exec\s+"
        ],
        device_types=["Cisco"],
        recommendation="EXEC 세션 추적을 위해 'aaa accounting exec default start-stop group tacacs+' 명령어를 설정하세요",
        reference="CIS Cisco IOS 12 Benchmark v4.0.0 - 1.1.9 (Scored) Level 2",
        logical_check_function=check_cis_1_1_9,
        vulnerability_examples={
            "Cisco": [
                "! AAA accounting exec 설정이 없는 경우",
                "hostname# sh run | incl aaa accounting exec",
                "! (결과 없음)"
            ]
        },
        safe_examples={
            "Cisco": [
                "aaa accounting exec default start-stop group tacacs+",
                "aaa accounting exec default start-stop group radius"
            ]
        }
    ),
    
    "CIS-1.1.10": SecurityRule(
        rule_id="CIS-1.1.10",
        title="Set 'aaa accounting network'",
        description="모든 네트워크 관련 서비스 요청에 대한 계정 추적을 실행합니다.",
        severity="중",
        category=RuleCategory.LOG_MANAGEMENT,
        patterns=[
            r"^(?!.*aaa\s+accounting\s+network).*$"
        ],
        negative_patterns=[
            r"aaa\s+accounting\s+network\s+"
        ],
        device_types=["Cisco"],
        recommendation="네트워크 서비스 추적을 위해 'aaa accounting network default start-stop group tacacs+' 명령어를 설정하세요",
        reference="CIS Cisco IOS 12 Benchmark v4.0.0 - 1.1.10 (Scored) Level 2",
        logical_check_function=check_cis_1_1_10,
        vulnerability_examples={
            "Cisco": [
                "! AAA accounting network 설정이 없는 경우",
                "hostname# sh run | incl aaa accounting network",
                "! (결과 없음)"
            ]
        },
        safe_examples={
            "Cisco": [
                "aaa accounting network default start-stop group tacacs+",
                "aaa accounting network default start-stop group radius"
            ]
        }
    ),
    
    "CIS-1.1.11": SecurityRule(
        rule_id="CIS-1.1.11",
        title="Set 'aaa accounting system'",
        description="사용자와 관련이 없는 모든 시스템 레벨 이벤트(재부팅 등)에 대한 계정 추적을 수행합니다.",
        severity="중",
        category=RuleCategory.LOG_MANAGEMENT,
        patterns=[
            r"^(?!.*aaa\s+accounting\s+system).*$"
        ],
        negative_patterns=[
            r"aaa\s+accounting\s+system\s+"
        ],
        device_types=["Cisco"],
        recommendation="시스템 이벤트 추적을 위해 'aaa accounting system default start-stop group tacacs+' 명령어를 설정하세요",
        reference="CIS Cisco IOS 12 Benchmark v4.0.0 - 1.1.11 (Scored) Level 2",
        logical_check_function=check_cis_1_1_11,
        vulnerability_examples={
            "Cisco": [
                "! AAA accounting system 설정이 없는 경우",
                "hostname# sh run | incl aaa accounting system",
                "! (결과 없음)"
            ]
        },
        safe_examples={
            "Cisco": [
                "aaa accounting system default start-stop group tacacs+",
                "aaa accounting system default start-stop group radius"
            ]
        }
    ),

    # ======================= 1.2 Access Rules (누락분) =======================

"CIS-1.2.1": SecurityRule(
    rule_id="CIS-1.2.1",
    title="Set 'privilege 1' for local users",
    description="Sets the privilege level for the user to level 1 (EXEC-level permissions only)",
    severity="상",
    category=RuleCategory.ACCESS_MANAGEMENT,
    patterns=[
        r"username\s+\w+\s+privilege\s+(?:[2-9]|1[0-5])\s"  # 🔥 단순화된 패턴
    ],
    negative_patterns=[
        r"username\s+\w+\s+privilege\s+1\s"
    ],
    device_types=["Cisco"],
    recommendation="Set all local users to privilege level 1: username <username> privilege 1",
    reference="CIS Cisco IOS 12 Benchmark v4.0.0 - 1.2.1",
    logical_check_function=check_cis_1_2_1,
),

"CIS-1.2.2": SecurityRule(
    rule_id="CIS-1.2.2", 
    title="Set 'transport input ssh' for 'line vty' connections",
    description="Selects only the SSH protocol for VTY access",
    severity="상",
    category=RuleCategory.ACCESS_MANAGEMENT,
    patterns=[
        r"line\s+vty.*?transport\s+input\s+(?!ssh\s*$)\w+",
        r"line\s+vty.*?transport\s+input\s+all"
    ],
    negative_patterns=[
        r"line\s+vty.*?transport\s+input\s+ssh\s*$"
    ],
    device_types=["Cisco"],
    recommendation="Configure VTY lines to only accept SSH: transport input ssh",
    reference="CIS Cisco IOS 12 Benchmark v4.0.0 - 1.2.2",
),

"CIS-1.2.3": SecurityRule(
    rule_id="CIS-1.2.3",
    title="Set 'no exec' for 'line aux 0'", 
    description="Restricts auxiliary line to outgoing connections only",
    severity="상",
    category=RuleCategory.ACCESS_MANAGEMENT,
    patterns=[
        r"line\s+aux\s+0(?!.*no\s+exec)"
    ],
    negative_patterns=[
        r"line\s+aux\s+0.*no\s+exec"
    ],
    device_types=["Cisco"],
    recommendation="Disable EXEC process on auxiliary port: line aux 0 -> no exec",
    reference="CIS Cisco IOS 12 Benchmark v4.0.0 - 1.2.3",
),

"CIS-1.2.4": SecurityRule(
    rule_id="CIS-1.2.4",
    title="Create 'access-list' for use with 'line vty'",
    description="Create access list to control VTY access from specific hosts/networks",
    severity="상", 
    category=RuleCategory.ACCESS_MANAGEMENT,
    patterns=[],
    negative_patterns=[
        r"access-list\s+\d+\s+permit.*any"
    ],
    device_types=["Cisco"],
    recommendation="Create and apply access-list to restrict VTY access to authorized management stations",
    reference="CIS Cisco IOS 12 Benchmark v4.0.0 - 1.2.4",
    logical_check_function=check_cis_1_2_4,
),

"CIS-1.2.5": SecurityRule(
    rule_id="CIS-1.2.5",
    title="Set 'access-class' for 'line vty'",
    description="Restricts VTY connections using access list",
    severity="상",
    category=RuleCategory.ACCESS_MANAGEMENT,
    patterns=[
        r"line\s+vty(?!.*access-class)"
    ],
    negative_patterns=[
        r"line\s+vty.*access-class\s+\d+\s+in"
    ],
    device_types=["Cisco"],
    recommendation="Apply access-class to VTY lines: access-class <acl_number> in",
    reference="CIS Cisco IOS 12 Benchmark v4.0.0 - 1.2.5",
    logical_check_function=check_cis_1_2_5,
),

"CIS-1.2.6": SecurityRule(
    rule_id="CIS-1.2.6",
    title="Set 'exec-timeout' to less than or equal to 10 minutes for 'line aux 0'",
    description="Sets session timeout for auxiliary line",
    severity="상",
    category=RuleCategory.ACCESS_MANAGEMENT,
    patterns=[
        r"line\s+aux\s+0.*exec-timeout\s+([1-9][1-9]|[6-9][0-9])",
        r"line\s+aux\s+0.*exec-timeout\s+0\s+0"
    ],
    negative_patterns=[
        r"line\s+aux\s+0.*exec-timeout\s+([1-9]|10)\s+[0-5]?[0-9]?"
    ],
    device_types=["Cisco"],
    recommendation="Set exec-timeout to 10 minutes or less: exec-timeout 10 0",
    reference="CIS Cisco IOS 12 Benchmark v4.0.0 - 1.2.6",
),

"CIS-1.2.7": SecurityRule(
    rule_id="CIS-1.2.7",
    title="Set 'exec-timeout' to less than or equal to 10 minutes for 'line console 0'",
    description="Sets session timeout for console line",
    severity="상",
    category=RuleCategory.ACCESS_MANAGEMENT,
    patterns=[
        r"line\s+con(?:sole)?\s+0.*exec-timeout\s+([1-9][1-9]|[6-9][0-9])",
        r"line\s+con(?:sole)?\s+0.*exec-timeout\s+0\s+0"
    ],
    negative_patterns=[
        r"line\s+con(?:sole)?\s+0.*exec-timeout\s+([1-9]|10)\s+[0-5]?[0-9]?"
    ],
    device_types=["Cisco"],
    recommendation="Set exec-timeout to 10 minutes or less: exec-timeout 10 0",
    reference="CIS Cisco IOS 12 Benchmark v4.0.0 - 1.2.7",
),

"CIS-1.2.8": SecurityRule(
    rule_id="CIS-1.2.8",
    title="Set 'exec-timeout' less than or equal to 10 minutes for 'line tty'",
    description="Sets session timeout for TTY lines",
    severity="상",
    category=RuleCategory.ACCESS_MANAGEMENT,
    patterns=[
        r"line\s+tty.*exec-timeout\s+([1-9][1-9]|[6-9][0-9])",
        r"line\s+tty.*exec-timeout\s+0\s+0"
    ],
    negative_patterns=[
        r"line\s+tty.*exec-timeout\s+([1-9]|10)\s+[0-5]?[0-9]?"
    ],
    device_types=["Cisco"],
    recommendation="Set exec-timeout to 10 minutes or less: exec-timeout 10 0",
    reference="CIS Cisco IOS 12 Benchmark v4.0.0 - 1.2.8",
),

"CIS-1.2.9": SecurityRule(
    rule_id="CIS-1.2.9",
    title="Set 'exec-timeout' to less than or equal to 10 minutes for 'line vty'",
    description="Sets session timeout for VTY lines",
    severity="상", 
    category=RuleCategory.ACCESS_MANAGEMENT,
    patterns=[
        r"line\s+vty.*exec-timeout\s+([1-9][1-9]|[6-9][0-9])",
        r"line\s+vty.*exec-timeout\s+0\s+0"
    ],
    negative_patterns=[
        r"line\s+vty.*exec-timeout\s+([1-9]|10)\s+[0-5]?[0-9]?"
    ],
    device_types=["Cisco"],
    recommendation="Set exec-timeout to 10 minutes or less: exec-timeout 10 0",
    reference="CIS Cisco IOS 12 Benchmark v4.0.0 - 1.2.9",
),

"CIS-1.2.10": SecurityRule(
    rule_id="CIS-1.2.10",
    title="Set 'transport input none' for 'line aux 0'",
    description="Disables inbound connections on auxiliary port",
    severity="상",
    category=RuleCategory.ACCESS_MANAGEMENT,
    patterns=[
        r"line\s+aux\s+0(?!.*transport\s+input\s+none)"
    ],
    negative_patterns=[
        r"line\s+aux\s+0.*transport\s+input\s+none"
    ],
    device_types=["Cisco"],
    recommendation="Disable inbound connections: transport input none",
    reference="CIS Cisco IOS 12 Benchmark v4.0.0 - 1.2.10",
),

# ======================= 1.3 Banner Rules =======================

"CIS-1.3.1": SecurityRule(
    rule_id="CIS-1.3.1",
    title="Set the 'banner-text' for 'banner exec'",
    description="Specifies a message to be displayed when an EXEC process is created",
    severity="중",
    category=RuleCategory.ACCESS_MANAGEMENT,
    patterns=[
        r"^(?!.*banner\s+exec).*$"  # 🔥 패턴 추가
    ],
    negative_patterns=[
        r"banner\s+exec\s+\S"
    ],
    device_types=["Cisco"],
    recommendation="Configure EXEC banner: banner exec c <banner-text> c",
    reference="CIS Cisco IOS 12 Benchmark v4.0.0 - 1.3.1",
    logical_check_function=check_cis_1_3_1,
),

"CIS-1.3.2": SecurityRule(
    rule_id="CIS-1.3.2",
    title="Set the 'banner-text' for 'banner login'",
    description="Configures login banner presented to users attempting to access device",
    severity="중",
    category=RuleCategory.ACCESS_MANAGEMENT,
    patterns=[
        r"^(?!.*banner\s+login).*$"  # 🔥 패턴 추가
    ],
    negative_patterns=[
        r"banner\s+login\s+\S"
    ],
    device_types=["Cisco"],
    recommendation="Configure login banner: banner login c <banner-text> c",
    reference="CIS Cisco IOS 12 Benchmark v4.0.0 - 1.3.2",
    logical_check_function=check_cis_1_3_2,
),

"CIS-1.3.3": SecurityRule(
    rule_id="CIS-1.3.3",
    title="Set the 'banner-text' for 'banner motd'",
    description="Configures message of the day banner",
    severity="중",
    category=RuleCategory.ACCESS_MANAGEMENT,
    patterns=[
        r"^(?!.*banner\s+motd).*$"  # 🔥 패턴 추가
    ],
    negative_patterns=[
        r"banner\s+motd\s+\S"
    ],
    device_types=["Cisco"],
    recommendation="Configure MOTD banner: banner motd c <banner-text> c",
    reference="CIS Cisco IOS 12 Benchmark v4.0.0 - 1.3.3",
    logical_check_function=check_cis_1_3_3,
),

# ======================= 1.4 Password Rules =======================

"CIS-1.4.1": SecurityRule(
    rule_id="CIS-1.4.1",
    title="Set 'password' for 'enable secret'",
    description="Use enable secret command for additional security layer",
    severity="상",
    category=RuleCategory.ACCOUNT_MANAGEMENT,
    patterns=[
        r"enable\s+password\s+\w+"
    ],
    negative_patterns=[
        r"enable\s+secret\s+\S+"
    ],
    device_types=["Cisco"],
    recommendation="Use enable secret instead of enable password: enable secret <password>",
    reference="CIS Cisco IOS 12 Benchmark v4.0.0 - 1.4.1",
),

"CIS-1.4.2": SecurityRule(
    rule_id="CIS-1.4.2",
    title="Enable 'service password-encryption'",
    description="Encrypts passwords in configuration file",
    severity="상", 
    category=RuleCategory.ACCOUNT_MANAGEMENT,
    patterns=[
        r"no\s+service\s+password-encryption"
    ],
    negative_patterns=[
        r"service\s+password-encryption"
    ],
    device_types=["Cisco"],
    recommendation="Enable password encryption: service password-encryption",
    reference="CIS Cisco IOS 12 Benchmark v4.0.0 - 1.4.2",
),

"CIS-1.4.3": SecurityRule(
    rule_id="CIS-1.4.3",
    title="Set 'username secret' for all local users",
    description="Configure username with MD5-encrypted password",
    severity="상",
    category=RuleCategory.ACCOUNT_MANAGEMENT,
    patterns=[
        r"username\s+\w+\s+password\s+\w+"
    ],
    negative_patterns=[
        r"username\s+\w+\s+secret\s+\S+"
    ],
    device_types=["Cisco"],
    recommendation="Use username secret: username <user> secret <password>",
    reference="CIS Cisco IOS 12 Benchmark v4.0.0 - 1.4.3",
),

# ======================= 1.5 SNMP Rules =======================

"CIS-1.5.1": SecurityRule(
    rule_id="CIS-1.5.1",
    title="Set 'no snmp-server' to disable SNMP when unused",
    description="Disables SNMP when not required",
    severity="상",
    category=RuleCategory.FUNCTION_MANAGEMENT,
    patterns=[
        r"snmp-server\s+community",
        r"snmp-server\s+enable"
    ],
    negative_patterns=[
        r"no\s+snmp-server"
    ],
    device_types=["Cisco"],
    recommendation="Disable SNMP if not used: no snmp-server",
    reference="CIS Cisco IOS 12 Benchmark v4.0.0 - 1.5.1",
    logical_check_function=check_cis_1_5_1,
),

"CIS-1.5.2": SecurityRule(
    rule_id="CIS-1.5.2",
    title="Unset 'private' for 'snmp-server community'",
    description="Remove default 'private' community string",
    severity="상",
    category=RuleCategory.FUNCTION_MANAGEMENT,
    patterns=[
        r"snmp-server\s+community\s+private"
    ],
    negative_patterns=[
        r"no\s+snmp-server\s+community\s+private"
    ],
    device_types=["Cisco"],
    recommendation="Remove default community: no snmp-server community private",
    reference="CIS Cisco IOS 12 Benchmark v4.0.0 - 1.5.2",
),

"CIS-1.5.3": SecurityRule(
    rule_id="CIS-1.5.3",
    title="Unset 'public' for 'snmp-server community'",
    description="Remove default 'public' community string",
    severity="상",
    category=RuleCategory.FUNCTION_MANAGEMENT,
    patterns=[
        r"snmp-server\s+community\s+public"
    ],
    negative_patterns=[
        r"no\s+snmp-server\s+community\s+public"
    ],
    device_types=["Cisco"],
    recommendation="Remove default community: no snmp-server community public",
    reference="CIS Cisco IOS 12 Benchmark v4.0.0 - 1.5.3",
),

"CIS-1.5.4": SecurityRule(
    rule_id="CIS-1.5.4",
    title="Do not set 'RW' for any 'snmp-server community'",
    description="Prevents SNMP write access",
    severity="상",
    category=RuleCategory.FUNCTION_MANAGEMENT,
    patterns=[
        r"snmp-server\s+community\s+\S+\s+rw"
    ],
    negative_patterns=[
        r"snmp-server\s+community\s+\S+\s+ro"
    ],
    device_types=["Cisco"],
    recommendation="Use read-only SNMP communities: snmp-server community <string> ro",
    reference="CIS Cisco IOS 12 Benchmark v4.0.0 - 1.5.4",
),

"CIS-1.5.5": SecurityRule(
    rule_id="CIS-1.5.5",
    title="Set the ACL for each 'snmp-server community'",
    description="Apply access list to SNMP community strings",
    severity="상",
    category=RuleCategory.FUNCTION_MANAGEMENT,
    patterns=[
        r"snmp-server\s+community\s+\S+\s+ro(?!\s+\d+)"
    ],
    negative_patterns=[
        r"snmp-server\s+community\s+\S+\s+ro\s+\d+"
    ],
    device_types=["Cisco"],
    recommendation="Apply ACL to SNMP communities: snmp-server community <string> ro <acl>",
    reference="CIS Cisco IOS 12 Benchmark v4.0.0 - 1.5.5",
),

"CIS-1.5.6": SecurityRule(
    rule_id="CIS-1.5.6",
    title="Create an 'access-list' for use with SNMP",
    description="Create access list to restrict SNMP access",
    severity="상",
    category=RuleCategory.FUNCTION_MANAGEMENT,
    patterns=[],
    negative_patterns=[],
    device_types=["Cisco"],
    recommendation="Create SNMP access list to restrict management station access",
    reference="CIS Cisco IOS 12 Benchmark v4.0.0 - 1.5.6",
    logical_check_function=check_cis_1_5_6,
),

"CIS-1.5.7": SecurityRule(
    rule_id="CIS-1.5.7",
    title="Set 'snmp-server host' when using SNMP",
    description="Configure SNMP trap recipients",
    severity="중",
    category=RuleCategory.FUNCTION_MANAGEMENT,
    patterns=[],
    negative_patterns=[
        r"snmp-server\s+host\s+\d+\.\d+\.\d+\.\d+"
    ],
    device_types=["Cisco"],
    recommendation="Configure SNMP trap hosts: snmp-server host <ip> <community>",
    reference="CIS Cisco IOS 12 Benchmark v4.0.0 - 1.5.7",
    logical_check_function=check_cis_1_5_7,
),

"CIS-1.5.8": SecurityRule(
    rule_id="CIS-1.5.8",
    title="Set 'snmp-server enable traps snmp'",
    description="Enable SNMP traps",
    severity="중",
    category=RuleCategory.FUNCTION_MANAGEMENT,
    patterns=[],
    negative_patterns=[
        r"snmp-server\s+enable\s+traps\s+snmp"
    ],
    device_types=["Cisco"],
    recommendation="Enable SNMP traps: snmp-server enable traps snmp",
    reference="CIS Cisco IOS 12 Benchmark v4.0.0 - 1.5.8",
),

"CIS-1.5.9": SecurityRule(
    rule_id="CIS-1.5.9",
    title="Set 'priv' for each 'snmp-server group' using SNMPv3",
    description="Configure SNMPv3 groups with privacy",
    severity="중",
    category=RuleCategory.FUNCTION_MANAGEMENT,
    patterns=[
        r"snmp-server\s+group\s+\S+\s+v3\s+(?!priv)"
    ],
    negative_patterns=[
        r"snmp-server\s+group\s+\S+\s+v3\s+priv"
    ],
    device_types=["Cisco"],
    recommendation="Use privacy for SNMPv3 groups: snmp-server group <group> v3 priv",
    reference="CIS Cisco IOS 12 Benchmark v4.0.0 - 1.5.9",
),

"CIS-1.5.10": SecurityRule(
    rule_id="CIS-1.5.10",
    title="Require 'aes 128' as minimum for 'snmp-server user' when using SNMPv3",
    description="Use minimum AES 128 encryption for SNMPv3 users",
    severity="중",
    category=RuleCategory.FUNCTION_MANAGEMENT,
    patterns=[
        r"snmp-server\s+user\s+\S+\s+\S+\s+v3.*priv\s+(?!aes\s+128)"
    ],
    negative_patterns=[
        r"snmp-server\s+user\s+\S+\s+\S+\s+v3.*priv\s+aes\s+128"
    ],
    device_types=["Cisco"],
    recommendation="Use AES 128 minimum: snmp-server user <user> <group> v3 auth sha <auth> priv aes 128 <priv>",
    reference="CIS Cisco IOS 12 Benchmark v4.0.0 - 1.5.10",
),
    # ======================= 2.1 Global Service Rules =======================
    
    "CIS-2.1.1.1.1": SecurityRule(
        rule_id="CIS-2.1.1.1.1",
        title="Set the 'hostname'",
        description="라우터의 호스트명을 설정합니다. SSH 서비스 구성을 위한 전제 조건입니다.",
        severity="중",
        category=RuleCategory.FUNCTION_MANAGEMENT,
        patterns=[
            r"^hostname\s+Router\s*$",  # 기본 호스트명 사용
            r"^(?!.*hostname\s+).*$"   # 호스트명 설정 없음
        ],
        negative_patterns=[
            r"hostname\s+(?!Router\s*$)\S+"  # Router가 아닌 다른 호스트명
        ],
        device_types=["Cisco"],
        recommendation="적절한 호스트명을 설정하세요: hostname {router_name}",
        reference="CIS Cisco IOS 12 Benchmark v4.0.0 - 2.1.1.1.1 (Scored) Level 1",
        logical_check_function=check_cis_2_1_1_1_1,
        vulnerability_examples={
            "Cisco": [
                "hostname Router",
                "! 또는 호스트명 설정이 없는 경우"
            ]
        },
        safe_examples={
            "Cisco": [
                "hostname CORP-RTR-01",
                "hostname BRANCH-ROUTER"
            ]
        }
    ),
    
    "CIS-2.1.1.1.2": SecurityRule(
        rule_id="CIS-2.1.1.1.2",
        title="Set the 'ip domain name'",
        description="Cisco IOS 소프트웨어가 비정규화된 호스트명을 완성하는 데 사용할 기본 도메인명을 정의합니다. SSH 서비스 구성을 위한 전제 조건입니다.",
        severity="중",
        category=RuleCategory.FUNCTION_MANAGEMENT,
        patterns=[
            r"^(?!.*ip\s+domain\s+name).*$"  # ip domain name 설정 없음
        ],
        negative_patterns=[
            r"ip\s+domain\s+name\s+\S+"
        ],
        device_types=["Cisco"],
        recommendation="적절한 도메인명을 설정하세요: ip domain name {domain-name}",
        reference="CIS Cisco IOS 12 Benchmark v4.0.0 - 2.1.1.1.2 (Scored) Level 1",
        logical_check_function=check_cis_2_1_1_1_2,
        vulnerability_examples={
            "Cisco": [
                "! ip domain name 설정이 없는 경우",
                "hostname# sh run | incl domain name",
                "! (결과 없음)"
            ]
        },
        safe_examples={
            "Cisco": [
                "ip domain name example.com",
                "ip domain name corp.local"
            ]
        }
    ),
    
    "CIS-2.1.1.1.3": SecurityRule(
        rule_id="CIS-2.1.1.1.3",
        title="Set 'modulus' to greater than or equal to 2048 for 'crypto key generate rsa'",
        description="Cisco 장비용 RSA 키 쌍을 생성합니다. RSA 키는 쌍으로 생성되며 최소 2048비트여야 합니다.",
        severity="상",
        category=RuleCategory.FUNCTION_MANAGEMENT,
        patterns=[
            r"^(?!.*crypto\s+key\s+mypubkey\s+rsa).*$"  # RSA 키가 생성되지 않음
        ],
        negative_patterns=[
            r"crypto\s+key\s+generate\s+rsa.*modulus\s+(204[8-9]|20[5-9]\d|2[1-9]\d{2}|[3-9]\d{3}|\d{5,})"
        ],
        device_types=["Cisco"],
        recommendation="2048비트 이상의 RSA 키 쌍을 생성하세요: crypto key generate rsa general-keys modulus 2048",
        reference="CIS Cisco IOS 12 Benchmark v4.0.0 - 2.1.1.1.3 (Not Scored) Level 1",
        logical_check_function=check_cis_2_1_1_1_3,
        vulnerability_examples={
            "Cisco": [
                "! RSA 키가 생성되지 않은 경우",
                "hostname# sh crypto key mypubkey rsa",
                "% Key pair was never generated"
            ]
        },
        safe_examples={
            "Cisco": [
                "crypto key generate rsa general-keys modulus 2048",
                "crypto key generate rsa general-keys modulus 4096"
            ]
        }
    ),
    
    "CIS-2.1.1.1.4": SecurityRule(
        rule_id="CIS-2.1.1.1.4",
        title="Set 'seconds' for 'ip ssh timeout'",
        description="라우터가 SSH 클라이언트의 응답을 기다리는 시간 간격을 설정하여 완료되지 않은 로그인 시도를 끊습니다.",
        severity="중",
        category=RuleCategory.ACCESS_MANAGEMENT,
        patterns=[
            r"^(?!.*ip\s+ssh\s+time-out).*$"  # SSH timeout 설정 없음
        ],
        negative_patterns=[
            r"ip\s+ssh\s+time-out\s+[1-9]\d*"
        ],
        device_types=["Cisco"],
        recommendation="SSH 타임아웃을 설정하세요: ip ssh time-out 60",
        reference="CIS Cisco IOS 12 Benchmark v4.0.0 - 2.1.1.1.4 (Scored) Level 1",
        logical_check_function=check_cis_2_1_1_1_4,
        vulnerability_examples={
            "Cisco": [
                "! SSH 타임아웃 설정이 없는 경우",
                "hostname# sh ip ssh",
                "SSH Disabled - version 1.99"
            ]
        },
        safe_examples={
            "Cisco": [
                "ip ssh time-out 60",
                "ip ssh time-out 120"
            ]
        }
    ),
    
    "CIS-2.1.1.1.5": SecurityRule(
        rule_id="CIS-2.1.1.1.5",
        title="Set maximum value for 'ip ssh authentication-retries'",
        description="SSH 로그인 세션이 끊어지기 전까지의 재시도 횟수를 설정합니다.",
        severity="중",
        category=RuleCategory.ACCESS_MANAGEMENT,
        patterns=[
            r"^(?!.*ip\s+ssh\s+authentication-retries).*$"  # SSH authentication-retries 설정 없음
        ],
        negative_patterns=[
            r"ip\s+ssh\s+authentication-retries\s+[1-5]"
        ],
        device_types=["Cisco"],
        recommendation="SSH 인증 재시도 횟수를 제한하세요: ip ssh authentication-retries 3",
        reference="CIS Cisco IOS 12 Benchmark v4.0.0 - 2.1.1.1.5 (Scored) Level 1",
        logical_check_function=check_cis_2_1_1_1_5,
        vulnerability_examples={
            "Cisco": [
                "! SSH 인증 재시도 설정이 없는 경우",
                "hostname# sh ip ssh",
                "Authentication retries: 3 (default)"
            ]
        },
        safe_examples={
            "Cisco": [
                "ip ssh authentication-retries 3",
                "ip ssh authentication-retries 2"
            ]
        }
    ),
    
    "CIS-2.1.1.2": SecurityRule(
        rule_id="CIS-2.1.1.2",
        title="Set version 2 for 'ip ssh version'",
        description="라우터에서 실행할 SSH(Secure Shell) 버전을 지정합니다.",
        severity="상",
        category=RuleCategory.ACCESS_MANAGEMENT,
        patterns=[
            r"^(?!.*ip\s+ssh\s+version\s+2).*$"  # SSH version 2 설정 없음
        ],
        negative_patterns=[
            r"ip\s+ssh\s+version\s+2"
        ],
        device_types=["Cisco"],
        recommendation="SSH 버전 2를 사용하도록 설정하세요: ip ssh version 2",
        reference="CIS Cisco IOS 12 Benchmark v4.0.0 - 2.1.1.2 (Scored) Level 1",
        logical_check_function=check_cis_2_1_1_2,
        vulnerability_examples={
            "Cisco": [
                "! SSH 버전 2 설정이 없는 경우",
                "hostname# sh ip ssh",
                "SSH Enabled - version 1.99"
            ]
        },
        safe_examples={
            "Cisco": [
                "ip ssh version 2"
            ]
        }
    ),
    
    "CIS-2.1.2": SecurityRule(
        rule_id="CIS-2.1.2",
        title="Set 'no cdp run'",
        description="장비 레벨에서 Cisco Discovery Protocol (CDP) 서비스를 비활성화합니다.",
        severity="중",
        category=RuleCategory.FUNCTION_MANAGEMENT,
        patterns=[
            r"^(?!.*no\s+cdp\s+run).*$",
            r"cdp\s+run"  # 명시적 활성화도 취약
        ],
        negative_patterns=[
            r"no\s+cdp\s+run"
        ],
        device_types=["Cisco"],
        recommendation="CDP 서비스를 전역적으로 비활성화하세요: no cdp run",
        reference="CIS Cisco IOS 12 Benchmark v4.0.0 - 2.1.2 (Scored) Level 1",
        logical_check_function=check_cis_2_1_2,
        vulnerability_examples={
            "Cisco": [
                "cdp run",
                "! CDP가 활성화된 상태"
            ]
        },
        safe_examples={
            "Cisco": [
                "no cdp run"
            ]
        }
    ),
    
    "CIS-2.1.3": SecurityRule(
        rule_id="CIS-2.1.3",
        title="Set 'no ip bootp server'",
        description="라우팅 장비에서 Bootstrap Protocol (BOOTP) 서비스를 비활성화합니다.",
        severity="중",
        category=RuleCategory.FUNCTION_MANAGEMENT,
        patterns=[
            r"ip\s+bootp\s+server"
        ],
        negative_patterns=[
            r"no\s+ip\s+bootp\s+server"
        ],
        device_types=["Cisco"],
        recommendation="BOOTP 서버를 비활성화하세요: no ip bootp server",
        reference="CIS Cisco IOS 12 Benchmark v4.0.0 - 2.1.3 (Scored) Level 1",
        logical_check_function=check_cis_2_1_3,
        vulnerability_examples={
            "Cisco": [
                "ip bootp server",
                "! BOOTP 서버가 활성화된 상태"
            ]
        },
        safe_examples={
            "Cisco": [
                "no ip bootp server"
            ]
        }
    ),
    
    "CIS-2.1.4": SecurityRule(
        rule_id="CIS-2.1.4",
        title="Set 'no service dhcp'",
        description="라우터에서 Dynamic Host Configuration Protocol (DHCP) 서버 및 릴레이 에이전트 기능을 비활성화합니다.",
        severity="중",
        category=RuleCategory.FUNCTION_MANAGEMENT,
        patterns=[
            r"service\s+dhcp"
        ],
        negative_patterns=[
            r"no\s+service\s+dhcp"
        ],
        device_types=["Cisco"],
        recommendation="DHCP 서비스를 비활성화하세요: no service dhcp",
        reference="CIS Cisco IOS 12 Benchmark v4.0.0 - 2.1.4 (Scored) Level 1",
        logical_check_function=check_cis_2_1_4,
        vulnerability_examples={
            "Cisco": [
                "service dhcp",
                "! DHCP 서비스가 활성화된 상태"
            ]
        },
        safe_examples={
            "Cisco": [
                "no service dhcp"
            ]
        }
    ),
    
    "CIS-2.1.5": SecurityRule(
        rule_id="CIS-2.1.5",
        title="Set 'no ip identd'",
        description="identification (identd) 서버를 비활성화합니다.",
        severity="중",
        category=RuleCategory.FUNCTION_MANAGEMENT,
        patterns=[
            r"^ip\s+identd$"
        ],
        negative_patterns=[
            r"no\s+ip\s+identd"
        ],
        device_types=["Cisco"],
        recommendation="identd 서버를 비활성화하세요: no ip identd",
        reference="CIS Cisco IOS 12 Benchmark v4.0.0 - 2.1.5 (Scored) Level 1",
        logical_check_function=check_cis_2_1_5,
        vulnerability_examples={
            "Cisco": [
                "ip identd",
                "! identd 서비스가 활성화된 상태"
            ]
        },
        safe_examples={
            "Cisco": [
                "no ip identd"
            ]
        }
    ),
    
    "CIS-2.1.6": SecurityRule(
        rule_id="CIS-2.1.6",
        title="Set 'service tcp-keepalives-in'",
        description="유휴 인커밍 네트워크 연결에서 keepalive 패킷을 생성합니다.",
        severity="중",
        category=RuleCategory.FUNCTION_MANAGEMENT,
        patterns=[
            r"^(?!.*service\s+tcp-keepalives-in).*$"
        ],
        negative_patterns=[
            r"service\s+tcp-keepalives-in"
        ],
        device_types=["Cisco"],
        recommendation="TCP keepalives-in 서비스를 활성화하세요: service tcp-keepalives-in",
        reference="CIS Cisco IOS 12 Benchmark v4.0.0 - 2.1.6 (Scored) Level 1",
        logical_check_function=check_cis_2_1_6,
        vulnerability_examples={
            "Cisco": [
                "! service tcp-keepalives-in 설정이 없는 경우",
                "hostname# show run | incl service tcp",
                "! (결과 없음)"
            ]
        },
        safe_examples={
            "Cisco": [
                "service tcp-keepalives-in"
            ]
        }
    ),
    
    "CIS-2.1.7": SecurityRule(
        rule_id="CIS-2.1.7",
        title="Set 'service tcp-keepalives-out'",
        description="유휴 아웃고잉 네트워크 연결에서 keepalive 패킷을 생성합니다.",
        severity="중",
        category=RuleCategory.FUNCTION_MANAGEMENT,
        patterns=[
            r"^(?!.*service\s+tcp-keepalives-out).*$"
        ],
        negative_patterns=[
            r"service\s+tcp-keepalives-out"
        ],
        device_types=["Cisco"],
        recommendation="TCP keepalives-out 서비스를 활성화하세요: service tcp-keepalives-out",
        reference="CIS Cisco IOS 12 Benchmark v4.0.0 - 2.1.7 (Scored) Level 1",
        logical_check_function=check_cis_2_1_7,
        vulnerability_examples={
            "Cisco": [
                "! service tcp-keepalives-out 설정이 없는 경우",
                "hostname# show run | incl service tcp",
                "! (결과 없음)"
            ]
        },
        safe_examples={
            "Cisco": [
                "service tcp-keepalives-out"
            ]
        }
    ),
    
    "CIS-2.1.8": SecurityRule(
        rule_id="CIS-2.1.8",
        title="Set 'no service pad'",
        description="X.25 Packet Assembler/Disassembler (PAD) 서비스를 비활성화합니다.",
        severity="중",
        category=RuleCategory.FUNCTION_MANAGEMENT,
        patterns=[
            r"service\s+pad"
        ],
        negative_patterns=[
            r"no\s+service\s+pad"
        ],
        device_types=["Cisco"],
        recommendation="PAD 서비스를 비활성화하세요: no service pad",
        reference="CIS Cisco IOS 12 Benchmark v4.0.0 - 2.1.8 (Scored) Level 1",
        logical_check_function=check_cis_2_1_8,
        vulnerability_examples={
            "Cisco": [
                "service pad",
                "! PAD 서비스가 활성화된 상태"
            ]
        },
        safe_examples={
            "Cisco": [
                "no service pad"
            ]
        }
    ),
    # ======================= 2.2 Logging Rules =======================

"CIS-2.2.1": SecurityRule(
    rule_id="CIS-2.2.1",
    title="Set 'logging on'",
    description="Enable logging of system messages",
    severity="상",
    category=RuleCategory.LOG_MANAGEMENT,
    patterns=[
        r"no\s+logging\s+on"
    ],
    negative_patterns=[
        r"logging\s+on"
    ],
    device_types=["Cisco"],
    recommendation="Enable system logging: logging on",
    reference="CIS Cisco IOS 12 Benchmark v4.0.0 - 2.2.1",
),

"CIS-2.2.2": SecurityRule(
    rule_id="CIS-2.2.2",
    title="Set 'buffer size' for 'logging buffered'",
    description="Enable system message logging to local buffer",
    severity="상",
    category=RuleCategory.LOG_MANAGEMENT,
    patterns=[],
    negative_patterns=[
        r"logging\s+buffered\s+\d+"
    ],
    device_types=["Cisco"],
    recommendation="Configure buffered logging: logging buffered 64000",
    reference="CIS Cisco IOS 12 Benchmark v4.0.0 - 2.2.2",
    logical_check_function=check_cis_2_2_2,
),

"CIS-2.2.3": SecurityRule(
    rule_id="CIS-2.2.3",
    title="Set 'logging console critical'",
    description="Limit console logging to critical messages",
    severity="상",
    category=RuleCategory.LOG_MANAGEMENT,
    patterns=[
        r"logging\s+console\s+(?!critical)"
    ],
    negative_patterns=[
        r"logging\s+console\s+critical"
    ],
    device_types=["Cisco"],
    recommendation="Set console logging level: logging console critical",
    reference="CIS Cisco IOS 12 Benchmark v4.0.0 - 2.2.3",
),

"CIS-2.2.4": SecurityRule(
    rule_id="CIS-2.2.4",
    title="Set IP address for 'logging host'",
    description="Configure syslog server",
    severity="상",
    category=RuleCategory.LOG_MANAGEMENT,
    patterns=[],
    negative_patterns=[
        r"logging\s+host\s+\d+\.\d+\.\d+\.\d+"
    ],
    device_types=["Cisco"],
    recommendation="Configure syslog server: logging host <ip_address>",
    reference="CIS Cisco IOS 12 Benchmark v4.0.0 - 2.2.4",
    logical_check_function=check_cis_2_2_4,
),

"CIS-2.2.5": SecurityRule(
    rule_id="CIS-2.2.5",
    title="Set 'logging trap informational'",
    description="Set syslog trap level to informational",
    severity="상",
    category=RuleCategory.LOG_MANAGEMENT,
    patterns=[
        r"logging\s+trap\s+(?!informational)"
    ],
    negative_patterns=[
        r"logging\s+trap\s+informational"
    ],
    device_types=["Cisco"],
    recommendation="Set trap logging level: logging trap informational",
    reference="CIS Cisco IOS 12 Benchmark v4.0.0 - 2.2.5",
),

"CIS-2.2.6": SecurityRule(
    rule_id="CIS-2.2.6",
    title="Set 'service timestamps debug datetime'",
    description="Configure timestamps for debug messages",
    severity="상",
    category=RuleCategory.LOG_MANAGEMENT,
    patterns=[],
    negative_patterns=[
        r"service\s+timestamps\s+debug\s+datetime"
    ],
    device_types=["Cisco"],
    recommendation="Configure debug timestamps: service timestamps debug datetime msec show-timezone",
    reference="CIS Cisco IOS 12 Benchmark v4.0.0 - 2.2.6",
),

"CIS-2.2.7": SecurityRule(
    rule_id="CIS-2.2.7",
    title="Set 'logging source interface'",
    description="Specify source interface for logging packets",
    severity="상",
    category=RuleCategory.LOG_MANAGEMENT,
    patterns=[],
    negative_patterns=[
        r"logging\s+source-interface\s+loopback"
    ],
    device_types=["Cisco"],
    recommendation="Configure logging source interface: logging source-interface loopback <number>",
    reference="CIS Cisco IOS 12 Benchmark v4.0.0 - 2.2.7",
    logical_check_function=check_cis_2_2_7,
),

# ======================= 2.3 NTP Rules =======================

"CIS-2.3.1.1": SecurityRule(
    rule_id="CIS-2.3.1.1",
    title="Set 'ntp authenticate'",
    description="Enable NTP authentication",
    severity="중",
    category=RuleCategory.FUNCTION_MANAGEMENT,
    patterns=[],
    negative_patterns=[
        r"ntp\s+authenticate"
    ],
    device_types=["Cisco"],
    recommendation="Enable NTP authentication: ntp authenticate",
    reference="CIS Cisco IOS 12 Benchmark v4.0.0 - 2.3.1.1",
),

"CIS-2.3.1.2": SecurityRule(
    rule_id="CIS-2.3.1.2",
    title="Set 'ntp authentication-key'",
    description="Define NTP authentication key",
    severity="중",
    category=RuleCategory.FUNCTION_MANAGEMENT,
    patterns=[],
    negative_patterns=[
        r"ntp\s+authentication-key\s+\d+\s+md5\s+\S+"
    ],
    device_types=["Cisco"],
    recommendation="Configure NTP authentication key: ntp authentication-key <id> md5 <key>",
    reference="CIS Cisco IOS 12 Benchmark v4.0.0 - 2.3.1.2",
    logical_check_function=check_cis_2_3_1_2,
),

"CIS-2.3.1.3": SecurityRule(
    rule_id="CIS-2.3.1.3",
    title="Set the 'ntp trusted-key'",
    description="Configure NTP trusted key",
    severity="중",
    category=RuleCategory.FUNCTION_MANAGEMENT,
    patterns=[],
    negative_patterns=[
        r"ntp\s+trusted-key\s+\d+"
    ],
    device_types=["Cisco"],
    recommendation="Configure NTP trusted key: ntp trusted-key <key_id>",
    reference="CIS Cisco IOS 12 Benchmark v4.0.0 - 2.3.1.3",
    logical_check_function=check_cis_2_3_1_3,
),

"CIS-2.3.1.4": SecurityRule(
    rule_id="CIS-2.3.1.4",
    title="Set 'key' for each 'ntp server'",
    description="Configure authentication key for NTP servers",
    severity="중",
    category=RuleCategory.FUNCTION_MANAGEMENT,
    patterns=[
        r"ntp\s+server\s+\S+(?!\s+key\s+\d+)"
    ],
    negative_patterns=[
        r"ntp\s+server\s+\S+\s+key\s+\d+"
    ],
    device_types=["Cisco"],
    recommendation="Configure NTP server with key: ntp server <ip> key <key_id>",
    reference="CIS Cisco IOS 12 Benchmark v4.0.0 - 2.3.1.4",
),

"CIS-2.3.2": SecurityRule(
    rule_id="CIS-2.3.2",
    title="Set 'ip address' for 'ntp server'",
    description="Configure NTP server IP address",
    severity="상",
    category=RuleCategory.FUNCTION_MANAGEMENT,
    patterns=[
        r"^(?!.*ntp\s+server).*$"  # 🔥 패턴 추가
    ],
    negative_patterns=[
        r"ntp\s+server\s+\d+\.\d+\.\d+\.\d+"
    ],
    device_types=["Cisco"],
    recommendation="Configure NTP server: ntp server <ip_address>",
    reference="CIS Cisco IOS 12 Benchmark v4.0.0 - 2.3.2",
    logical_check_function=check_cis_2_3_2,
),

# ======================= 2.4 Loopback Rules =======================

"CIS-2.4.1": SecurityRule(
    rule_id="CIS-2.4.1",
    title="Create a single 'interface loopback'",
    description="Configure loopback interface",
    severity="중",
    category=RuleCategory.FUNCTION_MANAGEMENT,
    patterns=[
        r"^(?!.*interface\s+loopback).*$"
    ],
    negative_patterns=[
        r"interface\s+loopback\s*\d+"
    ],
    device_types=["Cisco"],
    recommendation="Create loopback interface: interface loopback <number>",
    reference="CIS Cisco IOS 12 Benchmark v4.0.0 - 2.4.1",
    logical_check_function=check_cis_2_4_1,
),

"CIS-2.4.2": SecurityRule(
    rule_id="CIS-2.4.2",
    title="Set AAA 'source-interface'",
    description="Configure AAA source interface",
    severity="중",
    category=RuleCategory.FUNCTION_MANAGEMENT,
    patterns=[],
    negative_patterns=[
        r"ip\s+(tacacs|radius)\s+source-interface\s+loopback"
    ],
    device_types=["Cisco"],
    recommendation="Configure AAA source interface: ip tacacs source-interface loopback <number>",
    reference="CIS Cisco IOS 12 Benchmark v4.0.0 - 2.4.2",
    logical_check_function=check_cis_2_4_2,
),

"CIS-2.4.3": SecurityRule(
    rule_id="CIS-2.4.3",
    title="Set 'ntp source' to Loopback Interface",
    description="Configure NTP source interface",
    severity="중",
    category=RuleCategory.FUNCTION_MANAGEMENT,
    patterns=[],
    negative_patterns=[
        r"ntp\s+source\s+loopback"
    ],
    device_types=["Cisco"],
    recommendation="Configure NTP source interface: ntp source loopback <number>",
    reference="CIS Cisco IOS 12 Benchmark v4.0.0 - 2.4.3",
),

"CIS-2.4.4": SecurityRule(
    rule_id="CIS-2.4.4",
    title="Set 'ip tftp source-interface' to the Loopback Interface",
    description="Configure TFTP source interface",
    severity="중",
    category=RuleCategory.FUNCTION_MANAGEMENT,
    patterns=[],
    negative_patterns=[
        r"ip\s+tftp\s+source-interface\s+loopback"
    ],
    device_types=["Cisco"],
    recommendation="Configure TFTP source interface: ip tftp source-interface loopback <number>",
    reference="CIS Cisco IOS 12 Benchmark v4.0.0 - 2.4.4",
),

# ======================= 3.1 Routing Rules =======================

"CIS-3.1.1": SecurityRule(
    rule_id="CIS-3.1.1",
    title="Set 'no ip source-route'",
    description="Disable IP source routing",
    severity="상",
    category=RuleCategory.FUNCTION_MANAGEMENT,
    patterns=[
        r"ip\s+source-route"
    ],
    negative_patterns=[
        r"no\s+ip\s+source-route"
    ],
    device_types=["Cisco"],
    recommendation="소스 라우팅 비활성화: no ip source-route 명령어를 설정하세요.",
    reference="CIS Cisco IOS 12 Benchmark v4.0.0 - 3.1.1",
),

"CIS-3.1.2": SecurityRule(
    rule_id="CIS-3.1.2",
    title="Set 'no ip proxy-arp'",
    description="Disable proxy ARP on all interfaces",
    severity="중",
    category=RuleCategory.FUNCTION_MANAGEMENT,
    patterns=[
        r"ip\s+proxy-arp"
    ],
    negative_patterns=[
        r"no\s+ip\s+proxy-arp"
    ],
    device_types=["Cisco"],
    recommendation="Disable proxy ARP on interfaces: no ip proxy-arp",
    reference="CIS Cisco IOS 12 Benchmark v4.0.0 - 3.1.2",
    logical_check_function=check_cis_3_1_2,
),

"CIS-3.1.3": SecurityRule(
    rule_id="CIS-3.1.3",
    title="Set 'no interface tunnel'",
    description="Verify no tunnel interfaces are defined",
    severity="중",
    category=RuleCategory.FUNCTION_MANAGEMENT,
    patterns=[
        r"interface\s+tunnel"
    ],
    negative_patterns=[
        r"no\s+interface\s+tunnel"
    ],
    device_types=["Cisco"],
    recommendation="Remove tunnel interfaces: no interface tunnel <instance>",
    reference="CIS Cisco IOS 12 Benchmark v4.0.0 - 3.1.3",
),

"CIS-3.1.4": SecurityRule(
    rule_id="CIS-3.1.4",
    title="Set 'ip verify unicast source reachable-via'",
    description="Enable unicast reverse-path forwarding",
    severity="중",
    category=RuleCategory.FUNCTION_MANAGEMENT,
    patterns=[],
    negative_patterns=[
        r"ip\s+verify\s+unicast\s+source\s+reachable-via"
    ],
    device_types=["Cisco"],
    recommendation="Enable uRPF on external interfaces: ip verify unicast source reachable-via rx",
    reference="CIS Cisco IOS 12 Benchmark v4.0.0 - 3.1.4",
    logical_check_function=check_cis_3_1_4,
),

# ======================= 3.2 Border Router Filtering =======================

"CIS-3.2.1": SecurityRule(
    rule_id="CIS-3.2.1",
    title="Set 'ip access-list extended' to Forbid Private Source Addresses",
    description="Configure ACL to prevent spoofing from external networks",
    severity="중",
    category=RuleCategory.ACCESS_MANAGEMENT,
    patterns=[],
    negative_patterns=[],
    device_types=["Cisco"],
    recommendation="Configure extended ACL to deny private source addresses from external networks",
    reference="CIS Cisco IOS 12 Benchmark v4.0.0 - 3.2.1",
    logical_check_function=check_cis_3_2_1,
),

"CIS-3.2.2": SecurityRule(
    rule_id="CIS-3.2.2",
    title="Set inbound 'ip access-group' on the External Interface",
    description="Apply ACL to external interface",
    severity="중",
    category=RuleCategory.ACCESS_MANAGEMENT,
    patterns=[],
    negative_patterns=[],
    device_types=["Cisco"],
    recommendation="Apply access-group to external interface: ip access-group <acl> in",
    reference="CIS Cisco IOS 12 Benchmark v4.0.0 - 3.2.2",
    logical_check_function=check_cis_3_2_2,
),

# ======================= 3.3 Neighbor Authentication =======================

# 3.3.1 EIGRP Authentication Rules
"CIS-3.3.1.1": SecurityRule(
    rule_id="CIS-3.3.1.1",
    title="Set 'key chain' for EIGRP",
    description="Define authentication key chain for EIGRP",
    severity="중",
    category=RuleCategory.FUNCTION_MANAGEMENT,
    patterns=[],
    negative_patterns=[
        r"key\s+chain\s+\S+"
    ],
    device_types=["Cisco"],
    recommendation="Configure EIGRP key chain: key chain <name>",
    reference="CIS Cisco IOS 12 Benchmark v4.0.0 - 3.3.1.1",
    logical_check_function=check_cis_3_3_1_1,
),

"CIS-3.3.1.2": SecurityRule(
    rule_id="CIS-3.3.1.2",
    title="Set 'key' for EIGRP key chain",
    description="Configure authentication key on key chain",
    severity="중",
    category=RuleCategory.FUNCTION_MANAGEMENT,
    patterns=[],
    negative_patterns=[
        r"key\s+\d+"
    ],
    device_types=["Cisco"],
    recommendation="Configure key number: key <number>",
    reference="CIS Cisco IOS 12 Benchmark v4.0.0 - 3.3.1.2",
    logical_check_function=check_cis_3_3_1_2,
),

"CIS-3.3.1.3": SecurityRule(
    rule_id="CIS-3.3.1.3",
    title="Set 'key-string' for EIGRP",
    description="Configure authentication string for key",
    severity="중",
    category=RuleCategory.FUNCTION_MANAGEMENT,
    patterns=[],
    negative_patterns=[
        r"key-string\s+\S+"
    ],
    device_types=["Cisco"],
    recommendation="Configure key string: key-string <string>",
    reference="CIS Cisco IOS 12 Benchmark v4.0.0 - 3.3.1.3",
    logical_check_function=check_cis_3_3_1_3,
),

"CIS-3.3.1.4": SecurityRule(
    rule_id="CIS-3.3.1.4",
    title="Set 'address-family ipv4 autonomous-system' for EIGRP",
    description="Configure EIGRP address family",
    severity="중",
    category=RuleCategory.FUNCTION_MANAGEMENT,
    patterns=[],
    negative_patterns=[
        r"router\s+eigrp.*address-family\s+ipv4\s+autonomous-system"
    ],
    device_types=["Cisco"],
    recommendation="Configure EIGRP address family: address-family ipv4 autonomous-system <as>",
    reference="CIS Cisco IOS 12 Benchmark v4.0.0 - 3.3.1.4",
    logical_check_function=check_cis_3_3_1_4,
),

"CIS-3.3.1.5": SecurityRule(
    rule_id="CIS-3.3.1.5",
    title="Set 'af-interface default' for EIGRP",
    description="Define defaults for EIGRP interfaces in address-family",
    severity="중",
    category=RuleCategory.FUNCTION_MANAGEMENT,
    patterns=[],
    negative_patterns=[
        r"af-interface\s+default"
    ],
    device_types=["Cisco"],
    recommendation="Configure EIGRP af-interface: af-interface default",
    reference="CIS Cisco IOS 12 Benchmark v4.0.0 - 3.3.1.5",
    logical_check_function=check_cis_3_3_1_5,
),

"CIS-3.3.1.6": SecurityRule(
    rule_id="CIS-3.3.1.6",
    title="Set 'authentication key-chain' for EIGRP",
    description="Configure EIGRP address family key chain",
    severity="중",
    category=RuleCategory.FUNCTION_MANAGEMENT,
    patterns=[],
    negative_patterns=[
        r"authentication\s+key-chain\s+\S+"
    ],
    device_types=["Cisco"],
    recommendation="Configure EIGRP authentication key-chain: authentication key-chain <name>",
    reference="CIS Cisco IOS 12 Benchmark v4.0.0 - 3.3.1.6",
    logical_check_function=check_cis_3_3_1_6,
),

"CIS-3.3.1.7": SecurityRule(
    rule_id="CIS-3.3.1.7",
    title="Set 'authentication mode md5' for EIGRP",
    description="Configure EIGRP authentication mode",
    severity="중",
    category=RuleCategory.FUNCTION_MANAGEMENT,
    patterns=[],
    negative_patterns=[
        r"authentication\s+mode\s+md5"
    ],
    device_types=["Cisco"],
    recommendation="Configure EIGRP authentication mode: authentication mode md5",
    reference="CIS Cisco IOS 12 Benchmark v4.0.0 - 3.3.1.7",
    logical_check_function=check_cis_3_3_1_7,
),

"CIS-3.3.1.8": SecurityRule(
    rule_id="CIS-3.3.1.8",
    title="Set 'ip authentication key-chain eigrp'",
    description="Configure EIGRP authentication per interface",
    severity="중",
    category=RuleCategory.FUNCTION_MANAGEMENT,
    patterns=[],
    negative_patterns=[
        r"ip\s+authentication\s+key-chain\s+eigrp\s+\d+\s+\S+"
    ],
    device_types=["Cisco"],
    recommendation="Configure interface EIGRP key-chain: ip authentication key-chain eigrp <as> <chain>",
    reference="CIS Cisco IOS 12 Benchmark v4.0.0 - 3.3.1.8",
    logical_check_function=check_cis_3_3_1_8,
),

"CIS-3.3.1.9": SecurityRule(
    rule_id="CIS-3.3.1.9",
    title="Set 'ip authentication mode eigrp'",
    description="Configure EIGRP authentication mode per interface",
    severity="중",
    category=RuleCategory.FUNCTION_MANAGEMENT,
    patterns=[],
    negative_patterns=[
        r"ip\s+authentication\s+mode\s+eigrp\s+\d+\s+md5"
    ],
    device_types=["Cisco"],
    recommendation="Configure interface EIGRP auth mode: ip authentication mode eigrp <as> md5",
    reference="CIS Cisco IOS 12 Benchmark v4.0.0 - 3.3.1.9",
    logical_check_function=check_cis_3_3_1_9,
),

# 3.3.2 OSPF Authentication Rules
"CIS-3.3.2.1": SecurityRule(
    rule_id="CIS-3.3.2.1",
    title="Set 'authentication message-digest' for OSPF area",
    description="Enable MD5 authentication for OSPF area",
    severity="중",
    category=RuleCategory.FUNCTION_MANAGEMENT,
    patterns=[],
    negative_patterns=[
        r"area\s+\S+\s+authentication\s+message-digest"
    ],
    device_types=["Cisco"],
    recommendation="Configure OSPF area authentication: area <area> authentication message-digest",
    reference="CIS Cisco IOS 12 Benchmark v4.0.0 - 3.3.2.1",
    logical_check_function=check_cis_3_3_2_1,
),

"CIS-3.3.2.2": SecurityRule(
    rule_id="CIS-3.3.2.2",
    title="Set 'ip ospf message-digest-key md5'",
    description="Enable OSPF MD5 authentication per interface",
    severity="중",
    category=RuleCategory.FUNCTION_MANAGEMENT,
    patterns=[],
    negative_patterns=[
        r"ip\s+ospf\s+message-digest-key\s+\d+\s+md5\s+\S+"
    ],
    device_types=["Cisco"],
    recommendation="Configure interface OSPF MD5 key: ip ospf message-digest-key <id> md5 <key>",
    reference="CIS Cisco IOS 12 Benchmark v4.0.0 - 3.3.2.2",
    logical_check_function=check_cis_3_3_2_2,
),

# 3.3.3 RIPv2 Authentication Rules
"CIS-3.3.3.1": SecurityRule(
    rule_id="CIS-3.3.3.1",
    title="Set 'key chain' for RIPv2",
    description="Define authentication key chain for RIPv2",
    severity="중",
    category=RuleCategory.FUNCTION_MANAGEMENT,
    patterns=[],
    negative_patterns=[
        r"key\s+chain\s+\S+"
    ],
    device_types=["Cisco"],
    recommendation="Configure RIPv2 key chain: key chain <name>",
    reference="CIS Cisco IOS 12 Benchmark v4.0.0 - 3.3.3.1",
    logical_check_function=check_cis_3_3_3_1,
),

"CIS-3.3.3.2": SecurityRule(
    rule_id="CIS-3.3.3.2",
    title="Set 'key' for RIPv2 key chain",
    description="Configure authentication key on key chain for RIPv2",
    severity="중",
    category=RuleCategory.FUNCTION_MANAGEMENT,
    patterns=[],
    negative_patterns=[
        r"key\s+\d+"
    ],
    device_types=["Cisco"],
    recommendation="Configure key number: key <number>",
    reference="CIS Cisco IOS 12 Benchmark v4.0.0 - 3.3.3.2",
    logical_check_function=check_cis_3_3_3_2,
),

"CIS-3.3.3.3": SecurityRule(
    rule_id="CIS-3.3.3.3",
    title="Set 'key-string' for RIPv2",
    description="Configure authentication string for RIPv2 key",
    severity="중",
    category=RuleCategory.FUNCTION_MANAGEMENT,
    patterns=[],
    negative_patterns=[
        r"key-string\s+\S+"
    ],
    device_types=["Cisco"],
    recommendation="Configure key string: key-string <string>",
    reference="CIS Cisco IOS 12 Benchmark v4.0.0 - 3.3.3.3",
    logical_check_function=check_cis_3_3_3_3,
),

"CIS-3.3.3.4": SecurityRule(
    rule_id="CIS-3.3.3.4",
    title="Set 'ip rip authentication key-chain'",
    description="Enable RIPv2 authentication and specify key chain per interface",
    severity="중",
    category=RuleCategory.FUNCTION_MANAGEMENT,
    patterns=[],
    negative_patterns=[
        r"ip\s+rip\s+authentication\s+key-chain\s+\S+"
    ],
    device_types=["Cisco"],
    recommendation="Configure interface RIP authentication: ip rip authentication key-chain <name>",
    reference="CIS Cisco IOS 12 Benchmark v4.0.0 - 3.3.3.4",
    logical_check_function=check_cis_3_3_3_4,
),

"CIS-3.3.3.5": SecurityRule(
    rule_id="CIS-3.3.3.5",
    title="Set 'ip rip authentication mode' to 'md5'",
    description="Configure RIPv2 authentication mode to MD5",
    severity="중",
    category=RuleCategory.FUNCTION_MANAGEMENT,
    patterns=[],
    negative_patterns=[
        r"ip\s+rip\s+authentication\s+mode\s+md5"
    ],
    device_types=["Cisco"],
    recommendation="Configure RIP authentication mode: ip rip authentication mode md5",
    reference="CIS Cisco IOS 12 Benchmark v4.0.0 - 3.3.3.5",
    logical_check_function=check_cis_3_3_3_5,
),

# 3.3.4 BGP Authentication Rules
"CIS-3.3.4.1": SecurityRule(
    rule_id="CIS-3.3.4.1",
    title="Set 'neighbor password' for BGP",
    description="Enable MD5 authentication for BGP neighbors",
    severity="중",
    category=RuleCategory.FUNCTION_MANAGEMENT,
    patterns=[],
    negative_patterns=[
        r"neighbor\s+\S+\s+password\s+\S+"
    ],
    device_types=["Cisco"],
    recommendation="Configure BGP neighbor authentication: neighbor <ip> password <password>",
    reference="CIS Cisco IOS 12 Benchmark v4.0.0 - 3.3.4.1",
    logical_check_function=check_cis_3_3_4_1,
),
}

# 기존 호환성을 위한 별칭
COMPLETE_ENHANCED_CIS_RULES = CIS_RULES
CIS_SECURITY_RULES = CIS_RULES
ENHANCED_CIS_SECURITY_RULES = CIS_RULES