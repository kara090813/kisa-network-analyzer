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
from .kisa_rules import (
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
    check_cis_2_1_8
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
            r"cdp\s+run"
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
            r"ip\s+identd"
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
}

# 기존 호환성을 위한 별칭
COMPLETE_ENHANCED_CIS_RULES = CIS_RULES
CIS_SECURITY_RULES = CIS_RULES
ENHANCED_CIS_SECURITY_RULES = CIS_RULES