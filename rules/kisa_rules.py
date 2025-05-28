# -*- coding: utf-8 -*-
"""
rules/kisa_rules.py
KISA 네트워크 장비 보안 점검 룰셋 정의

KISA 가이드 기반 보안 룰들의 정의만 포함
logical_check_function은 checks_kisa.py에서 import
"""

import re
from dataclasses import dataclass, field
from typing import List, Dict, Pattern, Callable, Optional, Any, Tuple
from enum import Enum


class RuleCategory(Enum):
    """룰 카테고리"""
    ACCOUNT_MANAGEMENT = "계정 관리"
    ACCESS_MANAGEMENT = "접근 관리"
    PATCH_MANAGEMENT = "패치 관리"
    LOG_MANAGEMENT = "로그 관리"
    FUNCTION_MANAGEMENT = "기능 관리"


@dataclass
class ConfigContext:
    """설정 파일 분석 컨텍스트"""
    full_config: str
    config_lines: List[str]
    device_type: str
    parsed_interfaces: Dict[str, Dict[str, Any]] = field(default_factory=dict)
    parsed_users: List[Dict[str, Any]] = field(default_factory=list)
    parsed_services: Dict[str, bool] = field(default_factory=dict)
    global_settings: Dict[str, Any] = field(default_factory=dict)
    vty_lines: List[Dict[str, Any]] = field(default_factory=list)
    snmp_communities: List[Dict[str, Any]] = field(default_factory=list)
    access_lists: Dict[str, List[str]] = field(default_factory=dict)


@dataclass 
class LogicalCondition:
    """논리 조건 정의"""
    name: str
    description: str
    check_function: Callable[[str, int, ConfigContext], bool]
    examples: Dict[str, List[str]] = field(default_factory=dict)


@dataclass
class SecurityRule:
    """보안 룰 정의 - 완전한 논리 기반 분석"""
    rule_id: str
    title: str
    description: str
    severity: str  # 상/중/하
    category: RuleCategory
    patterns: List[str]  # 기존 호환성을 위한 기본 패턴들
    negative_patterns: List[str]  # 양호한 상태 패턴들
    device_types: List[str]
    recommendation: str
    reference: str
    
    # 논리 기반 분석을 위한 새로운 필드들
    logical_conditions: List[LogicalCondition] = field(default_factory=list)
    logical_check_function: Optional[Callable[[str, int, ConfigContext], List[Dict[str, Any]]]] = None
    vulnerability_examples: Dict[str, List[str]] = field(default_factory=dict)
    safe_examples: Dict[str, List[str]] = field(default_factory=dict)
    heuristic_rules: List[str] = field(default_factory=list)
    
    # 기존 호환성을 위한 필드들
    check_function: Optional[Callable] = None  # 기존 호환성 유지
    
    def __post_init__(self):
        """패턴들을 컴파일된 정규식으로 변환"""
        self.compiled_patterns = [re.compile(pattern, re.IGNORECASE | re.MULTILINE | re.DOTALL) 
                                 for pattern in self.patterns]
        self.compiled_negative_patterns = [re.compile(pattern, re.IGNORECASE | re.MULTILINE | re.DOTALL) 
                                         for pattern in self.negative_patterns]


# ==================== 강화된 파싱 유틸리티 함수들 ====================

def parse_config_context(config_text: str, device_type: str) -> ConfigContext:
    """설정 파일을 분석하여 완전한 컨텍스트 객체 생성"""
    context = ConfigContext(
        full_config=config_text,
        config_lines=config_text.splitlines(),
        device_type=device_type
    )
    
    # 장비별 파싱 로직 적용
    if device_type == "Cisco":
        _parse_cisco_config_complete(context)
    elif device_type == "Juniper":
        _parse_juniper_config_complete(context)
    elif device_type == "Alteon":
        _parse_alteon_config(context)
    elif device_type == "Piolink":
        _parse_piolink_config(context)
    
    return context


def _parse_cisco_config_complete(context: ConfigContext):
    """Cisco 설정 완전 파싱"""
    lines = context.config_lines
    current_interface = None
    interface_config = {}
    current_vty = None
    vty_config = {}
    current_section = None
    
    for i, line in enumerate(lines):
        line = line.strip()
        
        # 인터페이스 설정 파싱
        if line.startswith('interface '):
            if current_interface and interface_config:
                context.parsed_interfaces[current_interface] = interface_config
            
            current_interface = line.split('interface ', 1)[1]
            interface_config = {
                'name': current_interface,
                'line_number': i + 1,
                'config_lines': [line],
                'has_ip_address': False,
                'has_description': False,
                'is_shutdown': False,
                'has_vlan': False,
                'is_loopback': 'loopback' in current_interface.lower(),
                'is_management': 'mgmt' in current_interface.lower() or 'management' in current_interface.lower(),
                'port_type': _get_cisco_port_type(current_interface),
                'has_switchport': False,
                'vlan_id': None
            }
            
        elif current_interface and line and not line.startswith('!'):
            interface_config['config_lines'].append(line)
            
            # 인터페이스 속성 분석
            if line.startswith('ip address'):
                interface_config['has_ip_address'] = True
            elif line.startswith('description'):
                interface_config['has_description'] = True
                interface_config['description'] = line.split('description ', 1)[1] if len(line.split('description ', 1)) > 1 else ''
            elif line == 'shutdown':
                interface_config['is_shutdown'] = True
            elif line.startswith('switchport'):
                interface_config['has_switchport'] = True
                if 'access vlan' in line:
                    try:
                        interface_config['vlan_id'] = int(line.split()[-1])
                        interface_config['has_vlan'] = True
                    except:
                        pass
        
        # VTY 라인 파싱
        elif line.startswith('line vty'):
            if current_vty and vty_config:
                context.vty_lines.append(vty_config)
            
            current_vty = line
            vty_config = {
                'line': line,
                'line_number': i + 1,
                'has_password': False,
                'has_access_class': False,
                'transport_input': [],
                'exec_timeout': None,
                'login_method': None
            }
            
        elif current_vty and line and not line.startswith('!') and line.startswith(' '):
            if 'password' in line:
                vty_config['has_password'] = True
            elif 'access-class' in line:
                vty_config['has_access_class'] = True
                vty_config['access_class'] = line.split()[-2] if len(line.split()) > 2 else None
            elif 'transport input' in line:
                vty_config['transport_input'] = line.split()[2:]
            elif 'exec-timeout' in line:
                try:
                    timeout_parts = line.split()[1:3]
                    vty_config['exec_timeout'] = int(timeout_parts[0]) * 60 + (int(timeout_parts[1]) if len(timeout_parts) > 1 else 0)
                except:
                    pass
            elif line.strip() in ['login', 'login local']:
                vty_config['login_method'] = line.strip()
        
        # 사용자 계정 파싱
        elif line.startswith('username '):
            user_parts = line.split()
            if len(user_parts) >= 3:
                username = user_parts[1]
                user_info = {
                    'username': username,
                    'line_number': i + 1,
                    'has_password': 'password' in line,
                    'has_secret': 'secret' in line,
                    'privilege_level': 1,
                    'password_encrypted': False
                }
                
                if 'privilege' in line:
                    try:
                        priv_idx = user_parts.index('privilege')
                        if priv_idx + 1 < len(user_parts):
                            user_info['privilege_level'] = int(user_parts[priv_idx + 1])
                    except:
                        pass
                
                if 'password' in line and ('$' in line or '7 ' in line):
                    user_info['password_encrypted'] = True
                elif 'secret' in line:
                    user_info['password_encrypted'] = True
                
                context.parsed_users.append(user_info)
        
        # SNMP 커뮤니티 파싱
        elif line.startswith('snmp-server community'):
            parts = line.split()
            if len(parts) >= 3:
                community_info = {
                    'community': parts[2],
                    'line_number': i + 1,
                    'permission': parts[3] if len(parts) > 3 else 'RO',
                    'acl': parts[4] if len(parts) > 4 and parts[4].isdigit() else None,
                    'is_default': parts[2].lower() in ['public', 'private'],
                    'length': len(parts[2])
                }
                context.snmp_communities.append(community_info)
        
        # Access List 파싱
        elif line.startswith('access-list '):
            parts = line.split()
            if len(parts) >= 3:
                acl_number = parts[1]
                if acl_number not in context.access_lists:
                    context.access_lists[acl_number] = []
                context.access_lists[acl_number].append(line)
        
        # 글로벌 설정 파싱
        elif line.startswith('enable '):
            if 'password' in line:
                context.global_settings['enable_password_type'] = 'password'
                # 기본 패스워드 체크
                password_part = line.split('enable password ', 1)[1].strip() if 'enable password ' in line else ''
                context.global_settings['enable_password_value'] = password_part
            elif 'secret' in line:
                context.global_settings['enable_password_type'] = 'secret'
                
        elif line.startswith('service '):
            service_name = line.split('service ', 1)[1].strip()
            context.parsed_services[service_name] = True
            
        elif line.startswith('no service '):
            service_name = line.split('no service ', 1)[1].strip()
            context.parsed_services[service_name] = False
            
        elif line.startswith('ip '):
            # IP 관련 서비스 파싱
            if 'http server' in line:
                context.parsed_services['http_server'] = not line.startswith('no ')
            elif 'domain-lookup' in line or 'domain lookup' in line:
                context.parsed_services['domain_lookup'] = not line.startswith('no ')
            elif 'source-route' in line:
                context.parsed_services['source_route'] = not line.startswith('no ')
    
    # 마지막 인터페이스와 VTY 저장
    if current_interface and interface_config:
        context.parsed_interfaces[current_interface] = interface_config
    if current_vty and vty_config:
        context.vty_lines.append(vty_config)


def _parse_juniper_config_complete(context: ConfigContext):
    """Juniper 설정 완전 파싱"""
    lines = context.config_lines
    for i, line in enumerate(lines):
        line = line.strip()
        # Juniper 특화 파싱 로직 구현
        if 'system' in line and 'root-authentication' in context.full_config:
            context.global_settings['has_root_auth'] = True
        
        if 'snmp' in line and 'community' in line:
            # Juniper SNMP 파싱
            if 'public' in line or 'private' in line:
                context.snmp_communities.append({
                    'community': 'public' if 'public' in line else 'private',
                    'line_number': i + 1,
                    'is_default': True
                })


def _parse_alteon_config(context: ConfigContext):
    """Alteon 설정 파싱"""
    lines = context.config_lines
    for i, line in enumerate(lines):
        line = line.strip()
        # Alteon 특화 파싱 로직
        pass


def _parse_piolink_config(context: ConfigContext):
    """Piolink 설정 파싱"""
    lines = context.config_lines
    for i, line in enumerate(lines):
        line = line.strip()
        # Piolink 특화 파싱 로직
        pass


def _get_cisco_port_type(interface_name: str) -> str:
    """Cisco 포트 타입 판별"""
    interface_lower = interface_name.lower()
    if 'fastethernet' in interface_lower or 'fa' in interface_lower:
        return 'FastEthernet'
    elif 'gigabitethernet' in interface_lower or 'gi' in interface_lower:
        return 'GigabitEthernet'
    elif 'tengigabitethernet' in interface_lower or 'te' in interface_lower:
        return 'TenGigabitEthernet'
    elif 'serial' in interface_lower:
        return 'Serial'
    elif 'loopback' in interface_lower:
        return 'Loopback'
    elif 'vlan' in interface_lower:
        return 'VLAN'
    elif 'tunnel' in interface_lower:
        return 'Tunnel'
    else:
        return 'Unknown'


def _is_critical_interface(interface_name: str, device_type: str) -> bool:
    """중요 인터페이스 여부 판별 - 강화된 버전"""
    interface_lower = interface_name.lower()
    
    # 항상 중요한 인터페이스들
    critical_patterns = ['loopback', 'mgmt', 'management', 'console', 'tunnel', 'vlan1']
    
    if any(pattern in interface_lower for pattern in critical_patterns):
        return True
    
    # 장비별 특정 중요 인터페이스
    if device_type == "Cisco":
        # 첫 번째 물리 포트들은 일반적으로 업링크
        if (interface_lower.startswith('gi0/0') or interface_lower.startswith('fa0/0') or 
            interface_lower.startswith('gigabitethernet0/0') or interface_lower.startswith('fastethernet0/0')):
            return True
        
        # Serial 인터페이스는 WAN 연결용
        if interface_lower.startswith('serial'):
            return True
    
    return False


# ==================== KISA 룰셋 정의 ====================

# checks_kisa.py에서 logical_check_function들 import
from .checks_kisa import (
    check_basic_password_usage,
    check_password_complexity,
    check_password_encryption,
    check_vty_access_control,
    check_session_timeout,
    check_unused_interface_shutdown,
    check_snmp_security,
    check_ssh_protocol_usage
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

    # 여기에 나머지 N-06부터 N-38까지의 룰들을 추가...
    # 간단한 예시로 몇 개만 포함하고 실제로는 모든 38개 룰을 포함해야 함
    
    "N-25": SecurityRule(
        rule_id="N-25",
        title="Finger 서비스 차단",
        description="Finger 서비스를 차단하는지 점검",
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
        recommendation="각 장비별 Finger 서비스 제한 설정",
        reference="KISA 가이드 N-25 (중) 5.10 Finger 서비스 차단",
    ),

    "N-26": SecurityRule(
        rule_id="N-26",
        title="웹 서비스 차단",
        description="불필요한 웹 서비스를 비활성화하거나 특정 IP만 접근을 허용하는지 점검",
        severity="중",
        category=RuleCategory.FUNCTION_MANAGEMENT,
        patterns=[
            r"ip\s+http\s+server"
        ],
        negative_patterns=[
            r"no\s+ip\s+http\s+server"
        ],
        device_types=["Cisco", "Juniper", "Alteon", "Piolink"],
        recommendation="HTTP 서비스 차단 또는 HTTP 서버를 관리하는 관리자 접속 IP 설정",
        reference="KISA 가이드 N-26 (중) 5.11 웹 서비스 차단",
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
    ),
}

# 기존 호환성을 위한 별칭
COMPLETE_ENHANCED_KISA_RULES = KISA_RULES
KISA_SECURITY_RULES = KISA_RULES
ENHANCED_KISA_SECURITY_RULES = KISA_RULES