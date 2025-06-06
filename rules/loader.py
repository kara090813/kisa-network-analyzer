# -*- coding: utf-8 -*-
"""
rules/loader.py
보안 지침서별 룰셋 로더 (중앙화된 공통 구조 포함)

다양한 보안 지침서(KISA, CIS, 자체지침서서, NIST 등)의 룰셋을 로드하는 중앙 관리 모듈
공통 클래스 및 파싱 함수들을 중앙화하여 의존성 문제 해결
"""

import re
from dataclasses import dataclass, field
from typing import List, Dict, Pattern, Callable, Optional, Any, Tuple, Union
from enum import Enum

# cisco_defaults는 별도 모듈로 유지
from .cisco_defaults import CiscoDefaults


# ==================== 공통 클래스 정의 (중앙화) ====================

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
    
    def __post_init__(self):
        """초기화 후 처리 - IOS 버전 감지 추가"""
        if not hasattr(self, 'ios_version'):
            self.ios_version = self._detect_ios_version()
        if not hasattr(self, 'cisco_defaults'):
            self.cisco_defaults = CiscoDefaults()
    
    def _detect_ios_version(self) -> Optional[str]:
        """IOS 버전 감지"""
        for line in self.config_lines:
            if line.startswith('version '):
                return line.split('version ', 1)[1].strip()
            elif 'IOS Software' in line:
                # show version 출력에서 버전 추출
                version_match = re.search(r'Version (\d+\.\d+)', line)
                if version_match:
                    return version_match.group(1)
        return None
    
    def get_service_state(self, service_name: str, explicit_config: Optional[bool] = None) -> bool:
        """
        서비스의 실제 상태 반환 (기본값 고려)
        
        Args:
            service_name: 서비스명
            explicit_config: 명시적 설정 (None이면 기본값 사용)
        """
        if explicit_config is not None:
            return explicit_config
        
        return self.cisco_defaults.get_default_value(service_name, self.ios_version)


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


# ==================== 공통 파싱 함수들 (중앙화) ====================

def _extract_ios_version_number(version_string: str) -> float:
    """IOS 버전 번호 추출"""
    match = re.search(r'(\d+)\.(\d+)', version_string)
    if match:
        return float(f"{match.group(1)}.{match.group(2)}")
    return 15.0  # 기본값

def _parse_line_configs(config_lines: List[str]) -> Dict[str, Optional[Dict[str, Any]]]:
    """라인 설정을 직접 파싱하는 헬퍼 함수"""
    line_configs = {
        'con 0': None,
        'vty 0 4': None,
        'vty 0 15': None,
        'aux 0': None
    }
    
    current_line_type = None
    current_line_config = None
    
    for i, line in enumerate(config_lines):
        line_clean = line.strip()
        
        # 라인 섹션 시작 감지
        if line_clean.startswith('line '):
            # 이전 라인 설정 저장
            if current_line_type and current_line_config:
                line_configs[current_line_type] = current_line_config
            
            # 새 라인 타입 파싱
            parts = line_clean.split()
            if len(parts) >= 2:
                line_type_parts = parts[1:]
                current_line_type = ' '.join(line_type_parts)
                current_line_config = {
                    'line_number': i + 1,
                    'exec_timeout': None,
                    'has_password': False,
                    'has_login': False
                }
        
        # 라인 설정 내부
        elif current_line_type and line.startswith(' ') and not line_clean.startswith('!'):
            if 'exec-timeout' in line_clean:
                # exec-timeout 파싱
                match = re.search(r'exec-timeout\s+(\d+)\s+(\d+)', line_clean)
                if match:
                    minutes = int(match.group(1))
                    seconds = int(match.group(2))
                    current_line_config['exec_timeout'] = (minutes, seconds)
            elif 'password' in line_clean:
                current_line_config['has_password'] = True
            elif line_clean in ['login', 'login local']:
                current_line_config['has_login'] = True
        
        # 다른 섹션 시작 (라인 설정 종료)
        elif current_line_type and not line.startswith(' ') and line_clean and not line_clean.startswith('!'):
            line_configs[current_line_type] = current_line_config
            current_line_type = None
            current_line_config = None
    
    # 마지막 라인 설정 저장
    if current_line_type and current_line_config:
        line_configs[current_line_type] = current_line_config
    
    return line_configs

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
    """Cisco 설정 완전 파싱 - Domain lookup 버그 수정"""
    lines = context.config_lines
    current_interface = None
    interface_config = {}
    current_vty = None
    vty_config = {}
    current_section = None
    in_vty_section = False
    
    for i, line in enumerate(lines):
        original_line = line
        line = line.strip()
        
        # 인터페이스 설정 파싱
        if line.startswith('interface '):
            # 이전 인터페이스 저장
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
                'vlan_id': None,
                'is_subinterface': '.' in current_interface
            }
            current_section = 'interface'
            in_vty_section = False
            
        elif current_interface and line and not line.startswith('!') and original_line.startswith(' '):
            # 인터페이스 하위 설정
            interface_config['config_lines'].append(line)
            
            # 인터페이스 속성 분석
            if line.startswith('ip address') and not line.startswith('no ip address'):
                # IP 주소 패턴 확인 (DHCP 제외)
                if not 'dhcp' in line.lower():
                    interface_config['has_ip_address'] = True
                    # IP 주소 추출
                    ip_match = re.search(r'ip address (\d+\.\d+\.\d+\.\d+)', line)
                    if ip_match:
                        interface_config['ip_address'] = ip_match.group(1)
            elif line.startswith('no ip address'):
                interface_config['has_ip_address'] = False
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
            elif 'encapsulation dot1q' in line.lower() or 'encapsulation dot1Q' in line:
                interface_config['has_vlan'] = True
                try:
                    vlan_match = re.search(r'dot1[qQ]\s+(\d+)', line)
                    if vlan_match:
                        interface_config['vlan_id'] = int(vlan_match.group(1))
                except:
                    pass
        
        # VTY 라인 파싱 개선
        elif line.startswith('line vty'):
            # 이전 VTY 저장
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
                'login_method': None,
                'access_class': None
            }
            current_section = 'vty'
            in_vty_section = True
            
        elif in_vty_section and current_vty and original_line.startswith(' ') and line:
            # VTY 하위 설정
            if 'password' in line:
                vty_config['has_password'] = True
            elif 'access-class' in line:
                vty_config['has_access_class'] = True
                # ACL 이름/번호 추출
                parts = line.split()
                if len(parts) >= 2:
                    for j in range(len(parts)):
                        if parts[j] == 'access-class' and j + 1 < len(parts):
                            vty_config['access_class'] = parts[j + 1]
                            break
            elif 'transport input' in line:
                transport_parts = line.split('transport input')
                if len(transport_parts) > 1:
                    vty_config['transport_input'] = transport_parts[1].strip().split()
            elif 'exec-timeout' in line:
                try:
                    timeout_parts = line.split()
                    if len(timeout_parts) >= 2:
                        minutes = int(timeout_parts[1])
                        seconds = int(timeout_parts[2]) if len(timeout_parts) > 2 else 0
                        vty_config['exec_timeout'] = minutes * 60 + seconds
                except:
                    pass
            elif line.strip() in ['login', 'login local']:
                vty_config['login_method'] = line.strip()
        
        # 다른 섹션 시작시 VTY 섹션 종료
        elif in_vty_section and not original_line.startswith(' ') and line and not line.startswith('!'):
            in_vty_section = False
            current_section = None
        
        # 🔧 수정된 부분: Domain lookup 파싱 로직
        elif line.startswith('no ip domain-lookup'):
            context.parsed_services['domain_lookup'] = False  # 명시적 비활성화
        elif line.startswith('ip domain-lookup'):
            context.parsed_services['domain_lookup'] = True   # 명시적 활성화
        elif line.startswith('no ip domain lookup'):  # 공백 포함 버전
            context.parsed_services['domain_lookup'] = False
        elif line.startswith('ip domain lookup'):
            context.parsed_services['domain_lookup'] = True
            
        # 🔧 수정된 부분: Source routing 파싱 로직 (전역 설정)
        elif line.startswith('no ip source-route'):
            context.parsed_services['source_route'] = False
        elif line.startswith('ip source-route'):
            context.parsed_services['source_route'] = True
        
        # 사용자 계정 파싱 개선
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
                    'password_encrypted': False,
                    'encryption_type': None,
                    'algorithm_type': None,
                    'is_modern_encryption': False,
                    'password_type': 'secret' if 'secret' in line else 'password'
                }
                
                # 권한 레벨 파싱
                if 'privilege' in line:
                    try:
                        priv_idx = user_parts.index('privilege')
                        if priv_idx + 1 < len(user_parts):
                            user_info['privilege_level'] = int(user_parts[priv_idx + 1])
                    except:
                        pass
                
                # 최신 algorithm-type 확인
                if 'algorithm-type' in line:
                    try:
                        algo_idx = user_parts.index('algorithm-type')
                        if algo_idx + 1 < len(user_parts):
                            algorithm = user_parts[algo_idx + 1]
                            user_info['algorithm_type'] = algorithm
                            if algorithm.lower() in ['sha256', 'scrypt', 'pbkdf2']:
                                user_info['is_modern_encryption'] = True
                                user_info['password_encrypted'] = True
                    except:
                        pass
                
                # 암호화 타입 확인 (기존 방식)
                if 'password' in line:
                    if '$' in line or ' 7 ' in line or ' 0 ' in line:
                        user_info['password_encrypted'] = True
                        if ' 9 $' in line:
                            user_info['encryption_type'] = 'type9_scrypt'
                            user_info['is_modern_encryption'] = True
                        elif ' 8 $' in line:
                            user_info['encryption_type'] = 'type8_pbkdf2'  
                            user_info['is_modern_encryption'] = True
                        elif ' 5 $' in line:
                            user_info['encryption_type'] = 'type5_md5'
                        elif ' 7 ' in line:
                            user_info['encryption_type'] = 'type7_weak'
                        elif ' 0 ' in line:
                            user_info['encryption_type'] = 'type0_plaintext'
                            user_info['password_encrypted'] = False
                
                elif 'secret' in line:
                    user_info['password_encrypted'] = True
                    if re.search(r'secret\s+9\s+\$', line):
                        user_info['encryption_type'] = 'type9_scrypt'
                        user_info['is_modern_encryption'] = True
                    elif re.search(r'secret\s+8\s+\$', line):
                        user_info['encryption_type'] = 'type8_pbkdf2'
                        user_info['is_modern_encryption'] = True
                    elif re.search(r'secret\s+5\s+\$', line) or '$1$' in line:
                        user_info['encryption_type'] = 'type5_md5'
                    elif re.search(r'secret\s+0\s+', line):
                        user_info['encryption_type'] = 'type0_plaintext'
                        user_info['password_encrypted'] = False
                    else:
                        user_info['encryption_type'] = 'type5_md5'
                
                context.parsed_users.append(user_info)
        
        # SNMP 커뮤니티 파싱 개선
        elif line.startswith('snmp-server community'):
            parts = line.split()
            if len(parts) >= 4:
                community = parts[2]
                # 권한 확인 (RO/RW)
                permission = 'RO'  # 기본값
                acl = None
                
                for part in parts[3:]:
                    upper_part = part.upper()
                    # 권한 판별 및 정규화
                    if upper_part in ['RO', 'READ-ONLY']:
                        permission = 'RO'
                    elif upper_part in ['RW', 'READ-WRITE']:
                        permission = 'RW'
                    else:
                        # ACL 가능성 여부 확인 (숫자, 알파벳+숫자+특수문자)
                        if re.match(r'^[\w\-]+$', part):
                            acl = part
                
                community_info = {
                    'community': community,
                    'line_number': i + 1,
                    'permission': permission,
                    'acl': acl,
                    'is_default': community.lower() in ['public', 'private'],
                    'length': len(community)
                }
                context.snmp_communities.append(community_info)
        
        # 나머지 파싱 로직들...
        # Enable password 확인
        elif line.startswith('enable '):
            if 'password' in line:
                context.global_settings['enable_password_type'] = 'password'
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




# ==================== 추가 공통 유틸리티 함수들 ====================

def _analyze_network_environment(context: ConfigContext) -> Dict[str, Any]:
    """네트워크 환경 분석"""
    external_interfaces = []
    has_nat = False
    has_public_ip = False
    
    for interface_name, interface_config in context.parsed_interfaces.items():
        # NAT outside 인터페이스 확인
        config_lines = interface_config.get('config_lines', [])
        if any('nat outside' in line for line in config_lines):
            external_interfaces.append(interface_name)
            has_nat = True
        
        # 공인 IP 확인
        ip_address = interface_config.get('ip_address', '')
        if ip_address and not _is_private_ip(ip_address):
            external_interfaces.append(interface_name)
            has_public_ip = True
        
        # 설명 기반 외부 인터페이스 판단
        description = interface_config.get('description', '').lower()
        external_keywords = ['isp', 'internet', 'wan', 'external', 'outside', 'uplink']
        if any(keyword in description for keyword in external_keywords):
            external_interfaces.append(interface_name)
    
    return {
        'has_external_connection': len(external_interfaces) > 0,
        'external_interfaces': list(set(external_interfaces)),
        'has_nat': has_nat,
        'has_public_ip': has_public_ip
    }


def _is_private_ip(ip_address: str) -> bool:
    """사설 IP 대역 확인"""
    if re.match(r'^10\.', ip_address):
        return True
    if re.match(r'^172\.(1[6-9]|2[0-9]|3[0-1])\.', ip_address):
        return True
    if re.match(r'^192\.168\.', ip_address):
        return True
    return False


def _analyze_spoofing_protection_acls(context: ConfigContext) -> Dict[str, bool]:
    """스푸핑 방지 ACL 분석"""
    acl_protections = {
        'private_ranges': False,
        'loopback': False,
        'broadcast': False,
        'multicast': False,
        'bogons': False
    }
    
    config_text = context.full_config.lower()
    
    # Private IP 차단 확인
    private_patterns = [
        r'deny.*ip.*10\.0\.0\.0.*0\.255\.255\.255',
        r'deny.*ip.*172\.1[6-9]\.0\.0',
        r'deny.*ip.*172\.2[0-9]\.0\.0',
        r'deny.*ip.*172\.3[0-1]\.0\.0',
        r'deny.*ip.*192\.168\.0\.0.*0\.0\.255\.255'
    ]
    
    if any(re.search(pattern, config_text) for pattern in private_patterns):
        acl_protections['private_ranges'] = True
    
    # 루프백 차단 확인
    if re.search(r'deny.*ip.*127\.0\.0\.0', config_text):
        acl_protections['loopback'] = True
    
    # 멀티캐스트 차단 확인  
    if re.search(r'deny.*ip.*22[4-9]\.|deny.*ip.*23[0-9]\.', config_text):
        acl_protections['multicast'] = True
    
    # 브로드캐스트 차단 확인
    if re.search(r'deny.*ip.*\.255', config_text):
        acl_protections['broadcast'] = True
    
    # Bogon 네트워크 차단 확인
    bogon_patterns = [
        r'deny.*ip.*0\.0\.0\.0',
        r'deny.*ip.*169\.254\.0\.0'
    ]
    if any(re.search(pattern, config_text) for pattern in bogon_patterns):
        acl_protections['bogons'] = True
    
    return acl_protections


def _analyze_routing_protocols(context: ConfigContext) -> Dict[str, List[Dict]]:
    """라우팅 프로토콜 설정 분석"""
    routing_protocols = {
        'ospf': [],
        'eigrp': [],
        'bgp': [],
        'rip': []
    }
    
    lines = context.config_lines
    current_protocol = None
    current_config = None
    
    for i, line in enumerate(lines):
        line_clean = line.strip()
        
        # 라우팅 프로토콜 시작
        if line_clean.startswith('router '):
            parts = line_clean.split()
            if len(parts) >= 2:
                protocol = parts[1].lower()
                if protocol in routing_protocols:
                    current_protocol = protocol
                    current_config = {
                        'line_number': i + 1,
                        'config_start': line_clean,
                        'has_authentication': False,
                        'auth_type': None,
                        'config_lines': [line_clean]
                    }
                    routing_protocols[protocol].append(current_config)
        
        # 프로토콜 설정 내부
        elif current_protocol and current_config:
            if line_clean and not line_clean.startswith('!'):
                current_config['config_lines'].append(line_clean)
                
                # 인증 키워드 확인
                auth_keywords = [
                    'authentication message-digest',
                    'authentication mode md5',
                    'neighbor.*password',
                    'area.*authentication',
                    'key chain',
                    'authentication key-chain'
                ]
                
                for keyword in auth_keywords:
                    if re.search(keyword, line_clean, re.IGNORECASE):
                        current_config['has_authentication'] = True
                        current_config['auth_type'] = keyword
                        break
        
        # 새 섹션 시작
        elif not line_clean.startswith(' ') and line_clean:
            current_protocol = None
            current_config = None
    
    return routing_protocols


def _find_referenced_interfaces(context: ConfigContext) -> set:
    """설정에서 참조되는 인터페이스들 찾기"""
    referenced = set()
    
    for line in context.config_lines:
        line = line.strip()
        
        # NAT 설정에서 참조
        if 'ip nat' in line and 'interface' in line:
            match = re.search(r'interface\s+(\S+)', line)
            if match:
                referenced.add(match.group(1))
        
        # 라우팅에서 참조 (network 명령어)
        if line.startswith('network '):
            # 해당 네트워크를 가진 인터페이스 찾기
            network_match = re.search(r'network\s+(\d+\.\d+\.\d+\.\d+)', line)
            if network_match:
                network = network_match.group(1)
                for iface_name, iface_config in context.parsed_interfaces.items():
                    if iface_config.get('ip_address', '').startswith(network[:7]):  # 간단한 매칭
                        referenced.add(iface_name)
        
        # HSRP, VRRP 등에서 참조
        if any(protocol in line for protocol in ['standby', 'vrrp', 'hsrp']):
            # 현재 인터페이스 컨텍스트에서 실행되는 명령어이므로 별도 처리 필요
            pass
    
    return referenced


# ==================== 지침서 지원 정보 ====================

# 지원되는 보안 지침서 목록 (NW 지침서 추가)
SUPPORTED_SOURCES = {
    "KISA": {
        "name": "KISA 네트워크 장비 보안 가이드",
        "description": "한국인터넷진흥원(KISA) 네트워크 장비 보안 점검 가이드라인",
        "version": "2021",
        "total_rules": 38,
        "categories": ["계정 관리", "접근 관리", "패치 관리", "로그 관리", "기능 관리"]
    },
    "CIS": {
        "name": "CIS Controls",
        "description": "Center for Internet Security Controls",
        "version": "v8",
        "total_rules": 89,
        "categories": ["계정 관리", "접근 관리", "로그 관리"]
    },
    "자체룰셋": {
        "name": "NW 네트워크 장비 보안 가이드",
        "description": "NW 네트워크 장비 보안 점검 가이드라인",
        "version": "2025",
        "total_rules": 42,
        "categories": ["계정 관리", "접근 관리", "패치 관리", "로그 관리", "기능 관리"]
    },
    "NIST": {
        "name": "NIST Cybersecurity Framework",
        "description": "National Institute of Standards and Technology Framework",
        "version": "2.0",
        "total_rules": 0,  # 구현 예정
        "categories": []
    }
}


# ==================== 룰셋 로딩 함수들 ====================

def load_rules(source: str) -> Dict[str, SecurityRule]:
    """
    지침서별 보안 룰셋 로드
    
    Args:
        source: 지침서 이름 ("KISA", "CIS", "자체룰셋", "NIST" etc)
        
    Returns:
        Dict[str, SecurityRule]: 룰 ID를 키로 하는 보안 룰 딕셔너리
        
    Raises:
        ValueError: 지원되지 않는 지침서인 경우
        ImportError: 해당 지침서 모듈을 찾을 수 없는 경우
        NotImplementedError: 해당 지침서가 아직 구현되지 않은 경우
    """
    source = source.upper()
    
    if source not in SUPPORTED_SOURCES:
        raise ValueError(f"지원되지 않는 지침서입니다: {source}. "
                        f"지원되는 지침서: {', '.join(SUPPORTED_SOURCES.keys())}")
    
    if source == "KISA":
        from .kisa_rules import KISA_RULES
        return KISA_RULES
    elif source == "CIS":
        from .cis_rules import CIS_RULES
        return CIS_RULES
    elif source == "자체룰셋":
        from .nw_rules import NW_RULES
        return NW_RULES
    elif source == "NIST":
        # 향후 구현 예정
        raise NotImplementedError("NIST 룰셋은 아직 구현되지 않았습니다.")
    else:
        raise ValueError(f"알 수 없는 지침서: {source}")


def load_all_rules() -> Dict[str, Dict[str, SecurityRule]]:
    """
    모든 지원되는 지침서의 룰셋 로드
    
    Returns:
        Dict[str, Dict[str, SecurityRule]]: 지침서별 룰셋 딕셔너리
    """
    all_rules = {}
    
    for source in SUPPORTED_SOURCES.keys():
        try:
            rules = load_rules(source)
            if rules:  # 빈 딕셔너리가 아닌 경우만 추가
                all_rules[source] = rules
        except (NotImplementedError, ImportError):
            # 아직 구현되지 않은 지침서는 스킵
            continue
    
    return all_rules


def get_supported_sources() -> Dict[str, Dict[str, Union[str, int, List[str]]]]:
    """
    지원되는 보안 지침서 목록 반환
    
    Returns:
        Dict: 지침서별 메타정보
    """
    return SUPPORTED_SOURCES.copy()


def get_source_info(source: str) -> Optional[Dict[str, Union[str, int, List[str]]]]:
    """
    특정 지침서의 정보 반환
    
    Args:
        source: 지침서 이름
        
    Returns:
        Dict: 지침서 메타정보 또는 None
    """
    return SUPPORTED_SOURCES.get(source.upper())


def combine_rules(*sources: str) -> Dict[str, SecurityRule]:
    """
    여러 지침서의 룰을 결합
    
    Args:
        *sources: 결합할 지침서 이름들
        
    Returns:
        Dict[str, SecurityRule]: 결합된 룰셋
        
    Note:
        룰 ID가 중복되는 경우, 나중에 로드된 지침서의 룰이 우선됩니다.
    """
    combined_rules = {}
    
    for source in sources:
        try:
            rules = load_rules(source)
            combined_rules.update(rules)
        except (ValueError, NotImplementedError, ImportError) as e:
            print(f"Warning: {source} 지침서 로드 실패: {e}")
    
    return combined_rules


def get_rules_by_device_type(source: str, device_type: str) -> Dict[str, SecurityRule]:
    """
    특정 지침서에서 장비 타입별 룰 필터링
    
    Args:
        source: 지침서 이름
        device_type: 장비 타입 ("Cisco", "Juniper" 등)
        
    Returns:
        Dict[str, SecurityRule]: 필터링된 룰셋
    """
    rules = load_rules(source)
    return {
        rule_id: rule for rule_id, rule in rules.items()
        if device_type in rule.device_types
    }


def get_rules_by_severity(source: str, severity: str) -> Dict[str, SecurityRule]:
    """
    특정 지침서에서 심각도별 룰 필터링
    
    Args:
        source: 지침서 이름
        severity: 심각도 ("상", "중", "하")
        
    Returns:
        Dict[str, SecurityRule]: 필터링된 룰셋
    """
    rules = load_rules(source)
    return {
        rule_id: rule for rule_id, rule in rules.items()
        if rule.severity == severity
    }


def get_rules_by_category(source: str, category: Union[str, RuleCategory]) -> Dict[str, SecurityRule]:
    """
    특정 지침서에서 카테고리별 룰 필터링
    
    Args:
        source: 지침서 이름
        category: 룰 카테고리
        
    Returns:
        Dict[str, SecurityRule]: 필터링된 룰셋
    """
    rules = load_rules(source)
    
    if isinstance(category, str):
        # 문자열인 경우 RuleCategory와 매칭
        target_category = None
        for cat in RuleCategory:
            if cat.value == category:
                target_category = cat
                break
        if not target_category:
            return {}
        category = target_category
    
    return {
        rule_id: rule for rule_id, rule in rules.items()
        if rule.category == category
    }


def get_rule_by_id(source: str, rule_id: str) -> Optional[SecurityRule]:
    """
    특정 지침서에서 룰 ID로 룰 조회
    
    Args:
        source: 지침서 이름
        rule_id: 룰 ID
        
    Returns:
        SecurityRule: 해당 룰 또는 None
    """
    rules = load_rules(source)
    return rules.get(rule_id)


def validate_rule_compatibility(rule: SecurityRule, device_type: str) -> bool:
    """
    룰과 장비 타입의 호환성 검증
    
    Args:
        rule: 보안 룰
        device_type: 장비 타입
        
    Returns:
        bool: 호환 여부
    """
    return device_type in rule.device_types


def get_statistics(source: str) -> Dict[str, Union[int, Dict[str, int]]]:
    """
    특정 지침서의 룰셋 통계 반환
    
    Args:
        source: 지침서 이름
        
    Returns:
        Dict: 룰셋 통계 정보
    """
    try:
        rules = load_rules(source)
        
        # 심각도별 통계
        severity_stats = {"상": 0, "중": 0, "하": 0}
        
        # 카테고리별 통계
        category_stats = {}
        
        # 장비별 통계
        device_stats = {}
        
        for rule in rules.values():
            # 심각도 통계
            if rule.severity in severity_stats:
                severity_stats[rule.severity] += 1
            
            # 카테고리 통계
            category_name = rule.category.value
            category_stats[category_name] = category_stats.get(category_name, 0) + 1
            
            # 장비 통계
            for device_type in rule.device_types:
                device_stats[device_type] = device_stats.get(device_type, 0) + 1
        
        return {
            "totalRules": len(rules),
            "severityStats": severity_stats,
            "categoryStats": category_stats,
            "deviceStats": device_stats,
            "logicalRules": sum(1 for rule in rules.values() if rule.logical_check_function is not None),
            "patternRules": sum(1 for rule in rules.values() if rule.patterns and rule.logical_check_function is None)
        }
        
    except (ValueError, NotImplementedError, ImportError):
        return {
            "totalRules": 0,
            "severityStats": {"상": 0, "중": 0, "하": 0},
            "categoryStats": {},
            "deviceStats": {},
            "logicalRules": 0,
            "patternRules": 0
        }


def get_all_supported_frameworks() -> List[str]:
    """
    지원되는 모든 지침서 이름 반환
    
    Returns:
        List[str]: 지침서 이름 리스트
    """
    return list(SUPPORTED_SOURCES.keys())


def get_implemented_frameworks() -> List[str]:
    """
    실제 구현된 지침서 이름 반환

    
    Returns:
        List[str]: 구현된 지침서 이름 리스트
    """
    implemented = []
    
    for source in SUPPORTED_SOURCES.keys():
        try:
            rules = load_rules(source)
            if rules:  # 룰이 있는 경우만 구현된 것으로 간주
                implemented.append(source)
        except (NotImplementedError, ImportError):
            continue
    
    return implemented


def validate_framework_availability(source: str) -> Dict[str, bool]:
    """
    지침서 사용 가능성 검증
    
    Args:
        source: 지침서 이름
        
    Returns:
        Dict[str, bool]: 검증 결과
    """
    source = source.upper()
    
    result = {
        'is_supported': source in SUPPORTED_SOURCES,
        'is_implemented': False,
        'has_rules': False,
        'rule_count': 0
    }
    
    if result['is_supported']:
        try:
            rules = load_rules(source)
            result['is_implemented'] = True
            result['has_rules'] = len(rules) > 0
            result['rule_count'] = len(rules)
        except (NotImplementedError, ImportError):
            pass
    
    return result


# 기존 호환성을 위한 함수들 (기본적으로 KISA 사용)
def get_all_rules() -> Dict[str, SecurityRule]:
    """모든 보안 룰 반환 (기본: KISA)"""
    return load_rules("KISA")


def get_rules_by_device_type_legacy(device_type: str) -> Dict[str, SecurityRule]:
    """특정 장비 타입에 적용 가능한 룰들만 반환 (기본: KISA)"""
    return get_rules_by_device_type("KISA", device_type)


def get_rules_by_severity_legacy(severity: str) -> Dict[str, SecurityRule]:
    """특정 심각도의 룰들만 반환 (기본: KISA)"""
    return get_rules_by_severity("KISA", severity)


def get_rules_by_category_legacy(category: Union[str, RuleCategory]) -> Dict[str, SecurityRule]:
    """특정 카테고리의 룰들만 반환 (기본: KISA)"""
    return get_rules_by_category("KISA", category)


def get_rule_by_id_legacy(rule_id: str) -> Optional[SecurityRule]:
    """특정 룰 ID로 룰 반환 (기본: KISA)"""
    return get_rule_by_id("KISA", rule_id)


# NW 지침서 전용 함수들
def get_nw_rules() -> Dict[str, SecurityRule]:
    """NW 지침서 룰셋 반환"""
    return load_rules("NW")


def get_nw_rules_by_device_type(device_type: str) -> Dict[str, SecurityRule]:
    """NW 지침서에서 특정 장비 타입 룰 반환"""
    return get_rules_by_device_type("NW", device_type)


def compare_frameworks(*sources: str) -> Dict[str, Dict[str, Union[int, List[str]]]]:
    """
    여러 지침서 간 비교 분석
    
    Args:
        *sources: 비교할 지침서 이름들
        
    Returns:
        Dict: 비교 분석 결과
    """
    comparison = {}
    
    for source in sources:
        try:
            rules = load_rules(source)
            stats = get_statistics(source)
            
            comparison[source] = {
                'total_rules': len(rules),
                'rule_ids': list(rules.keys()),
                'severity_distribution': stats['severityStats'],
                'category_distribution': stats['categoryStats'],
                'device_support': stats['deviceStats'],
                'logical_rules': stats['logicalRules'],
                'pattern_rules': stats['patternRules']
            }
        except (ValueError, NotImplementedError, ImportError) as e:
            comparison[source] = {
                'error': str(e),
                'total_rules': 0,
                'rule_ids': [],
                'is_available': False
            }
    
    return comparison