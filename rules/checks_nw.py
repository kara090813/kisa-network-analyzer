# -*- coding: utf-8 -*-
"""
rules/checks_nw.py
NW 네트워크 장비 보안 점검 룰의 논리적 검증 함수들

각 NW 룰에 대한 logical_check_function들을 정의
"""
import re
from typing import List, Dict, Any
from .kisa_rules import ConfigContext


def check_nw_01(line: str, line_num: int, context: ConfigContext) -> List[Dict[str, Any]]:
    """NW-01: 기본 패스워드 설정 - 완전한 논리 기반 분석"""
    vulnerabilities = []
    
    # 기본 패스워드 패턴들 (확장)
    basic_passwords = [
        'cisco', 'admin', 'password', '123', '1234', '12345', '123456',
        'default', 'pass', 'root', 'user', 'guest', 'test', 'temp',
        'switch', 'router', 'manager', 'security', 'public', 'private'
    ]
    
    # Enable 패스워드 검사
    if context.global_settings.get('enable_password_type') == 'password':
        password_value = context.global_settings.get('enable_password_value', '')
        if any(basic_pwd in password_value.lower() for basic_pwd in basic_passwords):
            vulnerabilities.append({
                'line': line_num,
                'matched_text': f"enable password {password_value}",
                'details': {
                    'password_type': 'enable_password',
                    'vulnerability': 'basic_password_used',
                    'password_value': password_value,
                    'recommendation': 'Use enable secret with strong password'
                }
            })
    
    # 사용자 패스워드 검사
    for user in context.parsed_users:
        if user['has_password'] and not user['password_encrypted']:
            # 기본 사용자명과 패스워드 체크
            if user['username'].lower() in basic_passwords:
                vulnerabilities.append({
                    'line': user['line_number'],
                    'matched_text': f"username {user['username']} with basic credentials",
                    'details': {
                        'password_type': 'user_password',
                        'vulnerability': 'basic_username_password',
                        'username': user['username']
                    }
                })
    
    return vulnerabilities


def check_nw_02(line: str, line_num: int, context: ConfigContext) -> List[Dict[str, Any]]:
    """NW-02: 패스워드 복잡성 설정 - 논리 기반 분석"""
    vulnerabilities = []
    
    # 패스워드 최소 길이 설정 확인
    has_min_length = 'passwords min-length' in context.full_config
    has_complexity_policy = any([
        'username-password combination high' in context.full_config,
        'password-policy' in context.full_config
    ])
    
    if not has_min_length and not has_complexity_policy:
        vulnerabilities.append({
            'line': 0,
            'matched_text': '패스워드 복잡성 정책 설정 누락',
            'details': {
                'vulnerability': 'no_password_complexity_policy',
                'recommendation': 'Configure password complexity policy'
            }
        })
    
    # 약한 패스워드 패턴 검사
    for user in context.parsed_users:
        if user['has_password'] and not user['password_encrypted']:
            vulnerabilities.append({
                'line': user['line_number'],
                'matched_text': f"username {user['username']} password (weak complexity)",
                'details': {
                    'vulnerability': 'weak_password_complexity',
                    'username': user['username'],
                    'recommendation': 'Use complex password with minimum 8 characters'
                }
            })
    
    return vulnerabilities


def check_nw_03(line: str, line_num: int, context: ConfigContext) -> List[Dict[str, Any]]:
    """NW-03: 암호화된 비밀번호 사용 - 논리 기반 분석"""
    vulnerabilities = []
    
    # Service password-encryption 확인
    password_encryption_enabled = context.parsed_services.get('password-encryption', False)
    
    # Enable password vs secret 확인
    if context.global_settings.get('enable_password_type') == 'password':
        vulnerabilities.append({
            'line': 0,
            'matched_text': 'enable password (not secret)',
            'details': {
                'vulnerability': 'enable_password_not_secret',
                'recommendation': 'Use enable secret instead of enable password'
            }
        })
    
    # 암호화되지 않은 사용자 패스워드 확인
    unencrypted_users = [user for user in context.parsed_users if user['has_password'] and not user['password_encrypted']]
    
    if unencrypted_users:
        for user in unencrypted_users:
            vulnerabilities.append({
                'line': user['line_number'],
                'matched_text': f"username {user['username']} password (unencrypted)",
                'details': {
                    'vulnerability': 'unencrypted_user_password',
                    'username': user['username'],
                    'recommendation': 'Use username secret or enable service password-encryption'
                }
            })
    
    if not password_encryption_enabled and unencrypted_users:
        vulnerabilities.append({
            'line': 0,
            'matched_text': 'service password-encryption not enabled',
            'details': {
                'vulnerability': 'password_encryption_disabled',
                'recommendation': 'Enable service password-encryption'
            }
        })
    
    return vulnerabilities


def check_nw_04(line: str, line_num: int, context: ConfigContext) -> List[Dict[str, Any]]:
    """NW-04: 사용자·명령어별 권한 수준 설정 - 완전한 논리 기반 분석"""
    vulnerabilities = []
    
    # 모든 사용자가 최고 권한(privilege 15)을 가지는지 확인
    high_privilege_users = []
    total_users = len(context.parsed_users)
    
    for user in context.parsed_users:
        if user.get('privilege_level', 1) == 15:
            high_privilege_users.append(user)
    
    # 모든 사용자가 최고 권한을 가지는 경우
    if len(high_privilege_users) == total_users and total_users > 1:
        vulnerabilities.append({
            'line': 0,
            'matched_text': f"All {total_users} users have maximum privilege level 15",
            'details': {
                'vulnerability': 'all_users_max_privilege',
                'high_privilege_count': len(high_privilege_users),
                'total_users': total_users,
                'recommendation': 'Assign different privilege levels based on user roles'
            }
        })
    
    # 개별 사용자별 높은 권한 경고
    for user in high_privilege_users:
        if len(high_privilege_users) > 1:  # 여러 사용자가 최고 권한을 가지는 경우만
            vulnerabilities.append({
                'line': user['line_number'],
                'matched_text': f"username {user['username']} privilege 15",
                'details': {
                    'vulnerability': 'excessive_user_privilege',
                    'username': user['username'],
                    'privilege_level': user['privilege_level'],
                    'recommendation': 'Consider lower privilege level for this user'
                }
            })
    
    return vulnerabilities


def check_nw_05(line: str, line_num: int, context: ConfigContext) -> List[Dict[str, Any]]:
    """NW-05: VTY 접근(ACL) 설정 - 완전한 논리 기반 분석"""
    vulnerabilities = []
    
    for vty_line in context.vty_lines:
        issues = []
        
        # Access-class 확인
        if not vty_line['has_access_class']:
            issues.append('no_access_class')
        
        # Transport input 확인  
        transport_input = vty_line.get('transport_input', [])
        if 'all' in transport_input:
            issues.append('transport_all_allowed')
        
        # 패스워드 확인
        if not vty_line['has_password']:
            issues.append('no_password')
        
        if issues:
            vulnerability_details = {
                'line': vty_line['line_number'],
                'matched_text': vty_line['line'],
                'details': {
                    'issues': issues,
                    'vty_config': vty_line,
                    'has_access_class': vty_line['has_access_class'],
                    'transport_input': transport_input,
                    'recommendation': 'Configure access-class for VTY lines to restrict source IPs'
                }
            }
            vulnerabilities.append(vulnerability_details)
    
    return vulnerabilities


def check_nw_06(line: str, line_num: int, context: ConfigContext) -> List[Dict[str, Any]]:
    """NW-06: Session Timeout 설정 - 논리 기반 분석"""
    vulnerabilities = []
    
    for vty_line in context.vty_lines:
        exec_timeout = vty_line.get('exec_timeout')
        
        if exec_timeout is None:
            # 타임아웃 설정이 없음
            vulnerabilities.append({
                'line': vty_line['line_number'],
                'matched_text': vty_line['line'],
                'details': {
                    'vulnerability': 'no_exec_timeout',
                    'recommendation': 'Set exec-timeout 5 0 (5 minutes)'
                }
            })
        elif exec_timeout == 0:
            # 무제한 타임아웃
            vulnerabilities.append({
                'line': vty_line['line_number'],
                'matched_text': f"{vty_line['line']} (exec-timeout 0 0)",
                'details': {
                    'vulnerability': 'infinite_timeout',
                    'timeout_value': exec_timeout,
                    'recommendation': 'Set exec-timeout 5 0 (5 minutes)'
                }
            })
        elif exec_timeout > 300:  # 5분 초과
            vulnerabilities.append({
                'line': vty_line['line_number'],
                'matched_text': f"{vty_line['line']} (timeout: {exec_timeout}s)",
                'details': {
                    'vulnerability': 'excessive_timeout',
                    'timeout_value': exec_timeout,
                    'timeout_minutes': exec_timeout // 60,
                    'recommendation': 'Set exec-timeout to 5 minutes or less'
                }
            })
    
    return vulnerabilities


def check_nw_08(line: str, line_num: int, context: ConfigContext) -> List[Dict[str, Any]]:
    """NW-08: 불필요한 보조 입출력 포트 사용 금지 - 완전한 논리 기반 분석"""
    vulnerabilities = []
    
    for interface_name, interface_config in context.parsed_interfaces.items():
        # 사용 중인지 판단
        is_used = (
            interface_config['has_ip_address'] or
            interface_config['has_description'] or
            interface_config['has_vlan'] or
            interface_config['is_loopback'] or
            interface_config['is_management'] or
            interface_config['has_switchport']
        )
        
        is_active = not interface_config['is_shutdown']
        
        # 중요 인터페이스 예외 처리
        is_critical = _is_critical_interface_nw(interface_name, context.device_type)
        
        # 물리적 인터페이스만 체크 (VLAN, Loopback 제외)
        is_physical = interface_config['port_type'] in ['FastEthernet', 'GigabitEthernet', 'TenGigabitEthernet', 'Serial']
        
        # 보조 포트 판별 (AUX, Console 등)
        is_auxiliary_port = any(aux_type in interface_name.lower() for aux_type in ['aux', 'console', 'mgmt'])
        
        if not is_used and is_active and not is_critical and (is_physical or is_auxiliary_port):
            vulnerabilities.append({
                'line': interface_config['line_number'],
                'matched_text': f"interface {interface_name}",
                'details': {
                    'interface_name': interface_name,
                    'port_type': interface_config['port_type'],
                    'reason': 'Unused auxiliary or physical interface not shutdown',
                    'is_auxiliary': is_auxiliary_port,
                    'is_physical': is_physical,
                    'has_ip': interface_config['has_ip_address'],
                    'has_description': interface_config['has_description'],
                    'is_shutdown': interface_config['is_shutdown'],
                    'recommendation': 'Shutdown unused interfaces to prevent unauthorized access'
                }
            })
    
    return vulnerabilities


def _is_critical_interface_nw(interface_name: str, device_type: str) -> bool:
    """중요 인터페이스 여부 판별 - NW 지침서용 강화된 버전"""
    interface_lower = interface_name.lower()
    
    # 항상 중요한 인터페이스들
    critical_patterns = ['loopback', 'management', 'tunnel', 'vlan1']
    
    if any(pattern in interface_lower for pattern in critical_patterns):
        return True
    
    # 장비별 특정 중요 인터페이스
    if device_type in ["Cisco", "Juniper"]:
        # 첫 번째 물리 포트들은 일반적으로 업링크
        if (interface_lower.startswith('gi0/0') or interface_lower.startswith('fa0/0') or 
            interface_lower.startswith('gigabitethernet0/0') or interface_lower.startswith('fastethernet0/0')):
            return True
        
        # Serial 인터페이스는 WAN 연결용으로 중요
        if interface_lower.startswith('serial'):
            return True
    
    return False


def check_nw_11(line: str, line_num: int, context: ConfigContext) -> List[Dict[str, Any]]:
    """NW-11: 원격 로그서버 사용 - 논리 기반 분석"""
    vulnerabilities = []
    
    # 원격 로그 서버 설정 확인
    has_remote_logging = any([
        'logging' in context.full_config and any(
            f'{ip[0]}.{ip[1]}.{ip[2]}.{ip[3]}' in context.full_config 
            for ip in [[i,j,k,l] for i in range(1,255) for j in range(0,255) for k in range(0,255) for l in range(1,255)][:10]
        ),
        'syslog host' in context.full_config,
        'logging server' in context.full_config,
        'syslog remote' in context.full_config
    ])
    
    # IP 패턴으로 로그 서버 검색 (간소화된 방법)
    import re
    ip_pattern = r'logging\s+(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})'
    log_servers = re.findall(ip_pattern, context.full_config)
    
    if not log_servers and not has_remote_logging:
        vulnerabilities.append({
            'line': 0,
            'matched_text': 'No remote logging server configured',
            'details': {
                'vulnerability': 'no_remote_logging',
                'recommendation': 'Configure remote syslog server for log storage and analysis'
            }
        })
    
    return vulnerabilities


def check_nw_14(line: str, line_num: int, context: ConfigContext) -> List[Dict[str, Any]]:
    """NW-14: NTP 서버 연동 - 논리 기반 분석"""
    vulnerabilities = []
    
    # NTP 서버 설정 확인
    ntp_configured = any([
        'ntp server' in context.full_config,
        'sntp server' in context.full_config,
        'ntp enable' in context.full_config,
        'clock timezone' in context.full_config
    ])
    
    if not ntp_configured:
        vulnerabilities.append({
            'line': 0,
            'matched_text': 'No NTP server configuration found',
            'details': {
                'vulnerability': 'no_ntp_configuration',
                'recommendation': 'Configure NTP server for time synchronization'
            }
        })
    
    return vulnerabilities


def check_nw_16(line: str, line_num: int, context: ConfigContext) -> List[Dict[str, Any]]:
    """NW-16: SNMP 서비스 확인 - 논리 기반 분석"""
    vulnerabilities = []
    
    # SNMP 서비스 활성화 상태 확인
    snmp_enabled = len(context.snmp_communities) > 0 or any([
        'snmp-server enable' in context.full_config,
        'snmp enable' in context.full_config
    ])
    
    snmp_disabled = any([
        'no snmp-server' in context.full_config,
        'snmp disable' in context.full_config
    ])
    
    if snmp_enabled and not snmp_disabled:
        vulnerabilities.append({
            'line': 0,
            'matched_text': 'SNMP service is enabled',
            'details': {
                'vulnerability': 'snmp_service_enabled',
                'snmp_communities': len(context.snmp_communities),
                'recommendation': 'Disable SNMP service if not required for network management'
            }
        })
    
    return vulnerabilities


def check_nw_17(line: str, line_num: int, context: ConfigContext) -> List[Dict[str, Any]]:
    """NW-17: SNMP community string 복잡성 설정 - 논리 기반 분석"""
    vulnerabilities = []
    
    for community_info in context.snmp_communities:
        issues = []
        
        # 기본 커뮤니티 스트링 확인
        if community_info['is_default']:
            issues.append('default_community')
        
        # 길이 확인 (8자 미만)
        if community_info['length'] < 8:
            issues.append('too_short')
        
        # 단순한 패턴 확인
        simple_patterns = ['123', '456', '111', '000', 'admin', 'test', 'temp', 'snmp']
        if any(pattern in community_info['community'].lower() for pattern in simple_patterns):
            issues.append('simple_pattern')
        
        # 복잡성 부족 (숫자만 또는 문자만)
        community = community_info['community']
        if community.isdigit() or community.isalpha():
            issues.append('lacks_complexity')
        
        if issues:
            vulnerabilities.append({
                'line': community_info['line_number'],
                'matched_text': f"snmp-server community {community_info['community']}",
                'details': {
                    'community': community_info['community'],
                    'issues': issues,
                    'community_length': community_info['length'],
                    'recommendation': 'Use complex community string with minimum 8 characters'
                }
            })
    
    return vulnerabilities


def check_nw_18(line: str, line_num: int, context: ConfigContext) -> List[Dict[str, Any]]:
    """NW-18: SNMP ACL 설정 - 논리 기반 분석"""
    vulnerabilities = []
    
    for community_info in context.snmp_communities:
        # ACL 설정 확인
        if not community_info.get('acl'):
            vulnerabilities.append({
                'line': community_info['line_number'],
                'matched_text': f"snmp-server community {community_info['community']}",
                'details': {
                    'community': community_info['community'],
                    'vulnerability': 'no_acl_configured',
                    'permission': community_info.get('permission', 'unknown'),
                    'recommendation': 'Configure ACL to restrict SNMP access to authorized hosts only'
                }
            })
    
    return vulnerabilities


def check_nw_19(line: str, line_num: int, context: ConfigContext) -> List[Dict[str, Any]]:
    """NW-19: SNMP 커뮤니티 권한 설정 - 논리 기반 분석"""
    vulnerabilities = []
    
    for community_info in context.snmp_communities:
        permission = community_info.get('permission', '').upper()
        
        # RW(Read-Write) 권한 확인
        if permission in ['RW', 'READ-WRITE']:
            vulnerabilities.append({
                'line': community_info['line_number'],
                'matched_text': f"snmp-server community {community_info['community']} {permission}",
                'details': {
                    'community': community_info['community'],
                    'vulnerability': 'excessive_snmp_permission',
                    'current_permission': permission,
                    'recommendation': 'Change SNMP community permission to RO (Read-Only) unless write access is required'
                }
            })
    
    return vulnerabilities


def check_nw_21(line: str, line_num: int, context: ConfigContext) -> List[Dict[str, Any]]:
    """NW-21: Spoofing 방지 필터링 적용 - 논리 기반 분석"""
    vulnerabilities = []
    
    # 스푸핑 방지를 위한 주요 네트워크 차단 확인
    spoofing_blocks = {
        'loopback': r'access-list\s+\d+\s+deny\s+ip\s+127\.0\.0\.0\s+0\.255\.255\.255',
        'private_10': r'access-list\s+\d+\s+deny\s+ip\s+10\.0\.0\.0\s+0\.255\.255\.255',
        'private_172': r'access-list\s+\d+\s+deny\s+ip\s+172\.16\.0\.0\s+0\.15\.255\.255',
        'private_192': r'access-list\s+\d+\s+deny\s+ip\s+192\.168\.0\.0\s+0\.0\.255\.255',
        'broadcast': r'access-list\s+\d+\s+deny\s+ip\s+\d+\.\d+\.\d+\.255',
        'multicast': r'access-list\s+\d+\s+deny\s+ip\s+22[4-9]\.',
    }
    
    # Juniper 방화벽 필터 확인
    juniper_filters = [
        'firewall family inet filter',
        'policy-options prefix-list',
        'term anti-spoofing'
    ]
    
    missing_protections = []
    
    # Cisco ACL 기반 스푸핑 보호 확인
    for protection_type, pattern in spoofing_blocks.items():
        if not any(re.search(pattern, context.full_config, re.IGNORECASE) for pattern in [pattern]):
            missing_protections.append(protection_type)
    
    # Juniper 필터 확인
    has_juniper_protection = any(filter_type in context.full_config for filter_type in juniper_filters)
    
    # ACL이 전혀 없거나 기본 스푸핑 보호가 부족한 경우
    if len(missing_protections) >= 3 and not has_juniper_protection:
        vulnerabilities.append({
            'line': 0,
            'matched_text': 'Insufficient anti-spoofing protection',
            'details': {
                'vulnerability': 'inadequate_spoofing_protection',
                'missing_protections': missing_protections,
                'has_juniper_protection': has_juniper_protection,
                'recommendation': 'Configure ACLs to block spoofed source addresses (loopback, private ranges, broadcast)'
            }
        })
    
    return vulnerabilities


def check_nw_23(line: str, line_num: int, context: ConfigContext) -> List[Dict[str, Any]]:
    """NW-23: 사용하지 않는 인터페이스의 Shutdown 설정 - 원본 config 직접 파싱"""
    vulnerabilities = []
    
    try:
        print(f"\n=== NW-23 RAW CONFIG 파싱 시작 ===")
        
        # 1. 원본 config에서 인터페이스 직접 추출
        if hasattr(context, 'config_lines'):
            config_lines = context.config_lines
        elif hasattr(context, 'full_config'):
            config_lines = context.full_config.split('\n')
        else:
            print("ERROR: config 데이터를 찾을 수 없음!")
            return vulnerabilities
        
        print(f"총 config 라인 수: {len(config_lines)}")
        
        # 2. 인터페이스 블록 직접 파싱
        interfaces = {}
        current_interface = None
        current_config = []
        
        for i, line in enumerate(config_lines):
            line_clean = line.strip()
            
            # 인터페이스 시작 감지
            if line_clean.startswith('interface '):
                # 이전 인터페이스 저장
                if current_interface:
                    interfaces[current_interface] = {
                        'line_number': interfaces[current_interface]['line_number'],
                        'config_lines': current_config.copy()
                    }
                
                # 새 인터페이스 시작
                interface_name = line_clean.replace('interface ', '').strip()
                current_interface = interface_name
                current_config = [line_clean]
                interfaces[interface_name] = {'line_number': i + 1}
                print(f"인터페이스 발견: {interface_name} (라인 {i + 1})")
                
            # 인터페이스 내부 설정
            elif current_interface and (line_clean.startswith(' ') or line_clean == ''):
                if line_clean:  # 빈 줄이 아닌 경우만
                    current_config.append(line_clean)
                    
            # 인터페이스 블록 종료 (새로운 섹션 시작 또는 파일 끝)
            elif current_interface and line_clean and not line_clean.startswith(' '):
                # 이전 인터페이스 저장
                interfaces[current_interface] = {
                    'line_number': interfaces[current_interface]['line_number'],
                    'config_lines': current_config.copy()
                }
                current_interface = None
                current_config = []
        
        # 마지막 인터페이스 저장
        if current_interface:
            interfaces[current_interface] = {
                'line_number': interfaces[current_interface]['line_number'],
                'config_lines': current_config.copy()
            }
        
        print(f"파싱된 인터페이스 수: {len(interfaces)}")
        for name in interfaces.keys():
            print(f"  - {name}")
        
        # 3. 각 인터페이스 분석
        for interface_name, interface_data in interfaces.items():
            print(f"\n--- 분석 중: {interface_name} ---")
            config_lines = interface_data['config_lines']
            print(f"설정 라인 수: {len(config_lines)}")
            for line in config_lines:
                print(f"  {line}")
            
            # Step 1: 물리적 인터페이스 확인
            name_lower = interface_name.lower()
            
            # 가상 인터페이스 제외
            virtual_types = ['loopback', 'tunnel', 'vlan', 'bvi', 'dialer', 'null']
            if any(v in name_lower for v in virtual_types):
                print(f"  -> 가상 인터페이스 제외")
                continue
            
            # 물리적 인터페이스 확인
            physical_types = ['gigabitethernet', 'fastethernet', 'ethernet', 'serial']
            is_physical = any(p in name_lower for p in physical_types)
            print(f"  -> 물리적 인터페이스: {is_physical}")
            
            if not is_physical:
                continue
            
            # Step 2: shutdown 확인
            has_shutdown = any('shutdown' in line.strip().lower() for line in config_lines[1:])  # 첫 번째 라인(interface) 제외
            print(f"  -> shutdown 설정: {has_shutdown}")
            
            if has_shutdown:
                continue
            
            # Step 3: 사용 여부 확인
            
            # IP 주소 확인
            has_real_ip = False
            has_no_ip = False
            for line in config_lines:
                line_lower = line.strip().lower()
                if 'ip address' in line_lower:
                    if 'no ip address' in line_lower:
                        has_no_ip = True
                        print(f"    -> 'no ip address' 발견: {line.strip()}")
                    elif not 'dhcp' in line_lower:
                        has_real_ip = True
                        print(f"    -> 실제 IP 주소 발견: {line.strip()}")
            
            # 설명 확인
            has_description = any('description' in line.strip().lower() for line in config_lines)
            if has_description:
                for line in config_lines:
                    if 'description' in line.strip().lower():
                        print(f"    -> 설명 발견: {line.strip()}")
                        break
            
            # VLAN 설정 확인
            vlan_keywords = ['switchport', 'encapsulation dot1q', 'trunk']
            has_vlan = False
            for line in config_lines:
                line_lower = line.strip().lower()
                if any(keyword in line_lower for keyword in vlan_keywords):
                    has_vlan = True
                    print(f"    -> VLAN 설정 발견: {line.strip()}")
                    break
            
            # 기타 의미있는 설정
            meaningful_keywords = ['channel-group', 'port-security', 'access-group']
            has_meaningful = False
            for line in config_lines:
                line_lower = line.strip().lower()
                if any(keyword in line_lower for keyword in meaningful_keywords):
                    has_meaningful = True
                    print(f"    -> 의미있는 설정 발견: {line.strip()}")
                    break
            
            print(f"  -> IP: {has_real_ip}, 설명: {has_description}, VLAN: {has_vlan}, 기타: {has_meaningful}")
            
            # Step 4: 중요 인터페이스 예외
            is_critical = False
            
            # 관리 인터페이스
            if any(mgmt in name_lower for mgmt in ['management', 'mgmt', 'console']):
                is_critical = True
                print(f"  -> 관리 인터페이스")
            
            # 설명에 중요 키워드
            if has_description:
                for line in config_lines:
                    if 'description' in line.lower():
                        desc_line = line.lower()
                        important_words = ['uplink', 'trunk', 'core', 'wan', 'internet', 'isp', 'link to']
                        if any(word in desc_line for word in important_words):
                            is_critical = True
                            print(f"  -> 중요 설명: {line.strip()}")
                        break
            
            # 0/0 포트이면서 사용 중
            if '0/0' in interface_name and (has_real_ip or has_description or has_vlan):
                is_critical = True
                print(f"  -> 0/0 포트이면서 사용 중")
            
            # 서브인터페이스 확인
            base_name = interface_name.split('.')[0]
            subinterfaces = [name for name in interfaces.keys() if name.startswith(f"{base_name}.")]
            if subinterfaces:
                is_critical = True
                print(f"  -> 서브인터페이스 있음: {subinterfaces}")
            
            print(f"  -> 중요 인터페이스: {is_critical}")
            
            # Step 5: 최종 판정
            is_used = has_real_ip or has_description or has_vlan or has_meaningful
            is_vulnerable = not is_used and not is_critical
            
            print(f"  -> 사용 중: {is_used}")
            print(f"  -> 취약점: {is_vulnerable}")
            
            if is_vulnerable:
                print(f"  *** 취약점 발견! ***")
                vulnerabilities.append({
                    'line': interface_data['line_number'],
                    'matched_text': f"interface {interface_name}",
                    'details': {
                        'interface_name': interface_name,
                        'reason': 'Unused physical interface not shutdown',
                        'security_risk': 'Potential unauthorized physical access point',
                        'config_analysis': {
                            'has_real_ip': has_real_ip,
                            'has_no_ip': has_no_ip,
                            'has_description': has_description,
                            'has_vlan': has_vlan,
                            'has_meaningful': has_meaningful,
                            'is_critical': is_critical,
                            'raw_config': config_lines
                        },
                        'recommendation': 'Add "shutdown" command to disable unused interface'
                    }
                })
        
        print(f"\n=== 최종 결과: {len(vulnerabilities)}개 취약점 발견 ===")
        
    except Exception as e:
        print(f"ERROR in check_nw_23: {str(e)}")
        import traceback
        traceback.print_exc()
    
    return vulnerabilities


# 기존의 모든 복잡한 헬퍼 함수들을 제거하고 사용하지 않음
# 다른 룰에서 사용하는 경우를 위해 스텁 함수들만 남김

def _comprehensive_usage_analysis(interface_name, interface_config, context, network_context, learned_patterns):
    """더 이상 사용하지 않음 - 스텁 함수"""
    return {
        'usage_probability': 0.5,
        'confidence_level': 0.5,
        'layer_results': {},
        'primary_indicators': []
    }

def _enhanced_basic_usage_check(interface_name, interface_config, all_interfaces):
    """더 이상 사용하지 않음 - 스텁 함수"""
    return interface_config.get('has_ip_address', False) or interface_config.get('has_description', False)

def _analyze_configuration_complexity(interface_config):
    """더 이상 사용하지 않음 - 스텁 함수"""
    return {'usage_probability': 0.5, 'complexity_breakdown': {}}

def _analyze_network_context(interface_name, interface_config, network_context):
    """더 이상 사용하지 않음 - 스텁 함수"""
    return {'usage_probability': 0.5}

def _learn_organizational_patterns(all_interfaces):
    """더 이상 사용하지 않음 - 스텁 함수"""
    return {'used_keywords': {}, 'unused_keywords': {}, 'total_samples': 0}

def _match_organizational_patterns(interface_config, learned_patterns):
    """더 이상 사용하지 않음 - 스텁 함수"""
    return {'usage_probability': 0.5}

def _analyze_port_density(interface_name, all_interfaces):
    """더 이상 사용하지 않음 - 스텁 함수"""
    return {'usage_probability': 0.5, 'density_ratio': 0.5}

def _has_meaningful_ip_config(interface_config):
    """더 이상 사용하지 않음 - 스텁 함수"""
    return False

def _is_channel_member(interface_config):
    """더 이상 사용하지 않음 - 스텁 함수"""
    return False

def _has_active_subinterfaces(interface_name, all_interfaces):
    """더 이상 사용하지 않음 - 스텁 함수"""
    return False

def _has_special_protocol_config(interface_config):
    """더 이상 사용하지 않음 - 스텁 함수"""
    return False

def _is_physical_interface_enhanced(interface_name, device_type):
    """더 이상 사용하지 않음 - 스텁 함수"""
    return True

def _is_critical_interface_enhanced(interface_name, device_type, interface_config):
    """더 이상 사용하지 않음 - 스텁 함수"""
    return False

def _analyze_global_network_context(all_interfaces):
    """더 이상 사용하지 않음 - 스텁 함수"""
    return {'total_interfaces': 0, 'used_interfaces': 0, 'usage_ratio': 0, 'network_size': 'medium'}

def _analyze_port_position(interface_name, network_context):
    """더 이상 사용하지 않음 - 스텁 함수"""
    return 0.5

def _analyze_vlan_usage_context(interface_config, network_context):
    """더 이상 사용하지 않음 - 스텁 함수"""
    return 0.5

def _analyze_interface_type_pattern(interface_config, network_context):
    """더 이상 사용하지 않음 - 스텁 함수"""
    return 0.5

def _extract_keywords_from_descriptions(descriptions):
    """더 이상 사용하지 않음 - 스텁 함수"""
    return {}

def _find_adjacent_ports(interface_name, all_interfaces):
    """더 이상 사용하지 않음 - 스텁 함수"""
    return []

def _extract_port_number(interface_name):
    """더 이상 사용하지 않음 - 스텁 함수"""
    import re
    match = re.search(r'(\d+)(?:/\d+)*$', interface_name)
    return int(match.group(1)) if match else None

def _is_first_port_by_device(interface_name, device_type):
    """더 이상 사용하지 않음 - 스텁 함수"""
    return '0/0' in interface_name

def _calculate_analysis_confidence(scores):
    """더 이상 사용하지 않음 - 스텁 함수"""
    return 0.5

def _calculate_analysis_confidence_enhanced(scores, interface_config):
    """더 이상 사용하지 않음 - 스텁 함수"""
    return 0.5

def _extract_primary_indicators(analysis_results, interface_config):
    """더 이상 사용하지 않음 - 스텁 함수"""
    return []

def _calculate_risk_level(usage_analysis):
    """더 이상 사용하지 않음 - 스텁 함수"""
    return "Medium"

def _is_critical_interface_nw23(interface_name: str, device_type: str) -> bool:
    """더 이상 사용하지 않음 - 스텁 함수"""
    return False

def check_nw_33(line: str, line_num: int, context: ConfigContext) -> List[Dict[str, Any]]:
    """NW-33: ICMP unreachable, Redirect 차단 - 논리 기반 분석"""
    vulnerabilities = []
    
    # 각 인터페이스별로 ICMP unreachables와 redirects 설정 확인
    for interface_name, interface_config in context.parsed_interfaces.items():
        issues = []
        
        # 물리적 인터페이스만 체크 (Loopback 제외)
        if interface_config['is_loopback']:
            continue
            
        # 인터페이스 설정에서 ICMP 설정 확인
        interface_lines = interface_config.get('config_lines', [])
        has_no_unreachables = any('no ip unreachables' in line for line in interface_lines)
        has_no_redirects = any('no ip redirects' in line for line in interface_lines)
        
        # 글로벌 설정에서도 확인
        global_no_unreachables = 'no ip unreachables' in context.full_config
        global_no_redirects = 'no ip redirects' in context.full_config
        
        if not (has_no_unreachables or global_no_unreachables):
            issues.append('unreachables_not_disabled')
            
        if not (has_no_redirects or global_no_redirects):
            issues.append('redirects_not_disabled')
        
        if issues:
            vulnerabilities.append({
                'line': interface_config['line_number'],
                'matched_text': f"interface {interface_name}",
                'details': {
                    'interface_name': interface_name,
                    'issues': issues,
                    'has_no_unreachables': has_no_unreachables or global_no_unreachables,
                    'has_no_redirects': has_no_redirects or global_no_redirects,
                    'recommendation': 'Configure no ip unreachables and no ip redirects on each interface'
                }
            })
    
    return vulnerabilities


def check_nw_38(line: str, line_num: int, context: ConfigContext) -> List[Dict[str, Any]]:
    """NW-38: 스위치, 허브 보안 강화 - 논리 기반 분석"""
    vulnerabilities = []
    
    # 스위치 포트 보안 설정 확인
    for interface_name, interface_config in context.parsed_interfaces.items():
        # 스위치포트 모드가 access인 인터페이스만 체크
        if not interface_config.get('has_switchport', False):
            continue
            
        interface_lines = interface_config.get('config_lines', [])
        
        # switchport mode access 확인
        is_access_mode = any('switchport mode access' in line for line in interface_lines)
        
        # port-security 설정 확인
        has_port_security = any('switchport port-security' in line for line in interface_lines)
        
        if is_access_mode and not has_port_security:
            vulnerabilities.append({
                'line': interface_config['line_number'],
                'matched_text': f"interface {interface_name}",
                'details': {
                    'interface_name': interface_name,
                    'vulnerability': 'no_port_security',
                    'port_mode': 'access',
                    'has_port_security': has_port_security,
                    'recommendation': 'Configure switchport port-security to prevent MAC flooding attacks'
                }
            })
    
    # DHCP snooping 확인
    dhcp_snooping_enabled = 'ip dhcp snooping' in context.full_config
    
    if not dhcp_snooping_enabled:
        vulnerabilities.append({
            'line': 0,
            'matched_text': 'Missing DHCP snooping configuration',
            'details': {
                'vulnerability': 'no_dhcp_snooping',
                'recommendation': 'Enable DHCP snooping to prevent DHCP spoofing attacks'
            }
        })
    
    return vulnerabilities


def check_nw_40(line: str, line_num: int, context: ConfigContext) -> List[Dict[str, Any]]:
    """NW-40: 동적 라우팅 프로토콜 인증 여부 - 논리 기반 분석"""
    vulnerabilities = []
    
    # 라우팅 프로토콜 설정 확인
    routing_protocols = {
        'ospf': [],
        'rip': [],
        'eigrp': [],
        'bgp': []
    }
    
    lines = context.config_lines
    current_protocol = None
    
    for i, line in enumerate(lines):
        line_clean = line.strip()
        
        # 라우팅 프로토콜 시작 확인
        if line_clean.startswith('router '):
            protocol_parts = line_clean.split()
            if len(protocol_parts) >= 2:
                protocol_type = protocol_parts[1].lower()
                if protocol_type in routing_protocols:
                    current_protocol = protocol_type
                    routing_protocols[protocol_type].append({
                        'line_number': i + 1,
                        'config_start': line_clean,
                        'has_authentication': False,
                        'authentication_type': None
                    })
        
        # 인증 설정 확인
        elif current_protocol and line_clean and not line_clean.startswith('!'):
            if routing_protocols[current_protocol]:
                current_config = routing_protocols[current_protocol][-1]
                
                if any(auth_keyword in line_clean for auth_keyword in [
                    'authentication message-digest',
                    'authentication-key',
                    'message-digest-key',
                    'area authentication'
                ]):
                    current_config['has_authentication'] = True
                    current_config['authentication_type'] = line_clean
        
        # 새로운 섹션 시작시 current_protocol 리셋
        elif not line_clean.startswith(' ') and line_clean and not line_clean.startswith('!'):
            current_protocol = None
    
    # 인증이 설정되지 않은 라우팅 프로토콜 확인
    for protocol, configs in routing_protocols.items():
        for config in configs:
            if not config['has_authentication']:
                vulnerabilities.append({
                    'line': config['line_number'],
                    'matched_text': config['config_start'],
                    'details': {
                        'protocol': protocol,
                        'vulnerability': 'no_routing_authentication',
                        'has_authentication': config['has_authentication'],
                        'recommendation': f'Configure authentication for {protocol.upper()} routing protocol'
                    }
                })
    
    return vulnerabilities


def check_nw_41(line: str, line_num: int, context: ConfigContext) -> List[Dict[str, Any]]:
    """NW-41: 네트워크 장비 백업 관리 - 논리 기반 분석"""
    vulnerabilities = []
    
    # 백업 관련 설정 확인
    backup_indicators = [
        'archive',
        'backup',
        'copy running-config',
        'write memory',
        'tftp',
        'ftp',
        'scp'
    ]
    
    has_backup_config = any(
        indicator in context.full_config.lower() 
        for indicator in backup_indicators
    )
    
    # 자동 백업 설정 확인
    has_auto_backup = any([
        'archive' in context.full_config,
        'kron' in context.full_config,  # Cisco 스케줄러
        'event manager' in context.full_config
    ])
    
    if not has_backup_config:
        vulnerabilities.append({
            'line': 0,
            'matched_text': 'No backup configuration found',
            'details': {
                'vulnerability': 'no_backup_configuration',
                'has_backup_config': has_backup_config,
                'has_auto_backup': has_auto_backup,
                'recommendation': 'Configure automatic backup procedures for device configuration'
            }
        })
    elif not has_auto_backup:
        vulnerabilities.append({
            'line': 0,
            'matched_text': 'Manual backup only',
            'details': {
                'vulnerability': 'no_automatic_backup',
                'has_backup_config': has_backup_config,
                'has_auto_backup': has_auto_backup,
                'recommendation': 'Configure automatic backup scheduling to ensure regular backups'
            }
        })
    
    return vulnerabilities


def check_nw_42(line: str, line_num: int, context: ConfigContext) -> List[Dict[str, Any]]:
    """NW-42: 무선랜 통제대책 수립 - 논리 기반 분석"""
    vulnerabilities = []
    
    # 무선랜 설정 확인
    wireless_config_found = any([
        'wireless' in context.full_config.lower(),
        'wifi' in context.full_config.lower(),
        'wlan' in context.full_config.lower(),
        'ssid' in context.full_config.lower(),
        'access-point' in context.full_config.lower()
    ])
    
    if not wireless_config_found:
        # 무선랜 설정이 없으면 체크하지 않음
        return vulnerabilities
    
    # WEP 사용 확인 (취약)
    weak_encryption = any([
        'encryption wep' in context.full_config.lower(),
        'security wep' in context.full_config.lower(),
        'privacy wep' in context.full_config.lower()
    ])
    
    # 강력한 암호화 확인 (WPA2/WPA3)
    strong_encryption = any([
        'wpa2' in context.full_config.lower(),
        'wpa3' in context.full_config.lower(),
        'encryption wpa' in context.full_config.lower(),
        'authentication wpa' in context.full_config.lower()
    ])
    
    # 무선 보안 설정 부족 확인
    security_features = {
        'mac_filtering': 'mac-address-filter' in context.full_config.lower(),
        'radius_auth': 'radius' in context.full_config.lower(),
        'guest_network': 'guest' in context.full_config.lower(),
        'ssid_broadcast': 'ssid broadcast' in context.full_config.lower()
    }
    
    issues = []
    
    if weak_encryption:
        issues.append('weak_encryption_wep')
    
    if not strong_encryption:
        issues.append('no_strong_encryption')
    
    if not security_features['radius_auth']:
        issues.append('no_radius_authentication')
    
    if security_features['ssid_broadcast']:
        issues.append('ssid_broadcast_enabled')
    
    if issues:
        vulnerabilities.append({
            'line': 0,
            'matched_text': 'Wireless security configuration issues',
            'details': {
                'issues': issues,
                'weak_encryption': weak_encryption,
                'strong_encryption': strong_encryption,
                'security_features': security_features,
                'recommendation': 'Configure WPA2/WPA3 encryption, disable SSID broadcast, implement RADIUS authentication'
            }
        })
    
    return vulnerabilities