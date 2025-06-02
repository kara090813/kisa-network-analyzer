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
    """NW-23: 사용하지 않는 인터페이스의 Shutdown 설정 - 간소화된 버전"""
    vulnerabilities = []
    
    print(f"=== check_nw_23 실행 시작 ===")
    print(f"총 인터페이스 수: {len(context.parsed_interfaces)}")
    
    for interface_name, interface_config in context.parsed_interfaces.items():
        print(f"\n검사 중인 인터페이스: {interface_name}")
        
        # 1. 물리적 인터페이스 확인 (간단하게)
        interface_lower = interface_name.lower()
        is_physical = any(phy_type in interface_lower for phy_type in [
            'gigabitethernet', 'fastethernet', 'ethernet', 'tengigabitethernet', 
            'gi', 'fa', 'eth', 'te', 'serial'
        ])
        print(f"  물리적 인터페이스: {is_physical}")
        
        if not is_physical:
            continue
            
        # 2. Shutdown 상태 확인
        config_lines = interface_config.get('config_lines', [])
        config_text = ' '.join(config_lines).lower()
        
        # shutdown 키워드 직접 확인
        is_shutdown_explicit = any('shutdown' in line.lower() for line in config_lines)
        is_shutdown_from_config = interface_config.get('is_shutdown', False)
        is_shutdown = is_shutdown_explicit or is_shutdown_from_config
        
        print(f"  shutdown 설정됨 (명시적): {is_shutdown_explicit}")
        print(f"  shutdown 설정됨 (파싱): {is_shutdown_from_config}")
        print(f"  최종 shutdown 상태: {is_shutdown}")
        
        if is_shutdown:
            continue
            
        # 3. 사용 여부 확인 (매우 간단하게)
        has_ip_address = interface_config.get('has_ip_address', False)
        has_description = interface_config.get('has_description', False)
        has_vlan = interface_config.get('has_vlan', False)
        
        # config_lines에서 직접 확인
        has_ip_direct = any('ip address' in line.lower() and 'no ip address' not in line.lower() 
                           for line in config_lines)
        has_desc_direct = any('description' in line.lower() for line in config_lines)
        has_vlan_direct = any(vlan_keyword in config_text for vlan_keyword in [
            'switchport', 'vlan', 'encapsulation dot1q', 'trunk'
        ])
        
        # 의미있는 설정 확인
        meaningful_configs = any(keyword in config_text for keyword in [
            'channel-group', 'port-security', 'spanning-tree', 'access-group',
            'service-policy', 'tunnel', 'bridge-group'
        ])
        
        print(f"  IP 주소 (파싱): {has_ip_address}, (직접): {has_ip_direct}")
        print(f"  설명 (파싱): {has_description}, (직접): {has_desc_direct}")
        print(f"  VLAN (파싱): {has_vlan}, (직접): {has_vlan_direct}")
        print(f"  의미있는 설정: {meaningful_configs}")
        
        # 사용 중인 것으로 판단되는 조건들
        is_used = (has_ip_address or has_ip_direct or 
                   has_description or has_desc_direct or
                   has_vlan or has_vlan_direct or
                   meaningful_configs)
        
        print(f"  사용 중으로 판정: {is_used}")
        
        # 4. 중요 인터페이스 예외 처리 (간단하게)
        is_critical = False
        
        # 기본 중요 인터페이스들
        if any(critical in interface_lower for critical in [
            'loopback', 'management', 'mgmt', 'tunnel', 'vlan1', 'console'
        ]):
            is_critical = True
            
        # 설명에 중요 키워드가 있는 경우
        description = interface_config.get('description', '').lower()
        if description and any(keyword in description for keyword in [
            'uplink', 'trunk', 'core', 'wan', 'internet', 'isp', 'link to'
        ]):
            is_critical = True
            
        # 첫 번째 포트 (0/0)이고 실제로 사용 중인 경우만
        if ('0/0' in interface_name or interface_name.endswith('0/0')) and is_used:
            is_critical = True
            
        # 서브인터페이스가 있는 경우 (직접 확인)
        base_interface = interface_name.split('.')[0]
        has_subinterfaces = any(intf_name.startswith(f"{base_interface}.") 
                               for intf_name in context.parsed_interfaces.keys())
        if has_subinterfaces:
            is_critical = True
            print(f"  서브인터페이스 있음: {has_subinterfaces}")
            
        print(f"  중요 인터페이스: {is_critical}")
        
        # 5. 최종 판정
        is_vulnerable = not is_shutdown and not is_used and not is_critical
        print(f"  최종 취약점 판정: {is_vulnerable}")
        
        if is_vulnerable:
            print(f"  >>> {interface_name} 취약점으로 추가! <<<")
            vulnerabilities.append({
                'line': interface_config.get('line_number', 0),
                'matched_text': f"interface {interface_name}",
                'details': {
                    'interface_name': interface_name,
                    'port_type': interface_config.get('port_type', 'unknown'),
                    'reason': 'Unused physical interface not shutdown',
                    'security_risk': 'Potential unauthorized physical access point',
                    'analysis_summary': {
                        'is_shutdown': is_shutdown,
                        'is_used': is_used,
                        'is_critical': is_critical,
                        'has_ip': has_ip_address or has_ip_direct,
                        'has_description': has_description or has_desc_direct,
                        'has_vlan': has_vlan or has_vlan_direct,
                        'meaningful_configs': meaningful_configs
                    },
                    'recommendation': 'Shutdown unused interface to prevent unauthorized access'
                }
            })
    
    print(f"\n=== check_nw_23 완료: 총 {len(vulnerabilities)}개 취약점 발견 ===")
    return vulnerabilities


def _comprehensive_usage_analysis(interface_name, interface_config, context, network_context, learned_patterns):
    """종합적인 인터페이스 사용 여부 분석 - 수정됨"""
    
    analysis_results = {}
    
    # 1. 기본 사용 여부 분석 (40% 가중치로 증가) - 가장 중요한 지표
    basic_usage = _enhanced_basic_usage_check(interface_name, interface_config, context.parsed_interfaces)
    analysis_results['basic_usage'] = {'score': 0.9 if basic_usage else 0.05, 'weight': 0.40}
    
    # 2. 설정 복잡도 분석 (30% 가중치로 증가)
    complexity_result = _analyze_configuration_complexity(interface_config)
    analysis_results['complexity'] = {'score': complexity_result['usage_probability'], 'weight': 0.30}
    
    # 3. 네트워크 컨텍스트 분석 (15% 가중치로 감소)
    context_result = _analyze_network_context(interface_name, interface_config, network_context)
    analysis_results['network_context'] = {'score': context_result['usage_probability'], 'weight': 0.15}
    
    # 4. 조직 패턴 매칭 (10% 가중치로 감소)
    pattern_result = _match_organizational_patterns(interface_config, learned_patterns)
    analysis_results['pattern_matching'] = {'score': pattern_result['usage_probability'], 'weight': 0.10}
    
    # 5. 포트 밀도 분석 (5% 가중치로 감소)
    density_result = _analyze_port_density(interface_name, context.parsed_interfaces)
    analysis_results['port_density'] = {'score': density_result['usage_probability'], 'weight': 0.05}
    
    # 가중 평균 계산
    total_score = sum(result['score'] * result['weight'] for result in analysis_results.values())
    
    # 특별 조건: "no ip address"가 있고 기본 설정만 있는 경우 강제로 낮은 점수
    config_text = ' '.join(interface_config.get('config_lines', [])).lower()
    if ('no ip address' in config_text and 
        not interface_config.get('has_description') and
        not interface_config.get('has_vlan') and
        not any(meaningful in config_text for meaningful in ['encapsulation', 'tunnel', 'switchport', 'access-group'])):
        total_score = min(total_score, 0.15)  # 강제로 낮은 점수 적용
    
def _calculate_analysis_confidence_enhanced(scores, interface_config):
    """개선된 분석 신뢰도 계산"""
    if not scores:
        return 0.5
    
    # 기본 분산 기반 신뢰도
    mean_score = sum(scores) / len(scores)
    variance = sum((score - mean_score) ** 2 for score in scores) / len(scores)
    base_confidence = max(0.5, 1.0 - (variance * 2))
    
    # 명확한 지표가 있는 경우 신뢰도 증가
    config_text = ' '.join(interface_config.get('config_lines', [])).lower()
    
    # 높은 신뢰도 조건들
    high_confidence_indicators = [
        'no ip address' in config_text and not interface_config.get('has_description'),  # 명시적 미사용
        interface_config.get('has_ip_address') and interface_config.get('has_description'),  # 명시적 사용
        'shutdown' in config_text,  # 명시적으로 비활성화
    ]
    
    # 명확한 지표가 있으면 신뢰도 증가
    if any(high_confidence_indicators):
        base_confidence = max(base_confidence, 0.85)
    
    # "no ip address"만 있고 다른 설정이 없으면 매우 높은 신뢰도
    if ('no ip address' in config_text and 
        not interface_config.get('has_description') and
        not interface_config.get('has_vlan') and
        len(interface_config.get('config_lines', [])) <= 3):  # 기본 설정만
        base_confidence = 0.95
    
    return min(0.99, base_confidence)
    
    # 주요 지표 추출
    primary_indicators = _extract_primary_indicators(analysis_results, interface_config)
    
    return {
        'usage_probability': total_score,
        'confidence_level': confidence,
        'layer_results': analysis_results,
        'primary_indicators': primary_indicators
    }


def _enhanced_basic_usage_check(interface_name, interface_config, all_interfaces):
    """향상된 기본 사용 여부 체크 - 수정됨"""
    
    # 기본 사용 지표들
    basic_indicators = [
        interface_config.get('has_ip_address', False),
        interface_config.get('has_description', False),
        interface_config.get('has_vlan', False),
        interface_config.get('is_loopback', False),
        interface_config.get('is_management', False),
        interface_config.get('has_switchport', False)
    ]
    
    if any(basic_indicators):
        return True
    
    # "no ip address"가 명시된 경우 미사용으로 강하게 판단
    config_lines = interface_config.get('config_lines', [])
    config_text = ' '.join(config_lines).lower()
    if 'no ip address' in config_text:
        # 다른 의미있는 설정이 있는지 추가 확인
        meaningful_configs = [
            'encapsulation', 'tunnel', 'bridge-group', 'channel-group',
            'switchport', 'vlan', 'access-group', 'service-policy'
        ]
        if not any(config in config_text for config in meaningful_configs):
            return False  # 명시적으로 미사용으로 판단
    
    # 향상된 검사들
    enhanced_checks = [
        _has_meaningful_ip_config(interface_config),
        _is_channel_member(interface_config),
        _has_active_subinterfaces(interface_name, all_interfaces),
        _has_special_protocol_config(interface_config)
    ]
    
    return any(enhanced_checks)


def _analyze_configuration_complexity(interface_config):
    """설정 복잡도 기반 사용 가능성 분석 (보안 중심) - 수정됨"""
    config_lines = interface_config.get('config_lines', [])
    config_text = ' '.join(config_lines).lower()
    
    # 실제 사용을 나타내는 중요 지표들 (가중치 조정)
    complexity_scores = {
        'has_ip_address': 0.40 if interface_config.get('has_ip_address') else 0,  # IP가 가장 중요
        'has_meaningful_description': 0.25 if interface_config.get('has_description') and len(interface_config.get('description', '').strip()) > 0 else 0,
        'has_security_config': 0.20 if any(kw in config_text for kw in ['port-security', 'storm-control', 'access-group']) else 0,
        'has_vlan_config': 0.15 if any(kw in config_text for kw in ['switchport', 'vlan', 'trunk', 'encapsulation dot1q']) else 0,
        'has_qos_config': 0.10 if any(kw in config_text for kw in ['qos', 'service-policy']) else 0,
        # duplex/speed 설정은 기본 설정으로 제거 또는 매우 낮은 가중치
        'basic_physical_config': 0.01 if any(kw in config_text for kw in ['speed auto', 'duplex auto']) and not any(kw in config_text for kw in ['speed 100', 'speed 1000', 'duplex full', 'duplex half']) else 0.02 if any(kw in config_text for kw in ['speed', 'duplex']) else 0
    }
    
    # 추가: "no ip address"가 명시적으로 설정된 경우 사용하지 않음을 강하게 시사
    if 'no ip address' in config_text:
        complexity_scores['explicit_no_ip'] = -0.15  # 음수 점수로 미사용 가능성 증가
    
    total_complexity = sum(complexity_scores.values())
    usage_probability = max(0.0, total_complexity)  # 음수가 되지 않도록 보정
    
    return {
        'usage_probability': usage_probability,
        'complexity_breakdown': complexity_scores
    }


def _analyze_network_context(interface_name, interface_config, network_context):
    """네트워크 컨텍스트 기반 분석"""
    
    context_scores = []
    
    # 1. 포트 위치 기반 분석
    port_position_score = _analyze_port_position(interface_name, network_context)
    context_scores.append(port_position_score)
    
    # 2. VLAN 사용 컨텍스트
    vlan_context_score = _analyze_vlan_usage_context(interface_config, network_context)
    context_scores.append(vlan_context_score)
    
    # 3. 인터페이스 타입별 패턴
    type_pattern_score = _analyze_interface_type_pattern(interface_config, network_context)
    context_scores.append(type_pattern_score)
    
    avg_score = sum(context_scores) / len(context_scores) if context_scores else 0.5
    
    return {'usage_probability': avg_score}


def _learn_organizational_patterns(all_interfaces):
    """조직 네이밍 패턴 자동 학습"""
    used_descriptions = []
    unused_descriptions = []
    
    for name, config in all_interfaces.items():
        description = config.get('description', '').lower().strip()
        if description:
            is_used = _enhanced_basic_usage_check(name, config, all_interfaces)
            if is_used:
                used_descriptions.append(description)
            else:
                unused_descriptions.append(description)
    
    # 키워드 빈도 분석
    used_keywords = _extract_keywords_from_descriptions(used_descriptions)
    unused_keywords = _extract_keywords_from_descriptions(unused_descriptions)
    
    return {
        'used_keywords': used_keywords,
        'unused_keywords': unused_keywords,
        'total_samples': len(used_descriptions) + len(unused_descriptions)
    }


def _match_organizational_patterns(interface_config, learned_patterns):
    """학습된 패턴과 매칭"""
    description = interface_config.get('description', '').lower().strip()
    
    if not description:
        return {'usage_probability': 0.25}  # 설명 없으면 낮은 사용 가능성
    
    used_keywords = learned_patterns.get('used_keywords', {})
    unused_keywords = learned_patterns.get('unused_keywords', {})
    
    # 키워드 매칭 점수
    used_score = sum(weight for keyword, weight in used_keywords.items() if keyword in description)
    unused_score = sum(weight for keyword, weight in unused_keywords.items() if keyword in description)
    
    if used_score > unused_score:
        probability = 0.7 + min(0.2, used_score * 0.1)
    elif unused_score > used_score:
        probability = 0.3 - min(0.2, unused_score * 0.1)
    else:
        probability = 0.5
    
    return {'usage_probability': max(0.05, min(0.95, probability))}


def _analyze_port_density(interface_name, all_interfaces):
    """포트 밀도 기반 분석"""
    adjacent_ports = _find_adjacent_ports(interface_name, all_interfaces)
    
    if not adjacent_ports:
        return {'usage_probability': 0.5}
    
    used_adjacent = sum(1 for port in adjacent_ports 
                       if _enhanced_basic_usage_check(port, all_interfaces[port], all_interfaces))
    
    density_ratio = used_adjacent / len(adjacent_ports)
    
    # 밀도에 따른 사용 가능성
    if density_ratio >= 0.75:
        probability = 0.8
    elif density_ratio >= 0.5:
        probability = 0.6
    elif density_ratio >= 0.25:
        probability = 0.4
    else:
        probability = 0.2
    
    return {'usage_probability': probability, 'density_ratio': density_ratio}


# =========================== 헬퍼 함수들 ===========================

def _has_meaningful_ip_config(interface_config):
    """의미있는 IP 설정 확인"""
    config_lines = interface_config.get('config_lines', [])
    config_text = ' '.join(config_lines).lower()
    
    meaningful_indicators = [
        'ip address dhcp',
        'ipv6 address',
        'ppp',
        'frame-relay',
        'atm',
        'tunnel'
    ]
    
    return any(indicator in config_text for indicator in meaningful_indicators)


def _is_channel_member(interface_config):
    """포트 채널 멤버 확인"""
    config_lines = interface_config.get('config_lines', [])
    config_text = ' '.join(config_lines).lower()
    
    channel_indicators = ['channel-group', 'port-channel', 'lag', 'etherchannel']
    return any(indicator in config_text for indicator in channel_indicators)


def _has_active_subinterfaces(interface_name, all_interfaces):
    """활성 서브인터페이스 확인"""
    for intf_name in all_interfaces:
        if intf_name.startswith(f"{interface_name}."):
            subintf = all_interfaces[intf_name]
            if not subintf.get('is_shutdown', True):
                return True
    return False


def _has_special_protocol_config(interface_config):
    """특수 프로토콜 설정 확인"""
    config_lines = interface_config.get('config_lines', [])
    config_text = ' '.join(config_lines).lower()
    
    special_configs = [
        'spanning-tree', 'storm-control', 'port-security',
        'flowcontrol', 'service-policy', 'access-list'
    ]
    
    return any(config in config_text for config in special_configs)


def _is_physical_interface_enhanced(interface_name, device_type):
    """향상된 물리 인터페이스 판별"""
    interface_lower = interface_name.lower()
    
    # 가상 인터페이스 제외
    virtual_patterns = ['loopback', 'tunnel', 'vlan', 'bvi', 'dialer', 'null']
    if any(pattern in interface_lower for pattern in virtual_patterns):
        return False
    
    # 장비별 물리 인터페이스 패턴
    if device_type in ["Cisco"]:
        return any(pattern in interface_lower for pattern in [
            'ethernet', 'fastethernet', 'gigabitethernet', 'tengigabitethernet',
            'serial', 'bri', 'pri', 'fa', 'gi', 'te', 'eth'
        ])
    elif device_type in ["Juniper"]:
        return any(pattern in interface_lower for pattern in [
            'ge-', 'xe-', 'et-', 'fe-', 'so-', 'as-'
        ])
    elif device_type in ["HP", "Alcatel"]:
        import re
        if re.match(r'^\d+/\d+(/\d+)?$', interface_name):
            return True
        return any(pattern in interface_lower for pattern in ['ethernet', 'gigabit'])
    else:
        return any(pattern in interface_lower for pattern in [
            'ethernet', 'fast', 'giga', 'ten', 'serial'
        ])


def _is_critical_interface_enhanced(interface_name, device_type, interface_config):
    """향상된 중요 인터페이스 판별 - 수정됨"""
    interface_lower = interface_name.lower()
    
    # 기본 중요 인터페이스
    critical_patterns = [
        'loopback', 'management', 'mgmt', 'tunnel', 'vlan1',
        'console', 'null', 'dialer'
    ]
    if any(pattern in interface_lower for pattern in critical_patterns):
        return True
    
    # 설명 기반 중요 인터페이스 (더 엄격하게)
    description = interface_config.get('description', '').lower()
    critical_keywords = [
        'uplink', 'trunk', 'core', 'wan', 'internet', 'backup',
        'standby', 'primary', 'main', 'isp', 'critical', 'link to'
    ]
    if description and any(keyword in description for keyword in critical_keywords):
        return True
    
    # 첫 번째 포트 조건 완화 - 실제 설정이 있는 경우만
    if (_is_first_port_by_device(interface_name, device_type) and 
        (interface_config.get('has_ip_address') or 
         interface_config.get('has_description') or
         interface_config.get('has_vlan'))):
        return True
    
    # Serial 인터페이스는 실제 설정이 있는 경우만
    if interface_lower.startswith('serial'):
        return (interface_config.get('has_ip_address') or 
                interface_config.get('has_description') or
                _has_meaningful_ip_config(interface_config))
    
    # Subinterface가 있는 경우 (예: Gi0/1.10이 있으면 Gi0/1은 중요)
    interface_base = interface_name.split('.')[0]  # 서브인터페이스 제거
    if interface_base != interface_name:  # 이미 서브인터페이스인 경우
        return False
    
    # 해당 인터페이스에 서브인터페이스가 있는지 확인하는 로직은 context가 필요하므로 별도 처리
    
    return False


def _analyze_global_network_context(all_interfaces):
    """전체 네트워크 컨텍스트 분석"""
    total = len(all_interfaces)
    used = sum(1 for name, config in all_interfaces.items() 
               if _enhanced_basic_usage_check(name, config, all_interfaces))
    
    return {
        'total_interfaces': total,
        'used_interfaces': used,
        'usage_ratio': used / total if total > 0 else 0,
        'network_size': 'small' if total <= 24 else 'medium' if total <= 100 else 'large'
    }


def _analyze_port_position(interface_name, network_context):
    """포트 위치 기반 분석"""
    port_num = _extract_port_number(interface_name)
    if port_num is None:
        return 0.5
    
    network_size = network_context.get('network_size', 'medium')
    
    if network_size == 'small':
        return 0.8 if port_num <= 8 else 0.4 if port_num <= 16 else 0.2
    elif network_size == 'medium':
        return 0.7 if port_num <= 12 else 0.5 if port_num <= 24 else 0.3
    else:
        return 0.6 if port_num <= 16 else 0.4 if port_num <= 32 else 0.3


def _analyze_vlan_usage_context(interface_config, network_context):
    """VLAN 사용 컨텍스트 분석"""
    if not interface_config.get('has_vlan'):
        return 0.3
    
    # 실제 구현에서는 VLAN ID를 추출하여 전체 네트워크에서의 사용 빈도 확인
    return 0.6  # 기본값


def _analyze_interface_type_pattern(interface_config, network_context):
    """인터페이스 타입별 패턴 분석"""
    port_type = interface_config.get('port_type', '').lower()
    
    # 일반적인 타입별 사용 패턴
    type_usage_patterns = {
        'gigabitethernet': 0.7,
        'fastethernet': 0.6,
        'tengigabitethernet': 0.8,
        'serial': 0.5,
        'ethernet': 0.6
    }
    
    return type_usage_patterns.get(port_type, 0.5)


def _extract_keywords_from_descriptions(descriptions):
    """설명에서 키워드 추출 및 가중치 계산"""
    from collections import Counter
    
    all_words = []
    for desc in descriptions:
        words = [word.strip() for word in desc.split() if len(word.strip()) >= 3]
        all_words.extend(words)
    
    word_counts = Counter(all_words)
    total_descriptions = len(descriptions)
    
    # 빈도 기반 가중치 계산
    keywords = {}
    for word, count in word_counts.items():
        if count >= 2:  # 최소 2회 이상 등장
            weight = count / total_descriptions
            keywords[word] = weight
    
    return keywords


def _find_adjacent_ports(interface_name, all_interfaces):
    """인접 포트 찾기"""
    port_num = _extract_port_number(interface_name)
    if port_num is None:
        return []
    
    base_name = interface_name.rsplit(str(port_num), 1)[0]
    adjacent = []
    
    for i in range(max(1, port_num - 2), port_num + 3):
        if i != port_num:
            candidate = f"{base_name}{i}"
            if candidate in all_interfaces:
                adjacent.append(candidate)
    
    return adjacent


def _extract_port_number(interface_name):
    """포트 번호 추출"""
    import re
    match = re.search(r'(\d+)(?:/\d+)*$', interface_name)
    return int(match.group(1)) if match else None


def _is_first_port_by_device(interface_name, device_type):
    """장비별 첫 포트 판별"""
    interface_lower = interface_name.lower()
    
    first_port_patterns = {
        "Cisco": ['ethernet0/0', 'fastethernet0/0', 'gigabitethernet0/0', 'fa0/0', 'gi0/0'],
        "Juniper": ['ge-0/0/0', 'xe-0/0/0', 'et-0/0/0'],
        "HP": ['1/1/1', '1/1', 'a1'],
        "Alcatel": ['1/1/1', '1/1']
    }
    
    patterns = first_port_patterns.get(device_type, ['0/0', '1/1'])
    return any(pattern in interface_lower for pattern in patterns)


def _calculate_analysis_confidence(scores):
    """분석 신뢰도 계산"""
    if not scores:
        return 0.5
    
    # 점수들의 분산을 기반으로 신뢰도 계산
    mean_score = sum(scores) / len(scores)
    variance = sum((score - mean_score) ** 2 for score in scores) / len(scores)
    
    # 분산이 낮을수록 신뢰도 높음
    confidence = max(0.5, 1.0 - (variance * 2))
    return min(0.99, confidence)


def _extract_primary_indicators(analysis_results, interface_config):
    """주요 지표 추출"""
    indicators = []
    
    # 각 분석 결과에서 점수가 높은 것들을 주요 지표로 선정
    for category, result in analysis_results.items():
        if result['score'] > 0.7:
            indicators.append(f"High {category.replace('_', ' ')}")
        elif result['score'] < 0.3:
            indicators.append(f"Low {category.replace('_', ' ')}")
    
    return indicators[:3]  # 최대 3개까지


def _calculate_risk_level(usage_analysis):
    """위험 수준 계산"""
    usage_prob = usage_analysis['usage_probability']
    confidence = usage_analysis['confidence_level']
    
    if usage_prob < 0.1 and confidence > 0.9:
        return "High"
    elif usage_prob < 0.2 and confidence > 0.8:
        return "Medium"
    else:
        return "Low"


# 기존 함수 유지 (호환성)
def _is_critical_interface_nw23(interface_name: str, device_type: str) -> bool:
    """NW-23용 중요 인터페이스 판별 - 물리적 보안 관점에서 더 엄격한 기준"""
    interface_lower = interface_name.lower()
    
    # 항상 중요한 인터페이스들
    critical_patterns = [
        'loopback', 'management', 'mgmt', 'tunnel', 'vlan1', 
        'console', 'null', 'dialer'
    ]
    
    if any(pattern in interface_lower for pattern in critical_patterns):
        return True
    
    # 첫 번째 포트는 일반적으로 업링크로 사용
    first_port_patterns = [
        'ethernet0/0', 'fastethernet0/0', 'gigabitethernet0/0',
        'eth0/0', 'fa0/0', 'gi0/0', 'ge-0/0/0'
    ]
    
    if any(pattern in interface_lower for pattern in first_port_patterns):
        return True
    
    # Serial 인터페이스는 WAN 연결용으로 중요
    if interface_lower.startswith('serial'):
        return True
    
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