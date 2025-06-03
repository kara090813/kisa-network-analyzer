# -*- coding: utf-8 -*-
"""
rules/checks_kisa.py
KISA 네트워크 장비 보안 점검 룰의 논리적 검증 함수들 (완전판)

각 KISA 룰에 대한 logical_check_function들을 정의
"""

from typing import List, Dict, Any
from .kisa_rules import ConfigContext
import re


def check_basic_password_usage(line: str, line_num: int, context: ConfigContext) -> List[Dict[str, Any]]:
    """N-01: 기본 패스워드 사용 - 개선된 버전"""
    vulnerabilities = []
    
    # 확장된 기본 패스워드 패턴 (대소문자 변형 포함)
    basic_passwords = [
        'cisco', 'admin', 'password', '123', '1234', '12345', '123456',
        'default', 'pass', 'root', 'user', 'guest', 'test', 'temp',
        'switch', 'router', 'manager', 'security', 'public', 'private',
        'cisco123', 'admin123', 'password123', 'switch123', 'router123'
    ]
    
    # Enable 패스워드 검사 - secret은 제외
    if context.global_settings.get('enable_password_type') == 'password':
        password_value = context.global_settings.get('enable_password_value', '')
        # 대소문자 무시 검사 및 부분 문자열 검사
        if any(basic_pwd.lower() in password_value.lower() for basic_pwd in basic_passwords):
            vulnerabilities.append({
                'line': line_num,
                'matched_text': f"enable password {password_value}",
                'details': {
                    'password_type': 'enable_password',
                    'vulnerability': 'basic_password_used',
                    'password_value': password_value,
                    'recommendation': 'Use enable secret with strong password or algorithm-type',
                    'severity_adjusted': 'High'
                }
            })
    
    # 사용자 패스워드 검사 - 개선된 논리
    for user in context.parsed_users:
        # 이미 강력한 암호화를 사용하는 경우는 제외
        if user.get('is_modern_encryption', False):
            continue
            
        # secret 타입도 Type 5 이상인 경우 제외
        if (user.get('password_type') == 'secret' and 
            user.get('encryption_type') in ['type5_md5', 'type8_pbkdf2', 'type9_scrypt']):
            continue
        
        # 기본 패스워드 사용 여부 확인 (정교한 검사)
        if user['has_password'] and not user['password_encrypted']:
            username_lower = user['username'].lower()
            
            # 사용자명 자체가 기본 패스워드인 경우
            if username_lower in [pwd.lower() for pwd in basic_passwords]:
                vulnerabilities.append({
                    'line': user['line_number'],
                    'matched_text': f"username {user['username']} with basic username",
                    'details': {
                        'password_type': 'user_password',
                        'vulnerability': 'basic_username_used',
                        'username': user['username'],
                        'recommendation': 'Use non-standard username with username secret'
                    }
                })
        
        # 약한 암호화 사용 경고
        elif user.get('encryption_type') in ['type7_weak', 'type0_plaintext']:
            vulnerabilities.append({
                'line': user['line_number'],
                'matched_text': f"username {user['username']} using weak encryption",
                'details': {
                    'password_type': 'user_password',
                    'vulnerability': 'weak_encryption_used',
                    'username': user['username'],
                    'encryption_type': user.get('encryption_type'),
                    'recommendation': 'Upgrade to algorithm-type sha256 or scrypt encryption'
                }
            })
    
    return vulnerabilities


def check_password_complexity(line: str, line_num: int, context: ConfigContext) -> List[Dict[str, Any]]:
    """N-02: 패스워드 복잡성 설정 - 논리 기반 분석"""
    vulnerabilities = []
    
    # 패스워드 최소 길이 설정 확인
    has_min_length = 'passwords min-length' in context.full_config
    
    if not has_min_length:
        vulnerabilities.append({
            'line': 0,
            'matched_text': '패스워드 최소 길이 설정 누락',
            'details': {
                'vulnerability': 'no_password_min_length_policy',
                'recommendation': 'security passwords min-length 8'
            }
        })
    
    # 약한 패스워드 패턴 검사
    for user in context.parsed_users:
        if user['has_password'] and not user['password_encrypted']:
            vulnerabilities.append({
                'line': user['line_number'],
                'matched_text': f"username {user['username']} password (weak)",
                'details': {
                    'vulnerability': 'unencrypted_password',
                    'username': user['username']
                }
            })
    
    return vulnerabilities


def check_password_encryption(line: str, line_num: int, context: ConfigContext) -> List[Dict[str, Any]]:
    """N-03: 암호화된 패스워드 사용 - 개선된 논리 기반 분석"""
    vulnerabilities = []
    
    # Service password-encryption 확인
    password_encryption_enabled = context.parsed_services.get('password-encryption', False)
    
    # Console 라인에서 평문 패스워드 확인
    console_password_issues = []
    for line_content in context.config_lines:
        if 'line con' in line_content.lower():
            # console 설정 섹션 시작
            continue
        if line_content.strip().startswith('password ') and not any(enc in line_content for enc in ['secret', '$', '5']):
            # 평문 패스워드 발견
            console_password_issues.append(line_content.strip())
    
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
    
    # Service password-encryption이 비활성화되고 평문 패스워드가 있는 경우
    if not password_encryption_enabled and console_password_issues:
        vulnerabilities.append({
            'line': 0,
            'matched_text': 'service password-encryption disabled with plaintext passwords',
            'details': {
                'vulnerability': 'password_encryption_disabled',
                'plaintext_passwords': console_password_issues,
                'recommendation': 'Enable service password-encryption'
            }
        })
    
    # 사용자 패스워드 암호화 검사
    for user in context.parsed_users:
        user_issues = []
        
        # 이미 강력한 암호화를 사용하는 경우는 제외
        if user.get('is_modern_encryption', False):
            continue
            
        # Type 5 MD5 secret도 허용 (기본적으로 안전)
        if user.get('encryption_type') == 'type5_md5' and user['has_secret']:
            continue
        
        # 암호화되지 않은 패스워드
        if user['has_password'] and not user['password_encrypted']:
            user_issues.append('unencrypted_password')
        
        # 약한 암호화 사용
        elif user.get('encryption_type') == 'type7_weak':
            user_issues.append('weak_type7_encryption')
        
        # 플레인텍스트 (Type 0)
        elif user.get('encryption_type') == 'type0_plaintext':
            user_issues.append('plaintext_password')
        
        if user_issues:
            recommendation = "Use username secret with strong encryption"
            if 'weak_type7_encryption' in user_issues:
                recommendation = "Replace Type 7 encryption with secret"
            
            vulnerabilities.append({
                'line': user['line_number'],
                'matched_text': f"username {user['username']} password encryption issue",
                'details': {
                    'vulnerability': 'password_encryption_insufficient',
                    'username': user['username'],
                    'issues': user_issues,
                    'current_encryption': user.get('encryption_type', 'none'),
                    'recommendation': recommendation
                }
            })
    
    return vulnerabilities


def check_vty_access_control(line: str, line_num: int, context: ConfigContext) -> List[Dict[str, Any]]:
    """N-04: VTY 접근 제한 설정 - 개선된 논리 기반 분석"""
    vulnerabilities = []
    
    if not context.vty_lines:
        # VTY 설정이 아예 없는 경우
        vulnerabilities.append({
            'line': 0,
            'matched_text': 'No VTY configuration found',
            'details': {
                'vulnerability': 'no_vty_configuration',
                'recommendation': 'Configure VTY lines with access-class restrictions'
            }
        })
        return vulnerabilities
    
    for vty_line in context.vty_lines:
        issues = []
        
        # Access-class 확인
        if not vty_line['has_access_class']:
            issues.append('no_access_class')
        
        # Transport input 확인  
        transport_input = vty_line.get('transport_input', [])
        if 'all' in transport_input:
            issues.append('transport_all_allowed')
        elif 'telnet' in transport_input:
            issues.append('telnet_allowed')
        
        # 패스워드 확인
        if not vty_line['has_password'] and vty_line.get('login_method') != 'login local':
            issues.append('no_authentication')
        
        if issues:
            vulnerability_details = {
                'line': vty_line['line_number'],
                'matched_text': vty_line['line'],
                'details': {
                    'issues': issues,
                    'vty_config': vty_line,
                    'has_access_class': vty_line['has_access_class'],
                    'transport_input': transport_input,
                    'access_class': vty_line.get('access_class'),
                    'recommendation': 'Configure access-class for VTY lines to restrict source IPs'
                }
            }
            vulnerabilities.append(vulnerability_details)
    
    return vulnerabilities



def check_session_timeout(line: str, line_num: int, context: ConfigContext) -> List[Dict[str, Any]]:
    """N-05: Session Timeout 설정 - 논리 기반 분석"""
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


def check_security_patch_management(line: str, line_num: int, context: ConfigContext) -> List[Dict[str, Any]]:
    """N-06: 최신 보안 패치 및 벤더 권고사항 적용 - 논리 기반 분석"""
    vulnerabilities = []
    
    # 이 룰은 주로 문서화 및 정책 점검이므로 설정파일만으로는 완전한 검증이 어려움
    # 버전 정보 확인을 통한 기본적인 분석만 수행
    vulnerabilities.append({
        'line': 0,
        'matched_text': 'Security patch management policy verification required',
        'details': {
            'vulnerability': 'manual_verification_required',
            'recommendation': 'Verify security patch management policy and version updates',
            'check_items': [
                'Check current firmware/software version',
                'Compare with latest security patches',
                'Review vendor security advisories'
            ]
        }
    })
    
    return vulnerabilities


def check_snmp_service_status(line: str, line_num: int, context: ConfigContext) -> List[Dict[str, Any]]:
    """N-07: SNMP 서비스 확인 - 논리 기반 분석"""
    vulnerabilities = []
    
    # SNMP 서비스가 활성화되어 있는지 확인
    snmp_enabled = False
    for line in context.config_lines:
        if line.strip().startswith('snmp-server') and not line.strip().startswith('no snmp-server'):
            snmp_enabled = True
            break
    
    if snmp_enabled and not context.snmp_communities:
        vulnerabilities.append({
            'line': 0,
            'matched_text': 'SNMP service enabled but no communities configured',
            'details': {
                'vulnerability': 'snmp_service_misconfigured',
                'recommendation': 'Configure SNMP communities properly or disable SNMP service'
            }
        })
    
    return vulnerabilities


def check_snmp_security(line: str, line_num: int, context: ConfigContext) -> List[Dict[str, Any]]:
    """N-08: SNMP Community String 복잡성 - 개선된 논리 기반 분석"""
    vulnerabilities = []
    
    if not context.snmp_communities:
        # SNMP가 설정되지 않은 경우는 취약점이 아님
        return vulnerabilities
    
    for community_info in context.snmp_communities:
        issues = []
        
        # 기본 커뮤니티 스트링 확인
        if community_info['is_default']:
            issues.append('default_community')
        
        # 길이 확인
        if community_info['length'] < 8:
            issues.append('too_short')
        
        # 단순한 패턴 확인
        simple_patterns = ['123', '456', '111', '000', 'admin', 'test', 'temp', 'cisco', 'router', 'switch']
        if any(pattern in community_info['community'].lower() for pattern in simple_patterns):
            issues.append('simple_pattern')
        
        # 숫자만 또는 문자만으로 구성된 경우
        community = community_info['community']
        if len(community) > 3 and (community.isdigit() or community.isalpha()):
            issues.append('lacks_complexity')
        
        if issues:
            vulnerabilities.append({
                'line': community_info['line_number'],
                'matched_text': f"snmp-server community {community_info['community']}",
                'details': {
                    'community': community_info['community'],
                    'issues': issues,
                    'permission': community_info['permission'],
                    'has_acl': bool(community_info['acl']),
                    'community_length': community_info['length'],
                    'is_default': community_info['is_default'],
                    'recommendation': 'Use complex community string (min 8 chars, avoid default values like public/private)'
                }
            })
    
    return vulnerabilities


def check_snmp_acl_configuration(line: str, line_num: int, context: ConfigContext) -> List[Dict[str, Any]]:
    """N-09: SNMP ACL 설정 - 개선된 논리 기반 분석"""
    vulnerabilities = []
    
    for community_info in context.snmp_communities:
        # ACL 설정 확인
        if not community_info.get('acl'):
            vulnerabilities.append({
                'line': community_info['line_number'],
                'matched_text': f"snmp-server community {community_info['community']} {community_info['permission']}",
                'details': {
                    'community': community_info['community'],
                    'vulnerability': 'no_acl_configured',
                    'permission': community_info['permission'],
                    'recommendation': 'Configure ACL for SNMP community access restriction'
                }
            })
    
    return vulnerabilities


def check_snmp_community_permissions(line: str, line_num: int, context: ConfigContext) -> List[Dict[str, Any]]:
    """N-10: SNMP 커뮤니티 권한 설정 - 논리 기반 분석"""
    vulnerabilities = []
    
    for community_info in context.snmp_communities:
        if community_info['permission'] == 'RW':
            vulnerabilities.append({
                'line': community_info['line_number'],
                'matched_text': f"snmp-server community {community_info['community']} RW",
                'details': {
                    'vulnerability': 'snmp_write_permission',
                    'community': community_info['community'],
                    'current_permission': 'RW',
                    'recommendation': 'Change SNMP community permission to RO (read-only)'
                }
            })
    
    return vulnerabilities


def check_tftp_service_status(line: str, line_num: int, context: ConfigContext) -> List[Dict[str, Any]]:
    """N-11: TFTP 서비스 차단 - 논리 기반 분석"""
    vulnerabilities = []
    
    tftp_enabled = context.parsed_services.get('tftp', False)
    
    if tftp_enabled:
        vulnerabilities.append({
            'line': 0,
            'matched_text': 'service tftp',
            'details': {
                'vulnerability': 'tftp_service_enabled',
                'recommendation': 'Disable TFTP service: no service tftp'
            }
        })
    
    return vulnerabilities


def check_anti_spoofing_filtering(line: str, line_num: int, context: ConfigContext) -> List[Dict[str, Any]]:
    """N-12: Spoofing 방지 필터링 적용 - 논리 기반 분석"""
    vulnerabilities = []
    
    # 스푸핑 방지를 위한 ACL 패턴 확인
    spoofing_protection_found = False
    
    for acl_number, acl_lines in context.access_lists.items():
        for acl_line in acl_lines:
            # 사설망 대역 차단 ACL 확인
            if any(pattern in acl_line.lower() for pattern in ['10.0.0.0', '192.168.', '127.0.0.0']):
                spoofing_protection_found = True
                break
        if spoofing_protection_found:
            break
    
    if not spoofing_protection_found:
        vulnerabilities.append({
            'line': 0,
            'matched_text': 'Anti-spoofing filtering not configured',
            'details': {
                'vulnerability': 'no_anti_spoofing_filter',
                'recommendation': 'Configure anti-spoofing ACL to block private network ranges'
            }
        })
    
    return vulnerabilities


def check_ddos_protection(line: str, line_num: int, context: ConfigContext) -> List[Dict[str, Any]]:
    """N-13: DDoS 공격 방어 설정 - 논리 기반 분석"""
    vulnerabilities = []
    
    # DDoS 방어 기능 확인
    ddos_protection_found = False
    
    for line in context.config_lines:
        if any(pattern in line.lower() for pattern in ['tcp intercept', 'rate-limit', 'ip verify']):
            ddos_protection_found = True
            break
    
    if not ddos_protection_found:
        vulnerabilities.append({
            'line': 0,
            'matched_text': 'DDoS protection not configured',
            'details': {
                'vulnerability': 'no_ddos_protection',
                'recommendation': 'Configure DDoS protection features (TCP intercept, rate limiting, etc.)'
            }
        })
    
    return vulnerabilities


def check_unused_interface_shutdown(line: str, line_num: int, context: ConfigContext) -> List[Dict[str, Any]]:
    """N-14: 사용하지 않는 인터페이스 Shutdown - 정교한 개선된 버전"""
    vulnerabilities = []
    
    # 메인 인터페이스와 서브인터페이스 분리
    main_interfaces = {}
    sub_interfaces = {}
    
    for interface_name, interface_config in context.parsed_interfaces.items():
        if interface_config.get('is_subinterface', False):
            # 서브인터페이스
            main_name = interface_name.split('.')[0]
            if main_name not in sub_interfaces:
                sub_interfaces[main_name] = []
            sub_interfaces[main_name].append(interface_config)
        else:
            # 메인 인터페이스
            main_interfaces[interface_name] = interface_config
    
    # 라우팅, NAT 등에서 참조되는 인터페이스 확인
    referenced_interfaces = _find_referenced_interfaces(context)
    
    for interface_name, interface_config in main_interfaces.items():
        # 물리적 인터페이스만 체크
        is_physical = interface_config['port_type'] in [
            'FastEthernet', 'GigabitEthernet', 'TenGigabitEthernet', 'Serial'
        ]
        
        if not is_physical:
            continue
        
        # 사용 여부 정교한 판단
        usage_indicators = _analyze_interface_usage(
            interface_name, interface_config, sub_interfaces, referenced_interfaces, context
        )
        
        is_used = usage_indicators['is_used']
        is_shutdown = interface_config['is_shutdown']
        is_critical = usage_indicators['is_critical']
        
        # 미사용이면서 활성화된 물리 인터페이스만 보고
        if not is_used and not is_shutdown and not is_critical:
            vulnerabilities.append({
                'line': interface_config['line_number'],
                'matched_text': f"interface {interface_name}",
                'details': {
                    'interface_name': interface_name,
                    'port_type': interface_config['port_type'],
                    'reason': 'Unused physical interface not shutdown',
                    'usage_analysis': usage_indicators,
                    'recommendation': 'Add shutdown command to disable unused interface',
                    'security_risk': 'Potential unauthorized physical access point'
                }
            })
    
    return vulnerabilities
def _analyze_interface_usage(interface_name, interface_config, sub_interfaces, referenced_interfaces, context):
    """인터페이스 사용 여부 정교한 분석"""
    
    # 기본 사용 지표들
    has_ip_address = interface_config['has_ip_address']
    has_description = interface_config['has_description']
    has_vlan = interface_config['has_vlan']
    has_switchport = interface_config.get('has_switchport', False)
    is_loopback = interface_config.get('is_loopback', False)
    is_management = interface_config.get('is_management', False)
    
    # 서브인터페이스 존재 여부
    has_subinterfaces = interface_name in sub_interfaces
    
    # 다른 설정에서 참조 여부
    is_referenced = interface_name in referenced_interfaces
    
    # 중요한 설정 존재 여부
    config_lines = interface_config.get('config_lines', [])
    important_configs = [
        'channel-group', 'service-policy', 'access-group', 
        'nat', 'crypto map', 'tunnel', 'bridge-group'
    ]
    has_important_config = any(
        any(config_keyword in line for config_keyword in important_configs)
        for line in config_lines
    )
    
    # 트렁크 포트 여부
    is_trunk = any('switchport mode trunk' in line for line in config_lines)
    
    # 중요 인터페이스 여부 (더 정교한 판단)
    is_critical = (
        is_loopback or is_management or
        interface_name.lower().endswith('0/0') or  # 보통 첫 번째 포트는 중요
        'serial' in interface_config['port_type'].lower() or
        'console' in interface_name.lower() or
        'mgmt' in interface_name.lower()
    )
    
    # 설명 기반 중요도 판단
    if has_description:
        description = interface_config.get('description', '').lower()
        critical_keywords = ['uplink', 'trunk', 'core', 'wan', 'internet', 'isp', 'link', 'backbone']
        is_critical = is_critical or any(keyword in description for keyword in critical_keywords)
    
    # 최종 사용 여부 판단
    is_used = (
        has_ip_address or has_description or has_vlan or has_switchport or
        has_subinterfaces or is_referenced or has_important_config or is_trunk
    )
    
    return {
        'is_used': is_used,
        'is_critical': is_critical,
        'has_ip_address': has_ip_address,
        'has_description': has_description,
        'has_subinterfaces': has_subinterfaces,
        'is_referenced': is_referenced,
        'has_important_config': has_important_config,
        'is_trunk': is_trunk
    }


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



def check_user_privilege_levels(line: str, line_num: int, context: ConfigContext) -> List[Dict[str, Any]]:
    """N-15: 사용자·명령어별 권한 수준 설정 - 논리 기반 분석"""
    vulnerabilities = []
    
    # 권한 레벨 15 (최고 권한) 사용자 수 확인
    admin_users = [user for user in context.parsed_users if user['privilege_level'] == 15]
    
    if len(admin_users) > 2:  # 관리자 계정이 너무 많은 경우
        vulnerabilities.append({
            'line': 0,
            'matched_text': f'Too many administrative users ({len(admin_users)})',
            'details': {
                'vulnerability': 'excessive_admin_users',
                'admin_count': len(admin_users),
                'admin_users': [user['username'] for user in admin_users],
                'recommendation': 'Minimize the number of users with privilege level 15'
            }
        })
    
    return vulnerabilities


def check_ssh_protocol_usage(line: str, line_num: int, context: ConfigContext) -> List[Dict[str, Any]]:
    """N-16: VTY 안전한 프로토콜 사용 - 논리 기반 분석"""
    vulnerabilities = []
    
    for vty_line in context.vty_lines:
        transport_input = vty_line.get('transport_input', [])
        
        # Telnet 허용 확인
        if 'telnet' in transport_input or 'all' in transport_input:
            vulnerabilities.append({
                'line': vty_line['line_number'],
                'matched_text': f"{vty_line['line']} transport input {' '.join(transport_input)}",
                'details': {
                    'vulnerability': 'telnet_allowed',
                    'transport_input': transport_input,
                    'recommendation': 'Use transport input ssh only'
                }
            })
        
        # SSH 버전 확인
        if 'ssh' in transport_input:
            # SSH 버전 2 사용 여부 확인 (전역 설정에서)
            if 'ip ssh version 2' not in context.full_config.lower():
                vulnerabilities.append({
                    'line': vty_line['line_number'],
                    'matched_text': f"{vty_line['line']} (SSH version not specified)",
                    'details': {
                        'vulnerability': 'ssh_version_not_specified',
                        'recommendation': 'Add: ip ssh version 2'
                    }
                })
    
    return vulnerabilities


def check_auxiliary_port_security(line: str, line_num: int, context: ConfigContext) -> List[Dict[str, Any]]:
    """N-17: 불필요한 보조 입·출력 포트 사용 금지 - 논리 기반 분석"""
    vulnerabilities = []
    
    # AUX 포트 설정 확인
    aux_port_secure = False
    
    for line in context.config_lines:
        if line.strip().startswith('line aux'):
            # AUX 포트 보안 설정 확인
            if 'no exec' in context.full_config and 'transport input none' in context.full_config:
                aux_port_secure = True
            break
    
    if not aux_port_secure:
        vulnerabilities.append({
            'line': 0,
            'matched_text': 'AUX port not properly secured',
            'details': {
                'vulnerability': 'aux_port_not_secured',
                'recommendation': 'Configure AUX port with: no exec, transport input none'
            }
        })
    
    return vulnerabilities


def check_login_banner_message(line: str, line_num: int, context: ConfigContext) -> List[Dict[str, Any]]:
    """N-18: 로그온 시 경고 메시지 설정 - 논리 기반 분석"""
    vulnerabilities = []
    
    # 배너 메시지 설정 확인
    has_banner = any(line.strip().startswith('banner') for line in context.config_lines)
    
    if not has_banner:
        vulnerabilities.append({
            'line': 0,
            'matched_text': 'No login banner configured',
            'details': {
                'vulnerability': 'no_login_banner',
                'recommendation': 'Configure login banner message for unauthorized access warning'
            }
        })
    
    return vulnerabilities


def check_remote_log_server(line: str, line_num: int, context: ConfigContext) -> List[Dict[str, Any]]:
    """N-19: 원격 로그서버 사용 - 논리 기반 분석"""
    vulnerabilities = []
    
    # 원격 로그 서버 설정 확인
    has_remote_logging = False
    
    for line in context.config_lines:
        if re.match(r'^logging\s+\d+\.\d+\.\d+\.\d+', line.strip()):
            has_remote_logging = True
            break
    
    if not has_remote_logging:
        vulnerabilities.append({
            'line': 0,
            'matched_text': 'Remote log server not configured',
            'details': {
                'vulnerability': 'no_remote_log_server',
                'recommendation': 'Configure remote syslog server for centralized logging'
            }
        })
    
    return vulnerabilities


def check_logging_buffer_size(line: str, line_num: int, context: ConfigContext) -> List[Dict[str, Any]]:
    """N-20: 로깅 버퍼 크기 설정 - 논리 기반 분석"""
    vulnerabilities = []
    
    # 로깅 버퍼 크기 확인
    buffer_size = None
    
    for line in context.config_lines:
        match = re.match(r'^logging\s+buffered\s+(\d+)', line.strip())
        if match:
            buffer_size = int(match.group(1))
            break
    
    if buffer_size is None:
        vulnerabilities.append({
            'line': 0,
            'matched_text': 'Logging buffer size not configured',
            'details': {
                'vulnerability': 'no_logging_buffer_size',
                'recommendation': 'Configure appropriate logging buffer size (16000-32000 bytes)'
            }
        })
    elif buffer_size < 16000:
        vulnerabilities.append({
            'line': 0,
            'matched_text': f'Logging buffer size too small ({buffer_size})',
            'details': {
                'vulnerability': 'insufficient_logging_buffer_size',
                'current_size': buffer_size,
                'recommendation': 'Increase logging buffer size to at least 16000 bytes'
            }
        })
    
    return vulnerabilities


def check_logging_policy_configuration(line: str, line_num: int, context: ConfigContext) -> List[Dict[str, Any]]:
    """N-21: 정책에 따른 로깅 설정 - 논리 기반 분석"""
    vulnerabilities = []
    
    # 기본 로깅 설정 확인
    logging_enabled = any(line.strip().startswith('logging on') for line in context.config_lines)
    
    if not logging_enabled:
        vulnerabilities.append({
            'line': 0,
            'matched_text': 'Logging not enabled',
            'details': {
                'vulnerability': 'logging_disabled',
                'recommendation': 'Enable logging with appropriate policy configuration'
            }
        })
    
    return vulnerabilities


def check_ntp_server_configuration(line: str, line_num: int, context: ConfigContext) -> List[Dict[str, Any]]:
    """N-22: NTP 서버 연동 - 논리 기반 분석"""
    vulnerabilities = []
    
    # NTP 서버 설정 확인
    has_ntp_server = False
    
    for line in context.config_lines:
        if re.match(r'^ntp\s+server\s+\d+\.\d+\.\d+\.\d+', line.strip()):
            has_ntp_server = True
            break
    
    if not has_ntp_server:
        vulnerabilities.append({
            'line': 0,
            'matched_text': 'NTP server not configured',
            'details': {
                'vulnerability': 'no_ntp_server',
                'recommendation': 'Configure NTP server for time synchronization'
            }
        })
    
    return vulnerabilities


def check_timestamp_logging(line: str, line_num: int, context: ConfigContext) -> List[Dict[str, Any]]:
    """N-23: timestamp 로그 설정 - 논리 기반 분석"""
    vulnerabilities = []
    
    # 타임스탬프 로깅 설정 확인
    has_timestamp = any('service timestamps' in line for line in context.config_lines)
    
    if not has_timestamp:
        vulnerabilities.append({
            'line': 0,
            'matched_text': 'Timestamp logging not configured',
            'details': {
                'vulnerability': 'no_timestamp_logging',
                'recommendation': 'Configure service timestamps log datetime for log entries'
            }
        })
    
    return vulnerabilities


def check_tcp_keepalive_service(line: str, line_num: int, context: ConfigContext) -> List[Dict[str, Any]]:
    """N-24: TCP Keepalive 서비스 설정 - 논리 기반 분석"""
    vulnerabilities = []
    
    # TCP Keepalive 설정 확인
    tcp_keepalive_in = context.parsed_services.get('tcp-keepalives-in', False)
    tcp_keepalive_out = context.parsed_services.get('tcp-keepalives-out', False)
    
    if not tcp_keepalive_in or not tcp_keepalive_out:
        vulnerabilities.append({
            'line': 0,
            'matched_text': 'TCP Keepalive service not fully configured',
            'details': {
                'vulnerability': 'tcp_keepalive_not_configured',
                'tcp_keepalive_in': tcp_keepalive_in,
                'tcp_keepalive_out': tcp_keepalive_out,
                'recommendation': 'Configure both service tcp-keepalives-in and tcp-keepalives-out'
            }
        })
    
    return vulnerabilities


def check_finger_service_status(line: str, line_num: int, context: ConfigContext) -> List[Dict[str, Any]]:
    """N-25: Finger 서비스 차단 - 논리 기반 분석"""
    vulnerabilities = []
    
    # Finger 서비스 설정 확인
    finger_enabled = context.parsed_services.get('finger', False)
    
    if finger_enabled:
        vulnerabilities.append({
            'line': 0,
            'matched_text': 'Finger service enabled',
            'details': {
                'vulnerability': 'finger_service_enabled',
                'recommendation': 'Disable finger service: no service finger'
            }
        })
    
    return vulnerabilities


def check_web_service_security(line: str, line_num: int, context: ConfigContext) -> List[Dict[str, Any]]:
    """N-26: 웹 서비스 차단 - 논리 기반 분석"""
    vulnerabilities = []
    
    # HTTP 서버 설정 확인
    http_server_enabled = context.parsed_services.get('http_server', False)
    
    if http_server_enabled:
        vulnerabilities.append({
            'line': 0,
            'matched_text': 'HTTP server enabled',
            'details': {
                'vulnerability': 'http_server_enabled',
                'recommendation': 'Disable HTTP server: no ip http server'
            }
        })
    
    return vulnerabilities


def check_small_services_status(line: str, line_num: int, context: ConfigContext) -> List[Dict[str, Any]]:
    """N-27: TCP/UDP Small 서비스 차단 - 논리 기반 분석"""
    vulnerabilities = []
    
    # Small services 설정 확인
    tcp_small_servers = context.parsed_services.get('tcp-small-servers', False)
    udp_small_servers = context.parsed_services.get('udp-small-servers', False)
    
    if tcp_small_servers or udp_small_servers:
        vulnerabilities.append({
            'line': 0,
            'matched_text': 'Small services enabled',
            'details': {
                'vulnerability': 'small_services_enabled',
                'tcp_small_servers': tcp_small_servers,
                'udp_small_servers': udp_small_servers,
                'recommendation': 'Disable small services: no service tcp-small-servers, no service udp-small-servers'
            }
        })
    
    return vulnerabilities


def check_bootp_service_status(line: str, line_num: int, context: ConfigContext) -> List[Dict[str, Any]]:
    """N-28: Bootp 서비스 차단 - 논리 기반 분석"""
    vulnerabilities = []
    
    # BOOTP 서버 설정 확인
    bootp_server_enabled = False
    
    for line in context.config_lines:
        if line.strip().startswith('ip bootp server') and not line.strip().startswith('no ip bootp server'):
            bootp_server_enabled = True
            break
    
    if bootp_server_enabled:
        vulnerabilities.append({
            'line': 0,
            'matched_text': 'BOOTP server enabled',
            'details': {
                'vulnerability': 'bootp_server_enabled',
                'recommendation': 'Disable BOOTP server: no ip bootp server'
            }
        })
    
    return vulnerabilities


def check_cdp_service_status(line: str, line_num: int, context: ConfigContext) -> List[Dict[str, Any]]:
    """N-29: CDP 서비스 차단 - 논리 기반 분석"""
    vulnerabilities = []
    
    # CDP 서비스 설정 확인
    cdp_enabled = False
    
    for line in context.config_lines:
        if line.strip() == 'cdp run':
            cdp_enabled = True
            break
        elif line.strip() == 'no cdp run':
            cdp_enabled = False
            break
    
    if cdp_enabled:
        vulnerabilities.append({
            'line': 0,
            'matched_text': 'CDP service enabled',
            'details': {
                'vulnerability': 'cdp_service_enabled',
                'recommendation': 'Disable CDP service: no cdp run'
            }
        })
    
    return vulnerabilities


def check_directed_broadcast_status(line: str, line_num: int, context: ConfigContext) -> List[Dict[str, Any]]:
    """N-30: Directed-broadcast 차단 - 논리 기반 분석"""
    vulnerabilities = []
    
    # Directed broadcast 설정 확인
    for interface_name, interface_config in context.parsed_interfaces.items():
        directed_broadcast_disabled = False
        
        for config_line in interface_config.get('config_lines', []):
            if 'no ip directed-broadcast' in config_line:
                directed_broadcast_disabled = True
                break
        
        if not directed_broadcast_disabled and interface_config['port_type'] in ['FastEthernet', 'GigabitEthernet']:
            vulnerabilities.append({
                'line': interface_config['line_number'],
                'matched_text': f"interface {interface_name}",
                'details': {
                    'vulnerability': 'directed_broadcast_not_disabled',
                    'interface_name': interface_name,
                    'recommendation': 'Disable directed broadcast: no ip directed-broadcast'
                }
            })
    
    return vulnerabilities


def check_source_routing_status(line: str, line_num: int, context: ConfigContext) -> List[Dict[str, Any]]:
    """N-31: Source 라우팅 차단 - 논리 기반 분석"""
    vulnerabilities = []
    
    # Source routing 설정 확인
    source_routing_disabled = any('no ip source-route' in line for line in context.config_lines)
    
    if not source_routing_disabled:
        vulnerabilities.append({
            'line': 0,
            'matched_text': 'Source routing not disabled',
            'details': {
                'vulnerability': 'source_routing_enabled',
                'recommendation': 'Disable source routing: no ip source-route'
            }
        })
    
    return vulnerabilities


def check_proxy_arp_status(line: str, line_num: int, context: ConfigContext) -> List[Dict[str, Any]]:
    """N-32: Proxy ARP 차단 - 기본값 고려 개선된 버전"""
    vulnerabilities = []
    
    for interface_name, interface_config in context.parsed_interfaces.items():
        # 물리 인터페이스만 체크
        if interface_config['port_type'] not in ['FastEthernet', 'GigabitEthernet', 'TenGigabitEthernet']:
            continue
            
        # 루프백, 관리 인터페이스 제외
        if interface_config.get('is_loopback') or interface_config.get('is_management'):
            continue
            
        config_lines = interface_config.get('config_lines', [])
        
        # 명시적 설정 확인
        proxy_arp_explicitly_disabled = any('no ip proxy-arp' in line for line in config_lines)
        proxy_arp_explicitly_enabled = any(
            'ip proxy-arp' in line and not line.strip().startswith('no ') 
            for line in config_lines
        )
        
        # 실제 상태 판단 (기본값 고려)
        if proxy_arp_explicitly_disabled:
            actual_state = False  # 비활성화됨
        elif proxy_arp_explicitly_enabled:
            actual_state = True   # 명시적 활성화
        else:
            # 기본값 적용: Cisco는 기본적으로 proxy-arp enabled
            actual_state = context.get_service_state('proxy_arp')
        
        # 보안 기준: proxy-arp는 비활성화되어야 함
        if actual_state:  # 활성화된 경우 취약
            status = "explicitly_enabled" if proxy_arp_explicitly_enabled else "default_enabled"
            
            vulnerabilities.append({
                'line': interface_config['line_number'],
                'matched_text': f"interface {interface_name}",
                'details': {
                    'vulnerability': 'proxy_arp_enabled',
                    'interface_name': interface_name,
                    'status': status,
                    'recommendation': 'Add: no ip proxy-arp' if status == "default_enabled" 
                                    else 'Change to: no ip proxy-arp',
                    'default_behavior': 'Cisco default: proxy-arp enabled'
                }
            })
    
    return vulnerabilities


def check_icmp_services_status(line: str, line_num: int, context: ConfigContext) -> List[Dict[str, Any]]:
    """N-33: ICMP unreachable, Redirect 차단 - 논리 기반 분석"""
    vulnerabilities = []
    
    # ICMP unreachable, redirect 설정 확인
    for interface_name, interface_config in context.parsed_interfaces.items():
        unreachables_disabled = False
        redirects_disabled = False
        
        for config_line in interface_config.get('config_lines', []):
            if 'no ip unreachables' in config_line:
                unreachables_disabled = True
            if 'no ip redirects' in config_line:
                redirects_disabled = True
        
        if not unreachables_disabled or not redirects_disabled:
            vulnerabilities.append({
                'line': interface_config['line_number'],
                'matched_text': f"interface {interface_name}",
                'details': {
                    'vulnerability': 'icmp_services_not_disabled',
                    'interface_name': interface_name,
                    'unreachables_disabled': unreachables_disabled,
                    'redirects_disabled': redirects_disabled,
                    'recommendation': 'Disable ICMP unreachables and redirects: no ip unreachables, no ip redirects'
                }
            })
    
    return vulnerabilities


def check_identd_service_status(line: str, line_num: int, context: ConfigContext) -> List[Dict[str, Any]]:
    """N-34: identd 서비스 차단 - 논리 기반 분석"""
    vulnerabilities = []
    
    # identd 서비스 설정 확인
    identd_enabled = False
    
    for line in context.config_lines:
        if line.strip().startswith('ip identd') and not line.strip().startswith('no ip identd'):
            identd_enabled = True
            break
    
    if identd_enabled:
        vulnerabilities.append({
            'line': 0,
            'matched_text': 'identd service enabled',
            'details': {
                'vulnerability': 'identd_service_enabled',
                'recommendation': 'Disable identd service: no ip identd'
            }
        })
    
    return vulnerabilities


def check_domain_lookup_status(line: str, line_num: int, context: ConfigContext) -> List[Dict[str, Any]]:
    """N-35: Domain lookup 차단 - 논리 기반 분석"""
    vulnerabilities = []
    
    # Domain lookup 설정 확인
    domain_lookup_enabled = context.parsed_services.get('domain_lookup', True)  # 기본값은 enabled
    
    if domain_lookup_enabled:
        vulnerabilities.append({
            'line': 0,
            'matched_text': 'Domain lookup enabled',
            'details': {
                'vulnerability': 'domain_lookup_enabled',
                'recommendation': 'Disable domain lookup: no ip domain-lookup'
            }
        })
    
    return vulnerabilities


def check_pad_service_status(line: str, line_num: int, context: ConfigContext) -> List[Dict[str, Any]]:
    """N-36: PAD 차단 - 논리 기반 분석"""
    vulnerabilities = []
    
    # PAD 서비스 설정 확인
    pad_enabled = context.parsed_services.get('pad', False)
    
    if pad_enabled:
        vulnerabilities.append({
            'line': 0,
            'matched_text': 'PAD service enabled',
            'details': {
                'vulnerability': 'pad_service_enabled',
                'recommendation': 'Disable PAD service: no service pad'
            }
        })
    
    return vulnerabilities


def check_mask_reply_status(line: str, line_num: int, context: ConfigContext) -> List[Dict[str, Any]]:
    """N-37: mask-reply 차단 - 기본값 고려 개선된 버전"""
    vulnerabilities = []
    
    for interface_name, interface_config in context.parsed_interfaces.items():
        # 물리 인터페이스만 체크
        if interface_config['port_type'] not in ['FastEthernet', 'GigabitEthernet', 'TenGigabitEthernet']:
            continue
            
        config_lines = interface_config.get('config_lines', [])
        
        # 명시적 설정 확인
        mask_reply_explicitly_disabled = any('no ip mask-reply' in line for line in config_lines)
        mask_reply_explicitly_enabled = any(
            'ip mask-reply' in line and not line.strip().startswith('no ')
            for line in config_lines
        )
        
        # 실제 상태 판단 (버전별 기본값 고려)
        if mask_reply_explicitly_disabled:
            actual_state = False
        elif mask_reply_explicitly_enabled:
            actual_state = True
        else:
            # 기본값 적용 (버전별 차이 고려)
            actual_state = context.get_service_state('mask_reply')
        
        # 보안 기준: mask-reply는 비활성화되어야 함
        if actual_state:  # 활성화된 경우 취약
            status = "explicitly_enabled" if mask_reply_explicitly_enabled else "default_enabled"
            
            vulnerabilities.append({
                'line': interface_config['line_number'],
                'matched_text': f"interface {interface_name}",
                'details': {
                    'vulnerability': 'mask_reply_enabled',
                    'interface_name': interface_name,
                    'status': status,
                    'recommendation': 'Add: no ip mask-reply' if status == "default_enabled"
                                    else 'Change to: no ip mask-reply',
                    'ios_version': context.ios_version,
                    'default_behavior': f'IOS {context.ios_version}: mask-reply default {"enabled" if actual_state else "disabled"}'
                }
            })
    
    return vulnerabilities


def check_switch_hub_security(line: str, line_num: int, context: ConfigContext) -> List[Dict[str, Any]]:
    """N-38: 스위치, 허브 보안 강화 - 논리 기반 분석"""
    vulnerabilities = []
    
    # 포트 보안 및 SPAN 설정 확인
    port_security_configured = False
    span_configured = False
    
    for line in context.config_lines:
        if 'switchport port-security' in line:
            port_security_configured = True
        if 'monitor session' in line:
            span_configured = True
    
    if not port_security_configured:
        vulnerabilities.append({
            'line': 0,
            'matched_text': 'Port security not configured',
            'details': {
                'vulnerability': 'no_port_security',
                'recommendation': 'Configure port security on switch ports'
            }
        })
    
    if not span_configured:
        vulnerabilities.append({
            'line': 0,
            'matched_text': 'SPAN not configured',
            'details': {
                'vulnerability': 'no_span_configuration',
                'recommendation': 'Configure SPAN (Switch Port Analyzer) for monitoring'
            }
        })
    
    return vulnerabilities


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