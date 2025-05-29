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
    """N-01: 기본 패스워드 사용 - 완전한 논리 기반 분석 (최신 장비 지원)"""
    vulnerabilities = []
    
    # 기본 패스워드 패턴들 (확장)
    basic_passwords = [
        'cisco', 'admin', 'password', '123', '1234', '12345', '123456',
        'default', 'pass', 'root', 'user', 'guest', 'test', 'temp',
        'cisco123', 'admin123', 'password123'
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
                    'recommendation': 'Use enable secret with strong password or algorithm-type'
                }
            })
    
    # 사용자 패스워드 검사 (최신 버전 고려)
    for user in context.parsed_users:
        # 최신 암호화를 사용하는 경우는 양호
        if user.get('is_modern_encryption', False):
            continue
            
        # 기본 패스워드 사용 여부 확인
        if user['has_password'] and not user['password_encrypted']:
            if user['username'].lower() in basic_passwords:
                vulnerabilities.append({
                    'line': user['line_number'],
                    'matched_text': f"username {user['username']} with basic password",
                    'details': {
                        'password_type': 'user_password',
                        'vulnerability': 'username_as_password',
                        'username': user['username'],
                        'recommendation': 'Use username secret with algorithm-type sha256 or scrypt'
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
    """N-03: 암호화된 패스워드 사용 - 논리 기반 분석 (최신 장비 지원)"""
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
                'recommendation': 'Use enable secret with algorithm-type sha256 or enable algorithm-type scrypt secret'
            }
        })
    
    # 사용자 패스워드 암호화 검사
    for user in context.parsed_users:
        user_issues = []
        
        # 최신 강력한 암호화를 사용하는 경우는 양호
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
        
        # 오래된 MD5 암호화만 사용
        elif user.get('encryption_type') == 'type5_md5' and not user.get('algorithm_type'):
            user_issues.append('outdated_md5_only')
        
        if user_issues:
            recommendation = "Use username secret with algorithm-type sha256 or scrypt for modern security"
            if 'weak_type7_encryption' in user_issues:
                recommendation = "Replace Type 7 encryption with algorithm-type sha256 secret"
            elif 'outdated_md5_only' in user_issues:
                recommendation = "Consider upgrading from MD5 to algorithm-type sha256 for better security"
            
            vulnerabilities.append({
                'line': user['line_number'],
                'matched_text': f"username {user['username']} password encryption issue",
                'details': {
                    'vulnerability': 'password_encryption_insufficient',
                    'username': user['username'],
                    'issues': user_issues,
                    'current_encryption': user.get('encryption_type', 'none'),
                    'algorithm_type': user.get('algorithm_type'),
                    'recommendation': recommendation
                }
            })
    
    return vulnerabilities


def check_vty_access_control(line: str, line_num: int, context: ConfigContext) -> List[Dict[str, Any]]:
    """N-04: VTY 접근 제한 설정 - 완전한 논리 기반 분석"""
    vulnerabilities = []
    
    for vty_line in context.vty_lines:
        issues = []
        
        # Access-class 확인
        if not vty_line['has_access_class']:
            issues.append('no_access_class')
        
        # Transport input 확인  
        if 'all' in vty_line.get('transport_input', []) or 'telnet' in vty_line.get('transport_input', []):
            issues.append('insecure_transport')
        
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
                    'transport_input': vty_line.get('transport_input', [])
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


def check_snmp_acl_configuration(line: str, line_num: int, context: ConfigContext) -> List[Dict[str, Any]]:
    """N-09: SNMP ACL 설정 - 논리 기반 분석"""
    vulnerabilities = []
    
    for community_info in context.snmp_communities:
        if not community_info['acl']:
            vulnerabilities.append({
                'line': community_info['line_number'],
                'matched_text': f"snmp-server community {community_info['community']}",
                'details': {
                    'vulnerability': 'no_snmp_acl',
                    'community': community_info['community'],
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
    """N-14: 사용하지 않는 인터페이스의 Shutdown 설정 - 완전한 논리 기반 분석"""
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
        is_critical = _is_critical_interface(interface_name, context.device_type)
        
        # 물리적 인터페이스만 체크 (VLAN, Loopback 제외)
        is_physical = interface_config['port_type'] in ['FastEthernet', 'GigabitEthernet', 'TenGigabitEthernet', 'Serial']
        
        if not is_used and is_active and not is_critical and is_physical:
            vulnerabilities.append({
                'line': interface_config['line_number'],
                'matched_text': f"interface {interface_name}",
                'details': {
                    'interface_name': interface_name,
                    'port_type': interface_config['port_type'],
                    'reason': 'Unused physical interface not shutdown',
                    'has_ip': interface_config['has_ip_address'],
                    'has_description': interface_config['has_description'],
                    'has_vlan': interface_config['has_vlan'],
                    'is_shutdown': interface_config['is_shutdown'],
                    'analysis': {
                        'is_used': is_used,
                        'is_active': is_active,
                        'is_critical': is_critical,
                        'is_physical': is_physical
                    }
                }
            })
    
    return vulnerabilities


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
    """N-32: Proxy ARP 차단 - 논리 기반 분석"""
    vulnerabilities = []
    
    # Proxy ARP 설정 확인
    for interface_name, interface_config in context.parsed_interfaces.items():
        proxy_arp_disabled = False
        
        for config_line in interface_config.get('config_lines', []):
            if 'no ip proxy-arp' in config_line:
                proxy_arp_disabled = True
                break
        
        if not proxy_arp_disabled and interface_config['port_type'] in ['FastEthernet', 'GigabitEthernet']:
            vulnerabilities.append({
                'line': interface_config['line_number'],
                'matched_text': f"interface {interface_name}",
                'details': {
                    'vulnerability': 'proxy_arp_not_disabled',
                    'interface_name': interface_name,
                    'recommendation': 'Disable proxy ARP: no ip proxy-arp'
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
    """N-37: mask-reply 차단 - 논리 기반 분석"""
    vulnerabilities = []
    
    # Mask reply 설정 확인
    for interface_name, interface_config in context.parsed_interfaces.items():
        mask_reply_disabled = False
        
        for config_line in interface_config.get('config_lines', []):
            if 'no ip mask-reply' in config_line:
                mask_reply_disabled = True
                break
        
        if not mask_reply_disabled and interface_config['port_type'] in ['FastEthernet', 'GigabitEthernet']:
            vulnerabilities.append({
                'line': interface_config['line_number'],
                'matched_text': f"interface {interface_name}",
                'details': {
                    'vulnerability': 'mask_reply_not_disabled',
                    'interface_name': interface_name,
                    'recommendation': 'Disable mask reply: no ip mask-reply'
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


def check_snmp_security(line: str, line_num: int, context: ConfigContext) -> List[Dict[str, Any]]:
    """N-08: SNMP Community String 복잡성 - 완전한 논리 기반 분석"""
    vulnerabilities = []
    
    for community_info in context.snmp_communities:
        issues = []
        
        # 기본 커뮤니티 스트링 확인
        if community_info['is_default']:
            issues.append('default_community')
        
        # 길이 확인
        if community_info['length'] < 6:
            issues.append('too_short')
        
        # 단순한 패턴 확인
        simple_patterns = ['123', '456', '111', '000', 'admin', 'test', 'temp']
        if any(pattern in community_info['community'].lower() for pattern in simple_patterns):
            issues.append('simple_pattern')
        
        # ACL 확인
        if not community_info['acl']:
            issues.append('no_acl')
        
        if issues:
            vulnerabilities.append({
                'line': community_info['line_number'],
                'matched_text': f"snmp-server community {community_info['community']}",
                'details': {
                    'community': community_info['community'],
                    'issues': issues,
                    'permission': community_info['permission'],
                    'has_acl': bool(community_info['acl']),
                    'community_length': community_info['length']
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