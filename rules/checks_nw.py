# -*- coding: utf-8 -*-
"""
rules/checks_nw.py
NW 네트워크 장비 보안 점검 룰의 논리적 검증 함수들 (완전판)

각 NW 룰에 대한 logical_check_function들을 정의
"""
import re
from typing import List, Dict, Any
from .kisa_rules import ConfigContext


def check_nw_01(line: str, line_num: int, context: ConfigContext) -> List[Dict[str, Any]]:
    """NW-01: 기본 패스워드 설정 - 개선된 논리 기반 분석"""
    vulnerabilities = []
    
    # 기본 패스워드 패턴들 (확장)
    basic_passwords = [
        'cisco', 'admin', 'password', '123', '1234', '12345', '123456',
        'default', 'pass', 'root', 'user', 'guest', 'test', 'temp',
        'switch', 'router', 'manager', 'security', 'public', 'private'
    ]
    
    # Enable 패스워드 검사 - secret은 제외
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
                    'recommendation': 'Use enable secret with strong password',
                    'severity_adjusted': 'High'
                }
            })
    
    # 사용자 패스워드 검사 - secret 타입은 제외
    for user in context.parsed_users:
        # secret 타입은 이미 안전함
        if user.get('password_type') == 'secret':
            continue
            
        if user['has_password'] and not user['password_encrypted']:
            # 기본 사용자명과 패스워드 체크
            if user['username'].lower() in basic_passwords:
                vulnerabilities.append({
                    'line': user['line_number'],
                    'matched_text': f"username {user['username']} with basic credentials",
                    'details': {
                        'password_type': 'user_password',
                        'vulnerability': 'basic_username_password',
                        'username': user['username'],
                        'severity_adjusted': 'High'
                    }
                })
    
    return vulnerabilities


def check_nw_02(line: str, line_num: int, context: ConfigContext) -> List[Dict[str, Any]]:
    """NW-02: 패스워드 복잡성 설정 - 개선된 논리 기반 분석"""
    vulnerabilities = []
    
    # secret 타입 사용자 확인
    has_secret_users = any(
        user.get('password_type') == 'secret' 
        for user in context.parsed_users
    )
    
    # enable secret 사용 확인
    has_enable_secret = context.global_settings.get('enable_password_type') == 'secret'
    
    # 패스워드 암호화 서비스 확인
    password_encryption_enabled = context.parsed_services.get('password-encryption', False)
    
    # 패스워드 최소 길이 설정 확인
    has_min_length = any([
        'passwords min-length' in context.full_config,
        'password-policy' in context.full_config,
        'security passwords min-length' in context.full_config
    ])
    
    # 복잡성 정책이 필요한지 판단
    needs_complexity_policy = False
    weak_passwords = []
    
    for user in context.parsed_users:
        # secret 타입은 제외 (이미 복잡성 보장)
        if user.get('password_type') == 'secret':
            continue
            
        if user['has_password'] and not user['password_encrypted']:
            needs_complexity_policy = True
            weak_passwords.append(user)
    
    # 정책이 없고 약한 패스워드가 있는 경우만 보고
    if needs_complexity_policy and not has_min_length and not password_encryption_enabled:
        vulnerabilities.append({
            'line': 0,
            'matched_text': '패스워드 복잡성 정책 설정 필요',
            'details': {
                'vulnerability': 'no_password_complexity_policy',
                'has_secret_users': has_secret_users,
                'has_enable_secret': has_enable_secret,
                'weak_password_count': len(weak_passwords),
                'recommendation': 'Configure password complexity policy or use secret passwords',
                'severity_adjusted': 'Medium' if has_secret_users else 'High'
            }
        })
    
    # 개별 약한 패스워드 검사
    for user in weak_passwords:
        vulnerabilities.append({
            'line': user['line_number'],
            'matched_text': f"username {user['username']} password (weak complexity)",
            'details': {
                'vulnerability': 'weak_password_complexity',
                'username': user['username'],
                'recommendation': 'Use username secret or enable service password-encryption',
                'severity_adjusted': 'Medium'
            }
        })
    
    return vulnerabilities


def check_nw_03(line: str, line_num: int, context: ConfigContext) -> List[Dict[str, Any]]:
    """NW-03: 암호화된 비밀번호 사용 - 개선된 논리 기반 분석"""
    vulnerabilities = []
    
    # Service password-encryption 확인
    password_encryption_enabled = context.parsed_services.get('password-encryption', False)
    
    # Console 라인에서 평문 패스워드 확인
    console_password_found = False
    for line_content in context.config_lines:
        if line_content.strip().startswith('password ') and not any(enc in line_content for enc in ['secret', '$', '5']):
            console_password_found = True
            break
    
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
    
    # Service password-encryption 확인
    if not password_encryption_enabled and console_password_found:
        vulnerabilities.append({
            'line': 0,
            'matched_text': 'service password-encryption disabled with plaintext passwords',
            'details': {
                'vulnerability': 'password_encryption_disabled',
                'has_console_password': console_password_found,
                'recommendation': 'Enable service password-encryption'
            }
        })
    
    # 암호화되지 않은 사용자 패스워드 확인
    unencrypted_users = [user for user in context.parsed_users 
                        if user['has_password'] and not user['password_encrypted']]
    
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
    
    return vulnerabilities


def check_nw_04(line: str, line_num: int, context: ConfigContext) -> List[Dict[str, Any]]:
    """NW-04: 사용자·명령어별 권한 수준 설정 - 중복 제거 및 개선"""
    vulnerabilities = []
    
    # 실제 유니크한 사용자만 계산
    unique_users = {}
    for user in context.parsed_users:
        username = user.get('username')
        if username:
            unique_users[username] = user
    
    high_privilege_users = []
    total_unique_users = len(unique_users)
    
    for username, user in unique_users.items():
        if user.get('privilege_level', 1) == 15:
            high_privilege_users.append(user)
    
    # 2명 이상의 사용자가 있고 모두 최고 권한인 경우만 보고
    if total_unique_users > 1 and len(high_privilege_users) == total_unique_users:
        vulnerabilities.append({
            'line': 0,
            'matched_text': f"All {total_unique_users} users have maximum privilege level 15",
            'details': {
                'vulnerability': 'all_users_max_privilege',
                'high_privilege_count': len(high_privilege_users),
                'total_users': total_unique_users,
                'users': list(unique_users.keys()),
                'recommendation': 'Assign different privilege levels based on user roles',
                'severity_adjusted': 'Medium'
            }
        })
    
    # 개별 사용자 경고는 중복 제거
    # 3명 이상일 때만 개별 경고
    elif len(high_privilege_users) >= 3:
        for user in high_privilege_users[:1]:  # 대표 1개만
            vulnerabilities.append({
                'line': user['line_number'],
                'matched_text': f"{len(high_privilege_users)} users with privilege 15",
                'details': {
                    'vulnerability': 'multiple_max_privilege_users',
                    'high_privilege_count': len(high_privilege_users),
                    'recommendation': 'Consider implementing role-based access control',
                    'severity_adjusted': 'Low'
                }
            })
    
    return vulnerabilities


def check_nw_05(line: str, line_num: int, context: ConfigContext) -> List[Dict[str, Any]]:
    """NW-05: VTY 접근(ACL) 설정 - 개선된 논리 기반 분석"""
    vulnerabilities = []
    
    if not context.vty_lines:
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
                    'recommendation': 'VTY 라인에 access-class를 설정하여 접속 가능한 IP를 제한하세요.'
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
                    'recommendation': '입력 대기 시간이 5분이 되도록 exec-timeout 5 0을 설정하세요.'
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
                    'recommendation': '입력 대기 시간이 5분이 되도록 exec-timeout 5 0을 설정하세요.'
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


def check_nw_07(line: str, line_num: int, context: ConfigContext) -> List[Dict[str, Any]]:
    """NW-07: VTY 접속 시 안전한 프로토콜 사용 - 논리 기반 분석"""
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


def check_nw_08(line: str, line_num: int, context: ConfigContext) -> List[Dict[str, Any]]:
    """NW-08: 불필요한 보조 입출력 포트 사용 금지 - 보조 포트 전용 분석"""
    vulnerabilities = []
    
    # AUX 포트 보안 설정 확인
    aux_issues = _check_aux_port_security_nw08(context)
    vulnerabilities.extend(aux_issues)
    
    # Console 포트 보안 설정 확인
    console_issues = _check_console_port_security_nw08(context)
    vulnerabilities.extend(console_issues)
    
    return vulnerabilities


def _check_aux_port_security_nw08(context: ConfigContext) -> List[Dict[str, Any]]:
    """AUX 포트 보안 설정 확인 (NW-08 전용)"""
    issues = []
    
    # AUX 라인 설정 찾기
    config_lines = context.config_lines
    aux_line_found = False
    aux_line_number = 0
    aux_config = {
        'has_no_exec': False,
        'transport_input_none': False,
        'has_password': False,
        'exec_timeout_zero': False
    }
    
    in_aux_section = False
    
    for i, line in enumerate(config_lines):
        line_clean = line.strip()
        original_line = line
        
        # AUX 라인 시작
        if line_clean.startswith('line aux'):
            aux_line_found = True
            aux_line_number = i + 1
            in_aux_section = True
            continue
            
        # AUX 섹션 내부 설정
        elif in_aux_section and original_line.startswith(' '):
            if 'no exec' in line_clean:
                aux_config['has_no_exec'] = True
            elif 'transport input none' in line_clean:
                aux_config['transport_input_none'] = True
            elif 'password' in line_clean:
                aux_config['has_password'] = True
            elif 'exec-timeout 0' in line_clean:
                aux_config['exec_timeout_zero'] = True
                
        # 다른 섹션 시작하면 AUX 섹션 종료
        elif in_aux_section and not original_line.startswith(' ') and line_clean:
            in_aux_section = False
    
    if aux_line_found:
        # AUX 포트가 설정되었지만 보안 설정이 부족한 경우
        security_issues = []
        
        if not aux_config['has_no_exec']:
            security_issues.append('exec_enabled')
            
        if not aux_config['transport_input_none']:
            security_issues.append('transport_input_not_disabled')
            
        if aux_config['has_password'] and not aux_config['has_no_exec']:
            security_issues.append('password_set_but_exec_enabled')
            
        if aux_config['exec_timeout_zero']:
            security_issues.append('infinite_timeout')
        
        if security_issues:
            issues.append({
                'line': aux_line_number,
                'matched_text': 'line aux 0 (insecure configuration)',
                'details': {
                    'port_type': 'aux',
                    'vulnerability': 'aux_port_not_secured',
                    'security_issues': security_issues,
                    'current_config': aux_config,
                    'recommendation': 'Configure: no exec, transport input none to secure AUX port',
                    'severity_adjusted': 'High'
                }
            })
    
    return issues


def _check_console_port_security_nw08(context: ConfigContext) -> List[Dict[str, Any]]:
    """Console 포트 보안 설정 확인 (NW-08 전용)"""
    issues = []
    
    # Console 라인 설정 찾기
    config_lines = context.config_lines
    console_line_found = False
    console_line_number = 0
    console_config = {
        'has_password': False,
        'has_login': False,
        'exec_timeout': None,
        'has_logging_sync': False
    }
    
    in_console_section = False
    
    for i, line in enumerate(config_lines):
        line_clean = line.strip()
        original_line = line
        
        # Console 라인 시작 (line con 0 또는 line console 0)
        if line_clean.startswith('line con') or line_clean.startswith('line console'):
            console_line_found = True
            console_line_number = i + 1
            in_console_section = True
            continue
            
        # Console 섹션 내부 설정
        elif in_console_section and original_line.startswith(' '):
            if 'password' in line_clean:
                console_config['has_password'] = True
            elif line_clean in ['login', 'login local']:
                console_config['has_login'] = True
            elif 'exec-timeout' in line_clean:
                # exec-timeout 값 파싱
                parts = line_clean.split()
                if len(parts) >= 2:
                    try:
                        minutes = int(parts[1])
                        seconds = int(parts[2]) if len(parts) > 2 else 0
                        console_config['exec_timeout'] = minutes * 60 + seconds
                    except:
                        pass
            elif 'logging synchronous' in line_clean:
                console_config['has_logging_sync'] = True
                
        # 다른 섹션 시작하면 Console 섹션 종료
        elif in_console_section and not original_line.startswith(' ') and line_clean:
            in_console_section = False
    
    if console_line_found:
        # Console 포트 보안 권고사항 확인
        recommendations = []
        
        # 패스워드가 없는 경우
        if not console_config['has_password']:
            recommendations.append('set_console_password')
            
        # 로그인 설정이 없는 경우
        if not console_config['has_login']:
            recommendations.append('configure_login')
            
        # 무제한 타임아웃인 경우
        if console_config['exec_timeout'] == 0:
            recommendations.append('set_exec_timeout')
            
        # 로깅 동기화가 없는 경우 (보안과 직접 관련은 없지만 권고)
        if not console_config['has_logging_sync']:
            recommendations.append('enable_logging_sync')
        
        # 심각한 보안 문제만 보고 (패스워드나 로그인이 없는 경우)
        critical_issues = [r for r in recommendations if r in ['set_console_password', 'configure_login']]
        
        if critical_issues:
            issues.append({
                'line': console_line_number,
                'matched_text': 'line con 0 (security recommendations)',
                'details': {
                    'port_type': 'console',
                    'vulnerability': 'console_port_security_recommendations',
                    'critical_issues': critical_issues,
                    'all_recommendations': recommendations,
                    'current_config': console_config,
                    'recommendation': 'Secure console port with password and login configuration',
                    'severity_adjusted': 'Medium' if 'set_console_password' in critical_issues else 'Low'
                }
            })
    
    return issues


def _check_console_port_security_nw08(context: ConfigContext) -> List[Dict[str, Any]]:
    """Console 포트 보안 설정 확인 (NW-08 전용)"""
    issues = []
    
    # Console 라인 설정 찾기
    config_lines = context.config_lines
    console_line_found = False
    console_line_number = 0
    console_config = {
        'has_password': False,
        'has_login': False,
        'exec_timeout': None,
        'has_logging_sync': False
    }
    
    in_console_section = False
    
    for i, line in enumerate(config_lines):
        line_clean = line.strip()
        original_line = line
        
        # Console 라인 시작 (line con 0 또는 line console 0)
        if line_clean.startswith('line con') or line_clean.startswith('line console'):
            console_line_found = True
            console_line_number = i + 1
            in_console_section = True
            continue
            
        # Console 섹션 내부 설정
        elif in_console_section and original_line.startswith(' '):
            if 'password' in line_clean:
                console_config['has_password'] = True
            elif line_clean in ['login', 'login local']:
                console_config['has_login'] = True
            elif 'exec-timeout' in line_clean:
                # exec-timeout 값 파싱
                parts = line_clean.split()
                if len(parts) >= 2:
                    try:
                        minutes = int(parts[1])
                        seconds = int(parts[2]) if len(parts) > 2 else 0
                        console_config['exec_timeout'] = minutes * 60 + seconds
                    except:
                        pass
            elif 'logging synchronous' in line_clean:
                console_config['has_logging_sync'] = True
                
        # 다른 섹션 시작하면 Console 섹션 종료
        elif in_console_section and not original_line.startswith(' ') and line_clean:
            in_console_section = False
    
    if console_line_found:
        # Console 포트 보안 권고사항 확인
        recommendations = []
        
        # 패스워드가 없는 경우
        if not console_config['has_password']:
            recommendations.append('set_console_password')
            
        # 로그인 설정이 없는 경우
        if not console_config['has_login']:
            recommendations.append('configure_login')
            
        # 무제한 타임아웃인 경우
        if console_config['exec_timeout'] == 0:
            recommendations.append('set_exec_timeout')
            
        # 로깅 동기화가 없는 경우 (보안과 직접 관련은 없지만 권고)
        if not console_config['has_logging_sync']:
            recommendations.append('enable_logging_sync')
        
        # 심각한 보안 문제만 보고 (패스워드나 로그인이 없는 경우)
        critical_issues = [r for r in recommendations if r in ['set_console_password', 'configure_login']]
        
        if critical_issues:
            issues.append({
                'line': console_line_number,
                'matched_text': 'line con 0 (security recommendations)',
                'details': {
                    'port_type': 'console',
                    'vulnerability': 'console_port_security_recommendations',
                    'critical_issues': critical_issues,
                    'all_recommendations': recommendations,
                    'current_config': console_config,
                    'recommendation': 'Secure console port with password and login configuration',
                    'severity_adjusted': 'Medium' if 'set_console_password' in critical_issues else 'Low'
                }
            })
    
    return issues


def check_nw_09(line: str, line_num: int, context: ConfigContext) -> List[Dict[str, Any]]:
    """NW-09: 로그온 시 경고 메시지 설정 - 🔥 정확한 라인 번호 제공"""
    vulnerabilities = []
    
    # 다양한 배너 타입 확인
    banner_found = False
    banner_types = ['motd', 'login', 'exec', 'incoming']
    banner_line_number = 0
    
    for i, line in enumerate(context.config_lines):
        line_clean = line.strip()
        if line_clean.startswith('banner '):
            parts = line_clean.split()
            if len(parts) >= 2 and parts[1] in banner_types:
                banner_found = True
                banner_line_number = i + 1
                break
    
    if not banner_found:
        # 🔥 개선: 적절한 라인 번호 또는 위치 제안
        suggested_line = 1
        
        # hostname 다음에 배너를 추가하는 것이 일반적
        for i, line in enumerate(context.config_lines):
            if line.strip().startswith('hostname '):
                suggested_line = i + 2
                break
        
        vulnerabilities.append({
            'line': suggested_line,
            'matched_text': 'No login banner configured',
            'details': {
                'vulnerability': 'no_login_banner',
                'banner_types_checked': banner_types,
                'recommendation': '무단 사용자를 경고하기 위해 MOTD 배너 또는 로그인 배너를 설정하십시오.',
                'security_impact': 'Lack of warning message may encourage unauthorized access attempts',
                'suggested_config': 'banner motd ^C\nUnauthorized access prohibited!\n^C',
                'line_number': suggested_line
            }
        })
    
    return vulnerabilities


def check_nw_10(line: str, line_num: int, context: ConfigContext) -> List[Dict[str, Any]]:
    """NW-10: 네트워크 장비 펌웨어 최신화 관리 - 논리 기반 분석"""
    vulnerabilities = []
    
    # 이 룰은 주로 문서화 및 정책 점검이므로 설정파일만으로는 완전한 검증이 어려움
    # 버전 정보 확인을 통한 기본적인 분석만 수행
    vulnerabilities.append({
        'line': 0,
        'matched_text': 'Firmware management policy verification required',
        'details': {
            'vulnerability': 'manual_verification_required',
            'recommendation': 'Verify firmware update management policy and version updates',
            'check_items': [
                'Check current firmware/software version',
                'Compare with latest security patches',
                'Review vendor security advisories'
            ]
        }
    })
    
    return vulnerabilities


def check_nw_11(line: str, line_num: int, context: ConfigContext) -> List[Dict[str, Any]]:
    """NW-11: 원격 로그서버 사용 - 🔥 정확한 라인 번호 제공"""
    vulnerabilities = [] 
    
    # 원격 로그 서버 설정 확인
    has_remote_logging = False
    logging_line_number = 0
    
    # IP 패턴으로 로그 서버 검색
    import re
    
    for i, line in enumerate(context.config_lines):
        # logging x.x.x.x 패턴 찾기
        if re.match(r'logging\s+\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}', line.strip()):
            has_remote_logging = True
            logging_line_number = i + 1
            break
        # syslog host 패턴 찾기
        elif 'syslog host' in line.strip() or 'logging server' in line.strip():
            has_remote_logging = True
            logging_line_number = i + 1
            break
    
    if not has_remote_logging:
        # 🔥 개선: 적절한 위치 제안 (일반적으로 global config 영역)
        suggested_line = 1
        
        # service timestamps 다음이 적절한 위치
        for i, line in enumerate(context.config_lines):
            if 'service timestamps' in line.strip():
                suggested_line = i + 2
                break
            elif line.strip().startswith('hostname '):
                suggested_line = i + 2
        
        vulnerabilities.append({
            'line': suggested_line,
            'matched_text': 'No remote logging server configured',
            'details': {
                'vulnerability': 'no_remote_logging',
                'recommendation': 'Configure remote syslog server: logging x.x.x.x',
                'suggested_config': 'logging 192.168.1.100  ! Replace with actual syslog server IP',
                'line_number': suggested_line
            }
        })
    
    return vulnerabilities


def check_nw_12(line: str, line_num: int, context: ConfigContext) -> List[Dict[str, Any]]:
    """NW-12: 로깅 버퍼 크기 설정 - 논리 기반 분석"""
    vulnerabilities = []
    
    # 로깅 버퍼 크기 확인
    buffer_size = None
    buffer_line_num = 0
    
    for i, line in enumerate(context.config_lines):
        match = re.match(r'^logging\s+buffered\s+(\d+)', line.strip())
        if match:
            buffer_size = int(match.group(1))
            buffer_line_num = i + 1
            break
    
    # 로깅이 활성화되어 있는지 확인
    logging_enabled = any([
        'logging' in line and not line.strip().startswith('!')
        for line in context.config_lines
    ])
    
    if logging_enabled:
        if buffer_size is None:
            # 버퍼 크기가 명시되지 않음 (기본값 사용)
            vulnerabilities.append({
                'line': 0,
                'matched_text': 'Logging buffer size not explicitly configured',
                'details': {
                    'vulnerability': 'no_explicit_logging_buffer_size',
                    'current_status': 'using_default_size',
                    'recommendation': '로깅 버퍼 크기를 명시적으로 설정하세요. 권장 크기는 16,384바이트에서 32,768바이트 사이입니다.',
                    'severity_adjusted': 'Medium'
                }
            })
        elif buffer_size < 16384:  # 16KB 미만
            # 버퍼 크기가 너무 작음
            vulnerabilities.append({
                'line': buffer_line_num,
                'matched_text': f'logging buffered {buffer_size}',
                'details': {
                    'vulnerability': 'insufficient_logging_buffer_size',
                    'current_size': buffer_size,
                    'recommended_minimum': 16384,
                    'recommendation': 'Increase logging buffer size to at least 16KB',
                    'severity_adjusted': 'Medium'
                }
            })
    
    return vulnerabilities


def check_nw_13(line: str, line_num: int, context: ConfigContext) -> List[Dict[str, Any]]:
    """NW-13: 정책에 따른 로깅 설정 - 논리 기반 분석"""
    vulnerabilities = []
    
    # 기본 로깅 설정 확인
    logging_enabled = any(line.strip().startswith('logging') for line in context.config_lines)
    
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


def check_nw_14(line: str, line_num: int, context: ConfigContext) -> List[Dict[str, Any]]:
    """NW-14: NTP 서버 연동 - 🔥 정확한 라인 번호 제공"""
    vulnerabilities = []
    
    # NTP 서버 설정 확인
    ntp_configured = False
    ntp_line_number = 0
    
    for i, line in enumerate(context.config_lines):
        line_clean = line.strip()
        if (line_clean.startswith('ntp server ') or 
            line_clean.startswith('sntp server ') or 
            'clock timezone' in line_clean):
            ntp_configured = True
            ntp_line_number = i + 1
            break
    
    if not ntp_configured:
        # 🔥 개선: 적절한 위치 제안
        suggested_line = 1
        
        # logging 설정 다음이 적절한 위치
        for i, line in enumerate(context.config_lines):
            if line.strip().startswith('logging ') and not line.strip().startswith('logging buffered'):
                suggested_line = i + 2
                break
            elif line.strip().startswith('hostname '):
                suggested_line = i + 2
        
        vulnerabilities.append({
            'line': suggested_line,
            'matched_text': 'No NTP server configuration found',
            'details': {
                'vulnerability': 'no_ntp_configuration',
                'recommendation': '정확한 시간 동기화를 위해 NTP(Network Time Protocol) 서버를 설정하세요.',
                'suggested_config': 'ntp server pool.ntp.org  ! Replace with appropriate NTP server',
                'line_number': suggested_line
            }
        })
    
    return vulnerabilities


def check_nw_15(line: str, line_num: int, context: ConfigContext) -> List[Dict[str, Any]]:
    """NW-15: Timestamp 로그 설정 - 논리 기반 분석"""
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
                'recommendation': 'SNMP가 네트워크 운영에 필수적이지 않은 경우, 보안 강화를 위해 SNMP 서비스를 비활성화해야 합니다.'
            }
        })
    
    return vulnerabilities


def check_nw_17(line: str, line_num: int, context: ConfigContext) -> List[Dict[str, Any]]:
    """NW-17: SNMP community string 복잡성 설정 - 개선된 논리 기반 분석"""
    vulnerabilities = []
    
    if not context.snmp_communities:
        return vulnerabilities
    
    for community_info in context.snmp_communities:
        issues = []
        
        # 기본 커뮤니티 스트링 확인
        if community_info['is_default']:
            issues.append('default_community')
        
        # 길이 확인 (8자 미만)
        if community_info['length'] < 8:
            issues.append('too_short')
        
        # 단순한 패턴 확인
        simple_patterns = ['123', '456', '111', '000', 'admin', 'test', 'temp', 'snmp', 'cisco', 'router']
        if any(pattern in community_info['community'].lower() for pattern in simple_patterns):
            issues.append('simple_pattern')
        
        # 복잡성 부족 (숫자만 또는 문자만)
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
                    'community_length': community_info['length'],
                    'is_default': community_info['is_default'],
                    'recommendation': 'SNMP 커뮤니티 문자열은 기본값을 사용하지 말고, 최소 8자 이상의 복잡한 문자열로 설정하여 보안을 강화해야 합니다.'
                }
            })
    
    return vulnerabilities


def check_nw_18(line: str, line_num: int, context: ConfigContext) -> List[Dict[str, Any]]:
    """NW-18: SNMP ACL 설정 - 개선된 논리 기반 분석"""
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
                    'permission': community_info.get('permission', 'unknown'),
                    'recommendation': 'ACL을 설정하여 SNMP 접근을 허용된 호스트로만 제한하세요.'
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


def check_nw_20(line: str, line_num: int, context: ConfigContext) -> List[Dict[str, Any]]:
    """NW-20: TFTP 서비스 차단 - 논리 기반 분석"""
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


def check_nw_21(line: str, line_num: int, context: ConfigContext) -> List[Dict[str, Any]]:
    """NW-21: Spoofing 방지 필터링 - 환경별 차별화 개선된 버전"""
    vulnerabilities = []
    
    # 네트워크 환경 분석
    network_analysis = _analyze_network_environment(context)
    
    # 외부 연결이 없는 내부 전용 네트워크는 낮은 우선순위
    if not network_analysis['has_external_connection']:
        # 내부 전용 네트워크에서는 정보성 메시지만
        vulnerabilities.append({
            'line': 0,
            'matched_text': 'Internal network - Spoofing protection optional',
            'details': {
                'vulnerability': 'spoofing_protection_info',
                'network_type': 'internal_only',
                'recommendation': 'Consider spoofing protection for security best practices',
                'severity_adjusted': 'Info',
                'external_interfaces': network_analysis['external_interfaces']
            }
        })
        return vulnerabilities
    
    # ACL 내용 분석 (기존 로직 유지하되 개선)
    acl_protections = _analyze_spoofing_protection_acls(context)
    protection_count = sum(acl_protections.values())
    
    # 외부 인터페이스가 있는데 보호가 부족한 경우만 보고
    if protection_count < 3:  # 기본적인 보호 수준
        missing = [k for k, v in acl_protections.items() if not v]
        
        severity = 'High' if protection_count == 0 else 'Medium'
        
        vulnerabilities.append({
            'line': 0,
            'matched_text': 'Spoofing protection insufficient for external-facing network',
            'details': {
                'vulnerability': 'insufficient_spoofing_protection',
                'network_type': 'external_facing',
                'protection_level': protection_count,
                'missing_protections': missing,
                'external_interfaces': network_analysis['external_interfaces'],
                'recommendation': 'Implement spoofing protection ACLs for: ' + ', '.join(missing),
                'severity_adjusted': severity
            }
        })
    
    return vulnerabilities


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


def _is_private_ip(ip_address: str) -> bool:
    """사설 IP 대역 확인"""
    if re.match(r'^10\.', ip_address):
        return True
    if re.match(r'^172\.(1[6-9]|2[0-9]|3[0-1])\.', ip_address):
        return True
    if re.match(r'^192\.168\.', ip_address):
        return True
    return False



def check_nw_22(line: str, line_num: int, context: ConfigContext) -> List[Dict[str, Any]]:
    """NW-22: DDoS 공격 방어 설정 - 논리 기반 분석"""
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
                'recommendation': 'DDoS 보호 기능을 구성하세요 (예: TCP 인터셉트, 속도 제한 등).'
            }
        })
    
    return vulnerabilities


def check_nw_23(line: str, line_num: int, context: ConfigContext) -> List[Dict[str, Any]]:
    """NW-23: 사용하지 않는 인터페이스의 Shutdown 설정 - 🔥 개별 인터페이스별 보고로 개선"""
    vulnerabilities = []
    
    # config 데이터 확보
    config_text = ""
    if hasattr(context, 'full_config'):
        config_text = context.full_config
    elif hasattr(context, 'config_lines'):
        config_text = '\n'.join(context.config_lines)
    else:
        return vulnerabilities
    
    # 인터페이스 블록을 정규식으로 추출
    import re
    
    # interface로 시작하는 블록들을 모두 찾기
    interface_pattern = r'interface\s+(\S+)\s*\n((?:\s+.*\n?)*)'
    matches = re.findall(interface_pattern, config_text, re.MULTILINE)
    
    # 🔥 개선: 각 인터페이스별로 개별 취약점 보고
    for interface_name, config_block in matches:
        
        # 물리적 인터페이스만 체크
        name_lower = interface_name.lower()
        
        # 가상 인터페이스 제외
        if any(v in name_lower for v in ['loopback', 'tunnel', 'vlan', 'bvi', 'dialer', 'null']):
            continue
            
        # 물리적 인터페이스 확인
        if not any(p in name_lower for p in ['gigabit', 'fast', 'ethernet', 'serial']):
            continue
        
        # shutdown 확인
        if 'shutdown' in config_block:
            continue
        
        # 사용 여부 확인
        
        # 1. 실제 IP 주소 확인 (정규식 사용)
        ip_pattern = r'ip address \d+\.\d+\.\d+\.\d+ \d+\.\d+\.\d+\.\d+'
        has_real_ip = bool(re.search(ip_pattern, config_block))
        
        # 2. 설명 확인
        has_description = bool(re.search(r'description\s+\S+', config_block))
        
        # 3. VLAN 설정 확인
        vlan_pattern = r'(switchport|encapsulation dot1q|trunk)'
        has_vlan = bool(re.search(vlan_pattern, config_block))
        
        # 4. 기타 중요 설정 확인
        other_pattern = r'(channel-group|port-security|access-group|service-policy|nat)'
        has_other = bool(re.search(other_pattern, config_block))
        
        # 사용 중인지 판정
        is_used = has_real_ip or has_description or has_vlan or has_other
        
        # 중요 인터페이스 예외 처리
        is_critical = False
        
        # 관리 인터페이스
        if any(mgmt in name_lower for mgmt in ['management', 'mgmt', 'console']):
            is_critical = True
        
        # 설명에 중요 키워드
        if has_description:
            desc_match = re.search(r'description\s+(.+)', config_block)
            if desc_match:
                desc_text = desc_match.group(1).lower()
                if any(word in desc_text for word in ['uplink', 'trunk', 'core', 'wan', 'internet', 'isp', 'link']):
                    is_critical = True
        
        # 0/0 포트이면서 사용 중
        if interface_name.endswith('0/0') and is_used:
            is_critical = True
        
        # 서브인터페이스가 있는 경우
        base_name = interface_name.split('.')[0]
        subintf_pattern = re.escape(base_name) + r'\.\d+'
        if re.search(subintf_pattern, config_text):
            is_critical = True
        
        # 최종 판정: 미사용이면서 중요하지 않음
        if not is_used and not is_critical:
            # 라인 번호 찾기
            interface_line_match = re.search(f'interface\\s+{re.escape(interface_name)}', config_text)
            line_number = 0
            if interface_line_match:
                # 해당 위치까지의 줄 수 계산
                before_match = config_text[:interface_line_match.start()]
                line_number = before_match.count('\n') + 1
            
            vulnerabilities.append({
                'line': line_number,
                'matched_text': f"interface {interface_name} - unused and not shutdown",
                'details': {
                    'interface_name': interface_name,
                    'vulnerability': 'unused_interface_not_shutdown',
                    'reason': 'Unused physical interface not shutdown',
                    'security_risk': 'Potential unauthorized physical access point',
                    'analysis': {
                        'has_real_ip': has_real_ip,
                        'has_description': has_description,
                        'has_vlan': has_vlan,
                        'has_other_config': has_other,
                        'is_critical': is_critical,
                        'is_used': is_used,
                        'config_block': config_block.strip()
                    },
                    'recommendation': f'사용하지 않는 인터페이스는 shutdown해주세요 : {interface_name}',
                    'line_number': line_number
                }
            })
    
    return vulnerabilities


# 나머지 함수들 (NW-24 ~ NW-42)

def check_nw_24(line: str, line_num: int, context: ConfigContext) -> List[Dict[str, Any]]:
    """NW-24: TCP keepalive 서비스 설정 - 논리 기반 분석"""
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


def check_nw_25(line: str, line_num: int, context: ConfigContext) -> List[Dict[str, Any]]:
    """NW-25: Finger 서비스 차단 - 논리 기반 분석"""
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


def check_nw_26(line: str, line_num: int, context: ConfigContext) -> List[Dict[str, Any]]:
    """NW-26: 웹 서비스 차단 - 논리 기반 분석"""
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


def check_nw_27(line: str, line_num: int, context: ConfigContext) -> List[Dict[str, Any]]:
    """NW-27: TCP/UDP Small 서비스 차단 - 논리 기반 분석"""
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


def check_nw_28(line: str, line_num: int, context: ConfigContext) -> List[Dict[str, Any]]:
    """NW-28: Bootp 서비스 차단 - 논리 기반 분석"""
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


def check_nw_29(line: str, line_num: int, context: ConfigContext) -> List[Dict[str, Any]]:
    """NW-29: CDP 서비스 차단 - 논리 기반 분석"""
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


def check_nw_30(line: str, line_num: int, context: ConfigContext) -> List[Dict[str, Any]]:
    """NW-30: Directed-broadcast 차단 - 🔥 개별 인터페이스별 보고로 개선"""
    vulnerabilities = []
    
    # IOS 버전 확인
    ios_version = context.ios_version or "15.0"
    version_num = context.cisco_defaults._extract_version_number(ios_version)
    
    # 15.x에서는 기본값이 disabled이므로 덜 엄격하게 적용
    strict_check = version_num < 12.0
    
    # 🔥 개선: 각 인터페이스별로 개별 취약점 보고
    for interface_name, interface_config in context.parsed_interfaces.items():
        # 서브인터페이스는 제외 (의미없음)
        if interface_config.get('is_subinterface', False):
            continue
            
        # 루프백, 관리 인터페이스 제외
        if interface_config.get('is_loopback') or interface_config.get('is_management'):
            continue
            
        config_lines = interface_config.get('config_lines', [])
        
        # 명시적 설정 확인
        directed_broadcast_explicitly_disabled = any('no ip directed-broadcast' in line for line in config_lines)
        directed_broadcast_explicitly_enabled = any(
            'ip directed-broadcast' in line and not line.strip().startswith('no ')
            for line in config_lines
        )
        
        # 실제 상태 판단 (버전별 기본값 고려)
        if directed_broadcast_explicitly_disabled:
            actual_state = False
        elif directed_broadcast_explicitly_enabled:
            actual_state = True
        else:
            # 기본값 적용 (버전별)
            actual_state = context.get_service_state('directed_broadcast')
        
        # 취약점 판단
        is_vulnerable = False
        severity = "Medium"
        
        if directed_broadcast_explicitly_enabled:
            # 명시적으로 활성화된 경우는 항상 취약
            is_vulnerable = True
            severity = "High"
        elif actual_state and strict_check:
            # 구버전에서 기본값으로 활성화된 경우
            is_vulnerable = True
            severity = "Medium"
        elif actual_state and not strict_check:
            # 신버전에서는 정보성만 (실제로는 기본값이 disabled)
            is_vulnerable = True
            severity = "Low"
        
        if is_vulnerable:
            status = "explicitly_enabled" if directed_broadcast_explicitly_enabled else "default_state"
            
            vulnerabilities.append({
                'line': interface_config['line_number'],
                'matched_text': f"interface {interface_name} - directed-broadcast {status}",
                'details': {
                    'vulnerability': 'directed_broadcast_enabled',
                    'interface_name': interface_name,
                    'interface_type': interface_config['port_type'],
                    'status': status,
                    'ios_version': ios_version,
                    'version_based_default': actual_state,
                    'strict_check': strict_check,
                    'recommendation': f'Configure "no ip directed-broadcast" on interface {interface_name}',
                    'severity_adjusted': severity,
                    'line_number': interface_config['line_number']
                }
            })
    
    return vulnerabilities


def check_nw_31(line: str, line_num: int, context: ConfigContext) -> List[Dict[str, Any]]:
    """NW-31: Source 라우팅 차단 - 논리 기반 분석"""
    vulnerabilities = []
    
    # Source routing 설정 확인
    source_routing_disabled = any('no ip source-route' in line for line in context.config_lines)
    
    if not source_routing_disabled:
        vulnerabilities.append({
            'line': 0,
            'matched_text': 'Source routing not disabled',
            'details': {
                'vulnerability': 'source_routing_enabled',
                'recommendation': '소스 라우팅 비활성화: no ip source-route 명령어를 설정하세요.'
            }
        })
    
    return vulnerabilities


def check_nw_32(line: str, line_num: int, context: ConfigContext) -> List[Dict[str, Any]]:
    """NW-32: Proxy ARP 차단 - 🔥 개별 인터페이스별 보고로 개선"""
    vulnerabilities = []
    
    # 🔥 개선: 각 인터페이스별로 개별 취약점 보고
    for interface_name, interface_config in context.parsed_interfaces.items():
        # 서브인터페이스 제외
        if interface_config.get('is_subinterface', False):
            continue
            
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
                'matched_text': f"interface {interface_name} - proxy-arp {status}",
                'details': {
                    'vulnerability': 'proxy_arp_enabled',
                    'interface_name': interface_name,
                    'interface_type': interface_config['port_type'],
                    'status': status,
                    'recommendation': f'Configure "no ip proxy-arp" on interface {interface_name}',
                    'default_behavior': 'Cisco default: proxy-arp enabled',
                    'line_number': interface_config['line_number']
                }
            })
    
    return vulnerabilities


def check_nw_33(line: str, line_num: int, context: ConfigContext) -> List[Dict[str, Any]]:
    """NW-33: ICMP unreachable, Redirect 차단 - 🔥 개별 인터페이스별 보고로 개선"""
    vulnerabilities = []
    
    # 네트워크 환경 분석
    network_analysis = _analyze_network_environment(context)
    external_interfaces = set(network_analysis['external_interfaces'])
    
    # 🔥 개선: 각 인터페이스별로 개별 취약점 보고
    for interface_name, interface_config in context.parsed_interfaces.items():
        # 서브인터페이스 제외
        if interface_config.get('is_subinterface', False):
            continue
            
        # 루프백, 관리 인터페이스 제외
        if interface_config.get('is_loopback') or interface_config.get('is_management'):
            continue
        
        # 외부 인터페이스가 아니면 낮은 우선순위로 처리
        is_external = interface_name in external_interfaces
        
        # 외부 인터페이스가 아니고 외부 연결이 없으면 스킵
        if not is_external and not network_analysis['has_external_connection']:
            continue
            
        config_lines = interface_config.get('config_lines', [])
        
        # ICMP 설정 확인
        has_no_unreachables = any('no ip unreachables' in line for line in config_lines)
        has_no_redirects = any('no ip redirects' in line for line in config_lines)
        
        issues = []
        if not has_no_unreachables:
            issues.append('unreachables_enabled')
        if not has_no_redirects:
            issues.append('redirects_enabled')
        
        if issues:
            # 외부 인터페이스는 높은 우선순위, 내부는 낮은 우선순위
            severity = 'High' if is_external else 'Medium'
            
            # 문제된 서비스들을 텍스트로 표시
            services_text = []
            if 'unreachables_enabled' in issues:
                services_text.append('unreachables')
            if 'redirects_enabled' in issues:
                services_text.append('redirects')
            
            vulnerabilities.append({
                'line': interface_config['line_number'],
                'matched_text': f"interface {interface_name} - ICMP {'/'.join(services_text)} enabled",
                'details': {
                    'vulnerability': 'icmp_services_enabled',
                    'interface_name': interface_name,
                    'interface_type': 'external' if is_external else 'internal',
                    'port_type': interface_config['port_type'],
                    'issues': issues,
                    'unreachables_disabled': has_no_unreachables,
                    'redirects_disabled': has_no_redirects,
                    'recommendation': f'Configure on interface {interface_name}: ' + 
                                    ', '.join([
                                        'no ip unreachables' if 'unreachables_enabled' in issues else '',
                                        'no ip redirects' if 'redirects_enabled' in issues else ''
                                    ]).strip(', '),
                    'severity_adjusted': severity,
                    'line_number': interface_config['line_number']
                }
            })
    
    return vulnerabilities



def check_nw_34(line: str, line_num: int, context: ConfigContext) -> List[Dict[str, Any]]:
    """NW-34: identd 서비스 차단 - 논리 기반 분석"""
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


def check_nw_35(line: str, line_num: int, context: ConfigContext) -> List[Dict[str, Any]]:
    """NW-35: Domain lookup 차단 - 오탐 수정된 버전"""
    vulnerabilities = []
    
    # 🔧 수정: 명시적 설정 우선 확인
    domain_lookup_explicitly_disabled = any(
        'no ip domain-lookup' in line or 'no ip domain lookup' in line 
        for line in context.config_lines
    )
    
    domain_lookup_explicitly_enabled = any(
        ('ip domain-lookup' in line or 'ip domain lookup' in line) and 
        not line.strip().startswith('no ')
        for line in context.config_lines
    )
    
    # 실제 상태 판단
    if domain_lookup_explicitly_disabled:
        actual_state = False  # 비활성화됨 (양호)
    elif domain_lookup_explicitly_enabled:
        actual_state = True   # 명시적 활성화됨 (취약)
    else:
        # 기본값 적용: Cisco는 기본적으로 domain-lookup enabled
        actual_state = context.get_service_state('domain_lookup')
    
    # 보안 기준: domain-lookup은 비활성화되어야 함
    if actual_state:  # 활성화된 경우만 취약점으로 보고
        status = "explicitly_enabled" if domain_lookup_explicitly_enabled else "default_enabled"
        
        vulnerabilities.append({
            'line': 0,
            'matched_text': f'Domain lookup {status}',
            'details': {
                'vulnerability': 'domain_lookup_enabled',
                'status': status,
                'recommendation': 'Add: no ip domain-lookup' if status == "default_enabled" 
                                else 'Keep: no ip domain-lookup setting',
                'default_behavior': 'Cisco default: domain-lookup enabled',
                'current_config_check': {
                    'explicitly_disabled': domain_lookup_explicitly_disabled,
                    'explicitly_enabled': domain_lookup_explicitly_enabled
                }
            }
        })
    
    return vulnerabilities


def check_nw_36(line: str, line_num: int, context: ConfigContext) -> List[Dict[str, Any]]:
    """NW-36: PAD 차단 - 논리 기반 분석"""
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


def check_nw_37(line: str, line_num: int, context: ConfigContext) -> List[Dict[str, Any]]:
    """NW-37: mask-reply 차단 - 논리 기반 분석"""
    vulnerabilities = []
    
    # Mask reply 설정 확인
    for interface_name, interface_config in context.parsed_interfaces.items():
        mask_reply_enabled = False
        
        for config_line in interface_config.get('config_lines', []):
            if 'ip mask-reply' in config_line:
                mask_reply_enabled = True
                break
        
        if mask_reply_enabled and interface_config['port_type'] in ['FastEthernet', 'GigabitEthernet']:
            vulnerabilities.append({
                'line': interface_config['line_number'],
                'matched_text': f"interface {interface_name}",
                'details': {
                    'vulnerability': 'mask_reply_enabled',
                    'interface_name': interface_name,
                    'recommendation': 'Disable mask reply: no ip mask-reply'
                }
            })
    
    return vulnerabilities


def check_nw_38(line: str, line_num: int, context: ConfigContext) -> List[Dict[str, Any]]:
    """NW-38: 스위치 보안 - 장비 타입별 차별화"""
    vulnerabilities = []
    
    # 장비 타입 확인 - 스위치 기능이 있는지 확인
    device_type = context.device_type.lower()
    is_switch = any([
        'switch' in device_type,
        'catalyst' in device_type,
        'nexus' in device_type
    ])
    
    # 스위칭 기능 확인
    has_switching = any(
        interface.get('has_switchport', False) 
        for interface in context.parsed_interfaces.values()
    )
    
    # 라우터인데 스위칭 기능이 없으면 체크 안함
    if not is_switch and not has_switching:
        return vulnerabilities
    
    # 스위치포트가 있는 경우만 포트 보안 체크
    access_ports_without_security = []
    
    for interface_name, interface_config in context.parsed_interfaces.items():
        if not interface_config.get('has_switchport', False):
            continue
        
        config_lines = interface_config.get('config_lines', [])
        is_access_mode = any('switchport mode access' in line for line in config_lines)
        has_port_security = any('switchport port-security' in line for line in config_lines)
        
        # 음성 VLAN 등 특수 용도 확인
        has_voice_vlan = any('switchport voice vlan' in line for line in config_lines)
        
        if is_access_mode and not has_port_security and not has_voice_vlan:
            access_ports_without_security.append(interface_name)
    
    # 일정 비율 이상의 포트가 보안 설정이 없을 때만 보고
    if len(access_ports_without_security) > 3:
        vulnerabilities.append({
            'line': 0,
            'matched_text': f'{len(access_ports_without_security)} access ports without port-security',
            'details': {
                'vulnerability': 'multiple_ports_no_security',
                'affected_ports': access_ports_without_security[:5],  # 최대 5개만
                'total_affected': len(access_ports_without_security),
                'recommendation': 'Enable port-security on access ports to prevent MAC flooding',
                'severity_adjusted': 'Medium'
            }
        })
    
    # DHCP snooping은 스위치에서만 체크
    if is_switch and not any('dhcp snooping' in context.full_config for _ in [1]):
        vulnerabilities.append({
            'line': 0,
            'matched_text': 'DHCP snooping not configured',
            'details': {
                'vulnerability': 'no_dhcp_snooping',
                'device_type': device_type,
                'recommendation': 'Enable DHCP snooping on switches',
                'severity_adjusted': 'Low'
            }
        })
    
    return vulnerabilities


def check_nw_39(line: str, line_num: int, context: ConfigContext) -> List[Dict[str, Any]]:
    """NW-39: 환경설정 원격 로딩 - 논리 기반 분석"""
    vulnerabilities = []
    
    # 환경설정 원격 로딩 설정 확인
    remote_config_loading = any([
        'service config' in context.full_config,
        'boot network' in context.full_config,
        'boot host' in context.full_config
    ])
    
    if remote_config_loading:
        vulnerabilities.append({
            'line': 0,
            'matched_text': 'Remote configuration loading enabled',
            'details': {
                'vulnerability': 'remote_config_loading_enabled',
                'recommendation': 'Disable remote configuration loading if not required'
            }
        })
    
    return vulnerabilities


def check_nw_40(line: str, line_num: int, context: ConfigContext) -> List[Dict[str, Any]]:
    """NW-40: 라우팅 프로토콜 인증 - 네트워크 환경 고려"""
    vulnerabilities = []
    
    # 외부 연결 확인
    has_external_connection = False
    for interface in context.parsed_interfaces.values():
        desc = interface.get('description', '').lower()
        if any(word in desc for word in ['isp', 'internet', 'wan', 'external']):
            has_external_connection = True
            break
    
    # 라우팅 프로토콜 분석
    routing_configs = _analyze_routing_protocols(context)
    
    for protocol, configs in routing_configs.items():
        for config in configs:
            # 인증이 없는 경우
            if not config['has_authentication']:
                # BGP는 외부 연결시 필수
                if protocol == 'bgp' and has_external_connection:
                    severity = 'High'
                # OSPF/EIGRP는 권장
                elif protocol in ['ospf', 'eigrp']:
                    severity = 'Medium'
                # RIP는 낮음
                else:
                    severity = 'Low'
                
                # 내부 전용 네트워크는 심각도 낮춤
                if not has_external_connection:
                    severity = 'Low' if severity == 'Medium' else 'info'
                
                if severity in ['High', 'Medium', 'Low']:
                    vulnerabilities.append({
                        'line': config['line_number'],
                        'matched_text': config['config_start'],
                        'details': {
                            'protocol': protocol.upper(),
                            'vulnerability': 'no_routing_authentication',
                            'network_type': 'external' if has_external_connection else 'internal',
                            'recommendation': f'Configure MD5 authentication for {protocol.upper()}',
                            'severity_adjusted': severity
                        }
                    })
    
    return vulnerabilities


def check_nw_41(line: str, line_num: int, context: ConfigContext) -> List[Dict[str, Any]]:
    """NW-41: 백업 관리 - 실질적인 백업 설정 확인"""
    vulnerabilities = []
    
    # 백업 관련 상세 설정 확인
    backup_features = {
        'archive': 'archive' in context.full_config,
        'kron': 'kron' in context.full_config,
        'eem': 'event manager applet' in context.full_config,
        'backup_commands': any(cmd in context.full_config for cmd in [
            'copy running-config', 'write memory', 'wr mem'
        ])
    }
    
    # 외부 백업 서버 설정 확인
    external_backup = any(protocol in context.full_config.lower() for protocol in [
        'tftp://', 'ftp://', 'scp://', 'sftp://', 'https://'
    ])
    
    # 자동 백업 여부
    has_auto_backup = any([
        backup_features['archive'],
        backup_features['kron'],
        backup_features['eem']
    ])
    
    # 백업 설정이 전혀 없는 경우
    if not any(backup_features.values()) and not external_backup:
        vulnerabilities.append({
            'line': 0,
            'matched_text': 'No backup configuration found',
            'details': {
                'vulnerability': 'no_backup_configuration',
                'recommendation': 'Configure automatic backup using archive or kron',
                'severity_adjusted': 'High'
            }
        })
    # 수동 백업만 있는 경우
    elif not has_auto_backup and backup_features['backup_commands']:
        vulnerabilities.append({
            'line': 0,
            'matched_text': 'Only manual backup configured',
            'details': {
                'vulnerability': 'no_automatic_backup',
                'backup_features': backup_features,
                'recommendation': 'Configure scheduled automatic backups',
                'severity_adjusted': 'Medium'
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


# Helper Functions

def _is_private_ip(ip_address: str) -> bool:
    """사설 IP 대역 확인"""
    private_ranges = [
        (r'^10\.', ),
        (r'^172\.(1[6-9]|2[0-9]|3[0-1])\.', ),
        (r'^192\.168\.', ),
    ]
    
    for pattern in private_ranges:
        if re.match(pattern[0], ip_address):
            return True
    return False


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

def _is_critical_interface(interface_name: str, device_type: str) -> bool:
    """중요 인터페이스 여부 판별"""
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