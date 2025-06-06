# -*- coding: utf-8 -*-
"""
rules/checks_kisa.py
KISA 네트워크 장비 보안 점검 룰의 논리적 검증 함수들 (완전판)

각 KISA 룰에 대한 logical_check_function들을 정의
"""

from typing import List, Dict, Any, Optional
import re
from .loader import (
    RuleCategory, 
    ConfigContext, 
    LogicalCondition, 
    SecurityRule, 
    _parse_line_configs,
    _analyze_network_environment
)
from .cisco_defaults import CiscoDefaults

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
        if not vty_line['has_access-class']:
            issues.append('no_access-class')
        
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
                    'has_access-class': vty_line['has_access-class'],
                    'transport_input': transport_input,
                    'access-class': vty_line.get('access-class'),
                    'recommendation': 'VTY 라인에 access-class를 설정하여 접속 가능한 IP를 제한하세요.'
                }
            }
            vulnerabilities.append(vulnerability_details)
    
    return vulnerabilities



def check_session_timeout(line: str, line_num: int, context: ConfigContext) -> List[Dict[str, Any]]:
    """N-05: Session Timeout 설정 - 논리 기반 분석"""
    vulnerabilities = []
    
    # 컨피그에서 직접 라인 설정 파싱 (context의 라인 정보가 불완전할 수 있음)
    line_configs = _parse_line_configs(context.config_lines)
    
    for line_type, line_config in line_configs.items():
        if line_config is None:
            continue
            
        exec_timeout = line_config.get('exec_timeout')
        line_number = line_config.get('line_number', 0)
        
        if exec_timeout is None:
            # exec-timeout이 설정되지 않음 (기본값 10분)
            vulnerabilities.append({
                'line': line_number,
                'matched_text': f"line {line_type} (no exec-timeout configured)",
                'details': {
                    'vulnerability': 'no_exec_timeout',
                    'line_type': line_type.upper(),
                    'default_timeout': '10 minutes',
                    'recommendation': 'Set exec-timeout to 5 minutes or less (exec-timeout 5 0)'
                }
            })
        elif exec_timeout == (0, 0):
            # 무제한 타임아웃
            vulnerabilities.append({
                'line': line_number,
                'matched_text': f"line {line_type} (exec-timeout 0 0)",
                'details': {
                    'vulnerability': 'infinite_timeout',
                    'line_type': line_type.upper(),
                    'timeout_value': '0 0 (infinite)',
                    'recommendation': 'Set exec-timeout to 5 minutes (exec-timeout 5 0)'
                }
            })
        else:
            # 타임아웃 값 계산
            total_seconds = exec_timeout[0] * 60 + exec_timeout[1]
            
            if total_seconds > 300:  # 5분(300초) 초과
                vulnerabilities.append({
                    'line': line_number,
                    'matched_text': f"line {line_type} (exec-timeout {exec_timeout[0]} {exec_timeout[1]})",
                    'details': {
                        'vulnerability': 'excessive_timeout',
                        'line_type': line_type.upper(),
                        'timeout_value': f"{exec_timeout[0]} {exec_timeout[1]}",
                        'timeout_seconds': total_seconds,
                        'timeout_minutes': total_seconds / 60,
                        'recommendation': 'Set exec-timeout to 5 minutes or less (exec-timeout 5 0)'
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
    """N-08: SNMP Community String 복잡성 - 오탐/미탐 수정된 버전"""
    vulnerabilities = []
    
    if not context.snmp_communities:
        return vulnerabilities
    
    for community_info in context.snmp_communities:
        issues = []
        severity = '하'  # 기본 심각도
        
        # 1. 기본 커뮤니티 스트링 확인 (가장 위험)
        if community_info['is_default']:
            issues.append('default_community')
            severity = '상'  # 기본 커뮤니티는 매우 위험
        
        # 2. 매우 짧은 길이 확인 (4자 미만)
        elif community_info['length'] < 4:
            issues.append('very_short')
            severity = '상'
        
        # 3. 짧은 길이 확인 (6자 미만)
        elif community_info['length'] < 6:
            issues.append('short_length')
            severity = '중'
        
        # 4. 예측 가능한 패턴 확인
        community = community_info['community'].lower()
        predictable_patterns = [
            'public', 'private', '123', '1234', '12345', '123456',
            'admin', 'test', 'temp', 'cisco', 'router', 'switch',
            'snmp', 'community', 'read', 'write', 'monitor'
        ]
        
        if any(pattern == community or pattern in community for pattern in predictable_patterns):
            issues.append('predictable_pattern')
            if not issues or 'short_length' not in issues:  # 이미 다른 중요한 문제가 없으면
                severity = '상' if community in ['public', 'private'] else '중'
        
        # 5. 복잡성 부족 (6자 이상이지만 단순한 패턴)
        elif len(community) >= 6:
            if community.isdigit():
                issues.append('only_numbers')
                severity = '하'
            elif community.isalpha():
                issues.append('only_letters')
                severity = '하'
            elif len(set(community)) <= 3:  # 사용된 고유 문자가 3개 이하
                issues.append('low_character_diversity')
                severity = '하'
        
        # 취약점이 발견된 경우만 보고
        if issues:
            vulnerabilities.append({
                'line': community_info['line_number'],
                'matched_text': f"snmp-server community {community_info['community']} {community_info.get('permission', '')}",
                'details': {
                    'community': community_info['community'],
                    'issues': issues,
                    'community_length': community_info['length'],
                    'is_default': community_info['is_default'],
                    'permission': community_info.get('permission', 'RO'),
                    'severity_adjusted': severity,
                    'vulnerability': 'weak_snmp_community_string',
                    'recommendation': _generate_snmp_complexity_recommendation(issues)
                }
            })
    
    return vulnerabilities


def _generate_snmp_complexity_recommendation(issues: List[str]) -> str:
    """SNMP 커뮤니티 복잡성 권고사항 생성"""
    recommendations = []
    
    if 'default_community' in issues:
        recommendations.append("기본 커뮤니티 스트링(public, private) 사용 금지")
    if any(issue in issues for issue in ['very_short', 'short_length']):
        recommendations.append("커뮤니티 스트링 길이를 8자 이상으로 설정")
    if 'predictable_pattern' in issues:
        recommendations.append("예측하기 어려운 복잡한 문자열 사용")
    if any(issue in issues for issue in ['only_numbers', 'only_letters', 'low_character_diversity']):
        recommendations.append("숫자, 문자, 특수문자를 조합한 복잡한 문자열 사용")
    
    return '; '.join(recommendations)


def check_snmp_acl_configuration(line: str, line_num: int, context: ConfigContext) -> List[Dict[str, Any]]:
    """N-09: SNMP ACL 설정 - ACL 존재 및 효과성 검증"""
    vulnerabilities = []
    
    for community_info in context.snmp_communities:
        acl_name = community_info.get('acl')
        
        if not acl_name:
            # ACL이 전혀 설정되지 않음
            vulnerabilities.append({
                'line': community_info['line_number'],
                'matched_text': f"snmp-server community {community_info['community']} {community_info['permission']}",
                'details': {
                    'community': community_info['community'],
                    'vulnerability': 'no_acl_configured',
                    'permission': community_info['permission'],
                    'recommendation': 'Configure ACL for SNMP community access restriction',
                    'severity_adjusted': 'Medium'
                }
            })
        else:
            # ACL이 설정되어 있지만 효과성 검증
            acl_effectiveness = _analyze_snmp_acl_effectiveness(context, acl_name)
            
            if acl_effectiveness['effectiveness'] == 'none':
                # ACL이 참조되었지만 정의되지 않음
                vulnerabilities.append({
                    'line': community_info['line_number'],
                    'matched_text': f"snmp-server community {community_info['community']} {community_info['permission']} {acl_name}",
                    'details': {
                        'community': community_info['community'],
                        'vulnerability': 'acl_not_defined',
                        'acl_name': acl_name,
                        'permission': community_info['permission'],
                        'recommendation': f'access-list {acl_name}의 설정을 확인해주세요',
                        'severity_adjusted': 'High'
                    }
                })
            
            elif acl_effectiveness['effectiveness'] == 'weak':
                # ACL이 있지만 효과가 없음 (permit any 등)
                vulnerabilities.append({
                    'line': community_info['line_number'],
                    'matched_text': f"snmp-server community {community_info['community']} {community_info['permission']} {acl_name}",
                    'details': {
                        'community': community_info['community'],
                        'vulnerability': 'acl_ineffective',
                        'acl_name': acl_name,
                        'permission': community_info['permission'],
                        'acl_analysis': acl_effectiveness,
                        'recommendation': f'Strengthen access-list {acl_name} with specific IP restrictions',
                        'severity_adjusted': 'Medium'
                    }
                })
            
            # 'moderate' 또는 'strong'인 경우는 적절한 ACL로 판단하여 취약점 보고하지 않음
    
    return vulnerabilities


def _analyze_snmp_acl_effectiveness(context: ConfigContext, acl_name: str) -> Dict[str, Any]:
    """SNMP ACL의 효과성 분석"""
    if not acl_name:
        return {'effectiveness': 'none', 'reason': 'no_acl'}
    
    # ACL 정의 찾기
    acl_lines = []
    for line in context.config_lines:
        if f'access-list {acl_name}' in line or f'ip access-list {acl_name}' in line:
            acl_lines.append(line.strip())
    
    if not acl_lines:
        return {
            'effectiveness': 'none',
            'reason': 'acl_not_defined',
            'acl_exists': False,
            'rule_count': 0
        }
    
    # ACL 내용 분석
    analysis = {
        'permit_any': False,
        'specific_permits': [],
        'deny_rules': [],
        'host_permits': [],
        'network_permits': []
    }
    
    for line in acl_lines:
        line_lower = line.lower()
        
        if 'permit' in line_lower:
            if 'any' in line_lower and 'any any' in line_lower:
                analysis['permit_any'] = True
            elif 'host' in line_lower:
                # 특정 호스트 허용
                host_match = re.search(r'host\s+(\d+\.\d+\.\d+\.\d+)', line_lower)
                if host_match:
                    analysis['host_permits'].append(host_match.group(1))
            elif re.search(r'\d+\.\d+\.\d+\.\d+\s+\d+\.\d+\.\d+\.\d+', line_lower):
                # 네트워크 대역 허용
                network_match = re.search(r'(\d+\.\d+\.\d+\.\d+\s+\d+\.\d+\.\d+\.\d+)', line_lower)
                if network_match:
                    analysis['network_permits'].append(network_match.group(1))
            
            analysis['specific_permits'].append(line)
        
        elif 'deny' in line_lower:
            analysis['deny_rules'].append(line)
    
    # 효과성 판단
    total_permits = len(analysis['specific_permits'])
    specific_restrictions = len(analysis['host_permits']) + len(analysis['network_permits'])
    
    if analysis['permit_any'] and specific_restrictions == 0:
        effectiveness = 'weak'
        reason = 'permit_any_only'
    elif analysis['permit_any'] and specific_restrictions > 0:
        effectiveness = 'moderate'
        reason = 'mixed_rules_with_permit_any'
    elif specific_restrictions > 0:
        effectiveness = 'strong'
        reason = 'specific_restrictions_only'
    elif total_permits == 0 and len(analysis['deny_rules']) > 0:
        effectiveness = 'moderate'
        reason = 'deny_only_rules'
    else:
        effectiveness = 'weak'
        reason = 'unclear_restrictions'
    
    return {
        'effectiveness': effectiveness,
        'reason': reason,
        'acl_exists': True,
        'rule_count': len(acl_lines),
        'analysis': analysis,
        'specific_hosts': len(analysis['host_permits']),
        'network_ranges': len(analysis['network_permits']),
        'has_permit_any': analysis['permit_any']
    }


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
    """N-12: Spoofing 방지 필터링 - ACL 효과성 검증 강화"""
    vulnerabilities = []
    
    # 네트워크 환경 분석
    network_analysis = _analyze_network_environment(context)
    
    # 외부 연결이 없는 내부 전용 네트워크는 권고 수준
    if not network_analysis['has_external_connection']:
        vulnerabilities.append({
            'line': 0,
            'matched_text': 'Internal network - Spoofing protection recommended',
            'details': {
                'vulnerability': 'spoofing_protection_info',
                'network_type': 'internal_only',
                'recommendation': 'Consider spoofing protection for security best practices',
                'severity_adjusted': 'Low'
            }
        })
        return vulnerabilities
    
    # 외부 인터페이스별 스푸핑 방지 ACL 효과성 분석
    external_interfaces = network_analysis['external_interfaces']
    
    for interface_name in external_interfaces:
        interface_config = context.parsed_interfaces.get(interface_name, {})
        acl_protection = _analyze_interface_spoofing_protection(context, interface_name, interface_config)
        
        if acl_protection['protection_level'] < 3:  # 기본 보호 수준 미달
            missing_protections = acl_protection['missing_protections']
            ineffective_acls = acl_protection['ineffective_acls']
            
            severity = 'High' if acl_protection['protection_level'] == 0 else 'Medium'
            
            vulnerabilities.append({
                'line': interface_config.get('line_number', 0),
                'matched_text': f'interface {interface_name} - insufficient spoofing protection',
                'details': {
                    'vulnerability': 'insufficient_spoofing_protection',
                    'interface_name': interface_name,
                    'network_type': 'external_facing',
                    'protection_level': acl_protection['protection_level'],
                    'missing_protections': missing_protections,
                    'ineffective_acls': ineffective_acls,
                    'applied_acls': acl_protection['applied_acls'],
                    'recommendation': f'Strengthen spoofing protection on {interface_name}: ' + ', '.join(missing_protections),
                    'severity_adjusted': severity
                }
            })
    
    return vulnerabilities


def _analyze_interface_spoofing_protection(context: ConfigContext, interface_name: str, interface_config: Dict) -> Dict[str, Any]:
    """인터페이스별 스푸핑 방지 효과성 분석"""
    
    # 인터페이스에 적용된 ACL 찾기
    applied_acls = []
    config_lines = interface_config.get('config_lines', [])
    
    for line in config_lines:
        if 'ip access-group' in line and 'in' in line:
            acl_match = re.search(r'ip access-group\s+(\S+)\s+in', line)
            if acl_match:
                applied_acls.append(acl_match.group(1))
    
    # 각 ACL의 스푸핑 방지 효과 분석
    protection_analysis = {
        'private_ranges': False,
        'loopback': False,
        'broadcast': False,
        'multicast': False,
        'bogons': False
    }
    
    ineffective_acls = []
    
    for acl_name in applied_acls:
        acl_effectiveness = _analyze_acl_spoofing_rules(context, acl_name)
        
        # ACL이 permit any를 포함하면 무효화됨
        if acl_effectiveness['has_permit_any']:
            ineffective_acls.append(f"{acl_name} (has permit any)")
            continue
        
        # 각 보호 영역 확인
        for protection_type, is_protected in acl_effectiveness['protections'].items():
            if is_protected:
                protection_analysis[protection_type] = True
    
    protection_count = sum(protection_analysis.values())
    missing_protections = [k for k, v in protection_analysis.items() if not v]
    
    return {
        'protection_level': protection_count,
        'missing_protections': missing_protections,
        'applied_acls': applied_acls,
        'ineffective_acls': ineffective_acls,
        'protection_details': protection_analysis
    }


def _analyze_acl_spoofing_rules(context: ConfigContext, acl_name: str) -> Dict[str, Any]:
    """ACL의 스푸핑 방지 룰 분석"""
    
    acl_lines = []
    for line in context.config_lines:
        if f'access-list {acl_name}' in line:
            acl_lines.append(line.strip())
    
    protections = {
        'private_ranges': False,
        'loopback': False,
        'broadcast': False,
        'multicast': False,
        'bogons': False
    }
    
    has_permit_any = False
    
    for line in acl_lines:
        line_lower = line.lower()
        
        # permit any 확인 (보호 무력화)
        if 'permit' in line_lower and 'any' in line_lower:
            has_permit_any = True
        
        # 스푸핑 방지 룰 확인
        if 'deny' in line_lower:
            # Private IP 대역
            if any(pattern in line_lower for pattern in ['10.0.0.0', '172.16.0.0', '192.168.0.0']):
                protections['private_ranges'] = True
            # 루프백
            if '127.0.0.0' in line_lower:
                protections['loopback'] = True
            # 멀티캐스트
            if any(f'22{i}.0.0.0' in line_lower for i in range(4, 10)) or any(f'23{i}.0.0.0' in line_lower for i in range(0, 10)):
                protections['multicast'] = True
            # 브로드캐스트
            if '.255' in line_lower:
                protections['broadcast'] = True
            # Bogon 네트워크
            if any(pattern in line_lower for pattern in ['0.0.0.0', '169.254.0.0']):
                protections['bogons'] = True
    
    return {
        'protections': protections,
        'has_permit_any': has_permit_any,
        'total_rules': len(acl_lines)
    }


def check_ddos_protection(line: str, line_num: int, context: ConfigContext) -> List[Dict[str, Any]]:
    """N-13: DDoS 공격 방어 설정 - 논리 기반 분석"""
    vulnerabilities = []
    
    # DDoS 방어 기능 확인
    ddos_protection_found = False
    
    for line in context.config_lines:
        if any(pattern in line.lower() for pattern in ['ip access-list']):
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
    """N-16: VTY 안전한 프로토콜 사용 - SSH 버전 및 암호화 강화"""
    vulnerabilities = []
    
    # SSH 전역 설정 분석
    ssh_config = _analyze_ssh_configuration(context)
    
    for vty_line in context.vty_lines:
        transport_input = vty_line.get('transport_input', [])
        
        # 1. Telnet 허용 확인
        if 'telnet' in transport_input or 'all' in transport_input:
            vulnerabilities.append({
                'line': vty_line['line_number'],
                'matched_text': f"{vty_line['line']} transport input {' '.join(transport_input)}",
                'details': {
                    'vulnerability': 'telnet_allowed',
                    'transport_input': transport_input,
                    'recommendation': 'Use transport input ssh only',
                    'security_risk': 'Telnet transmits credentials in plain text',
                    'severity_adjusted': 'High'
                }
            })
        
        # 2. SSH만 허용하는 경우 SSH 설정 품질 확인
        elif 'ssh' in transport_input and 'telnet' not in transport_input:
            ssh_issues = []
            
            # SSH 버전 확인
            if ssh_config['version'] == 1:
                ssh_issues.append('ssh_version_1_enabled')
            elif ssh_config['version'] == 'both':
                ssh_issues.append('ssh_version_both_enabled')
            elif not ssh_config['version_specified']:
                ssh_issues.append('ssh_version_not_specified')
            
            # 약한 암호화 알고리즘 확인
            if ssh_config['weak_algorithms']:
                ssh_issues.append('weak_encryption_algorithms')
            
            # Key 길이 확인
            if ssh_config['key_bits'] and ssh_config['key_bits'] < 2048:
                ssh_issues.append('weak_key_length')
            
            # 로그인 인증 방식 확인
            if not vty_line.get('has_password') and vty_line.get('login_method') != 'login local':
                ssh_issues.append('no_authentication_configured')
            
            if ssh_issues:
                severity = 'High' if 'ssh_version_1_enabled' in ssh_issues else 'Medium'
                
                vulnerabilities.append({
                    'line': vty_line['line_number'],
                    'matched_text': f"{vty_line['line']} (SSH configuration issues)",
                    'details': {
                        'vulnerability': 'ssh_configuration_weak',
                        'ssh_issues': ssh_issues,
                        'ssh_config': ssh_config,
                        'recommendation': _generate_ssh_recommendations(ssh_issues),
                        'severity_adjusted': severity
                    }
                })
        
        # 3. Transport input이 none인 경우 (접근 불가)
        elif 'none' in transport_input:
            # 이는 보안상 안전하지만 관리 접근이 불가능함을 알림
            vulnerabilities.append({
                'line': vty_line['line_number'],
                'matched_text': f"{vty_line['line']} transport input none",
                'details': {
                    'vulnerability': 'vty_access_disabled',
                    'recommendation': 'VTY access is disabled. Ensure console access is available.',
                    'severity_adjusted': 'Info'
                }
            })
    
    return vulnerabilities


def _analyze_ssh_configuration(context: ConfigContext) -> Dict[str, Any]:
    """SSH 전역 설정 분석"""
    ssh_config = {
        'version': None,
        'version_specified': False,
        'key_bits': None,
        'weak_algorithms': [],
        'timeout': None,
        'retries': None
    }
    
    for line in context.config_lines:
        line_clean = line.strip().lower()
        
        # SSH 버전 확인
        if 'ip ssh version' in line_clean:
            ssh_config['version_specified'] = True
            if 'version 1' in line_clean:
                ssh_config['version'] = 1
            elif 'version 2' in line_clean:
                ssh_config['version'] = 2
            else:
                # version 1과 2 모두 허용하는 경우가 있을 수 있음
                ssh_config['version'] = 'both'
        
        # SSH Key 길이 확인
        elif 'crypto key generate rsa' in line_clean:
            key_match = re.search(r'modulus\s+(\d+)', line_clean)
            if key_match:
                ssh_config['key_bits'] = int(key_match.group(1))
        
        # SSH 타임아웃 확인
        elif 'ip ssh time-out' in line_clean:
            timeout_match = re.search(r'time-out\s+(\d+)', line_clean)
            if timeout_match:
                ssh_config['timeout'] = int(timeout_match.group(1))
        
        # SSH 재시도 횟수 확인
        elif 'ip ssh authentication-retries' in line_clean:
            retries_match = re.search(r'authentication-retries\s+(\d+)', line_clean)
            if retries_match:
                ssh_config['retries'] = int(retries_match.group(1))
    
    # 기본값 설정 (버전이 명시되지 않은 경우)
    if not ssh_config['version_specified']:
        ssh_config['version'] = 'both'  # 기본값은 보통 1과 2 모두 허용
    
    return ssh_config


def _generate_ssh_recommendations(ssh_issues: List[str]) -> str:
    """SSH 권고사항 생성"""
    recommendations = []
    
    if 'ssh_version_1_enabled' in ssh_issues:
        recommendations.append("SSH 버전 1 비활성화 (ip ssh version 2)")
    if 'ssh_version_both_enabled' in ssh_issues or 'ssh_version_not_specified' in ssh_issues:
        recommendations.append("SSH 버전 2만 허용 (ip ssh version 2)")
    if 'weak_encryption_algorithms' in ssh_issues:
        recommendations.append("강력한 암호화 알고리즘 설정")
    if 'weak_key_length' in ssh_issues:
        recommendations.append("RSA 키 길이 2048비트 이상 사용")
    if 'no_authentication_configured' in ssh_issues:
        recommendations.append("적절한 인증 방식 설정 (login local 또는 password)")
    
    return '; '.join(recommendations)


def check_auxiliary_port_security(line: str, line_num: int, context: ConfigContext) -> List[Dict[str, Any]]:
    """N-17: 불필요한 보조 입·출력 포트 사용 금지 - 논리 기반 분석"""
    vulnerabilities = []
    
    # AUX 포트 보안 설정 확인
    aux_issues = _check_aux_port_security(context)
    vulnerabilities.extend(aux_issues)
    
    # Console 포트 보안 설정 확인
    console_issues = _check_console_port_security(context)
    vulnerabilities.extend(console_issues)
    
    return vulnerabilities


def _check_aux_port_security(context: ConfigContext) -> List[Dict[str, Any]]:
    """AUX 포트 보안 설정 확인"""
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


def _check_console_port_security(context: ConfigContext) -> List[Dict[str, Any]]:
    """Console 포트 보안 설정 확인"""
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
    buffer_line_num = 0
    
    for i, line in enumerate(context.config_lines):
        match = re.match(r'^logging\s+(buffer|buffered)\s+(\d+)', line.strip())
        if match:
            buffer_size = int(match.group(2))
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
        elif buffer_size < 16000:  # 16KB 미만
            # 버퍼 크기가 너무 작음
            vulnerabilities.append({
                'line': buffer_line_num,
                'matched_text': f'logging buffered {buffer_size}',
                'details': {
                    'vulnerability': 'insufficient_logging_buffer_size',
                    'current_size': buffer_size,
                    'recommended_minimum': 16000,
                    'recommendation': 'Increase logging buffer size to at least 16KB',
                    'severity_adjusted': 'Medium'
                }
            })
    
    return vulnerabilities


def check_logging_policy_configuration(line: str, line_num: int, context: ConfigContext) -> List[Dict[str, Any]]:
    """N-21: 정책에 따른 로깅 설정 - 논리 기반 분석"""
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
    """N-26: 웹 서비스 차단 - HTTP/HTTPS 구분 및 보안 강화"""
    vulnerabilities = []
    
    # 웹 서비스 설정 분석
    web_services = _analyze_web_services(context)
    
    # HTTP 서버가 활성화된 경우
    if web_services['http_enabled']:
        # HTTPS도 함께 활성화되어 있는지 확인
        if web_services['https_enabled']:
            # HTTPS가 있지만 HTTP도 활성화된 경우 (보안 위험)
            vulnerabilities.append({
                'line': web_services['http_line'],
                'matched_text': 'ip http server (with HTTPS enabled)',
                'details': {
                    'vulnerability': 'http_with_https_enabled',
                    'recommendation': 'Disable HTTP server and use only HTTPS (no ip http server)',
                    'security_risk': 'HTTP transmits data in plain text even when HTTPS is available',
                    'severity_adjusted': 'Medium'
                }
            })
        else:
            # HTTP만 활성화된 경우 (높은 위험)
            vulnerabilities.append({
                'line': web_services['http_line'],
                'matched_text': 'ip http server (no HTTPS)',
                'details': {
                    'vulnerability': 'http_server_only',
                    'recommendation': 'Disable HTTP server or configure HTTPS instead',
                    'security_risk': 'HTTP transmits credentials and data in plain text',
                    'severity_adjusted': 'High'
                }
            })
    
    # HTTPS 서버 보안 설정 확인
    if web_services['https_enabled']:
        https_issues = []
        
        # HTTPS 인증서 확인
        if not web_services['ssl_certificate']:
            https_issues.append('no_ssl_certificate')
        
        # HTTP 접근 제한 확인
        if not web_services['access_restricted']:
            https_issues.append('no_access_restriction')
        
        # 약한 SSL/TLS 버전 확인
        if web_services['weak_ssl_versions']:
            https_issues.append('weak_ssl_versions')
        
        # HTTPS 이슈가 있는 경우에만 보고
        if https_issues:
            vulnerabilities.append({
                'line': web_services['https_line'],
                'matched_text': 'ip http secure-server (security issues)',
                'details': {
                    'vulnerability': 'https_configuration_weak',
                    'https_issues': https_issues,
                    'web_config': web_services,
                    'recommendation': _generate_https_recommendations(https_issues),
                    'severity_adjusted': 'Medium'
                }
            })
    
    return vulnerabilities


def _analyze_web_services(context: ConfigContext) -> Dict[str, Any]:
    """웹 서비스 설정 분석"""
    web_config = {
        'http_enabled': False,
        'https_enabled': False,
        'http_line': 0,
        'https_line': 0,
        'ssl_certificate': False,
        'access_restricted': False,
        'weak_ssl_versions': [],
        'authentication_configured': False
    }
    
    for i, line in enumerate(context.config_lines):
        line_clean = line.strip().lower()
        
        # HTTP 서버 확인
        if 'ip http server' in line_clean and not line_clean.startswith('no '):
            web_config['http_enabled'] = True
            web_config['http_line'] = i + 1
        
        # HTTPS 서버 확인
        elif 'ip http secure-server' in line_clean and not line_clean.startswith('no '):
            web_config['https_enabled'] = True
            web_config['https_line'] = i + 1
        
        # SSL 인증서 확인
        elif 'crypto pki certificate' in line_clean or 'ssl certificate' in line_clean:
            web_config['ssl_certificate'] = True
        
        # 웹 접근 제한 확인
        elif 'ip http access-class' in line_clean:
            web_config['access_restricted'] = True
        
        # 웹 인증 설정 확인
        elif 'ip http authentication' in line_clean:
            web_config['authentication_configured'] = True
        
        # SSL/TLS 버전 확인
        elif 'ssl version' in line_clean or 'tls version' in line_clean:
            if any(weak_version in line_clean for weak_version in ['ssl 3.0', 'tls 1.0', 'tls 1.1']):
                version_match = re.search(r'(ssl \d\.\d|tls \d\.\d)', line_clean)
                if version_match:
                    web_config['weak_ssl_versions'].append(version_match.group(1))
    
    return web_config


def _generate_https_recommendations(https_issues: List[str]) -> str:
    """HTTPS 권고사항 생성"""
    recommendations = []
    
    if 'no_ssl_certificate' in https_issues:
        recommendations.append("SSL 인증서 설정 (crypto pki)")
    if 'no_access_restriction' in https_issues:
        recommendations.append("웹 접근 제한 설정 (ip http access-class)")
    if 'weak_ssl_versions' in https_issues:
        recommendations.append("강력한 TLS 버전 사용 (TLS 1.2 이상)")
    
    return '; '.join(recommendations)


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
    """N-30: Directed-broadcast 차단 - 버전별 기본값 정확한 반영"""
    vulnerabilities = []
    
    # IOS 버전 확인 및 기본값 판단
    ios_version = context.ios_version or "15.0"
    version_num = context.cisco_defaults._extract_version_number(ios_version)
    
    # 버전별 기본 동작
    default_enabled = version_num < 12.0  # 12.0 이전에서만 기본 enabled
    
    for interface_name, interface_config in context.parsed_interfaces.items():
        # 서브인터페이스, 루프백, 관리 인터페이스 제외
        if (interface_config.get('is_subinterface', False) or 
            interface_config.get('is_loopback') or 
            interface_config.get('is_management')):
            continue
            
        config_lines = interface_config.get('config_lines', [])
        
        # 명시적 설정 확인
        explicitly_disabled = any('no ip directed-broadcast' in line for line in config_lines)
        explicitly_enabled = any(
            'ip directed-broadcast' in line and not line.strip().startswith('no ')
            for line in config_lines
        )
        
        # 실제 상태 판단
        if explicitly_disabled:
            actual_state = False  # 안전
            continue  # 명시적으로 비활성화된 경우는 문제없음
        elif explicitly_enabled:
            actual_state = True   # 위험
            status = "explicitly_enabled"
            severity = "High"
        else:
            # 명시적 설정이 없는 경우 기본값 적용
            actual_state = default_enabled
            if actual_state:
                status = "default_enabled"
                severity = "Medium" if version_num < 12.0 else "Low"
            else:
                continue  # 기본값이 disabled면 문제없음
        
        # 취약점 보고 (actual_state가 True인 경우만)
        if actual_state:
            recommendation = 'Add: no ip directed-broadcast' if status == "default_enabled" else 'Change to: no ip directed-broadcast'
            
            vulnerabilities.append({
                'line': interface_config['line_number'],
                'matched_text': f"interface {interface_name}",
                'details': {
                    'vulnerability': 'directed_broadcast_not_disabled',
                    'interface_name': interface_name,
                    'status': status,
                    'ios_version': ios_version,
                    'version_default': default_enabled,
                    'recommendation': recommendation,
                    'severity_adjusted': severity,
                    'version_info': f'IOS {ios_version}: default {"enabled" if default_enabled else "disabled"}'
                }
            })
    
    return vulnerabilities


def check_source_routing_status(line: str, line_num: int, context: ConfigContext) -> List[Dict[str, Any]]:
    """N-31: Source 라우팅 차단 - 개선된 논리 기반 분석"""
    vulnerabilities = []
    
    # 전역 source routing 설정 확인
    source_routing_explicitly_disabled = any('no ip source-route' in line for line in context.config_lines)
    source_routing_explicitly_enabled = any(
        'ip source-route' in line and not line.strip().startswith('no ')
        for line in context.config_lines
    )
    
    # 실제 상태 판단
    if source_routing_explicitly_disabled:
        actual_state = False  # 비활성화됨 (양호)
    elif source_routing_explicitly_enabled:
        actual_state = True   # 명시적 활성화됨 (취약)
    else:
        # 기본값 적용: Cisco는 기본적으로 source-route enabled
        actual_state = context.get_service_state('source_route')
    
    # 보안 기준: source routing은 비활성화되어야 함
    if actual_state:  # 활성화된 경우 취약점으로 보고
        status = "explicitly_enabled" if source_routing_explicitly_enabled else "default_enabled"
        
        vulnerabilities.append({
            'line': 0,
            'matched_text': f'Source routing {status}',
            'details': {
                'vulnerability': 'source_routing_enabled',
                'status': status,
                'scope': 'global',
                'recommendation': 'Add: no ip source-route' if status == "default_enabled" 
                                else 'Change to: no ip source-route',
                'default_behavior': 'Cisco default: source-route enabled',
                'security_impact': 'Allows packet routing manipulation attacks'
            }
        })
    
    return vulnerabilities


def check_proxy_arp_status(line: str, line_num: int, context: ConfigContext) -> List[Dict[str, Any]]:
    """N-32: Proxy ARP 차단 - 서브인터페이스 제외 개선된 버전"""
    vulnerabilities = []
    
    for interface_name, interface_config in context.parsed_interfaces.items():
        # 🔧 개선: 서브인터페이스 제외 (Proxy ARP는 물리 인터페이스에서만 의미있음)
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
                'matched_text': f"interface {interface_name}",
                'details': {
                    'vulnerability': 'proxy_arp_enabled',
                    'interface_name': interface_name,
                    'interface_type': 'physical',
                    'status': status,
                    'recommendation': 'Add: no ip proxy-arp' if status == "default_enabled" 
                                    else 'Change to: no ip proxy-arp',
                    'default_behavior': 'Cisco default: proxy-arp enabled'
                }
            })
    
    return vulnerabilities


def check_icmp_services_status(line: str, line_num: int, context: ConfigContext) -> List[Dict[str, Any]]:
    """N-33: ICMP unreachable, Redirect 차단 - 외부 인터페이스만 선별적 적용"""
    vulnerabilities = []
    
    # 네트워크 환경 분석
    network_analysis = _analyze_network_environment_kisa(context)
    external_interfaces = set(network_analysis['external_interfaces'])
    
    for interface_name, interface_config in context.parsed_interfaces.items():
        # 🔧 개선: 서브인터페이스 제외
        if interface_config.get('is_subinterface', False):
            continue
            
        # 루프백, 관리 인터페이스 제외
        if interface_config.get('is_loopback') or interface_config.get('is_management'):
            continue
        
        # 🔧 개선: 외부 인터페이스 우선 체크, 내부는 권장 수준
        is_external = interface_name in external_interfaces
        
        # 외부 인터페이스가 아니면 낮은 우선순위로 처리
        if not is_external and not network_analysis['has_external_connection']:
            continue  # 완전 내부 네트워크는 스킵
            
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
            
            vulnerabilities.append({
                'line': interface_config['line_number'],
                'matched_text': f"interface {interface_name}",
                'details': {
                    'vulnerability': 'icmp_services_not_disabled',
                    'interface_name': interface_name,
                    'interface_type': 'external' if is_external else 'internal',
                    'issues': issues,
                    'unreachables_disabled': has_no_unreachables,
                    'redirects_disabled': has_no_redirects,
                    'recommendation': 'Disable ICMP unreachables and redirects: no ip unreachables, no ip redirects' + 
                                    (' (Critical for external interfaces)' if is_external else ' (Recommended)'),
                    'severity_adjusted': severity
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
    """N-35: Domain lookup 차단 - 명시적 설정 정확한 처리"""
    vulnerabilities = []
    
    # 명시적 설정 정확한 파싱
    explicitly_disabled_lines = []
    explicitly_enabled_lines = []
    
    for i, line in enumerate(context.config_lines):
        line_clean = line.strip()
        
        # 비활성화 설정 확인 (다양한 형태)
        if any(pattern in line_clean for pattern in ['no ip domain-lookup', 'no ip domain lookup']):
            explicitly_disabled_lines.append(i + 1)
        
        # 활성화 설정 확인 (no로 시작하지 않는 경우만)
        elif (any(pattern in line_clean for pattern in ['ip domain-lookup', 'ip domain lookup']) and
              not line_clean.startswith('no ')):
            explicitly_enabled_lines.append(i + 1)
    
    # 최종 설정 상태 판단 (마지막 설정이 우선)
    all_settings = []
    
    for line_num in explicitly_disabled_lines:
        all_settings.append((line_num, False))  # disabled
    
    for line_num in explicitly_enabled_lines:
        all_settings.append((line_num, True))   # enabled
    
    # 라인 번호순으로 정렬하여 마지막 설정 확인
    all_settings.sort(key=lambda x: x[0])
    
    if all_settings:
        # 명시적 설정이 있는 경우
        last_line, last_setting = all_settings[-1]
        
        if last_setting:  # 마지막이 enabled 설정인 경우만 취약점
            vulnerabilities.append({
                'line': last_line,
                'matched_text': 'Domain lookup explicitly enabled',
                'details': {
                    'vulnerability': 'domain_lookup_enabled',
                    'status': 'explicitly_enabled',
                    'last_config_line': last_line,
                    'all_settings': all_settings,
                    'recommendation': 'Change to: no ip domain-lookup',
                    'severity_adjusted': 'Medium'
                }
            })
        # explicitly disabled인 경우는 안전하므로 보고하지 않음
    else:
        # 명시적 설정이 없는 경우 - 기본값 확인
        default_enabled = context.get_service_state('domain_lookup')
        
        if default_enabled:
            vulnerabilities.append({
                'line': 0,
                'matched_text': 'Domain lookup using default (enabled)',
                'details': {
                    'vulnerability': 'domain_lookup_default_enabled',
                    'status': 'default_enabled',
                    'ios_version': context.ios_version,
                    'recommendation': 'Add: no ip domain-lookup',
                    'severity_adjusted': 'Low',
                    'note': 'Default behavior varies by IOS version'
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
    """N-37: mask-reply 차단 - 버전별 기본값 정확한 처리"""
    vulnerabilities = []
    
    # IOS 버전별 기본값 확인
    ios_version = context.ios_version or "15.0"
    version_num = context.cisco_defaults._extract_version_number(ios_version)
    
    # 버전별 기본 동작 (12.4 이후부터 기본 disabled)
    default_enabled = version_num < 12.4
    
    for interface_name, interface_config in context.parsed_interfaces.items():
        # 서브인터페이스, 루프백, 관리 인터페이스 제외
        if (interface_config.get('is_subinterface', False) or 
            interface_config.get('is_loopback') or 
            interface_config.get('is_management')):
            continue
            
        # 물리 인터페이스만 체크
        if interface_config['port_type'] not in ['FastEthernet', 'GigabitEthernet', 'TenGigabitEthernet']:
            continue
            
        config_lines = interface_config.get('config_lines', [])
        
        # 명시적 설정 확인
        explicitly_disabled = any('no ip mask-reply' in line for line in config_lines)
        explicitly_enabled = any(
            'ip mask-reply' in line and not line.strip().startswith('no ')
            for line in config_lines
        )
        
        # 실제 상태 판단
        if explicitly_disabled:
            actual_state = False  # 안전
            continue
        elif explicitly_enabled:
            actual_state = True   # 위험
            status = "explicitly_enabled"
            severity = "High"
        else:
            # 명시적 설정이 없는 경우 기본값 적용
            actual_state = default_enabled
            if actual_state:
                status = "default_enabled"
                # 구버전에서만 중간 위험도, 신버전에서는 실제로 기본값이 disabled
                severity = "Medium" if version_num < 12.4 else "Info"
            else:
                continue  # 기본값이 disabled면 안전
        
        # 취약점 보고 (actual_state가 True인 경우만)
        if actual_state:
            # 신버전에서 기본값이 disabled인데 Info로 보고하는 것은 실제로는 문제가 없으므로 Skip
            if status == "default_enabled" and version_num >= 12.4:
                continue
                
            recommendation = 'Add: no ip mask-reply' if status == "default_enabled" else 'Change to: no ip mask-reply'
            
            vulnerabilities.append({
                'line': interface_config['line_number'],
                'matched_text': f"interface {interface_name}",
                'details': {
                    'vulnerability': 'mask_reply_not_disabled',
                    'interface_name': interface_name,
                    'status': status,
                    'ios_version': ios_version,
                    'version_default': default_enabled,
                    'recommendation': recommendation,
                    'severity_adjusted': severity,
                    'version_info': f'IOS {ios_version}: default {"enabled" if default_enabled else "disabled"} (changed in 12.4+)'
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

# KISA 전용 헬퍼 함수
def _analyze_network_environment_kisa(context: ConfigContext) -> Dict[str, Any]:
    """네트워크 환경 분석 - KISA 버전"""
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
        if ip_address and not _is_private_ip_kisa(ip_address):
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


def _is_private_ip_kisa(ip_address: str) -> bool:
    """사설 IP 대역 확인 - KISA 버전"""
    import re
    
    if re.match(r'^10\.', ip_address):
        return True
    if re.match(r'^172\.(1[6-9]|2[0-9]|3[0-1])\.', ip_address):
        return True
    if re.match(r'^192\.168\.', ip_address):
        return True
    return False