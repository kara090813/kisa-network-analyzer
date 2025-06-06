# -*- coding: utf-8 -*-
"""
rules/checks_cis.py
CIS Cisco IOS 12 Benchmark v4.0.0 네트워크 장비 보안 점검 룰의 논리적 검증 함수들

각 CIS 룰에 대한 logical_check_function들을 정의
"""
import re
from typing import List, Dict, Any
from .loader import ConfigContext


# ======================= 1.1 Local Authentication, Authorization and Accounting (AAA) Rules =======================

def check_cis_1_1_1(line: str, line_num: int, context: ConfigContext) -> List[Dict[str, Any]]:
    """CIS-1.1.1: Enable 'aaa new-model' - AAA 시스템 활성화 확인"""
    vulnerabilities = []
    
    # AAA new-model 설정 확인
    has_aaa_new_model = 'aaa new-model' in context.full_config
    
    if not has_aaa_new_model:
        vulnerabilities.append({
            'line': 0,
            'matched_text': 'AAA new-model 설정 누락',
            'details': {
                'vulnerability': 'aaa_new_model_missing',
                'description': 'AAA 접근 제어 시스템이 비활성화되어 있음',
                'recommendation': 'aaa new-model 명령어를 설정하여 AAA 시스템을 활성화하세요',
                'impact': 'centralized authentication, authorization, accounting 기능 사용 불가'
            }
        })
    
    return vulnerabilities


def check_cis_1_1_2(line: str, line_num: int, context: ConfigContext) -> List[Dict[str, Any]]:
    """CIS-1.1.2: Enable 'aaa authentication login' - 로그인 AAA 인증 확인"""
    vulnerabilities = []
    
    # AAA authentication login 설정 확인
    has_aaa_auth_login = 'aaa authentication login' in context.full_config
    
    if not has_aaa_auth_login:
        vulnerabilities.append({
            'line': 0,
            'matched_text': 'AAA authentication login 설정 누락',
            'details': {
                'vulnerability': 'aaa_authentication_login_missing',
                'description': 'AAA 로그인 인증이 설정되지 않음',
                'recommendation': 'aaa authentication login default method1 [method2] 명령어를 설정하세요',
                'impact': '중앙집중식 로그인 인증 기능 사용 불가'
            }
        })
    
    return vulnerabilities


def check_cis_1_1_3(line: str, line_num: int, context: ConfigContext) -> List[Dict[str, Any]]:
    """CIS-1.1.3: Enable 'aaa authentication enable default' - Enable 모드 AAA 인증 확인"""
    vulnerabilities = []
    
    # AAA authentication enable 설정 확인
    has_aaa_auth_enable = 'aaa authentication enable' in context.full_config
    
    if not has_aaa_auth_enable:
        vulnerabilities.append({
            'line': 0,
            'matched_text': 'AAA authentication enable 설정 누락',
            'details': {
                'vulnerability': 'aaa_authentication_enable_missing',
                'description': 'Enable 모드 접근 시 AAA 인증이 설정되지 않음',
                'recommendation': 'aaa authentication enable default method1 enable 명령어를 설정하세요',
                'impact': '특권 모드 접근 시 중앙집중식 인증 기능 사용 불가'
            }
        })
    
    return vulnerabilities


def check_cis_1_1_4(line: str, line_num: int, context: ConfigContext) -> List[Dict[str, Any]]:
    """CIS-1.1.4: Set 'login authentication for 'line con 0' - 콘솔 라인 인증 확인"""
    vulnerabilities = []
    
    # 콘솔 라인 설정에서 login authentication 확인
    console_lines = [line for line in context.config_lines if 'line con 0' in line.lower()]
    
    if console_lines:
        # 콘솔 라인이 설정되어 있는 경우, login authentication 확인
        console_section_found = False
        has_login_auth = False
        
        for i, config_line in enumerate(context.config_lines):
            if 'line con 0' in config_line.lower():
                console_section_found = True
                # 다음 라인들에서 login authentication 찾기
                for j in range(i + 1, min(i + 10, len(context.config_lines))):
                    next_line = context.config_lines[j].strip()
                    if next_line.startswith('line ') and 'con 0' not in next_line:
                        break
                    if 'login authentication' in next_line:
                        has_login_auth = True
                        break
                break
        
        if console_section_found and not has_login_auth:
            vulnerabilities.append({
                'line': 0,
                'matched_text': 'line con 0 섹션에 login authentication 설정 누락',
                'details': {
                    'vulnerability': 'console_login_authentication_missing',
                    'description': '콘솔 라인에 AAA 인증이 설정되지 않음',
                    'recommendation': 'line con 0 섹션에 login authentication default 명령어를 설정하세요',
                    'impact': '콘솔 접근 시 중앙집중식 인증 기능 사용 불가'
                }
            })
    
    return vulnerabilities


def check_cis_1_1_5(line: str, line_num: int, context: ConfigContext) -> List[Dict[str, Any]]:
    """CIS-1.1.5: Set 'login authentication for 'line tty' - TTY 라인 인증 확인"""
    vulnerabilities = []
    
    # TTY 라인 설정에서 login authentication 확인
    tty_lines = [line for line in context.config_lines if 'line tty' in line.lower()]
    
    if tty_lines:
        for tty_line in tty_lines:
            has_login_auth = False
            
            # TTY 라인 섹션에서 login authentication 찾기
            for i, config_line in enumerate(context.config_lines):
                if config_line.strip() == tty_line.strip():
                    # 다음 라인들에서 login authentication 찾기
                    for j in range(i + 1, min(i + 10, len(context.config_lines))):
                        next_line = context.config_lines[j].strip()
                        if next_line.startswith('line ') and 'tty' not in next_line:
                            break
                        if 'login authentication' in next_line:
                            has_login_auth = True
                            break
                    break
            
            if not has_login_auth:
                vulnerabilities.append({
                    'line': 0,
                    'matched_text': f'{tty_line} 섹션에 login authentication 설정 누락',
                    'details': {
                        'vulnerability': 'tty_login_authentication_missing',
                        'description': 'TTY 라인에 AAA 인증이 설정되지 않음',
                        'recommendation': 'TTY 라인 섹션에 login authentication default 명령어를 설정하세요',
                        'impact': 'TTY 접근 시 중앙집중식 인증 기능 사용 불가'
                    }
                })
    
    return vulnerabilities


def check_cis_1_1_6(line: str, line_num: int, context: ConfigContext) -> List[Dict[str, Any]]:
    """CIS-1.1.6: Set 'login authentication for 'line vty' - VTY 라인 인증 확인"""
    vulnerabilities = []
    
    # VTY 라인에서 login authentication 확인 - 기존 context.vty_lines 활용
    for vty_line in context.vty_lines:
        if vty_line.get('login_method') != 'login authentication':
            # login authentication이 설정되지 않은 경우
            vulnerabilities.append({
                'line': vty_line['line_number'],
                'matched_text': vty_line['line'],
                'details': {
                    'vulnerability': 'vty_login_authentication_missing',
                    'description': 'VTY 라인에 AAA 인증이 설정되지 않음',
                    'vty_config': vty_line,
                    'current_login_method': vty_line.get('login_method', 'none'),
                    'recommendation': 'VTY 라인 섹션에 login authentication default 명령어를 설정하세요',
                    'impact': 'VTY 원격 접근 시 중앙집중식 인증 기능 사용 불가'
                }
            })
    
    return vulnerabilities


def check_cis_1_1_7(line: str, line_num: int, context: ConfigContext) -> List[Dict[str, Any]]:
    """CIS-1.1.7: Set 'aaa accounting commands 15' - 권한 명령어 추적 확인"""
    vulnerabilities = []
    
    # AAA accounting commands 15 설정 확인
    has_accounting_commands_15 = 'aaa accounting commands 15' in context.full_config
    
    if not has_accounting_commands_15:
        vulnerabilities.append({
            'line': 0,
            'matched_text': 'AAA accounting commands 15 설정 누락',
            'details': {
                'vulnerability': 'aaa_accounting_commands_15_missing',
                'description': '권한 레벨 15 명령어에 대한 계정 추적이 설정되지 않음',
                'recommendation': 'aaa accounting commands 15 default start-stop group tacacs+ 명령어를 설정하세요',
                'impact': '특권 명령어 사용에 대한 감사 추적 기능 사용 불가',
                'level': 'Level 2'
            }
        })
    
    return vulnerabilities


def check_cis_1_1_8(line: str, line_num: int, context: ConfigContext) -> List[Dict[str, Any]]:
    """CIS-1.1.8: Set 'aaa accounting connection' - 연결 추적 확인"""
    vulnerabilities = []
    
    # AAA accounting connection 설정 확인
    has_accounting_connection = 'aaa accounting connection' in context.full_config
    
    if not has_accounting_connection:
        vulnerabilities.append({
            'line': 0,
            'matched_text': 'AAA accounting connection 설정 누락',
            'details': {
                'vulnerability': 'aaa_accounting_connection_missing',
                'description': '아웃바운드 연결에 대한 계정 추적이 설정되지 않음',
                'recommendation': 'aaa accounting connection default start-stop group tacacs+ 명령어를 설정하세요',
                'impact': '네트워크 연결에 대한 감사 추적 기능 사용 불가',
                'level': 'Level 2'
            }
        })
    
    return vulnerabilities


def check_cis_1_1_9(line: str, line_num: int, context: ConfigContext) -> List[Dict[str, Any]]:
    """CIS-1.1.9: Set 'aaa accounting exec' - EXEC 세션 추적 확인"""
    vulnerabilities = []
    
    # AAA accounting exec 설정 확인
    has_accounting_exec = 'aaa accounting exec' in context.full_config
    
    if not has_accounting_exec:
        vulnerabilities.append({
            'line': 0,
            'matched_text': 'AAA accounting exec 설정 누락',
            'details': {
                'vulnerability': 'aaa_accounting_exec_missing',
                'description': 'EXEC 셸 세션에 대한 계정 추적이 설정되지 않음',
                'recommendation': 'aaa accounting exec default start-stop group tacacs+ 명령어를 설정하세요',
                'impact': 'EXEC 세션에 대한 감사 추적 기능 사용 불가',
                'level': 'Level 2'
            }
        })
    
    return vulnerabilities


def check_cis_1_1_10(line: str, line_num: int, context: ConfigContext) -> List[Dict[str, Any]]:
    """CIS-1.1.10: Set 'aaa accounting network' - 네트워크 서비스 추적 확인"""
    vulnerabilities = []
    
    # AAA accounting network 설정 확인
    has_accounting_network = 'aaa accounting network' in context.full_config
    
    if not has_accounting_network:
        vulnerabilities.append({
            'line': 0,
            'matched_text': 'AAA accounting network 설정 누락',
            'details': {
                'vulnerability': 'aaa_accounting_network_missing',
                'description': '네트워크 관련 서비스 요청에 대한 계정 추적이 설정되지 않음',
                'recommendation': 'aaa accounting network default start-stop group tacacs+ 명령어를 설정하세요',
                'impact': '네트워크 서비스에 대한 감사 추적 기능 사용 불가',
                'level': 'Level 2'
            }
        })
    
    return vulnerabilities


def check_cis_1_1_11(line: str, line_num: int, context: ConfigContext) -> List[Dict[str, Any]]:
    """CIS-1.1.11: Set 'aaa accounting system' - 시스템 이벤트 추적 확인"""
    vulnerabilities = []
    
    # AAA accounting system 설정 확인
    has_accounting_system = 'aaa accounting system' in context.full_config
    
    if not has_accounting_system:
        vulnerabilities.append({
            'line': 0,
            'matched_text': 'AAA accounting system 설정 누락',
            'details': {
                'vulnerability': 'aaa_accounting_system_missing',
                'description': '시스템 레벨 이벤트(재부팅 등)에 대한 계정 추적이 설정되지 않음',
                'recommendation': 'aaa accounting system default start-stop group tacacs+ 명령어를 설정하세요',
                'impact': '시스템 이벤트에 대한 감사 추적 기능 사용 불가',
                'level': 'Level 2'
            }
        })
    
    return vulnerabilities

def check_cis_1_2_1(line: str, line_num: int, context: ConfigContext) -> List[Dict[str, Any]]:
    """CIS-1.2.1: Set 'privilege 1' for local users (개선된 버전)"""
    vulnerabilities = []
    
    # 🔥 개선: 사용자별 상세 체크
    for user in context.parsed_users:
        privilege_level = user.get('privilege_level', 1)
        if privilege_level > 1:
            vulnerabilities.append({
                'line': user['line_number'],
                'matched_text': f"username {user['username']} privilege {privilege_level}",
                'details': {
                    'username': user['username'],
                    'current_privilege': privilege_level,
                    'vulnerability': 'excessive_privilege_level',
                    'recommendation': f'사용자 {user["username"]}의 권한을 1로 설정: username {user["username"]} privilege 1',
                    'impact': '높은 권한으로 인한 보안 위험'
                }
            })
    
    return vulnerabilities

def check_cis_1_2_4(line: str, line_num: int, context: ConfigContext) -> List[Dict[str, Any]]:
    """CIS-1.2.4: Create 'access-list' for use with 'line vty'"""
    vulnerabilities = []
    
    # VTY 라인이 있는지 확인
    has_vty_lines = len(context.vty_lines) > 0
    
    if has_vty_lines:
        # VTY용 ACL이 정의되어 있는지 확인
        vty_acls_defined = False
        for vty_line in context.vty_lines:
            if vty_line.get('access_class'):
                # 해당 ACL이 실제로 정의되어 있는지 확인
                acl_number = vty_line['access_class']
                if acl_number in context.access_lists:
                    vty_acls_defined = True
                    break
        
        if not vty_acls_defined:
            vulnerabilities.append({
                'line': 0,
                'matched_text': 'VTY access-list not properly configured',
                'details': {
                    'vulnerability': 'missing_vty_access_list',
                    'recommendation': 'Create access-list for VTY line restriction'
                }
            })
    
    return vulnerabilities


def check_cis_1_2_5(line: str, line_num: int, context: ConfigContext) -> List[Dict[str, Any]]:
    """CIS-1.2.5: Set 'access-class' for 'line vty'"""
    vulnerabilities = []
    
    for vty_line in context.vty_lines:
        if not vty_line.get('has_access_class'):
            vulnerabilities.append({
                'line': vty_line['line_number'],
                'matched_text': vty_line['line'],
                'details': {
                    'vulnerability': 'missing_access_class',
                    'recommendation': 'Apply access-class to VTY line'
                }
            })
    
    return vulnerabilities


def check_cis_1_3_1(line: str, line_num: int, context: ConfigContext) -> List[Dict[str, Any]]:
    """CIS-1.3.1: Set the 'banner-text' for 'banner exec' (개선된 버전)"""
    vulnerabilities = []
    
    # 🔥 개선: 더 정확한 banner exec 체크
    has_exec_banner = False
    
    for config_line in context.config_lines:
        if config_line.strip().startswith('banner exec '):
            has_exec_banner = True
            break
    
    if not has_exec_banner:
        vulnerabilities.append({
            'line': 0,
            'matched_text': 'banner exec 설정 누락',
            'details': {
                'vulnerability': 'missing_exec_banner',
                'description': 'EXEC 배너가 설정되지 않음',
                'recommendation': 'EXEC 배너 설정: banner exec c <적절한 경고 메시지> c',
                'impact': '사용자에게 적절한 보안 경고 제공 불가'
            }
        })
    
    return vulnerabilities


def check_cis_1_3_2(line: str, line_num: int, context: ConfigContext) -> List[Dict[str, Any]]:
    """CIS-1.3.2: Set the 'banner-text' for 'banner login' (개선된 버전)"""
    vulnerabilities = []
    
    # 🔥 개선: 더 정확한 banner login 체크
    has_login_banner = False
    
    for config_line in context.config_lines:
        if config_line.strip().startswith('banner login '):
            has_login_banner = True
            break
    
    if not has_login_banner:
        vulnerabilities.append({
            'line': 0,
            'matched_text': 'banner login 설정 누락',
            'details': {
                'vulnerability': 'missing_login_banner',
                'description': '로그인 배너가 설정되지 않음',
                'recommendation': '로그인 배너 설정: banner login c <적절한 경고 메시지> c',
                'impact': '로그인 시 법적 경고 메시지 제공 불가'
            }
        })
    
    return vulnerabilities


def check_cis_1_3_3(line: str, line_num: int, context: ConfigContext) -> List[Dict[str, Any]]:
    """CIS-1.3.3: Set the 'banner-text' for 'banner motd' (개선된 버전)"""
    vulnerabilities = []
    
    # 🔥 개선: 더 정확한 banner motd 체크
    has_motd_banner = False
    
    for config_line in context.config_lines:
        if config_line.strip().startswith('banner motd '):
            has_motd_banner = True
            break
    
    if not has_motd_banner:
        vulnerabilities.append({
            'line': 0,
            'matched_text': 'banner motd 설정 누락',
            'details': {
                'vulnerability': 'missing_motd_banner',
                'description': 'MOTD 배너가 설정되지 않음',
                'recommendation': 'MOTD 배너 설정: banner motd c <적절한 시스템 정보> c',
                'impact': '사용자에게 시스템 상태 정보 제공 불가'
            }
        })
    
    return vulnerabilities


def check_cis_1_5_1(line: str, line_num: int, context: ConfigContext) -> List[Dict[str, Any]]:
    """CIS-1.5.1: Set 'no snmp-server' to disable SNMP when unused"""
    vulnerabilities = []
    
    # SNMP 커뮤니티나 기타 SNMP 설정이 있는지 확인
    has_snmp_config = (
        len(context.snmp_communities) > 0 or
        'snmp-server enable' in context.full_config or
        'snmp-server host' in context.full_config
    )
    
    has_snmp_disabled = 'no snmp-server' in context.full_config
    
    if has_snmp_config and not has_snmp_disabled:
        vulnerabilities.append({
            'line': 0,
            'matched_text': 'SNMP services enabled',
            'details': {
                'vulnerability': 'snmp_enabled_without_security_review',
                'snmp_communities_count': len(context.snmp_communities),
                'recommendation': 'Disable SNMP if not needed: no snmp-server'
            }
        })
    
    return vulnerabilities


def check_cis_1_5_6(line: str, line_num: int, context: ConfigContext) -> List[Dict[str, Any]]:
    """CIS-1.5.6: Create an 'access-list' for use with SNMP"""
    vulnerabilities = []
    
    for community_info in context.snmp_communities:
        if not community_info.get('acl'):
            vulnerabilities.append({
                'line': community_info['line_number'],
                'matched_text': f"snmp-server community {community_info['community']}",
                'details': {
                    'community': community_info['community'],
                    'vulnerability': 'missing_snmp_acl',
                    'recommendation': 'Create and apply access-list for SNMP community'
                }
            })
    
    return vulnerabilities


def check_cis_1_5_7(line: str, line_num: int, context: ConfigContext) -> List[Dict[str, Any]]:
    """CIS-1.5.7: Set 'snmp-server host' when using SNMP"""
    vulnerabilities = []
    
    has_snmp_communities = len(context.snmp_communities) > 0
    has_snmp_host = 'snmp-server host' in context.full_config
    
    if has_snmp_communities and not has_snmp_host:
        vulnerabilities.append({
            'line': 0,
            'matched_text': 'SNMP communities configured without trap hosts',
            'details': {
                'vulnerability': 'missing_snmp_trap_hosts',
                'recommendation': 'Configure SNMP trap hosts: snmp-server host <ip> <community>'
            }
        })
    
    return vulnerabilities


# ======================= 2.1 Global Service Rules =======================

def check_cis_2_1_1_1_1(line: str, line_num: int, context: ConfigContext) -> List[Dict[str, Any]]:
    """CIS-2.1.1.1.1: Set the 'hostname' - 호스트명 설정 확인"""
    vulnerabilities = []
    
    # 호스트명 설정 확인
    hostname_lines = [line for line in context.config_lines if line.strip().startswith('hostname ')]
    
    if not hostname_lines:
        vulnerabilities.append({
            'line': 0,
            'matched_text': 'hostname 설정 누락',
            'details': {
                'vulnerability': 'hostname_not_configured',
                'description': '호스트명이 설정되지 않음',
                'recommendation': 'hostname {router_name} 명령어를 설정하세요',
                'impact': 'SSH 서비스 구성을 위한 전제 조건 미충족'
            }
        })
    else:
        # 기본 호스트명 사용 여부 확인
        for hostname_line in hostname_lines:
            if 'hostname Router' in hostname_line:
                vulnerabilities.append({
                    'line': 0,
                    'matched_text': hostname_line.strip(),
                    'details': {
                        'vulnerability': 'default_hostname_used',
                        'description': '기본 호스트명 "Router"를 사용함',
                        'recommendation': '의미있는 호스트명으로 변경하세요',
                        'impact': '장비 식별 및 관리의 어려움'
                    }
                })
    
    return vulnerabilities


def check_cis_2_1_1_1_2(line: str, line_num: int, context: ConfigContext) -> List[Dict[str, Any]]:
    """CIS-2.1.1.1.2: Set the 'ip domain name' - 도메인명 설정 확인"""
    vulnerabilities = []
    
    # IP domain name 설정 확인
    has_domain_name = 'ip domain name' in context.full_config
    
    if not has_domain_name:
        vulnerabilities.append({
            'line': 0,
            'matched_text': 'ip domain name 설정 누락',
            'details': {
                'vulnerability': 'ip_domain_name_missing',
                'description': 'IP 도메인명이 설정되지 않음',
                'recommendation': 'ip domain name {domain-name} 명령어를 설정하세요',
                'impact': 'SSH 서비스 구성을 위한 전제 조건 미충족'
            }
        })
    
    return vulnerabilities


def check_cis_2_1_1_1_3(line: str, line_num: int, context: ConfigContext) -> List[Dict[str, Any]]:
    """CIS-2.1.1.1.3: Set 'modulus' to greater than or equal to 2048 - RSA 키 확인"""
    vulnerabilities = []
    
    # RSA 키 생성 확인 (실제로는 show crypto key mypubkey rsa 명령어로 확인해야 함)
    # 설정 파일에서는 crypto key generate rsa 명령어가 저장되지 않으므로 간접적으로 확인
    has_ssh_version = 'ip ssh version' in context.full_config
    has_domain_name = 'ip domain name' in context.full_config
    hostname_configured = any('hostname ' in line and 'Router' not in line for line in context.config_lines)
    
    # SSH가 설정되어 있지만 전제 조건들이 충족되지 않은 경우
    if has_ssh_version and not (has_domain_name and hostname_configured):
        vulnerabilities.append({
            'line': 0,
            'matched_text': 'RSA 키 생성을 위한 전제 조건 미충족',
            'details': {
                'vulnerability': 'rsa_key_prerequisites_missing',
                'description': 'RSA 키 생성을 위한 hostname 및 domain name이 설정되지 않음',
                'recommendation': 'crypto key generate rsa general-keys modulus 2048 명령어를 실행하세요',
                'impact': 'SSH 서비스 사용 불가'
            }
        })
    
    return vulnerabilities


def check_cis_2_1_1_1_4(line: str, line_num: int, context: ConfigContext) -> List[Dict[str, Any]]:
    """CIS-2.1.1.1.4: Set 'seconds' for 'ip ssh timeout' - SSH 타임아웃 확인"""
    vulnerabilities = []
    
    # SSH timeout 설정 확인
    has_ssh_timeout = 'ip ssh time-out' in context.full_config
    
    if not has_ssh_timeout:
        vulnerabilities.append({
            'line': 0,
            'matched_text': 'ip ssh time-out 설정 누락',
            'details': {
                'vulnerability': 'ssh_timeout_missing',
                'description': 'SSH 타임아웃이 설정되지 않음',
                'recommendation': 'ip ssh time-out 60 명령어를 설정하세요',
                'impact': '비활성 SSH 세션이 무제한으로 유지될 수 있음'
            }
        })
    
    return vulnerabilities


def check_cis_2_1_1_1_5(line: str, line_num: int, context: ConfigContext) -> List[Dict[str, Any]]:
    """CIS-2.1.1.1.5: Set maximum value for 'ip ssh authentication-retries' - SSH 인증 재시도 확인"""
    vulnerabilities = []
    
    # SSH authentication-retries 설정 확인
    has_ssh_auth_retries = 'ip ssh authentication-retries' in context.full_config
    
    if not has_ssh_auth_retries:
        vulnerabilities.append({
            'line': 0,
            'matched_text': 'ip ssh authentication-retries 설정 누락',
            'details': {
                'vulnerability': 'ssh_authentication_retries_missing',
                'description': 'SSH 인증 재시도 횟수가 설정되지 않음',
                'recommendation': 'ip ssh authentication-retries 3 명령어를 설정하세요',
                'impact': '무제한 인증 시도로 인한 브루트 포스 공격 위험'
            }
        })
    
    return vulnerabilities


def check_cis_2_1_1_2(line: str, line_num: int, context: ConfigContext) -> List[Dict[str, Any]]:
    """CIS-2.1.1.2: Set version 2 for 'ip ssh version' - SSH 버전 확인"""
    vulnerabilities = []
    
    # SSH version 2 설정 확인
    has_ssh_version_2 = 'ip ssh version 2' in context.full_config
    
    if not has_ssh_version_2:
        vulnerabilities.append({
            'line': 0,
            'matched_text': 'ip ssh version 2 설정 누락',
            'details': {
                'vulnerability': 'ssh_version_2_missing',
                'description': 'SSH 버전 2가 설정되지 않음',
                'recommendation': 'ip ssh version 2 명령어를 설정하세요',
                'impact': '취약한 SSH 버전 1 사용 가능'
            }
        })
    
    return vulnerabilities


def check_cis_2_1_2(line: str, line_num: int, context: ConfigContext) -> List[Dict[str, Any]]:
    """CIS-2.1.2: Set 'no cdp run' - CDP 서비스 비활성화 확인"""
    vulnerabilities = []
    
    # CDP 서비스 상태 확인
    has_cdp_run = 'cdp run' in context.full_config
    has_no_cdp_run = 'no cdp run' in context.full_config
    
    # cdp run이 있고 no cdp run이 없는 경우
    if has_cdp_run and not has_no_cdp_run:
        vulnerabilities.append({
            'line': 0,
            'matched_text': 'cdp run',
            'details': {
                'vulnerability': 'cdp_enabled',
                'description': 'CDP 서비스가 활성화되어 있음',
                'recommendation': 'no cdp run 명령어를 설정하여 CDP를 비활성화하세요',
                'impact': '정보 노출 및 DoS 공격 위험'
            }
        })
    # 명시적으로 no cdp run이 없는 경우 (기본적으로 활성화됨)
    elif not has_no_cdp_run:
        vulnerabilities.append({
            'line': 0,
            'matched_text': 'CDP 서비스 비활성화 설정 누락',
            'details': {
                'vulnerability': 'cdp_not_disabled',
                'description': 'CDP 서비스가 명시적으로 비활성화되지 않음',
                'recommendation': 'no cdp run 명령어를 설정하세요',
                'impact': '정보 노출 및 DoS 공격 위험'
            }
        })
    
    return vulnerabilities


def check_cis_2_1_3(line: str, line_num: int, context: ConfigContext) -> List[Dict[str, Any]]:
    """CIS-2.1.3: Set 'no ip bootp server' - BOOTP 서버 비활성화 확인"""
    vulnerabilities = []
    
    # BOOTP 서버 상태 확인
    has_bootp_server = 'ip bootp server' in context.full_config
    has_no_bootp_server = 'no ip bootp server' in context.full_config
    
    if has_bootp_server and not has_no_bootp_server:
        vulnerabilities.append({
            'line': 0,
            'matched_text': 'ip bootp server',
            'details': {
                'vulnerability': 'bootp_server_enabled',
                'description': 'BOOTP 서버가 활성화되어 있음',
                'recommendation': 'no ip bootp server 명령어를 설정하세요',
                'impact': '불필요한 IP 주소 할당 서비스로 인한 보안 위험'
            }
        })
    
    return vulnerabilities


def check_cis_2_1_4(line: str, line_num: int, context: ConfigContext) -> List[Dict[str, Any]]:
    """CIS-2.1.4: Set 'no service dhcp' - DHCP 서비스 비활성화 확인"""
    vulnerabilities = []
    
    # DHCP 서비스 상태 확인 (기존 context.parsed_services 활용)
    dhcp_service_enabled = context.parsed_services.get('dhcp', True)  # 기본값은 활성화
    
    if dhcp_service_enabled:
        vulnerabilities.append({
            'line': 0,
            'matched_text': 'DHCP 서비스 활성화',
            'details': {
                'vulnerability': 'dhcp_service_enabled',
                'description': 'DHCP 서비스가 활성화되어 있음',
                'recommendation': 'no service dhcp 명령어를 설정하세요',
                'impact': '불필요한 DHCP 서비스로 인한 DoS 공격 위험'
            }
        })
    
    return vulnerabilities


def check_cis_2_1_5(line: str, line_num: int, context: ConfigContext) -> List[Dict[str, Any]]:
    """CIS-2.1.5: Set 'no ip identd' - identd 서버 비활성화 확인"""
    vulnerabilities = []
    
    # identd 서비스 상태 확인
    has_ip_identd = 'ip identd' in context.full_config
    has_no_ip_identd = 'no ip identd' in context.full_config
    
    # ip identd가 명시적으로 활성화되어 있거나, 비활성화되지 않은 경우
    if has_ip_identd and not has_no_ip_identd:
        vulnerabilities.append({
            'line': 0,
            'matched_text': 'ip identd',
            'details': {
                'vulnerability': 'identd_enabled',
                'description': 'identd 서버가 활성화되어 있음',
                'recommendation': 'no ip identd 명령어를 설정하세요',
                'impact': '정보 노출 위험'
            }
        })
    elif not has_no_ip_identd:
        # 기본적으로 활성화되어 있으므로 명시적 비활성화 필요
        vulnerabilities.append({
            'line': 0,
            'matched_text': 'identd 서비스 비활성화 설정 누락',
            'details': {
                'vulnerability': 'identd_not_disabled',
                'description': 'identd 서버가 명시적으로 비활성화되지 않음',
                'recommendation': 'no ip identd 명령어를 설정하세요',
                'impact': '정보 노출 위험'
            }
        })
    
    return vulnerabilities


def check_cis_2_1_6(line: str, line_num: int, context: ConfigContext) -> List[Dict[str, Any]]:
    """CIS-2.1.6: Set 'service tcp-keepalives-in' - TCP keepalives-in 확인"""
    vulnerabilities = []
    
    # TCP keepalives-in 서비스 확인
    tcp_keepalives_in_enabled = context.parsed_services.get('tcp-keepalives-in', False)
    
    if not tcp_keepalives_in_enabled:
        vulnerabilities.append({
            'line': 0,
            'matched_text': 'service tcp-keepalives-in 설정 누락',
            'details': {
                'vulnerability': 'tcp_keepalives_in_missing',
                'description': 'TCP keepalives-in 서비스가 설정되지 않음',
                'recommendation': 'service tcp-keepalives-in 명령어를 설정하세요',
                'impact': '유휴 인커밍 연결이 정리되지 않아 리소스 낭비 및 보안 위험'
            }
        })
    
    return vulnerabilities


def check_cis_2_1_7(line: str, line_num: int, context: ConfigContext) -> List[Dict[str, Any]]:
    """CIS-2.1.7: Set 'service tcp-keepalives-out' - TCP keepalives-out 확인"""
    vulnerabilities = []
    
    # TCP keepalives-out 서비스 확인
    tcp_keepalives_out_enabled = context.parsed_services.get('tcp-keepalives-out', False)
    
    if not tcp_keepalives_out_enabled:
        vulnerabilities.append({
            'line': 0,
            'matched_text': 'service tcp-keepalives-out 설정 누락',
            'details': {
                'vulnerability': 'tcp_keepalives_out_missing',
                'description': 'TCP keepalives-out 서비스가 설정되지 않음',
                'recommendation': 'service tcp-keepalives-out 명령어를 설정하세요',
                'impact': '유휴 아웃고잉 연결이 정리되지 않아 리소스 낭비 및 보안 위험'
            }
        })
    
    return vulnerabilities


def check_cis_2_1_8(line: str, line_num: int, context: ConfigContext) -> List[Dict[str, Any]]:
    """CIS-2.1.8: Set 'no service pad' - PAD 서비스 비활성화 확인"""
    vulnerabilities = []
    
    # PAD 서비스 상태 확인
    pad_service_enabled = context.parsed_services.get('pad', True)  # 기본값은 활성화
    
    if pad_service_enabled:
        vulnerabilities.append({
            'line': 0,
            'matched_text': 'PAD 서비스 활성화',
            'details': {
                'vulnerability': 'pad_service_enabled',
                'description': 'X.25 PAD 서비스가 활성화되어 있음',
                'recommendation': 'no service pad 명령어를 설정하세요',
                'impact': '불필요한 X.25 PAD 서비스로 인한 보안 위험'
            }
        })
    
    return vulnerabilities

def check_cis_2_2_2(line: str, line_num: int, context: ConfigContext) -> List[Dict[str, Any]]:
    """CIS-2.2.2: Set 'buffer size' for 'logging buffered' (명령어 축약 고려)"""
    vulnerabilities = []
    
    # 🔥 개선: Cisco 명령어 축약 형태 모두 고려
    logging_buffered_patterns = [
        r'^logging\s+buffered\s+(\d+)',      # logging buffered 12345
        r'^logging\s+buffer\s+(\d+)',        # logging buffer 12345  
        r'^log\s+buffered\s+(\d+)',          # log buffered 12345
        r'^log\s+buffer\s+(\d+)',            # log buffer 12345
        r'^logging\s+buffered$',             # logging buffered (기본값)
        r'^logging\s+buffer$',               # logging buffer (기본값)
        r'^log\s+buffered$',                 # log buffered (기본값)
        r'^log\s+buffer$'                    # log buffer (기본값)
    ]
    
    has_logging_buffered = False
    buffered_size = None
    matched_command = None
    
    for config_line in context.config_lines:
        line_clean = config_line.strip()
        
        for pattern in logging_buffered_patterns:
            match = re.search(pattern, line_clean, re.IGNORECASE)
            if match:
                has_logging_buffered = True
                matched_command = line_clean
                
                # 크기가 지정된 경우 추출
                if match.groups():
                    try:
                        buffered_size = int(match.group(1))
                    except (ValueError, IndexError):
                        pass
                break
        
        if has_logging_buffered:
            break
    
    if not has_logging_buffered:
        vulnerabilities.append({
            'line': 0,
            'matched_text': 'logging buffered 설정 누락',
            'details': {
                'vulnerability': 'missing_logging_buffered',
                'description': '로컬 버퍼 로깅이 설정되지 않음',
                'recommendation': '버퍼 로깅 설정: logging buffered 64000',
                'impact': '로컬 로그 저장 불가',
                'checked_patterns': ['logging buffered', 'logging buffer', 'log buffered', 'log buffer']
            }
        })
    elif buffered_size is not None and buffered_size < 4096:
        vulnerabilities.append({
            'line': 0,
            'matched_text': matched_command,
            'details': {
                'vulnerability': 'insufficient_logging_buffer_size',
                'description': f'로깅 버퍼 크기가 너무 작음 ({buffered_size} bytes)',
                'current_size': buffered_size,
                'current_command': matched_command,
                'recommendation': '적절한 크기로 버퍼 설정: logging buffered 64000',
                'impact': '로그 손실 위험'
            }
        })
    
    return vulnerabilities


def check_cis_2_2_4(line: str, line_num: int, context: ConfigContext) -> List[Dict[str, Any]]:
    """CIS-2.2.4: Set IP address for 'logging host' (명령어 축약 고려)"""
    vulnerabilities = []
    
    # 🔥 개선: logging host 명령어 축약 형태들
    logging_host_patterns = [
        r'logging\s+host\s+\d+\.\d+\.\d+\.\d+',    # logging host 192.168.1.1
        r'logging\s+\d+\.\d+\.\d+\.\d+',           # logging 192.168.1.1
        r'log\s+host\s+\d+\.\d+\.\d+\.\d+',        # log host 192.168.1.1  
        r'log\s+\d+\.\d+\.\d+\.\d+'                # log 192.168.1.1
    ]
    
    has_logging_host = False
    
    for config_line in context.config_lines:
        line_clean = config_line.strip()
        
        for pattern in logging_host_patterns:
            if re.search(pattern, line_clean, re.IGNORECASE):
                has_logging_host = True
                break
        
        if has_logging_host:
            break
    
    if not has_logging_host:
        vulnerabilities.append({
            'line': 0,
            'matched_text': 'logging host 설정 누락',
            'details': {
                'vulnerability': 'missing_syslog_server',
                'description': 'Syslog 서버가 설정되지 않음',
                'recommendation': 'Syslog 서버 설정: logging host <ip_address>',
                'impact': '중앙집중식 로그 관리 불가',
                'checked_patterns': ['logging host', 'logging <ip>', 'log host', 'log <ip>']
            }
        })
    
    return vulnerabilities


def check_cis_2_2_7(line: str, line_num: int, context: ConfigContext) -> List[Dict[str, Any]]:
    """CIS-2.2.7: Set 'logging source interface'"""
    vulnerabilities = []
    
    has_logging_source = 'logging source-interface' in context.full_config
    if not has_logging_source:
        vulnerabilities.append({
            'line': 0,
            'matched_text': 'logging source-interface not configured',
            'details': {
                'vulnerability': 'missing_logging_source_interface',
                'recommendation': 'Configure logging source: logging source-interface loopback <number>'
            }
        })
    
    return vulnerabilities


def check_cis_2_3_1_2(line: str, line_num: int, context: ConfigContext) -> List[Dict[str, Any]]:
    """CIS-2.3.1.2: Set 'ntp authentication-key'"""
    vulnerabilities = []
    
    has_ntp_auth_key = 'ntp authentication-key' in context.full_config
    has_ntp_authenticate = 'ntp authenticate' in context.full_config
    
    if has_ntp_authenticate and not has_ntp_auth_key:
        vulnerabilities.append({
            'line': 0,
            'matched_text': 'ntp authenticate enabled without authentication keys',
            'details': {
                'vulnerability': 'missing_ntp_authentication_keys',
                'recommendation': 'Configure NTP authentication keys: ntp authentication-key <id> md5 <key>'
            }
        })
    
    return vulnerabilities


def check_cis_2_3_1_3(line: str, line_num: int, context: ConfigContext) -> List[Dict[str, Any]]:
    """CIS-2.3.1.3: Set the 'ntp trusted-key'"""
    vulnerabilities = []
    
    has_ntp_trusted_key = 'ntp trusted-key' in context.full_config
    has_ntp_authenticate = 'ntp authenticate' in context.full_config
    
    if has_ntp_authenticate and not has_ntp_trusted_key:
        vulnerabilities.append({
            'line': 0,
            'matched_text': 'ntp authenticate enabled without trusted keys',
            'details': {
                'vulnerability': 'missing_ntp_trusted_keys',
                'recommendation': 'Configure NTP trusted keys: ntp trusted-key <key_id>'
            }
        })
    
    return vulnerabilities


def check_cis_2_3_2(line: str, line_num: int, context: ConfigContext) -> List[Dict[str, Any]]:
    """CIS-2.3.2: Set 'ip address' for 'ntp server' (명령어 축약 고려)"""
    vulnerabilities = []
    
    # 🔥 개선: NTP 관련 명령어 축약 형태들
    ntp_server_patterns = [
        r'^ntp\s+server\s+\d+\.\d+\.\d+\.\d+',     # ntp server 192.168.1.1
        r'^ntp\s+srv\s+\d+\.\d+\.\d+\.\d+',        # ntp srv 192.168.1.1 (극도 축약)
        r'^ntp\s+\d+\.\d+\.\d+\.\d+'               # ntp 192.168.1.1 (일부 버전)
    ]
    
    ntp_servers = []
    
    for i, config_line in enumerate(context.config_lines):
        line_clean = config_line.strip()
        
        for pattern in ntp_server_patterns:
            if re.search(pattern, line_clean, re.IGNORECASE):
                ntp_servers.append({
                    'line_number': i + 1,
                    'config': line_clean
                })
                break
    
    if not ntp_servers:
        vulnerabilities.append({
            'line': 0,
            'matched_text': 'NTP 서버 설정 누락',
            'details': {
                'vulnerability': 'missing_ntp_server',
                'description': 'NTP 서버가 설정되지 않음',
                'recommendation': 'NTP 서버 설정: ntp server <신뢰할 수 있는 NTP 서버 IP>',
                'impact': '시간 동기화 불가로 인한 로그 분석 및 보안 문제',
                'checked_patterns': ['ntp server', 'ntp srv', 'ntp <ip>']
            }
        })
    
    return vulnerabilities


def _check_cisco_command_variations(config_lines: List[str], base_command: str, 
                                   variations: List[str] = None) -> List[Dict[str, Any]]:
    """
    🔥 새로운 헬퍼 함수: Cisco 명령어 축약 형태들을 체크
    
    Args:
        config_lines: 설정 라인들
        base_command: 기본 명령어 (예: 'logging buffered')
        variations: 추가 확인할 축약 형태들
        
    Returns:
        매치된 명령어들의 정보
    """
    if variations is None:
        # 일반적인 Cisco 축약 패턴들
        command_parts = base_command.split()
        variations = []
        
        # 각 단어의 축약 형태 생성
        for i, part in enumerate(command_parts):
            if len(part) >= 3:
                # 최소 3글자 이상인 경우 축약 가능
                for length in range(3, len(part)):
                    short_form = part[:length]
                    new_command = command_parts.copy()
                    new_command[i] = short_form
                    variations.append(' '.join(new_command))
    
    matches = []
    all_patterns = [base_command] + variations
    
    for i, line in enumerate(config_lines):
        line_clean = line.strip()
        
        for pattern in all_patterns:
            if line_clean.startswith(pattern + ' ') or line_clean == pattern:
                matches.append({
                    'line_number': i + 1,
                    'matched_command': line_clean,
                    'pattern_used': pattern
                })
                break
    
    return matches


def check_cis_2_4_1(line: str, line_num: int, context: ConfigContext) -> List[Dict[str, Any]]:
    """CIS-2.4.1: Create a single 'interface loopback' (개선된 버전)"""
    vulnerabilities = []
    
    # 🔥 개선: 루프백 인터페이스 정확한 체크
    loopback_interfaces = []
    
    for interface_name, interface_config in context.parsed_interfaces.items():
        if interface_config.get('is_loopback'):
            loopback_interfaces.append(interface_name)
    
    if len(loopback_interfaces) == 0:
        vulnerabilities.append({
            'line': 0,
            'matched_text': '루프백 인터페이스 설정 누락',
            'details': {
                'vulnerability': 'missing_loopback_interface',
                'description': '루프백 인터페이스가 설정되지 않음',
                'recommendation': '루프백 인터페이스 생성: interface loopback 0',
                'impact': '안정적인 관리 인터페이스 부재'
            }
        })
    elif len(loopback_interfaces) > 1:
        vulnerabilities.append({
            'line': 0,
            'matched_text': f'다중 루프백 인터페이스: {", ".join(loopback_interfaces)}',
            'details': {
                'vulnerability': 'multiple_loopback_interfaces',
                'loopback_count': len(loopback_interfaces),
                'loopback_list': loopback_interfaces,
                'recommendation': '하나의 루프백 인터페이스만 사용하세요',
                'impact': '관리 복잡성 증가'
            }
        })
    
    return vulnerabilities


def _parse_routing_section(context: ConfigContext, protocol: str) -> Dict[str, Any]:
    """🔥 개선된 라우팅 프로토콜 섹션 파싱"""
    routing_info = {
        'configured': False,
        'config_lines': [],
        'start_line': 0,
        'authentication_configured': False,
        'auth_details': []
    }
    
    in_routing_section = False
    current_section_start = 0
    
    for i, line in enumerate(context.config_lines):
        line_clean = line.strip()
        
        # 라우팅 프로토콜 섹션 시작
        if line_clean.startswith(f'router {protocol}'):
            in_routing_section = True
            current_section_start = i + 1
            routing_info['configured'] = True
            routing_info['start_line'] = current_section_start
            routing_info['config_lines'].append(line_clean)
            continue
        
        # 라우팅 섹션 내부
        if in_routing_section:
            # 다른 섹션 시작하면 라우팅 섹션 종료
            if (not line.startswith(' ') and 
                line_clean and 
                not line_clean.startswith('!') and
                not line_clean.startswith(f'router {protocol}')):
                in_routing_section = False
                continue
            
            # 라우팅 섹션 내 설정 수집
            if line.startswith(' ') and line_clean:
                routing_info['config_lines'].append(line_clean)
                
                # 인증 관련 키워드 체크
                auth_keywords = [
                    'authentication', 'key-chain', 'message-digest', 
                    'password', 'neighbor.*password'
                ]
                
                for keyword in auth_keywords:
                    if re.search(keyword, line_clean, re.IGNORECASE):
                        routing_info['authentication_configured'] = True
                        routing_info['auth_details'].append({
                            'line': i + 1,
                            'config': line_clean,
                            'auth_type': keyword
                        })
                        break
    
    return routing_info


def check_cis_2_4_2(line: str, line_num: int, context: ConfigContext) -> List[Dict[str, Any]]:
    """CIS-2.4.2: Set AAA 'source-interface'"""
    vulnerabilities = []
    
    has_tacacs_source = 'ip tacacs source-interface' in context.full_config
    has_radius_source = 'ip radius source-interface' in context.full_config
    has_aaa_config = 'aaa new-model' in context.full_config
    
    if has_aaa_config and not (has_tacacs_source or has_radius_source):
        vulnerabilities.append({
            'line': 0,
            'matched_text': 'AAA configured without source-interface',
            'details': {
                'vulnerability': 'missing_aaa_source_interface',
                'recommendation': 'Configure AAA source interface: ip tacacs source-interface loopback <number>'
            }
        })
    
    return vulnerabilities


def check_cis_3_1_2(line: str, line_num: int, context: ConfigContext) -> List[Dict[str, Any]]:
    """CIS-3.1.2: Set 'no ip proxy-arp'"""
    vulnerabilities = []
    
    for interface_name, interface_config in context.parsed_interfaces.items():
        # 물리적 인터페이스에 대해서만 검사
        if interface_config.get('port_type') in ['FastEthernet', 'GigabitEthernet', 'TenGigabitEthernet']:
            # proxy-arp 설정 확인 (기본적으로 활성화됨)
            has_no_proxy_arp = any('no ip proxy-arp' in line for line in interface_config.get('config_lines', []))
            
            if not has_no_proxy_arp:
                vulnerabilities.append({
                    'line': interface_config['line_number'],
                    'matched_text': f"interface {interface_name}",
                    'details': {
                        'interface_name': interface_name,
                        'vulnerability': 'proxy_arp_enabled',
                        'recommendation': 'Disable proxy ARP: no ip proxy-arp'
                    }
                })
    
    return vulnerabilities


def check_cis_3_1_4(line: str, line_num: int, context: ConfigContext) -> List[Dict[str, Any]]:
    """CIS-3.1.4: Set 'ip verify unicast source reachable-via'"""
    vulnerabilities = []
    
    for interface_name, interface_config in context.parsed_interfaces.items():
        # 외부 인터페이스 판별 (실제 환경에서는 더 정교한 로직 필요)
        is_external = (
            not interface_config.get('is_loopback') and
            not interface_config.get('is_management') and
            interface_config.get('has_ip_address')
        )
        
        if is_external:
            has_urpf = any('ip verify unicast source reachable-via' in line 
                          for line in interface_config.get('config_lines', []))
            
            if not has_urpf:
                vulnerabilities.append({
                    'line': interface_config['line_number'],
                    'matched_text': f"interface {interface_name}",
                    'details': {
                        'interface_name': interface_name,
                        'vulnerability': 'missing_urpf',
                        'recommendation': 'Enable uRPF: ip verify unicast source reachable-via rx'
                    }
                })
    
    return vulnerabilities


def check_cis_3_2_1(line: str, line_num: int, context: ConfigContext) -> List[Dict[str, Any]]:
    """CIS-3.2.1: Set 'ip access-list extended' to Forbid Private Source Addresses"""
    vulnerabilities = []
    
    # RFC 1918 및 기타 예약 주소 차단용 ACL 확인
    private_ranges = ['10.0.0.0', '172.16.0.0', '192.168.0.0', '127.0.0.0', '169.254.0.0']
    
    has_antispoofing_acl = False
    for acl_name, acl_lines in context.access_lists.items():
        for acl_line in acl_lines:
            if any(private_range in acl_line and 'deny' in acl_line 
                  for private_range in private_ranges):
                has_antispoofing_acl = True
                break
        if has_antispoofing_acl:
            break
    
    if not has_antispoofing_acl:
        vulnerabilities.append({
            'line': 0,
            'matched_text': 'anti-spoofing ACL not configured',
            'details': {
                'vulnerability': 'missing_antispoofing_acl',
                'recommendation': 'Create extended ACL to deny private source addresses from external networks'
            }
        })
    
    return vulnerabilities


def check_cis_3_2_2(line: str, line_num: int, context: ConfigContext) -> List[Dict[str, Any]]:
    """CIS-3.2.2: Set inbound 'ip access-group' on the External Interface"""
    vulnerabilities = []
    
    for interface_name, interface_config in context.parsed_interfaces.items():
        # 외부 인터페이스 판별
        is_external = (
            not interface_config.get('is_loopback') and
            not interface_config.get('is_management') and
            interface_config.get('has_ip_address') and
            interface_config.get('port_type') in ['FastEthernet', 'GigabitEthernet', 'TenGigabitEthernet', 'Serial']
        )
        
        if is_external:
            has_inbound_acl = any('ip access-group' in line and 'in' in line 
                                 for line in interface_config.get('config_lines', []))
            
            if not has_inbound_acl:
                vulnerabilities.append({
                    'line': interface_config['line_number'],
                    'matched_text': f"interface {interface_name}",
                    'details': {
                        'interface_name': interface_name,
                        'vulnerability': 'missing_inbound_acl',
                        'recommendation': 'Apply inbound access-group: ip access-group <acl> in'
                    }
                })
    
    return vulnerabilities


# ==================== 라우팅 프로토콜 인증 체크 함수들 ====================

def check_cis_3_3_1_1(line: str, line_num: int, context: ConfigContext) -> List[Dict[str, Any]]:
    """CIS-3.3.1.1: Set 'key chain' for EIGRP (개선된 버전)"""
    vulnerabilities = []
    
    # 🔥 개선: EIGRP와 key chain 연관성 체크
    eigrp_info = _parse_routing_section(context, 'eigrp')
    
    if eigrp_info['configured']:
        # EIGRP가 설정되어 있으면 key chain 확인
        has_key_chain = 'key chain' in context.full_config
        
        if not has_key_chain:
            vulnerabilities.append({
                'line': eigrp_info['start_line'],
                'matched_text': 'EIGRP configured without key chain',
                'details': {
                    'vulnerability': 'missing_eigrp_key_chain',
                    'description': 'EIGRP가 설정되어 있으나 key chain이 없음',
                    'recommendation': 'EIGRP 인증을 위한 key chain 설정',
                    'impact': 'EIGRP 라우팅 프로토콜 인증 부재'
                }
            })
    
    return vulnerabilities


def check_cis_3_3_1_2(line: str, line_num: int, context: ConfigContext) -> List[Dict[str, Any]]:
    """CIS-3.3.1.2: Set 'key' for EIGRP key chain"""
    vulnerabilities = []
    
    has_key_chain = 'key chain' in context.full_config
    has_key_number = 'key ' in context.full_config and any(line.strip().startswith('key ') 
                     for line in context.config_lines)
    
    if has_key_chain and not has_key_number:
        vulnerabilities.append({
            'line': 0,
            'matched_text': 'key chain configured without key numbers',
            'details': {
                'vulnerability': 'missing_key_numbers',
                'recommendation': 'Configure key numbers in key chain'
            }
        })
    
    return vulnerabilities


def check_cis_3_3_1_3(line: str, line_num: int, context: ConfigContext) -> List[Dict[str, Any]]:
    """CIS-3.3.1.3: Set 'key-string' for EIGRP"""
    vulnerabilities = []
    
    has_key_chain = 'key chain' in context.full_config
    has_key_string = 'key-string' in context.full_config
    
    if has_key_chain and not has_key_string:
        vulnerabilities.append({
            'line': 0,
            'matched_text': 'key chain configured without key-string',
            'details': {
                'vulnerability': 'missing_key_strings',
                'recommendation': 'Configure key-string for keys in key chain'
            }
        })
    
    return vulnerabilities


def check_cis_3_3_1_4(line: str, line_num: int, context: ConfigContext) -> List[Dict[str, Any]]:
    """CIS-3.3.1.4: Set 'address-family ipv4 autonomous-system' for EIGRP"""
    vulnerabilities = []
    
    has_eigrp = 'router eigrp' in context.full_config
    has_address_family = 'address-family ipv4 autonomous-system' in context.full_config
    
    if has_eigrp and not has_address_family:
        vulnerabilities.append({
            'line': 0,
            'matched_text': 'EIGRP configured without address-family',
            'details': {
                'vulnerability': 'missing_eigrp_address_family',
                'recommendation': 'Configure EIGRP address-family: address-family ipv4 autonomous-system <as>'
            }
        })
    
    return vulnerabilities


def check_cis_3_3_1_5(line: str, line_num: int, context: ConfigContext) -> List[Dict[str, Any]]:
    """CIS-3.3.1.5: Set 'af-interface default' for EIGRP"""
    vulnerabilities = []
    
    has_address_family = 'address-family ipv4 autonomous-system' in context.full_config
    has_af_interface = 'af-interface default' in context.full_config
    
    if has_address_family and not has_af_interface:
        vulnerabilities.append({
            'line': 0,
            'matched_text': 'EIGRP address-family without af-interface default',
            'details': {
                'vulnerability': 'missing_af_interface_default',
                'recommendation': 'Configure af-interface default in address-family'
            }
        })
    
    return vulnerabilities


def check_cis_3_3_1_6(line: str, line_num: int, context: ConfigContext) -> List[Dict[str, Any]]:
    """CIS-3.3.1.6: Set 'authentication key-chain' for EIGRP"""
    vulnerabilities = []
    
    has_af_interface = 'af-interface default' in context.full_config
    has_auth_keychain = 'authentication key-chain' in context.full_config
    
    if has_af_interface and not has_auth_keychain:
        vulnerabilities.append({
            'line': 0,
            'matched_text': 'EIGRP af-interface without authentication key-chain',
            'details': {
                'vulnerability': 'missing_eigrp_auth_keychain',
                'recommendation': 'Configure authentication key-chain in af-interface'
            }
        })
    
    return vulnerabilities


def check_cis_3_3_1_7(line: str, line_num: int, context: ConfigContext) -> List[Dict[str, Any]]:
    """CIS-3.3.1.7: Set 'authentication mode md5' for EIGRP"""
    vulnerabilities = []
    
    has_af_interface = 'af-interface default' in context.full_config
    has_auth_mode = 'authentication mode md5' in context.full_config
    
    if has_af_interface and not has_auth_mode:
        vulnerabilities.append({
            'line': 0,
            'matched_text': 'EIGRP af-interface without authentication mode md5',
            'details': {
                'vulnerability': 'missing_eigrp_auth_mode',
                'recommendation': 'Configure authentication mode md5 in af-interface'
            }
        })
    
    return vulnerabilities


def check_cis_3_3_1_8(line: str, line_num: int, context: ConfigContext) -> List[Dict[str, Any]]:
    """CIS-3.3.1.8: Set 'ip authentication key-chain eigrp'"""
    vulnerabilities = []
    
    has_eigrp = 'router eigrp' in context.full_config
    
    if has_eigrp:
        for interface_name, interface_config in context.parsed_interfaces.items():
            has_eigrp_auth = any('ip authentication key-chain eigrp' in line 
                               for line in interface_config.get('config_lines', []))
            
            # EIGRP가 활성화된 인터페이스에 인증이 없는 경우
            if not has_eigrp_auth and interface_config.get('has_ip_address'):
                vulnerabilities.append({
                    'line': interface_config['line_number'],
                    'matched_text': f"interface {interface_name}",
                    'details': {
                        'interface_name': interface_name,
                        'vulnerability': 'missing_eigrp_interface_auth',
                        'recommendation': 'Configure ip authentication key-chain eigrp <as> <chain>'
                    }
                })
    
    return vulnerabilities


def check_cis_3_3_1_9(line: str, line_num: int, context: ConfigContext) -> List[Dict[str, Any]]:
    """CIS-3.3.1.9: Set 'ip authentication mode eigrp'"""
    vulnerabilities = []
    
    has_eigrp = 'router eigrp' in context.full_config
    
    if has_eigrp:
        for interface_name, interface_config in context.parsed_interfaces.items():
            has_eigrp_auth_mode = any('ip authentication mode eigrp' in line and 'md5' in line
                                    for line in interface_config.get('config_lines', []))
            
            if not has_eigrp_auth_mode and interface_config.get('has_ip_address'):
                vulnerabilities.append({
                    'line': interface_config['line_number'],
                    'matched_text': f"interface {interface_name}",
                    'details': {
                        'interface_name': interface_name,
                        'vulnerability': 'missing_eigrp_interface_auth_mode',
                        'recommendation': 'Configure ip authentication mode eigrp <as> md5'
                    }
                })
    
    return vulnerabilities


def check_cis_3_3_2_1(line: str, line_num: int, context: ConfigContext) -> List[Dict[str, Any]]:
    """CIS-3.3.2.1: Set 'authentication message-digest' for OSPF area (개선된 버전)"""
    vulnerabilities = []
    
    # 🔥 개선: OSPF 섹션 정확한 파싱
    ospf_info = _parse_routing_section(context, 'ospf')
    
    if ospf_info['configured']:
        # OSPF가 설정되어 있으면 area authentication 확인
        has_area_auth = any('area' in line and 'authentication message-digest' in line 
                           for line in ospf_info['config_lines'])
        
        if not has_area_auth:
            vulnerabilities.append({
                'line': ospf_info['start_line'],
                'matched_text': 'OSPF configured without area authentication',
                'details': {
                    'vulnerability': 'missing_ospf_area_authentication',
                    'description': 'OSPF가 설정되어 있으나 area 인증이 없음',
                    'recommendation': 'OSPF area authentication 설정: area <area> authentication message-digest',
                    'impact': 'OSPF 라우팅 프로토콜 인증 부재'
                }
            })
    
    return vulnerabilities


def check_cis_3_3_2_2(line: str, line_num: int, context: ConfigContext) -> List[Dict[str, Any]]:
    """CIS-3.3.2.2: Set 'ip ospf message-digest-key md5'"""
    vulnerabilities = []
    
    has_ospf = 'router ospf' in context.full_config
    
    if has_ospf:
        for interface_name, interface_config in context.parsed_interfaces.items():
            has_ospf_md5 = any('ip ospf message-digest-key' in line and 'md5' in line
                             for line in interface_config.get('config_lines', []))
            
            if not has_ospf_md5 and interface_config.get('has_ip_address'):
                vulnerabilities.append({
                    'line': interface_config['line_number'],
                    'matched_text': f"interface {interface_name}",
                    'details': {
                        'interface_name': interface_name,
                        'vulnerability': 'missing_ospf_interface_md5',
                        'recommendation': 'Configure ip ospf message-digest-key <id> md5 <key>'
                    }
                })
    
    return vulnerabilities


def check_cis_3_3_3_1(line: str, line_num: int, context: ConfigContext) -> List[Dict[str, Any]]:
    """CIS-3.3.3.1: Set 'key chain' for RIPv2"""
    vulnerabilities = []
    
    has_rip = 'router rip' in context.full_config and 'version 2' in context.full_config
    has_key_chain = 'key chain' in context.full_config
    
    if has_rip and not has_key_chain:
        vulnerabilities.append({
            'line': 0,
            'matched_text': 'RIPv2 configured without key chain',
            'details': {
                'vulnerability': 'missing_ripv2_key_chain',
                'recommendation': 'Configure key chain for RIPv2 authentication'
            }
        })
    
    return vulnerabilities


def check_cis_3_3_3_2(line: str, line_num: int, context: ConfigContext) -> List[Dict[str, Any]]:
    """CIS-3.3.3.2: Set 'key' for RIPv2 key chain"""
    vulnerabilities = []
    
    has_rip = 'router rip' in context.full_config and 'version 2' in context.full_config
    has_key_chain = 'key chain' in context.full_config
    has_key_number = 'key ' in context.full_config and any(line.strip().startswith('key ') 
                     for line in context.config_lines)
    
    if has_rip and has_key_chain and not has_key_number:
        vulnerabilities.append({
            'line': 0,
            'matched_text': 'RIPv2 key chain without key numbers',
            'details': {
                'vulnerability': 'missing_ripv2_key_numbers',
                'recommendation': 'Configure key numbers in RIPv2 key chain'
            }
        })
    
    return vulnerabilities


def check_cis_3_3_3_3(line: str, line_num: int, context: ConfigContext) -> List[Dict[str, Any]]:
    """CIS-3.3.3.3: Set 'key-string' for RIPv2"""
    vulnerabilities = []
    
    has_rip = 'router rip' in context.full_config and 'version 2' in context.full_config
    has_key_chain = 'key chain' in context.full_config
    has_key_string = 'key-string' in context.full_config
    
    if has_rip and has_key_chain and not has_key_string:
        vulnerabilities.append({
            'line': 0,
            'matched_text': 'RIPv2 key chain without key-string',
            'details': {
                'vulnerability': 'missing_ripv2_key_strings',
                'recommendation': 'Configure key-string for RIPv2 keys'
            }
        })
    
    return vulnerabilities


def check_cis_3_3_3_4(line: str, line_num: int, context: ConfigContext) -> List[Dict[str, Any]]:
    """CIS-3.3.3.4: Set 'ip rip authentication key-chain'"""
    vulnerabilities = []
    
    has_rip = 'router rip' in context.full_config and 'version 2' in context.full_config
    
    if has_rip:
        for interface_name, interface_config in context.parsed_interfaces.items():
            has_rip_auth = any('ip rip authentication key-chain' in line 
                             for line in interface_config.get('config_lines', []))
            
            if not has_rip_auth and interface_config.get('has_ip_address'):
                vulnerabilities.append({
                    'line': interface_config['line_number'],
                    'matched_text': f"interface {interface_name}",
                    'details': {
                        'interface_name': interface_name,
                        'vulnerability': 'missing_rip_interface_auth',
                        'recommendation': 'Configure ip rip authentication key-chain <chain>'
                    }
                })
    
    return vulnerabilities


def check_cis_3_3_3_5(line: str, line_num: int, context: ConfigContext) -> List[Dict[str, Any]]:
    """CIS-3.3.3.5: Set 'ip rip authentication mode' to 'md5'"""
    vulnerabilities = []
    
    has_rip = 'router rip' in context.full_config and 'version 2' in context.full_config
    
    if has_rip:
        for interface_name, interface_config in context.parsed_interfaces.items():
            has_rip_auth_mode = any('ip rip authentication mode md5' in line 
                                  for line in interface_config.get('config_lines', []))
            
            if not has_rip_auth_mode and interface_config.get('has_ip_address'):
                vulnerabilities.append({
                    'line': interface_config['line_number'],
                    'matched_text': f"interface {interface_name}",
                    'details': {
                        'interface_name': interface_name,
                        'vulnerability': 'missing_rip_interface_auth_mode',
                        'recommendation': 'Configure ip rip authentication mode md5'
                    }
                })
    
    return vulnerabilities


def check_cis_3_3_4_1(line: str, line_num: int, context: ConfigContext) -> List[Dict[str, Any]]:
    """CIS-3.3.4.1: Set 'neighbor password' for BGP (개선된 버전)"""
    vulnerabilities = []
    
    # 🔥 개선: BGP 섹션 정확한 파싱
    bgp_info = _parse_routing_section(context, 'bgp')
    
    if bgp_info['configured']:
        # BGP가 설정되어 있으면 neighbor password 확인
        has_neighbor_password = any('neighbor' in line and 'password' in line 
                                  for line in bgp_info['config_lines'])
        
        if not has_neighbor_password:
            vulnerabilities.append({
                'line': bgp_info['start_line'],
                'matched_text': 'BGP configured without neighbor passwords',
                'details': {
                    'vulnerability': 'missing_bgp_neighbor_passwords',
                    'description': 'BGP가 설정되어 있으나 neighbor 인증이 없음',
                    'recommendation': 'BGP neighbor 인증 설정: neighbor <ip> password <password>',
                    'impact': 'BGP 라우팅 프로토콜 인증 부재'
                }
            })
    
    return vulnerabilities