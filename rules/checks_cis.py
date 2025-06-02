# -*- coding: utf-8 -*-
"""
rules/checks_cis.py
CIS Cisco IOS 12 Benchmark v4.0.0 네트워크 장비 보안 점검 룰의 논리적 검증 함수들

각 CIS 룰에 대한 logical_check_function들을 정의
"""

from typing import List, Dict, Any
from .kisa_rules import ConfigContext


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