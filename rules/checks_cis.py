# -*- coding: utf-8 -*-
"""
rules/checks_cis.py
CIS Cisco IOS 12 Benchmark v4.0.0 네트워크 장비 보안 점검 룰의 논리적 검증 함수들

각 CIS 룰에 대한 logical_check_function들을 정의
"""

from typing import List, Dict, Any
from .kisa_rules import ConfigContext


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