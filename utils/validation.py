# -*- coding: utf-8 -*-
"""
utils/validation.py
요청 데이터 검증 유틸리티

API 요청 데이터의 유효성을 검증하는 함수들
"""

import re
from typing import List, Dict, Any
from dataclasses import dataclass

from models.analysis_request import AnalysisRequest
from rules.security_rules import get_all_rules


@dataclass
class ValidationResult:
    """검증 결과"""
    is_valid: bool
    errors: List[str]
    warnings: List[str] = None
    
    def __post_init__(self):
        if self.warnings is None:
            self.warnings = []


def validate_request(request: AnalysisRequest) -> ValidationResult:
    """
    분석 요청 데이터 검증
    
    Args:
        request: 분석 요청 객체
        
    Returns:
        ValidationResult: 검증 결과
    """
    errors = []
    warnings = []
    
    # 기본 필드 검증
    basic_errors = request.validate()
    errors.extend(basic_errors)
    
    # 설정 텍스트 내용 검증
    config_errors, config_warnings = validate_config_content(
        request.config_text, 
        request.device_type
    )
    errors.extend(config_errors)
    warnings.extend(config_warnings)
    
    # 룰 ID 검증
    rule_errors = validate_rule_ids(request.options.specific_rule_ids)
    errors.extend(rule_errors)
    
    # 장비별 특수 검증
    device_errors, device_warnings = validate_device_specific(
        request.config_text, 
        request.device_type
    )
    errors.extend(device_errors)
    warnings.extend(device_warnings)
    
    return ValidationResult(
        is_valid=len(errors) == 0,
        errors=errors,
        warnings=warnings
    )


def validate_config_content(config_text: str, device_type: str) -> tuple[List[str], List[str]]:
    """
    설정 파일 내용 검증
    
    Args:
        config_text: 설정 파일 텍스트
        device_type: 장비 타입
        
    Returns:
        Tuple[List[str], List[str]]: (에러 목록, 경고 목록)
    """
    errors = []
    warnings = []
    
    lines = config_text.splitlines()
    
    # 최소 라인 수 검증
    if len(lines) < 5:
        warnings.append("설정 파일이 너무 짧습니다. 완전한 설정인지 확인하세요.")
    
    # 최대 라인 수 검증
    if len(lines) > 10000:
        warnings.append("설정 파일이 매우 큽니다. 분석에 시간이 오래 걸릴 수 있습니다.")
    
    # 빈 라인만 있는지 검증
    non_empty_lines = [line for line in lines if line.strip()]
    if len(non_empty_lines) == 0:
        errors.append("유효한 설정 라인이 없습니다.")
    
    # 장비별 기본 구조 검증
    if device_type == "Cisco":
        cisco_errors, cisco_warnings = validate_cisco_structure(lines)
        errors.extend(cisco_errors)
        warnings.extend(cisco_warnings)
    elif device_type == "Juniper":
        juniper_errors, juniper_warnings = validate_juniper_structure(lines)
        errors.extend(juniper_errors)
        warnings.extend(juniper_warnings)
    
    return errors, warnings


def validate_cisco_structure(lines: List[str]) -> tuple[List[str], List[str]]:
    """Cisco 설정 구조 검증"""
    errors = []
    warnings = []
    
    has_hostname = False
    has_version = False
    has_interface = False
    
    for line in lines:
        line = line.strip()
        if line.startswith('hostname '):
            has_hostname = True
        elif line.startswith('version '):
            has_version = True
        elif line.startswith('interface '):
            has_interface = True
    
    if not has_hostname:
        warnings.append("hostname 설정을 찾을 수 없습니다.")
    
    if not has_version:
        warnings.append("version 정보를 찾을 수 없습니다.")
    
    # 잘못된 문자 검증
    for line_num, line in enumerate(lines, 1):
        if re.search(r'[^\x00-\x7F]', line):
            warnings.append(f"라인 {line_num}: 비ASCII 문자가 포함되어 있습니다.")
    
    return errors, warnings


def validate_juniper_structure(lines: List[str]) -> tuple[List[str], List[str]]:
    """Juniper 설정 구조 검증"""
    errors = []
    warnings = []
    
    has_system = False
    has_interfaces = False
    
    for line in lines:
        line = line.strip()
        if line.startswith('system '):
            has_system = True
        elif line.startswith('interfaces '):
            has_interfaces = True
    
    if not has_system:
        warnings.append("system 설정을 찾을 수 없습니다.")
    
    return errors, warnings


def validate_rule_ids(rule_ids: List[str]) -> List[str]:
    """룰 ID 유효성 검증"""
    errors = []
    
    if not rule_ids:
        return errors
    
    available_rules = get_all_rules()
    
    for rule_id in rule_ids:
        if rule_id not in available_rules:
            errors.append(f"존재하지 않는 룰 ID입니다: {rule_id}")
    
    return errors


def validate_device_specific(config_text: str, device_type: str) -> tuple[List[str], List[str]]:
    """장비별 특수 검증"""
    errors = []
    warnings = []
    
    if device_type == "Cisco":
        # Cisco 특수 검증
        if "enable secret" not in config_text and "enable password" not in config_text:
            warnings.append("enable 패스워드 설정을 찾을 수 없습니다.")
        
        # VTY 라인 검증
        if "line vty" not in config_text:
            warnings.append("VTY 라인 설정을 찾을 수 없습니다.")
    
    elif device_type == "Juniper":
        # Juniper 특수 검증
        if "root-authentication" not in config_text:
            warnings.append("root 인증 설정을 찾을 수 없습니다.")
    
    elif device_type == "Piolink":
        # Piolink 특수 검증
        if "password" not in config_text:
            warnings.append("패스워드 설정을 찾을 수 없습니다.")
    
    return errors, warnings


def validate_file_format(file_content: bytes, filename: str) -> ValidationResult:
    """
    업로드된 파일 형식 검증
    
    Args:
        file_content: 파일 내용 (바이트)
        filename: 파일명
        
    Returns:
        ValidationResult: 검증 결과
    """
    errors = []
    warnings = []
    
    # 파일 크기 검증
    if len(file_content) == 0:
        errors.append("빈 파일입니다.")
    elif len(file_content) > 50 * 1024 * 1024:  # 50MB
        errors.append("파일이 너무 큽니다. (최대 50MB)")
    
    # 파일 확장자 검증
    allowed_extensions = ['.txt', '.cfg', '.conf', '.config']
    if filename and not any(filename.lower().endswith(ext) for ext in allowed_extensions):
        warnings.append("지원되지 않는 파일 확장자입니다. 텍스트 파일을 권장합니다.")
    
    # 텍스트 파일 여부 검증
    try:
        content_str = file_content.decode('utf-8')
    except UnicodeDecodeError:
        try:
            content_str = file_content.decode('latin-1')
            warnings.append("파일 인코딩이 UTF-8이 아닙니다.")
        except UnicodeDecodeError:
            errors.append("텍스트 파일이 아니거나 지원되지 않는 인코딩입니다.")
            return ValidationResult(False, errors, warnings)
    
    # 바이너리 데이터 검증
    if '\x00' in content_str:
        errors.append("바이너리 데이터가 포함되어 있습니다.")
    
    return ValidationResult(
        is_valid=len(errors) == 0,
        errors=errors,
        warnings=warnings
    )


def sanitize_config_text(config_text: str) -> str:
    """
    설정 텍스트 정제
    
    Args:
        config_text: 원본 설정 텍스트
        
    Returns:
        str: 정제된 설정 텍스트
    """
    # 줄 끝 문자 통일
    config_text = config_text.replace('\r\n', '\n').replace('\r', '\n')
    
    # 연속된 빈 줄 제거
    lines = config_text.split('\n')
    cleaned_lines = []
    prev_empty = False
    
    for line in lines:
        is_empty = not line.strip()
        if not (is_empty and prev_empty):  # 연속된 빈 줄이 아닌 경우만 추가
            cleaned_lines.append(line)
        prev_empty = is_empty
    
    return '\n'.join(cleaned_lines)


def extract_device_info(config_text: str, device_type: str) -> Dict[str, Any]:
    """
    설정에서 장비 정보 추출
    
    Args:
        config_text: 설정 텍스트
        device_type: 장비 타입
        
    Returns:
        Dict[str, Any]: 추출된 장비 정보
    """
    info = {
        'hostname': None,
        'version': None,
        'model': None,
        'serial': None
    }
    
    lines = config_text.splitlines()
    
    if device_type == "Cisco":
        for line in lines:
            line = line.strip()
            if line.startswith('hostname '):
                info['hostname'] = line.split('hostname ', 1)[1]
            elif line.startswith('version '):
                info['version'] = line.split('version ', 1)[1]
            elif 'processor' in line.lower() and 'bytes' in line.lower():
                # Cisco 모델 정보 추출 시도
                match = re.search(r'cisco\s+(\S+)', line, re.IGNORECASE)
                if match:
                    info['model'] = match.group(1)
    
    elif device_type == "Juniper":
        for line in lines:
            line = line.strip()
            if 'set system host-name' in line:
                info['hostname'] = line.split()[-1]
            elif 'JUNOS' in line:
                info['version'] = line
    
    return info
