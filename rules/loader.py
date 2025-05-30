# -*- coding: utf-8 -*-
"""
rules/loader.py
보안 지침서별 룰셋 로더 (NW 지침서 지원 추가)

다양한 보안 지침서(KISA, CIS, NW, NIST 등)의 룰셋을 로드하는 중앙 관리 모듈
"""

from typing import Dict, List, Optional, Union
from .kisa_rules import SecurityRule, RuleCategory


# 지원되는 보안 지침서 목록 (NW 지침서 추가)
SUPPORTED_SOURCES = {
    "KISA": {
        "name": "KISA 네트워크 장비 보안 가이드",
        "description": "한국인터넷진흥원(KISA) 네트워크 장비 보안 점검 가이드라인",
        "version": "2024",
        "total_rules": 38,
        "categories": ["계정 관리", "접근 관리", "패치 관리", "로그 관리", "기능 관리"]
    },
    "CIS": {
        "name": "CIS Controls",
        "description": "Center for Internet Security Controls",
        "version": "v8",
        "total_rules": 11,
        "categories": ["계정 관리", "접근 관리", "로그 관리"]
    },
    "NW": {
        "name": "NW 네트워크 장비 보안 가이드",
        "description": "NW 네트워크 장비 보안 점검 가이드라인",
        "version": "2024",
        "total_rules": 42,
        "categories": ["계정 관리", "접근 관리", "패치 관리", "로그 관리", "기능 관리"]
    },
    "NIST": {
        "name": "NIST Cybersecurity Framework",
        "description": "National Institute of Standards and Technology Framework",
        "version": "2.0",
        "total_rules": 0,  # 구현 예정
        "categories": []
    }
}


def load_rules(source: str) -> Dict[str, SecurityRule]:
    """
    지침서별 보안 룰셋 로드
    
    Args:
        source: 지침서 이름 ("KISA", "CIS", "NW", "NIST" etc)
        
    Returns:
        Dict[str, SecurityRule]: 룰 ID를 키로 하는 보안 룰 딕셔너리
        
    Raises:
        ValueError: 지원되지 않는 지침서인 경우
        ImportError: 해당 지침서 모듈을 찾을 수 없는 경우
        NotImplementedError: 해당 지침서가 아직 구현되지 않은 경우
    """
    source = source.upper()
    
    if source not in SUPPORTED_SOURCES:
        raise ValueError(f"지원되지 않는 지침서입니다: {source}. "
                        f"지원되는 지침서: {', '.join(SUPPORTED_SOURCES.keys())}")
    
    if source == "KISA":
        from .kisa_rules import KISA_RULES
        return KISA_RULES
    elif source == "CIS":
        from .cis_rules import CIS_RULES
        return CIS_RULES
    elif source == "NW":
        from .nw_rules import NW_RULES
        return NW_RULES
    elif source == "NIST":
        # 향후 구현 예정
        raise NotImplementedError("NIST 룰셋은 아직 구현되지 않았습니다.")
    else:
        raise ValueError(f"알 수 없는 지침서: {source}")


def load_all_rules() -> Dict[str, Dict[str, SecurityRule]]:
    """
    모든 지원되는 지침서의 룰셋 로드
    
    Returns:
        Dict[str, Dict[str, SecurityRule]]: 지침서별 룰셋 딕셔너리
    """
    all_rules = {}
    
    for source in SUPPORTED_SOURCES.keys():
        try:
            rules = load_rules(source)
            if rules:  # 빈 딕셔너리가 아닌 경우만 추가
                all_rules[source] = rules
        except (NotImplementedError, ImportError):
            # 아직 구현되지 않은 지침서는 스킵
            continue
    
    return all_rules


def get_supported_sources() -> Dict[str, Dict[str, Union[str, int, List[str]]]]:
    """
    지원되는 보안 지침서 목록 반환
    
    Returns:
        Dict: 지침서별 메타정보
    """
    return SUPPORTED_SOURCES.copy()


def get_source_info(source: str) -> Optional[Dict[str, Union[str, int, List[str]]]]:
    """
    특정 지침서의 정보 반환
    
    Args:
        source: 지침서 이름
        
    Returns:
        Dict: 지침서 메타정보 또는 None
    """
    return SUPPORTED_SOURCES.get(source.upper())


def combine_rules(*sources: str) -> Dict[str, SecurityRule]:
    """
    여러 지침서의 룰을 결합
    
    Args:
        *sources: 결합할 지침서 이름들
        
    Returns:
        Dict[str, SecurityRule]: 결합된 룰셋
        
    Note:
        룰 ID가 중복되는 경우, 나중에 로드된 지침서의 룰이 우선됩니다.
    """
    combined_rules = {}
    
    for source in sources:
        try:
            rules = load_rules(source)
            combined_rules.update(rules)
        except (ValueError, NotImplementedError, ImportError) as e:
            print(f"Warning: {source} 지침서 로드 실패: {e}")
    
    return combined_rules


def get_rules_by_device_type(source: str, device_type: str) -> Dict[str, SecurityRule]:
    """
    특정 지침서에서 장비 타입별 룰 필터링
    
    Args:
        source: 지침서 이름
        device_type: 장비 타입 ("Cisco", "Juniper" 등)
        
    Returns:
        Dict[str, SecurityRule]: 필터링된 룰셋
    """
    rules = load_rules(source)
    return {
        rule_id: rule for rule_id, rule in rules.items()
        if device_type in rule.device_types
    }


def get_rules_by_severity(source: str, severity: str) -> Dict[str, SecurityRule]:
    """
    특정 지침서에서 심각도별 룰 필터링
    
    Args:
        source: 지침서 이름
        severity: 심각도 ("상", "중", "하")
        
    Returns:
        Dict[str, SecurityRule]: 필터링된 룰셋
    """
    rules = load_rules(source)
    return {
        rule_id: rule for rule_id, rule in rules.items()
        if rule.severity == severity
    }


def get_rules_by_category(source: str, category: Union[str, RuleCategory]) -> Dict[str, SecurityRule]:
    """
    특정 지침서에서 카테고리별 룰 필터링
    
    Args:
        source: 지침서 이름
        category: 룰 카테고리
        
    Returns:
        Dict[str, SecurityRule]: 필터링된 룰셋
    """
    rules = load_rules(source)
    
    if isinstance(category, str):
        # 문자열인 경우 RuleCategory와 매칭
        target_category = None
        for cat in RuleCategory:
            if cat.value == category:
                target_category = cat
                break
        if not target_category:
            return {}
        category = target_category
    
    return {
        rule_id: rule for rule_id, rule in rules.items()
        if rule.category == category
    }


def get_rule_by_id(source: str, rule_id: str) -> Optional[SecurityRule]:
    """
    특정 지침서에서 룰 ID로 룰 조회
    
    Args:
        source: 지침서 이름
        rule_id: 룰 ID
        
    Returns:
        SecurityRule: 해당 룰 또는 None
    """
    rules = load_rules(source)
    return rules.get(rule_id)


def validate_rule_compatibility(rule: SecurityRule, device_type: str) -> bool:
    """
    룰과 장비 타입의 호환성 검증
    
    Args:
        rule: 보안 룰
        device_type: 장비 타입
        
    Returns:
        bool: 호환 여부
    """
    return device_type in rule.device_types


def get_statistics(source: str) -> Dict[str, Union[int, Dict[str, int]]]:
    """
    특정 지침서의 룰셋 통계 반환
    
    Args:
        source: 지침서 이름
        
    Returns:
        Dict: 룰셋 통계 정보
    """
    try:
        rules = load_rules(source)
        
        # 심각도별 통계
        severity_stats = {"상": 0, "중": 0, "하": 0}
        
        # 카테고리별 통계
        category_stats = {}
        
        # 장비별 통계
        device_stats = {}
        
        for rule in rules.values():
            # 심각도 통계
            if rule.severity in severity_stats:
                severity_stats[rule.severity] += 1
            
            # 카테고리 통계
            category_name = rule.category.value
            category_stats[category_name] = category_stats.get(category_name, 0) + 1
            
            # 장비 통계
            for device_type in rule.device_types:
                device_stats[device_type] = device_stats.get(device_type, 0) + 1
        
        return {
            "totalRules": len(rules),
            "severityStats": severity_stats,
            "categoryStats": category_stats,
            "deviceStats": device_stats,
            "logicalRules": sum(1 for rule in rules.values() if rule.logical_check_function is not None),
            "patternRules": sum(1 for rule in rules.values() if rule.patterns and rule.logical_check_function is None)
        }
        
    except (ValueError, NotImplementedError, ImportError):
        return {
            "totalRules": 0,
            "severityStats": {"상": 0, "중": 0, "하": 0},
            "categoryStats": {},
            "deviceStats": {},
            "logicalRules": 0,
            "patternRules": 0
        }


def get_all_supported_frameworks() -> List[str]:
    """
    지원되는 모든 지침서 이름 반환
    
    Returns:
        List[str]: 지침서 이름 리스트
    """
    return list(SUPPORTED_SOURCES.keys())


def get_implemented_frameworks() -> List[str]:
    """
    실제 구현된 지침서 이름 반환
    
    Returns:
        List[str]: 구현된 지침서 이름 리스트
    """
    implemented = []
    
    for source in SUPPORTED_SOURCES.keys():
        try:
            rules = load_rules(source)
            if rules:  # 룰이 있는 경우만 구현된 것으로 간주
                implemented.append(source)
        except (NotImplementedError, ImportError):
            continue
    
    return implemented


def validate_framework_availability(source: str) -> Dict[str, bool]:
    """
    지침서 사용 가능성 검증
    
    Args:
        source: 지침서 이름
        
    Returns:
        Dict[str, bool]: 검증 결과
    """
    source = source.upper()
    
    result = {
        'is_supported': source in SUPPORTED_SOURCES,
        'is_implemented': False,
        'has_rules': False,
        'rule_count': 0
    }
    
    if result['is_supported']:
        try:
            rules = load_rules(source)
            result['is_implemented'] = True
            result['has_rules'] = len(rules) > 0
            result['rule_count'] = len(rules)
        except (NotImplementedError, ImportError):
            pass
    
    return result


# 기존 호환성을 위한 함수들 (기본적으로 KISA 사용)
def get_all_rules() -> Dict[str, SecurityRule]:
    """모든 보안 룰 반환 (기본: KISA)"""
    return load_rules("KISA")


def get_rules_by_device_type_legacy(device_type: str) -> Dict[str, SecurityRule]:
    """특정 장비 타입에 적용 가능한 룰들만 반환 (기본: KISA)"""
    return get_rules_by_device_type("KISA", device_type)


def get_rules_by_severity_legacy(severity: str) -> Dict[str, SecurityRule]:
    """특정 심각도의 룰들만 반환 (기본: KISA)"""
    return get_rules_by_severity("KISA", severity)


def get_rules_by_category_legacy(category: Union[str, RuleCategory]) -> Dict[str, SecurityRule]:
    """특정 카테고리의 룰들만 반환 (기본: KISA)"""
    return get_rules_by_category("KISA", category)


def get_rule_by_id_legacy(rule_id: str) -> Optional[SecurityRule]:
    """특정 룰 ID로 룰 반환 (기본: KISA)"""
    return get_rule_by_id("KISA", rule_id)


# NW 지침서 전용 함수들
def get_nw_rules() -> Dict[str, SecurityRule]:
    """NW 지침서 룰셋 반환"""
    return load_rules("NW")


def get_nw_rules_by_device_type(device_type: str) -> Dict[str, SecurityRule]:
    """NW 지침서에서 특정 장비 타입 룰 반환"""
    return get_rules_by_device_type("NW", device_type)


def compare_frameworks(*sources: str) -> Dict[str, Dict[str, Union[int, List[str]]]]:
    """
    여러 지침서 간 비교 분석
    
    Args:
        *sources: 비교할 지침서 이름들
        
    Returns:
        Dict: 비교 분석 결과
    """
    comparison = {}
    
    for source in sources:
        try:
            rules = load_rules(source)
            stats = get_statistics(source)
            
            comparison[source] = {
                'total_rules': len(rules),
                'rule_ids': list(rules.keys()),
                'severity_distribution': stats['severityStats'],
                'category_distribution': stats['categoryStats'],
                'device_support': stats['deviceStats'],
                'logical_rules': stats['logicalRules'],
                'pattern_rules': stats['patternRules']
            }
        except (ValueError, NotImplementedError, ImportError) as e:
            comparison[source] = {
                'error': str(e),
                'total_rules': 0,
                'rule_ids': [],
                'is_available': False
            }
    
    return comparison