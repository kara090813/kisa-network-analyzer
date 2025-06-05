# -*- coding: utf-8 -*-
"""
rules/__init__.py
보안 룰셋 패키지 초기화

기존 코드와의 호환성을 위해 기존 함수들을 re-export
새로운 loader 기반 함수들도 제공
"""

# 기존 호환성을 위한 import
from .loader import (
    # 기존 함수들 (KISA 기본)
    get_all_rules,
    get_rules_by_device_type_legacy as get_rules_by_device_type,
    get_rules_by_severity_legacy as get_rules_by_severity,
    get_rules_by_category_legacy as get_rules_by_category,
    get_rule_by_id_legacy as get_rule_by_id,
    
    # 새로운 확장 가능한 함수들
    load_rules,
    load_all_rules,
    get_supported_sources,
    get_source_info,
    combine_rules,
    get_statistics,
    validate_rule_compatibility
)

# 기본 클래스들 import
from .loader import (
    SecurityRule,
    RuleCategory,
    ConfigContext, 
    LogicalCondition,
    parse_config_context,
    _is_critical_interface
)

# 기존 호환성을 위한 별칭들
from .kisa_rules import (
    KISA_RULES as KISA_SECURITY_RULES,
    KISA_RULES as COMPLETE_ENHANCED_KISA_RULES,
    KISA_RULES as ENHANCED_KISA_SECURITY_RULES
)

# 새로운 권장 사용법을 위한 함수들
def get_kisa_rules():
    """KISA 룰셋 반환 (새로운 명명 규칙)"""
    return load_rules("KISA")


def get_rules_by_source(source: str):
    """지침서별 룰셋 반환 (새로운 방식)"""
    return load_rules(source)


def get_available_sources():
    """사용 가능한 지침서 목록 반환"""
    return list(get_supported_sources().keys())


# 기존 코드와의 완전한 호환성을 위한 상수들
KISA_SECURITY_RULES = load_rules("KISA")

# 패키지 메타정보
__version__ = "2.0.0"
__description__ = "네트워크 장비 보안 룰셋 - 다중 지침서 지원"
__author__ = "KISA Network Security Team"

# 외부에서 사용할 수 있는 모든 요소들
__all__ = [
    # 기존 호환성 함수들
    'get_all_rules',
    'get_rules_by_device_type', 
    'get_rules_by_severity',
    'get_rules_by_category',
    'get_rule_by_id',
    
    # 새로운 확장 가능한 함수들
    'load_rules',
    'load_all_rules',
    'get_supported_sources',
    'get_source_info',
    'combine_rules',
    'get_statistics',
    'validate_rule_compatibility',
    
    # 권장 사용법 함수들
    'get_kisa_rules',
    'get_rules_by_source',
    'get_available_sources',
    
    # 기본 클래스들
    'SecurityRule',
    'RuleCategory',
    'ConfigContext',
    'LogicalCondition',
    'parse_config_context',
    '_is_critical_interface',
    
    # 기존 호환성 상수들
    'KISA_SECURITY_RULES',
    'COMPLETE_ENHANCED_KISA_RULES',
    'ENHANCED_KISA_SECURITY_RULES'
]