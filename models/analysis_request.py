# -*- coding: utf-8 -*-
"""
models/analysis_request.py (수정된 버전)
분석 요청 데이터 모델 - 통과 항목 추적 옵션 추가

KISA 네트워크 장비 취약점 분석 요청을 위한 데이터 구조 정의
"""

from dataclasses import dataclass
from typing import List, Optional, Dict, Any


@dataclass
class AnalysisOptions:
    """분석 옵션 - 통과 항목 추적 기능 추가"""
    check_all_rules: bool = True
    specific_rule_ids: Optional[List[str]] = None
    return_raw_matches: bool = False
    skip_safe_checks: bool = False
    include_recommendations: bool = True
    # 🔥 새로운 옵션들 추가
    include_passed_rules: bool = False  # 통과된 룰 포함 여부
    include_skipped_rules: bool = False  # 건너뛴 룰 포함 여부
    use_consolidation: bool = True  # 통합 통계 사용 여부
    show_detailed_info: bool = True  # 상세 정보 표시 여부
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'AnalysisOptions':
        """딕셔너리로부터 AnalysisOptions 객체 생성"""
        return cls(
            check_all_rules=data.get('checkAllRules', True),
            specific_rule_ids=data.get('specificRuleIds'),
            return_raw_matches=data.get('returnRawMatches', False),
            skip_safe_checks=data.get('skipSafeChecks', False),
            include_recommendations=data.get('includeRecommendations', True),
            # 🔥 새로운 옵션들 처리
            include_passed_rules=data.get('includePassedRules', False),
            include_skipped_rules=data.get('includeSkippedRules', False),
            use_consolidation=data.get('useConsolidation', True),
            show_detailed_info=data.get('showDetailedInfo', True)
        )
    
    def to_dict(self) -> Dict[str, Any]:
        """딕셔너리로 변환"""
        return {
            'checkAllRules': self.check_all_rules,
            'specificRuleIds': self.specific_rule_ids,
            'returnRawMatches': self.return_raw_matches,
            'skipSafeChecks': self.skip_safe_checks,
            'includeRecommendations': self.include_recommendations,
            # 🔥 새로운 옵션들 포함
            'includePassedRules': self.include_passed_rules,
            'includeSkippedRules': self.include_skipped_rules,
            'useConsolidation': self.use_consolidation,
            'showDetailedInfo': self.show_detailed_info
        }


@dataclass
class AnalysisRequest:
    """네트워크 장비 설정 분석 요청"""
    device_type: str
    config_text: str
    options: AnalysisOptions
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'AnalysisRequest':
        """딕셔너리로부터 AnalysisRequest 객체 생성"""
        if 'deviceType' not in data:
            raise ValueError("deviceType은 필수 필드입니다")
        if 'configText' not in data:
            raise ValueError("configText는 필수 필드입니다")
        
        options_data = data.get('options', {})
        options = AnalysisOptions.from_dict(options_data)
        
        return cls(
            device_type=data['deviceType'],
            config_text=data['configText'],
            options=options
        )
    
    def to_dict(self) -> Dict[str, Any]:
        """딕셔너리로 변환"""
        return {
            'deviceType': self.device_type,
            'configText': self.config_text,
            'options': self.options.to_dict()
        }
    
    def validate(self) -> List[str]:
        """요청 데이터 유효성 검증"""
        errors = []
        
        # 장비 타입 검증
        if not self.device_type or not self.device_type.strip():
            errors.append("deviceType은 비어있을 수 없습니다")
        
        # 설정 텍스트 검증
        if not self.config_text or not self.config_text.strip():
            errors.append("configText는 비어있을 수 없습니다")
        
        # 지원되는 장비 타입 확인
        supported_devices = ['Cisco', 'Juniper', 'Radware', 'Passport', 'Piolink']
        if self.device_type not in supported_devices:
            errors.append(f"지원되지 않는 장비 타입입니다. 지원되는 타입: {', '.join(supported_devices)}")
        
        # 설정 파일 크기 제한 (10MB)
        if len(self.config_text.encode('utf-8')) > 10 * 1024 * 1024:
            errors.append("설정 파일 크기가 10MB를 초과합니다")
        
        # 특정 룰 ID 검증
        if (not self.options.check_all_rules and 
            (not self.options.specific_rule_ids or len(self.options.specific_rule_ids) == 0)):
            errors.append("checkAllRules가 false인 경우 specificRuleIds가 필요합니다")
        
        return errors
    
    def get_config_lines(self) -> List[str]:
        """설정 텍스트를 라인별로 분할하여 반환"""
        return self.config_text.splitlines()
    
    def get_line_count(self) -> int:
        """설정 파일의 라인 수 반환"""
        return len(self.get_config_lines())