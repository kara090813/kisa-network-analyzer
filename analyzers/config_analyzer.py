# -*- coding: utf-8 -*-
"""
analyzers/config_analyzer.py (Fixed Multi-Framework Version)
네트워크 장비 설정 파일 분석 엔진 - 다중 지침서 완전 지원

수정사항:
- 실제 다중 지침서 분석 기능 구현
- CIS 룰셋 연동 완료
- API 호출 시 지침서 선택 기능 활성화
"""

import re
import time
from typing import List, Dict, Optional, Tuple, Any, Set
import logging
from collections import defaultdict

# 룰 로더 시스템 import
from rules.loader import (
    load_rules, 
    get_rules_by_device_type, 
    get_rules_by_severity,
    get_rule_by_id,
    get_supported_sources,
    validate_rule_compatibility
)
from rules.kisa_rules import (
    SecurityRule, 
    RuleCategory, 
    ConfigContext, 
    parse_config_context
)

from models.analysis_request import AnalysisRequest
from models.analysis_response import (
    VulnerabilityIssue, AnalysisResult, AnalysisStatistics
)


class MultiFrameworkAnalyzer:
    """다중 지침서 분석기 - 완전 구현 버전"""
    
    def __init__(self, default_framework: str = "KISA"):
        """
        다중 지침서 분석기 초기화
        
        Args:
            default_framework: 기본 사용할 지침서
        """
        self.logger = logging.getLogger(__name__)
        self.default_framework = default_framework.upper()
        
        # 지원되는 지침서 목록 로드
        self.supported_frameworks = list(get_supported_sources().keys())
        
        # 분석 통계
        self.analysis_stats = {
            'total_analyses': 0,
            'framework_usage': defaultdict(int)
        }
        
        self.logger.info(f"다중 지침서 분석기 초기화 완료 - 지원 지침서: {', '.join(self.supported_frameworks)}")
    
    def analyze_config(self, request: AnalysisRequest, framework: Optional[str] = None) -> AnalysisResult:
        """
        설정 파일 분석 - 지정된 지침서 사용
        
        Args:
            request: 분석 요청 객체
            framework: 사용할 지침서 (None이면 기본값 사용)
            
        Returns:
            AnalysisResult: 분석 결과
        """
        start_time = time.time()
        
        # 지침서 결정
        target_framework = (framework or self.default_framework).upper()
        
        try:
            # 지침서별 룰 로드
            rules_dict = load_rules(target_framework)
            device_rules = {
                rule_id: rule for rule_id, rule in rules_dict.items()
                if request.device_type in rule.device_types
            }
            
            self.logger.info(f"분석 시작 - 지침서: {target_framework}, "
                           f"장비: {request.device_type}, "
                           f"적용 룰: {len(device_rules)}개")
            
        except ValueError as e:
            self.logger.error(f"지원되지 않는 지침서: {target_framework}")
            raise ValueError(f"지원되지 않는 지침서: {target_framework}")
        except NotImplementedError as e:
            self.logger.error(f"구현되지 않은 지침서: {target_framework}")
            raise NotImplementedError(f"{target_framework} 지침서는 아직 구현되지 않았습니다")
        
        # 컨텍스트 파싱 - 향상된 버전
        config_context = self._enhanced_parse_context(request.config_text, request.device_type)
        
        # 룰 필터링 (특정 룰 지정된 경우)
        if not request.options.check_all_rules and request.options.specific_rule_ids:
            device_rules = {
                rule_id: rule for rule_id, rule in device_rules.items()
                if rule_id in request.options.specific_rule_ids
            }
        
        # 분석 실행
        vulnerabilities = self._perform_analysis(
            request.get_config_lines(), 
            device_rules, 
            config_context, 
            request.options,
            target_framework
        )
        
        # 통계 생성
        statistics = self._generate_statistics(vulnerabilities, device_rules)
        
        analysis_time = time.time() - start_time
        
        # 통계 업데이트
        self.analysis_stats['total_analyses'] += 1
        self.analysis_stats['framework_usage'][target_framework] += 1
        
        self.logger.info(f"분석 완료 - 지침서: {target_framework}, "
                        f"취약점: {len(vulnerabilities)}개, "
                        f"분석시간: {analysis_time:.2f}초")
        
        return AnalysisResult(
            vulnerabilities=vulnerabilities,
            analysis_time=analysis_time,
            statistics=statistics
        )
    
    def _perform_analysis(
        self, 
        config_lines: List[str], 
        rules: Dict[str, SecurityRule],
        context: ConfigContext,
        options,
        framework: str
    ) -> List[VulnerabilityIssue]:
        """실제 분석 수행"""
        vulnerabilities = []
        
        for rule_id, rule in rules.items():
            rule_vulnerabilities = []
            
            # 1. 논리 기반 분석 (우선순위)
            if rule.logical_check_function:
                try:
                    logical_results = rule.logical_check_function("", 0, context)
                    for result in logical_results:
                        issue = VulnerabilityIssue(
                            rule_id=rule.rule_id,
                            severity=rule.severity,
                            line=result.get('line', 0),
                            matched_text=result.get('matched_text', ''),
                            description=rule.description,
                            recommendation=rule.recommendation,
                            reference=rule.reference,
                            category=rule.category.value,
                            raw_match=result.get('matched_text') if options.return_raw_matches else None
                        )
                        
                        # 지침서 정보 추가
                        issue_dict = issue.to_dict()
                        issue_dict['framework'] = framework
                        issue_dict['analysisType'] = 'logical'
                        
                        enhanced_issue = VulnerabilityIssue.from_dict(issue_dict)
                        rule_vulnerabilities.append(enhanced_issue)
                        
                except Exception as e:
                    self.logger.error(f"논리 기반 분석 오류 ({rule_id}): {e}")
            
            # 2. 패턴 매칭 분석 (논리 분석이 없는 경우)
            elif rule.patterns:
                for line_num, line in enumerate(config_lines, 1):
                    if not line.strip() or line.strip().startswith('!'):
                        continue
                    
                    # Negative 패턴 확인 (양호한 상태)
                    is_safe = any(neg_pattern.search(line) for neg_pattern in rule.compiled_negative_patterns)
                    if is_safe:
                        continue
                    
                    # 취약점 패턴 확인
                    for pattern in rule.compiled_patterns:
                        match = pattern.search(line)
                        if match:
                            issue = VulnerabilityIssue(
                                rule_id=rule.rule_id,
                                severity=rule.severity,
                                line=line_num,
                                matched_text=match.group(0),
                                description=rule.description,
                                recommendation=rule.recommendation,
                                reference=rule.reference,
                                category=rule.category.value,
                                raw_match=line.strip() if options.return_raw_matches else None
                            )
                            
                            # 지침서 정보 추가
                            issue_dict = issue.to_dict()
                            issue_dict['framework'] = framework
                            issue_dict['analysisType'] = 'pattern'
                            
                            enhanced_issue = VulnerabilityIssue.from_dict(issue_dict)
                            rule_vulnerabilities.append(enhanced_issue)
                            break
            
            vulnerabilities.extend(rule_vulnerabilities)
        
        return vulnerabilities
    
    def _generate_statistics(
        self, 
        vulnerabilities: List[VulnerabilityIssue], 
        rules: Dict[str, SecurityRule]
    ) -> AnalysisStatistics:
        """분석 통계 생성"""
        severity_counts = {"상": 0, "중": 0, "하": 0}
        
        for vuln in vulnerabilities:
            if vuln.severity in severity_counts:
                severity_counts[vuln.severity] += 1
        
        failed_rule_ids = set(vuln.rule_id for vuln in vulnerabilities)
        rules_failed = len(failed_rule_ids)
        rules_passed = len(rules) - rules_failed
        
        return AnalysisStatistics(
            total_rules_checked=len(rules),
            rules_passed=rules_passed,
            rules_failed=rules_failed,
            high_severity_issues=severity_counts["상"],
            medium_severity_issues=severity_counts["중"],
            low_severity_issues=severity_counts["하"]
        )
    
    def get_supported_device_types(self, framework: str = None) -> List[str]:
        """지원되는 장비 타입 반환"""
        target_framework = (framework or self.default_framework).upper()
        
        try:
            rules_dict = load_rules(target_framework)
            device_types = set()
            for rule in rules_dict.values():
                device_types.update(rule.device_types)
            return sorted(list(device_types))
        except:
            return ["Cisco", "Juniper", "Radware", "Passport", "Piolink"]
    
    def get_available_rules(self, framework: str = None) -> List[Dict[str, Any]]:
        """사용 가능한 룰 목록 반환"""
        target_framework = (framework or self.default_framework).upper()
        
        try:
            rules_dict = load_rules(target_framework)
            return [
                {
                    "ruleId": rule.rule_id,
                    "title": rule.title,
                    "description": rule.description,
                    "severity": rule.severity,
                    "category": rule.category.value,
                    "deviceTypes": rule.device_types,
                    "reference": rule.reference,
                    "framework": target_framework,
                    "hasLogicalAnalysis": rule.logical_check_function is not None
                }
                for rule in rules_dict.values()
            ]
        except:
            return []
    
    def validate_config_syntax(self, config_text: str, device_type: str) -> List[Dict[str, Any]]:
        """설정 파일 문법 검증"""
        errors = []
        lines = config_text.splitlines()
        
        for line_num, line in enumerate(lines, 1):
            line = line.strip()
            if not line or line.startswith('!'):
                continue
            
            # 기본적인 문법 검증
            if device_type == "Cisco":
                # Cisco 특화 문법 검증
                if line.startswith(' ') and not any(lines[i].strip().startswith(cmd) 
                                                 for i in range(max(0, line_num-10), line_num-1)
                                                 for cmd in ['interface', 'line', 'router', 'access-list']):
                    errors.append({
                        "line": line_num,
                        "error": "Indented line without parent command",
                        "text": line
                    })
        
        return errors
    
    def analyze_single_line(self, line: str, device_type: str, rule_ids: Optional[List[str]] = None, framework: str = None) -> List[VulnerabilityIssue]:
        """단일 라인 분석"""
        target_framework = (framework or self.default_framework).upper()
        
        try:
            rules_dict = load_rules(target_framework)
            
            if rule_ids:
                rules_dict = {rid: rule for rid, rule in rules_dict.items() if rid in rule_ids}
            
            vulnerabilities = []
            
            for rule_id, rule in rules_dict.items():
                if device_type not in rule.device_types:
                    continue
                
                # 패턴 매칭만 수행 (단일 라인이므로 논리 분석 제외)
                if rule.patterns:
                    for pattern in rule.compiled_patterns:
                        match = pattern.search(line)
                        if match:
                            issue = VulnerabilityIssue(
                                rule_id=rule.rule_id,
                                severity=rule.severity,
                                line=1,
                                matched_text=match.group(0),
                                description=rule.description,
                                recommendation=rule.recommendation,
                                reference=rule.reference,
                                category=rule.category.value
                            )
                            vulnerabilities.append(issue)
                            break
            
            return vulnerabilities
        except:
            return []
    
    def get_analysis_statistics(self) -> Dict[str, Any]:
        """분석 통계 반환"""
        return {
            "analysisStats": dict(self.analysis_stats),
            "supportedFrameworks": self.supported_frameworks,
            "defaultFramework": self.default_framework
        }


# 기존 호환성을 위한 별칭 - 수정됨
class EnhancedConfigAnalyzer(MultiFrameworkAnalyzer):
    """Enhanced Config Analyzer - 기존 호환성 유지"""
    
    def __init__(self):
        super().__init__(default_framework="KISA")


# 기존 호환성을 위한 별칭
ConfigAnalyzer = EnhancedConfigAnalyzer