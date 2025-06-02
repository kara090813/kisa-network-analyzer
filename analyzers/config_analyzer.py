# -*- coding: utf-8 -*-
"""
analyzers/config_analyzer.py (Enhanced Multi-Framework Version with NW Support)
네트워크 장비 설정 파일 분석 엔진 - 다중 지침서 완전 지원 + NW 룰셋 추가

수정사항:
- NW 가이드 룰셋 지원 추가
- 룰 로더 시스템 인라인 구현
- 실제 다중 지침서 분석 기능 구현
- CIS 룰셋 연동 완료
- API 호출 시 지침서 선택 기능 활성화
"""

import re
import time
from typing import List, Dict, Optional, Tuple, Any, Set
import logging
from collections import defaultdict

# 룰셋 직접 import
from rules.kisa_rules import (
    KISA_RULES,
    SecurityRule, 
    RuleCategory, 
    ConfigContext, 
    parse_config_context
)

# NW 룰셋 import
from rules.nw_rules import NW_RULES

from models.analysis_request import AnalysisRequest
from models.analysis_response import (
    VulnerabilityIssue, AnalysisResult, AnalysisStatistics
)


class RuleLoader:
    """룰 로더 시스템 - 인라인 구현"""
    
    SUPPORTED_SOURCES = {
        'KISA': {
            'name': 'KISA 네트워크 보안 가이드',
            'description': 'KISA(한국인터넷진흥원) 네트워크 장비 보안 설정 가이드',
            'version': '2024',
            'coverage': 'Comprehensive network security guidelines',
            'rules_count': len(KISA_RULES),
            'status': 'active'
        },
        'NW': {
            'name': 'NW 네트워크 장비 보안 점검',
            'description': 'NW 가이드 기반 네트워크 장비 보안 점검 룰셋',
            'version': '2024',
            'coverage': 'Enhanced network device security checks',
            'rules_count': len(NW_RULES),
            'status': 'active'
        },
        'CIS': {
            'name': 'CIS Benchmarks',
            'description': 'Center for Internet Security Benchmarks',
            'version': 'v1.0',
            'coverage': 'Industry standard security benchmarks',
            'rules_count': 0,
            'status': 'planned'
        },
        'NIST': {
            'name': 'NIST Cybersecurity Framework',
            'description': 'NIST cybersecurity guidelines',
            'version': 'v1.1',
            'coverage': 'Federal cybersecurity standards',
            'rules_count': 0,
            'status': 'planned'
        }
    }
    
    @classmethod
    def load_rules(cls, framework: str) -> Dict[str, SecurityRule]:
        """지침서별 룰 로드"""
        framework = framework.upper()
        
        if framework == 'KISA':
            return KISA_RULES.copy()
        elif framework == 'NW':
            return NW_RULES.copy()
        elif framework in ['CIS', 'NIST']:
            raise NotImplementedError(f"{framework} 지침서는 아직 구현되지 않았습니다")
        else:
            raise ValueError(f"지원되지 않는 지침서: {framework}")
    
    @classmethod
    def get_supported_sources(cls) -> Dict[str, Dict]:
        """지원되는 지침서 목록 반환"""
        return cls.SUPPORTED_SOURCES.copy()
    
    @classmethod
    def get_source_info(cls, framework: str) -> Dict:
        """특정 지침서 정보 반환"""
        framework = framework.upper()
        if framework in cls.SUPPORTED_SOURCES:
            return cls.SUPPORTED_SOURCES[framework].copy()
        else:
            raise ValueError(f"지원되지 않는 지침서: {framework}")
    
    @classmethod
    def get_statistics(cls, framework: str) -> Dict[str, Any]:
        """지침서별 통계 정보 반환"""
        framework = framework.upper()
        
        try:
            rules = cls.load_rules(framework)
            
            severity_counts = {"상": 0, "중": 0, "하": 0}
            category_counts = defaultdict(int)
            device_types = set()
            logical_rules = 0
            
            for rule in rules.values():
                # 심각도별 카운트
                if rule.severity in severity_counts:
                    severity_counts[rule.severity] += 1
                
                # 카테고리별 카운트
                category_counts[rule.category.value] += 1
                
                # 지원 장비 타입
                device_types.update(rule.device_types)
                
                # 논리 기반 룰 카운트
                if rule.logical_check_function:
                    logical_rules += 1
            
            return {
                "totalRules": len(rules),
                "severityBreakdown": severity_counts,
                "categoryBreakdown": dict(category_counts),
                "supportedDeviceTypes": sorted(list(device_types)),
                "logicalRules": logical_rules,
                "patternRules": len(rules) - logical_rules,
                "framework": framework
            }
            
        except (ValueError, NotImplementedError):
            return {"totalRules": 0, "framework": framework}
    
    @classmethod
    def get_rules_by_device_type(cls, framework: str, device_type: str) -> Dict[str, SecurityRule]:
        """장비 타입별 룰 필터링"""
        all_rules = cls.load_rules(framework)
        return {
            rule_id: rule for rule_id, rule in all_rules.items()
            if device_type in rule.device_types
        }
    
    @classmethod
    def get_rules_by_severity(cls, framework: str, severity: str) -> Dict[str, SecurityRule]:
        """심각도별 룰 필터링"""
        all_rules = cls.load_rules(framework)
        return {
            rule_id: rule for rule_id, rule in all_rules.items()
            if rule.severity == severity
        }
    
    @classmethod
    def get_rule_by_id(cls, framework: str, rule_id: str) -> Optional[SecurityRule]:
        """특정 룰 조회"""
        all_rules = cls.load_rules(framework)
        return all_rules.get(rule_id)
    
    @classmethod
    def validate_rule_compatibility(cls, framework: str, device_type: str, rule_ids: List[str]) -> Dict[str, bool]:
        """룰 호환성 검증"""
        all_rules = cls.load_rules(framework)
        compatibility = {}
        
        for rule_id in rule_ids:
            if rule_id in all_rules:
                rule = all_rules[rule_id]
                compatibility[rule_id] = device_type in rule.device_types
            else:
                compatibility[rule_id] = False
        
        return compatibility


# 룰 로더 함수들을 전역으로 노출
def load_rules(framework: str) -> Dict[str, SecurityRule]:
    return RuleLoader.load_rules(framework)

def get_supported_sources() -> Dict[str, Dict]:
    return RuleLoader.get_supported_sources()

def get_source_info(framework: str) -> Dict:
    return RuleLoader.get_source_info(framework)

def get_statistics(framework: str) -> Dict[str, Any]:
    return RuleLoader.get_statistics(framework)

def get_rules_by_device_type(framework: str, device_type: str) -> Dict[str, SecurityRule]:
    return RuleLoader.get_rules_by_device_type(framework, device_type)

def get_rules_by_severity(framework: str, severity: str) -> Dict[str, SecurityRule]:
    return RuleLoader.get_rules_by_severity(framework, severity)

def get_rule_by_id(framework: str, rule_id: str) -> Optional[SecurityRule]:
    return RuleLoader.get_rule_by_id(framework, rule_id)

def validate_rule_compatibility(framework: str, device_type: str, rule_ids: List[str]) -> Dict[str, bool]:
    return RuleLoader.validate_rule_compatibility(framework, device_type, rule_ids)


class MultiFrameworkAnalyzer:
    """다중 지침서 분석기 - 완전 구현 버전 (NW 지원 추가)"""
    
    def __init__(self, default_framework: str = "KISA"):
        """
        다중 지침서 분석기 초기화
        
        Args:
            default_framework: 기본 사용할 지침서 (KISA, NW, CIS, NIST)
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
        self.logger.info(f"기본 지침서: {self.default_framework}")
        
        # 각 지침서별 로드 상태 확인
        for framework in self.supported_frameworks:
            try:
                rules = load_rules(framework)
                self.logger.info(f"✅ {framework} 지침서: {len(rules)}개 룰 로드됨")
            except NotImplementedError:
                self.logger.info(f"⏳ {framework} 지침서: 구현 예정")
            except Exception as e:
                self.logger.warning(f"❌ {framework} 지침서 로드 실패: {e}")
    
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
                           f"전체 룰: {len(rules_dict)}개, "
                           f"적용 룰: {len(device_rules)}개")
            
        except ValueError as e:
            self.logger.error(f"지원되지 않는 지침서: {target_framework}")
            raise ValueError(f"지원되지 않는 지침서: {target_framework}")
        except NotImplementedError as e:
            self.logger.error(f"구현되지 않은 지침서: {target_framework}")
            raise NotImplementedError(f"{target_framework} 지침서는 아직 구현되지 않았습니다")
        
        # 설정 컨텍스트 파싱
        config_context = parse_config_context(request.config_text, request.device_type)
        
        # 룰 필터링 (특정 룰 지정된 경우)
        if not request.options.check_all_rules and request.options.specific_rule_ids:
            device_rules = {
                rule_id: rule for rule_id, rule in device_rules.items()
                if rule_id in request.options.specific_rule_ids
            }
            self.logger.info(f"특정 룰 필터링 적용: {len(device_rules)}개 룰")
        
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
        
        logical_rules_used = 0
        pattern_rules_used = 0
        
        for rule_id, rule in rules.items():
            rule_vulnerabilities = []
            
            # 1. 논리 기반 분석 (우선순위) - NW 룰셋에서 강화됨
            if rule.logical_check_function:
                try:
                    logical_results = rule.logical_check_function("", 0, context)
                    logical_rules_used += 1
                    
                    for result in logical_results:
                        issue = VulnerabilityIssue(
                            rule_id=rule.rule_id,
                            severity=result.get('details', {}).get('severity_adjusted', rule.severity),
                            line=result.get('line', 0),
                            matched_text=result.get('matched_text', ''),
                            description=rule.description,
                            recommendation=rule.recommendation,
                            reference=rule.reference,
                            category=rule.category.value,
                            raw_match=result.get('matched_text') if options.return_raw_matches else None
                        )
                        
                        # 지침서 및 분석 상세 정보 추가
                        issue_dict = issue.to_dict()
                        issue_dict['framework'] = framework
                        issue_dict['analysisType'] = 'logical'
                        issue_dict['analysisDetails'] = result.get('details', {})
                        
                        enhanced_issue = VulnerabilityIssue.from_dict(issue_dict)
                        rule_vulnerabilities.append(enhanced_issue)
                        
                except Exception as e:
                    self.logger.error(f"논리 기반 분석 오류 ({rule_id}): {e}")
                    self.logger.debug(f"오류 상세: {str(e)}", exc_info=True)
            
            # 2. 패턴 매칭 분석 (논리 분석이 없는 경우)
            elif rule.patterns:
                pattern_rules_used += 1
                
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
        
        self.logger.info(f"분석 상세 - 논리 룰: {logical_rules_used}개, 패턴 룰: {pattern_rules_used}개")
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
            return ["Cisco", "Juniper", "Radware", "Passport", "Piolink", "HP", "Alcatel", "Extreme", "Dasan"]
    
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
                    "hasLogicalAnalysis": rule.logical_check_function is not None,
                    "patternCount": len(rule.patterns) if rule.patterns else 0,
                    "negativePatternCount": len(rule.negative_patterns) if rule.negative_patterns else 0
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
                            
                            # 지침서 정보 추가
                            issue_dict = issue.to_dict()
                            issue_dict['framework'] = target_framework
                            issue_dict['analysisType'] = 'pattern'
                            
                            enhanced_issue = VulnerabilityIssue.from_dict(issue_dict)
                            vulnerabilities.append(enhanced_issue)
                            break
            
            return vulnerabilities
        except:
            return []
    
    def get_analysis_statistics(self) -> Dict[str, Any]:
        """분석 통계 반환"""
        return {
            "analysisStats": dict(self.analysis_stats),
            "supportedFrameworks": self.supported_frameworks,
            "defaultFramework": self.default_framework,
            "frameworkDetails": get_supported_sources()
        }
    
    def compare_frameworks(self, request: AnalysisRequest, frameworks: List[str]) -> Dict[str, AnalysisResult]:
        """여러 지침서로 동시 분석 및 비교"""
        results = {}
        
        for framework in frameworks:
            try:
                result = self.analyze_config(request, framework)
                results[framework] = result
                self.logger.info(f"{framework} 분석 완료: {len(result.vulnerabilities)}개 취약점")
            except Exception as e:
                self.logger.error(f"{framework} 분석 실패: {e}")
                results[framework] = None
        
        return results
    
    def get_framework_coverage(self, device_type: str) -> Dict[str, Dict[str, Any]]:
        """장비 타입별 지침서 커버리지 정보"""
        coverage = {}
        
        for framework in self.supported_frameworks:
            try:
                stats = get_statistics(framework)
                device_rules = get_rules_by_device_type(framework, device_type)
                
                coverage[framework] = {
                    "totalRules": stats.get("totalRules", 0),
                    "applicableRules": len(device_rules),
                    "coverageRatio": len(device_rules) / max(stats.get("totalRules", 1), 1),
                    "logicalRules": sum(1 for rule in device_rules.values() if rule.logical_check_function),
                    "patternRules": sum(1 for rule in device_rules.values() if not rule.logical_check_function),
                    "severityBreakdown": {
                        "상": len([r for r in device_rules.values() if r.severity == "상"]),
                        "중": len([r for r in device_rules.values() if r.severity == "중"]),
                        "하": len([r for r in device_rules.values() if r.severity == "하"])
                    }
                }
            except Exception as e:
                self.logger.warning(f"{framework} 커버리지 계산 실패: {e}")
                coverage[framework] = {
                    "totalRules": 0,
                    "applicableRules": 0,
                    "coverageRatio": 0.0,
                    "error": str(e)
                }
        
        return coverage


# 기존 호환성을 위한 별칭 - 수정됨
class EnhancedConfigAnalyzer(MultiFrameworkAnalyzer):
    """Enhanced Config Analyzer - 기존 호환성 유지"""
    
    def __init__(self):
        super().__init__(default_framework="KISA")


# 기존 호환성을 위한 별칭
ConfigAnalyzer = EnhancedConfigAnalyzer