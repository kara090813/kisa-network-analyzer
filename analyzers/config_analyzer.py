# -*- coding: utf-8 -*-
"""
analyzers/config_analyzer.py (개선된 버전)
네트워크 장비 설정 파일 분석 엔진 - 상세 정보 보존 및 통과 항목 추적

🔥 개선사항:
- 개별 취약점의 상세 정보 보존
- 정확한 라인 번호 제공
- 통과된 룰들도 추적하여 반환
- 통합 통계에서도 영향받는 항목들의 정보 유지
"""

import re
import time
from typing import List, Dict, Optional, Tuple, Any, Set
import logging
from collections import defaultdict

# 룰셋 직접 import (CIS 추가)
from rules.kisa_rules import (
    KISA_RULES,
    SecurityRule, 
    RuleCategory, 
    ConfigContext, 
    parse_config_context
)

# NW 룰셋 import
from rules.nw_rules import NW_RULES

# CIS 룰셋 import 추가
from rules.cis_rules import CIS_RULES

from models.analysis_request import AnalysisRequest
from models.analysis_response import (
    VulnerabilityIssue, 
    PassedRule,  # 🔥 새로 추가
    SkippedRule,  # 🔥 새로 추가
    AnalysisResult, 
    AnalysisStatistics,
    calculate_consolidated_statistics,
    enhance_vulnerability_with_line_info
)


class RuleLoader:
    """룰 로더 시스템 - 인라인 구현 (CIS 지원 완전 추가)"""
    
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
            'name': 'CIS Cisco IOS 12 Benchmark',
            'description': 'Center for Internet Security Cisco IOS 12 Benchmark v4.0.0',
            'version': 'v4.0.0',
            'coverage': 'Industry standard Cisco security benchmarks',
            'rules_count': len(CIS_RULES),
            'status': 'active'
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
        """지침서별 룰 로드 (CIS 지원 추가)"""
        framework = framework.upper()
        
        if framework == 'KISA':
            return KISA_RULES.copy()
        elif framework == 'NW':
            return NW_RULES.copy()
        elif framework == 'CIS':
            return CIS_RULES.copy()
        elif framework == 'NIST':
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


# 룰 로더 함수들을 전역으로 노출
def load_rules(framework: str) -> Dict[str, SecurityRule]:
    return RuleLoader.load_rules(framework)

def get_supported_sources() -> Dict[str, Dict]:
    return RuleLoader.get_supported_sources()

def get_source_info(framework: str) -> Dict:
    return RuleLoader.get_source_info(framework)

def get_statistics(framework: str) -> Dict[str, Any]:
    return RuleLoader.get_statistics(framework)


class MultiFrameworkAnalyzer:
    """🔥 개선된 다중 지침서 분석기 - 상세 정보 보존 및 통과 항목 추적"""
    
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
        
        self.logger.info(f"개선된 다중 지침서 분석기 초기화 완료 - 지원 지침서: {', '.join(self.supported_frameworks)}")
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
    
    def analyze_config(self, request: AnalysisRequest, framework: Optional[str] = None, 
                      use_consolidation: bool = True, include_passed: bool = False) -> AnalysisResult:
        """
        🔥 개선된 설정 파일 분석 - 상세 정보 보존 및 통과 항목 추적 옵션 추가
        
        Args:
            request: 분석 요청 객체
            framework: 사용할 지침서 (None이면 기본값 사용)
            use_consolidation: 통합 통계 사용 여부
            include_passed: 통과된 룰 정보 포함 여부 (🔥 새로운 옵션)
            
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
                           f"적용 룰: {len(device_rules)}개, "
                           f"통과 항목 포함: {include_passed}")
            
        except ValueError as e:
            self.logger.error(f"지원되지 않는 지침서: {target_framework}")
            raise ValueError(f"지원되지 않는 지침서: {target_framework}")
        except NotImplementedError as e:
            self.logger.error(f"구현되지 않은 지침서: {target_framework}")
            raise NotImplementedError(f"{target_framework} 지침서는 아직 구현되지 않았습니다")
        
        # 설정 컨텍스트 파싱 (모든 지침서에서 동일한 ConfigContext 사용)
        config_context = parse_config_context(request.config_text, request.device_type)
        
        # 룰 필터링 (특정 룰 지정된 경우)
        if not request.options.check_all_rules and request.options.specific_rule_ids:
            device_rules = {
                rule_id: rule for rule_id, rule in device_rules.items()
                if rule_id in request.options.specific_rule_ids
            }
            self.logger.info(f"특정 룰 필터링 적용: {len(device_rules)}개 룰")
        
        # 🔥 개선된 분석 실행 - 통과된 룰도 추적
        analysis_results = self._perform_enhanced_analysis_with_passed(
            request.get_config_lines(), 
            device_rules, 
            config_context, 
            request.options,
            target_framework,
            include_passed
        )
        
        raw_vulnerabilities = analysis_results['vulnerabilities']
        passed_rules = analysis_results['passed_rules'] if include_passed else []
        skipped_rules = analysis_results['skipped_rules'] if include_passed else []
        
        # 🔥 라인 번호 개선
        enhanced_vulnerabilities = []
        for vuln in raw_vulnerabilities:
            enhanced_vuln = enhance_vulnerability_with_line_info(vuln, request.get_config_lines())
            enhanced_vulnerabilities.append(enhanced_vuln)
        
        # 🔥 통합 통계 적용 (옵션)
        if use_consolidation:
            consolidation_result = calculate_consolidated_statistics(enhanced_vulnerabilities)
            final_vulnerabilities = consolidation_result['consolidated_vulnerabilities']
            
            # 통합 통계로 AnalysisStatistics 생성
            consolidated_stats = consolidation_result['statistics']
            statistics = AnalysisStatistics(
                total_rules_checked=len(device_rules),
                rules_passed=len(device_rules) - consolidated_stats['total_vulnerabilities'],
                rules_failed=consolidated_stats['total_vulnerabilities'],
                rules_skipped=len(skipped_rules),
                high_severity_issues=consolidated_stats['high_severity'],
                medium_severity_issues=consolidated_stats['medium_severity'],
                low_severity_issues=consolidated_stats['low_severity'],
                total_individual_findings=consolidated_stats['total_individual_findings'],
                consolidated_rules=consolidated_stats['consolidated_rules']
            )
            
            self.logger.info(f"통합 통계 적용 - 개별 발견: {consolidated_stats['total_individual_findings']}개, "
                           f"통합 룰: {consolidated_stats['consolidated_rules']}개")
        else:
            # 기존 방식으로 통계 생성
            final_vulnerabilities = enhanced_vulnerabilities
            statistics = self._generate_legacy_statistics(final_vulnerabilities, device_rules, len(skipped_rules))
        
        analysis_time = time.time() - start_time
        
        # 통계 업데이트
        self.analysis_stats['total_analyses'] += 1
        self.analysis_stats['framework_usage'][target_framework] += 1
        
        self.logger.info(f"분석 완료 - 지침서: {target_framework}, "
                        f"최종 취약점: {len(final_vulnerabilities)}개, "
                        f"통과된 룰: {len(passed_rules)}개, "
                        f"건너뛴 룰: {len(skipped_rules)}개, "
                        f"분석시간: {analysis_time:.2f}초")
        
        return AnalysisResult(
            vulnerabilities=final_vulnerabilities,
            passed_rules=passed_rules,
            skipped_rules=skipped_rules,
            analysis_time=analysis_time,
            statistics=statistics
        )
    
    def _perform_enhanced_analysis_with_passed(
        self, 
        config_lines: List[str], 
        rules: Dict[str, SecurityRule],
        context: ConfigContext,
        options,
        framework: str,
        include_passed: bool = False
    ) -> Dict[str, List]:
        """🔥 개선된 분석 수행 - 상세 정보 보존 및 통과된 룰 추적"""
        vulnerabilities = []
        passed_rules = []
        skipped_rules = []
        
        logical_rules_used = 0
        pattern_rules_used = 0
        
        for rule_id, rule in rules.items():
            rule_vulnerabilities = []
            rule_passed = False
            rule_skipped = False
            skip_reason = ""
            
            # 1. 논리 기반 분석 (우선순위)
            if rule.logical_check_function:
                try:
                    logical_results = rule.logical_check_function("", 0, context)
                    logical_rules_used += 1
                    
                    if logical_results:
                        # 취약점 발견
                        for result in logical_results:
                            # 🔥 개선된 취약점 객체 생성
                            issue = self._create_enhanced_vulnerability(
                                rule, result, framework, 'logical', options
                            )
                            rule_vulnerabilities.append(issue)
                    else:
                        # 논리 분석에서 취약점 없음 = 통과
                        rule_passed = True
                        
                except Exception as e:
                    self.logger.error(f"논리 기반 분석 오류 ({rule_id}): {e}")
                    self.logger.debug(f"오류 상세: {str(e)}", exc_info=True)
                    rule_skipped = True
                    skip_reason = f"Analysis error: {str(e)}"
            
            # 2. 패턴 매칭 분석 (논리 분석이 없는 경우)
            elif rule.patterns:
                pattern_rules_used += 1
                
                found_vulnerability = False
                found_safe_pattern = False
                
                for line_num, line in enumerate(config_lines, 1):
                    if not line.strip() or line.strip().startswith('!'):
                        continue
                    
                    # Negative 패턴 확인 (양호한 상태)
                    is_safe = any(neg_pattern.search(line) for neg_pattern in rule.compiled_negative_patterns)
                    if is_safe:
                        found_safe_pattern = True
                        continue
                    
                    # 취약점 패턴 확인
                    for pattern in rule.compiled_patterns:
                        match = pattern.search(line)
                        if match:
                            found_vulnerability = True
                            # 🔥 패턴 매칭 결과도 개선된 형태로 생성
                            pattern_result = {
                                'line': line_num,
                                'matched_text': match.group(0),
                                'details': {
                                    'pattern_matched': pattern.pattern,
                                    'full_line': line.strip(),
                                    'match_position': match.span()
                                }
                            }
                            
                            issue = self._create_enhanced_vulnerability(
                                rule, pattern_result, framework, 'pattern', options
                            )
                            rule_vulnerabilities.append(issue)
                            break
                
                # 패턴 분석 결과 판단
                if not found_vulnerability:
                    if found_safe_pattern:
                        rule_passed = True
                    else:
                        # 패턴을 찾지 못함 - 설정이 없는 경우로 판단
                        # 룰의 특성에 따라 이것이 취약점인지 양호한 상태인지 결정
                        if self._is_rule_pass_when_no_config(rule_id):
                            rule_passed = True
                        else:
                            # 기본값이 취약한 경우 - 설정이 없으면 취약점
                            default_vuln_result = {
                                'line': 0,
                                'matched_text': 'Configuration not found (default may be vulnerable)',
                                'details': {
                                    'analysis_type': 'default_check',
                                    'issue': 'missing_configuration'
                                }
                            }
                            issue = self._create_enhanced_vulnerability(
                                rule, default_vuln_result, framework, 'default', options
                            )
                            rule_vulnerabilities.append(issue)
            else:
                # 패턴도 논리 함수도 없는 룰
                rule_skipped = True
                skip_reason = "No analysis method defined"
            
            # 결과 분류
            if rule_vulnerabilities:
                vulnerabilities.extend(rule_vulnerabilities)
            elif rule_passed and include_passed:
                # 🔥 통과된 룰 정보 생성
                passed_rule = PassedRule(
                    rule_id=rule.rule_id,
                    title=rule.title,
                    description=rule.description,
                    severity=rule.severity,
                    category=rule.category.value,
                    reference=rule.reference,
                    reason="Configuration compliant",
                    analysis_details={
                        'analysis_type': 'logical' if rule.logical_check_function else 'pattern',
                        'framework': framework,
                        'check_passed': True
                    }
                )
                passed_rules.append(passed_rule)
            elif rule_skipped and include_passed:
                # 🔥 건너뛴 룰 정보 생성
                skipped_rule = SkippedRule(
                    rule_id=rule.rule_id,
                    title=rule.title,
                    description=rule.description,
                    severity=rule.severity,
                    category=rule.category.value,
                    reference=rule.reference,
                    reason=skip_reason
                )
                skipped_rules.append(skipped_rule)
        
        self.logger.info(f"분석 상세 - 논리 룰: {logical_rules_used}개, 패턴 룰: {pattern_rules_used}개, "
                        f"통과: {len(passed_rules)}개, 건너뜀: {len(skipped_rules)}개")
        
        return {
            'vulnerabilities': vulnerabilities,
            'passed_rules': passed_rules,
            'skipped_rules': skipped_rules
        }
    
    def _is_rule_pass_when_no_config(self, rule_id: str) -> bool:
        """룰별로 설정이 없을 때 통과로 처리할지 결정"""
        # 서비스 비활성화 관련 룰들 - 설정이 없으면 기본값으로 비활성화되므로 통과
        pass_when_no_config_rules = [
            'N-11', 'N-25', 'N-26', 'N-27', 'N-28', 'N-29', 'N-34', 'N-35', 'N-36',  # KISA
            'NW-20', 'NW-25', 'NW-26', 'NW-27', 'NW-28', 'NW-29', 'NW-34', 'NW-35', 'NW-36',  # NW
            'CIS-2.1.3', 'CIS-2.1.4', 'CIS-2.1.5', 'CIS-2.1.8'  # CIS
        ]
        
        return rule_id in pass_when_no_config_rules
    
    def _create_enhanced_vulnerability(self, rule: SecurityRule, result: Dict[str, Any], 
                                     framework: str, analysis_type: str, options) -> VulnerabilityIssue:
        """🔥 개선된 취약점 객체 생성"""
        
        # 기본 정보 추출
        line_number = result.get('line', 0)
        matched_text = result.get('matched_text', '')
        details = result.get('details', {})
        
        # 심각도 조정 (분석 상세 정보에서 조정된 심각도가 있는 경우)
        severity = details.get('severity_adjusted', rule.severity)
        
        # 상세 분석 정보 구성
        analysis_details = {
            'analysis_type': analysis_type,
            'framework': framework,
            'rule_category': rule.category.value,
            'original_line': line_number,
            **details
        }
        
        # 영향받는 항목 정보 구성
        affected_items = None
        summary_info = None
        
        if details:
            # 인터페이스 관련 정보
            if 'interface_name' in details:
                affected_items = [{
                    'type': 'interface',
                    'name': details['interface_name'],
                    'line': line_number
                }]
                summary_info = {
                    'affected_type': 'interface',
                    'affected_list': [details['interface_name']],
                    'total_affected': 1
                }
            
            # 사용자 관련 정보
            elif 'username' in details:
                affected_items = [{
                    'type': 'user',
                    'name': details['username'],
                    'line': line_number
                }]
                summary_info = {
                    'affected_type': 'user',
                    'affected_list': [details['username']],
                    'total_affected': 1
                }
            
            # 서비스 관련 정보
            elif 'service_name' in details:
                affected_items = [{
                    'type': 'service',
                    'name': details['service_name'],
                    'line': line_number
                }]
                summary_info = {
                    'affected_type': 'service',
                    'affected_list': [details['service_name']],
                    'total_affected': 1
                }
        
        return VulnerabilityIssue(
            rule_id=rule.rule_id,
            severity=severity,
            line=line_number,
            matched_text=matched_text,
            description=rule.description,
            recommendation=details.get('recommendation', rule.recommendation),
            reference=rule.reference,
            category=rule.category.value,
            raw_match=result.get('matched_text') if options.return_raw_matches else None,
            affected_items=affected_items,
            summary_info=summary_info,
            analysis_details=analysis_details
        )
    
    def _generate_legacy_statistics(
        self, 
        vulnerabilities: List[VulnerabilityIssue], 
        rules: Dict[str, SecurityRule],
        skipped_count: int = 0
    ) -> AnalysisStatistics:
        """기존 방식의 분석 통계 생성"""
        severity_counts = {"상": 0, "중": 0, "하": 0}
        
        for vuln in vulnerabilities:
            if vuln.severity in severity_counts:
                severity_counts[vuln.severity] += 1
        
        failed_rule_ids = set(vuln.rule_id for vuln in vulnerabilities)
        rules_failed = len(failed_rule_ids)
        rules_passed = len(rules) - rules_failed - skipped_count
        
        return AnalysisStatistics(
            total_rules_checked=len(rules),
            rules_passed=max(0, rules_passed),  # 음수 방지
            rules_failed=rules_failed,
            rules_skipped=skipped_count,
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
    
    def analyze_single_line(self, line: str, device_type: str, rule_ids: Optional[List[str]] = None, 
                          framework: str = None) -> List[VulnerabilityIssue]:
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
                            pattern_result = {
                                'line': 1,
                                'matched_text': match.group(0),
                                'details': {
                                    'pattern_matched': pattern.pattern,
                                    'full_line': line.strip()
                                }
                            }
                            
                            # 단순한 옵션 객체 생성
                            simple_options = type('Options', (), {'return_raw_matches': False})()
                            
                            issue = self._create_enhanced_vulnerability(
                                rule, pattern_result, target_framework, 'pattern', simple_options
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
            "defaultFramework": self.default_framework,
            "frameworkDetails": get_supported_sources()
        }


# 기존 호환성을 위한 별칭
class EnhancedConfigAnalyzer(MultiFrameworkAnalyzer):
    """Enhanced Config Analyzer - 기존 호환성 유지"""
    
    def __init__(self):
        super().__init__(default_framework="KISA")


# 기존 호환성을 위한 별칭
ConfigAnalyzer = EnhancedConfigAnalyzer