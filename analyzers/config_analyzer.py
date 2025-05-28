# -*- coding: utf-8 -*-
"""
analyzers/config_analyzer.py (Enhanced Multi-Framework Version - Step 2)
네트워크 장비 설정 파일 분석 엔진 - 지침서 조합 분석 기능 추가

새로운 기능:
- 다중 지침서 동시 분석 (Combined Analysis)
- 지침서별 결과 비교 (Comparison Analysis)  
- 중복 제거 및 우선순위 처리
- 지침서별 가중치 적용
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
    get_supported_sources
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
    """다중 지침서 분석기 - 지침서 조합 및 비교 분석 지원"""
    
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
        
        # 지침서별 가중치 설정 (우선순위)
        self.framework_weights = {
            "KISA": 1.0,    # 국내 표준이므로 기본 가중치
            "CIS": 0.9,     # 국제 표준이지만 국내 환경에서는 보조
            "NIST": 0.8     # 향후 추가 시
        }
        
        # 분석 통계
        self.analysis_stats = {
            'total_analyses': 0,
            'single_framework_analyses': 0,
            'multi_framework_analyses': 0,
            'comparison_analyses': 0,
            'framework_usage': defaultdict(int)
        }
        
        self.logger.info(f"다중 지침서 분석기 초기화 완료 - 지원 지침서: {', '.join(self.supported_frameworks)}")
    
    def analyze_config_multi_framework(
        self, 
        request: AnalysisRequest, 
        frameworks: List[str],
        analysis_mode: str = "combined"
    ) -> Dict[str, Any]:
        """
        다중 지침서를 사용한 설정 분석
        
        Args:
            request: 분석 요청 객체
            frameworks: 사용할 지침서 목록
            analysis_mode: 분석 모드 ("combined" or "comparison")
            
        Returns:
            Dict: 다중 지침서 분석 결과
        """
        start_time = time.time()
        
        # 지침서 유효성 검증
        valid_frameworks = self._validate_frameworks(frameworks)
        if not valid_frameworks:
            raise ValueError(f"유효한 지침서가 없습니다: {frameworks}")
        
        # 설정 컨텍스트 파싱
        config_context = parse_config_context(request.config_text, request.device_type)
        
        # 분석 모드별 처리
        if analysis_mode == "combined":
            result = self._analyze_combined(request, valid_frameworks, config_context)
        elif analysis_mode == "comparison":
            result = self._analyze_comparison(request, valid_frameworks, config_context)
        else:
            raise ValueError(f"지원되지 않는 분석 모드: {analysis_mode}")
        
        # 분석 시간 추가
        result["analysisTime"] = time.time() - start_time
        result["analysisMode"] = analysis_mode
        result["frameworks"] = valid_frameworks
        
        # 통계 업데이트
        self.analysis_stats['total_analyses'] += 1
        self.analysis_stats['multi_framework_analyses'] += 1
        if analysis_mode == "comparison":
            self.analysis_stats['comparison_analyses'] += 1
        
        for framework in valid_frameworks:
            self.analysis_stats['framework_usage'][framework] += 1
        
        self.logger.info(f"다중 지침서 분석 완료 - 모드: {analysis_mode}, "
                        f"지침서: {', '.join(valid_frameworks)}, "
                        f"분석시간: {result['analysisTime']:.2f}초")
        
        return result
    
    def _analyze_combined(
        self, 
        request: AnalysisRequest, 
        frameworks: List[str], 
        context: ConfigContext
    ) -> Dict[str, Any]:
        """
        지침서 조합 분석 - 여러 지침서의 룰을 합쳐서 하나의 결과로 제공
        """
        # 모든 지침서의 룰을 수집
        combined_rules = {}
        framework_rule_mapping = {}  # 룰 ID -> 지침서 매핑
        
        for framework in frameworks:
            try:
                framework_rules = get_rules_by_device_type(framework, request.device_type)
                
                for rule_id, rule in framework_rules.items():
                    # 중복 룰 처리 (같은 ID의 룰이 여러 지침서에 있는 경우)
                    combined_rule_id = f"{framework}-{rule_id}"
                    combined_rules[combined_rule_id] = rule
                    framework_rule_mapping[combined_rule_id] = framework
                    
            except (ValueError, NotImplementedError) as e:
                self.logger.warning(f"지침서 {framework} 로드 실패: {e}")
                continue
        
        # 조합된 룰로 분석 수행
        vulnerabilities = self._perform_combined_analysis(
            request.get_config_lines(), 
            combined_rules, 
            context, 
            request.options,
            framework_rule_mapping
        )
        
        # 중복 제거 및 우선순위 적용
        deduplicated_vulnerabilities = self._deduplicate_vulnerabilities(
            vulnerabilities, 
            framework_rule_mapping
        )
        
        # 통계 생성
        statistics = self._generate_combined_statistics(
            deduplicated_vulnerabilities, 
            combined_rules, 
            frameworks
        )
        
        return {
            "success": True,
            "deviceType": request.device_type,
            "totalLines": len(request.get_config_lines()),
            "issuesFound": len(deduplicated_vulnerabilities),
            "results": [vuln.to_dict() for vuln in deduplicated_vulnerabilities],
            "statistics": statistics.to_dict(),
            "frameworkDetails": self._get_framework_analysis_details(frameworks, combined_rules),
            "deduplicationInfo": {
                "originalIssues": len(vulnerabilities),
                "deduplicatedIssues": len(deduplicated_vulnerabilities),
                "reductionPercentage": round((1 - len(deduplicated_vulnerabilities) / max(len(vulnerabilities), 1)) * 100, 1)
            }
        }
    
    def _analyze_comparison(
        self, 
        request: AnalysisRequest, 
        frameworks: List[str], 
        context: ConfigContext
    ) -> Dict[str, Any]:
        """
        지침서 비교 분석 - 각 지침서별로 분석하여 결과를 비교
        """
        framework_results = {}
        all_vulnerabilities = []
        
        # 각 지침서별로 개별 분석
        for framework in frameworks:
            try:
                framework_rules = get_rules_by_device_type(framework, request.device_type)
                
                # 개별 분석 수행
                framework_vulnerabilities = self._perform_framework_analysis(
                    request.get_config_lines(),
                    framework_rules,
                    context,
                    request.options,
                    framework
                )
                
                # 지침서별 통계
                framework_stats = self._generate_framework_statistics(
                    framework_vulnerabilities, 
                    framework_rules
                )
                
                framework_results[framework] = {
                    "framework": framework,
                    "issuesFound": len(framework_vulnerabilities),
                    "results": [vuln.to_dict() for vuln in framework_vulnerabilities],
                    "statistics": framework_stats.to_dict(),
                    "rulesCovered": len(framework_rules)
                }
                
                all_vulnerabilities.extend(framework_vulnerabilities)
                
            except (ValueError, NotImplementedError) as e:
                self.logger.warning(f"지침서 {framework} 분석 실패: {e}")
                framework_results[framework] = {
                    "framework": framework,
                    "error": str(e),
                    "issuesFound": 0,
                    "results": [],
                    "statistics": {},
                    "rulesCovered": 0
                }
        
        # 비교 분석 결과 생성
        comparison_analysis = self._generate_comparison_analysis(framework_results)
        
        return {
            "success": True,
            "deviceType": request.device_type,
            "totalLines": len(request.get_config_lines()),
            "frameworkResults": framework_results,
            "comparisonAnalysis": comparison_analysis,
            "summary": {
                "totalFrameworks": len(frameworks),
                "successfulAnalyses": len([r for r in framework_results.values() if "error" not in r]),
                "totalUniqueIssues": len(self._get_unique_issues(all_vulnerabilities)),
                "mostStrictFramework": self._get_most_strict_framework(framework_results),
                "consensusIssues": self._get_consensus_issues(framework_results)
            }
        }
    
    def _perform_combined_analysis(
        self, 
        config_lines: List[str], 
        rules: Dict[str, SecurityRule],
        context: ConfigContext,
        options,
        framework_mapping: Dict[str, str]
    ) -> List[VulnerabilityIssue]:
        """조합 분석 수행"""
        vulnerabilities = []
        
        for rule_id, rule in rules.items():
            framework = framework_mapping[rule_id]
            rule_vulnerabilities = []
            
            # 논리 기반 분석
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
                        issue_dict['combinedRuleId'] = rule_id
                        
                        # VulnerabilityIssue 객체 재생성 (framework 정보 포함)
                        enhanced_issue = VulnerabilityIssue.from_dict(issue_dict)
                        rule_vulnerabilities.append(enhanced_issue)
                        
                except Exception as e:
                    self.logger.error(f"논리 기반 분석 오류 ({rule_id}): {e}")
            
            # 패턴 매칭 분석
            elif rule.patterns:
                for line_num, line in enumerate(config_lines, 1):
                    if not line.strip() or line.strip().startswith('!'):
                        continue
                    
                    # Negative 패턴 확인
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
                            issue_dict['combinedRuleId'] = rule_id
                            
                            enhanced_issue = VulnerabilityIssue.from_dict(issue_dict)
                            rule_vulnerabilities.append(enhanced_issue)
                            break
            
            vulnerabilities.extend(rule_vulnerabilities)
        
        return vulnerabilities
    
    def _perform_framework_analysis(
        self, 
        config_lines: List[str], 
        rules: Dict[str, SecurityRule],
        context: ConfigContext,
        options,
        framework: str
    ) -> List[VulnerabilityIssue]:
        """개별 지침서 분석 수행"""
        # 기존 단일 지침서 분석 로직과 동일하지만 framework 정보 추가
        vulnerabilities = []
        
        for rule_id, rule in rules.items():
            # 논리 기반 또는 패턴 매칭 분석 (위와 동일한 로직)
            # 각 취약점에 framework 정보 추가
            pass  # 실제 구현은 _perform_combined_analysis와 유사
        
        return vulnerabilities
    
    def _deduplicate_vulnerabilities(
        self, 
        vulnerabilities: List[VulnerabilityIssue], 
        framework_mapping: Dict[str, str]
    ) -> List[VulnerabilityIssue]:
        """
        중복 취약점 제거 및 우선순위 적용
        
        같은 라인, 같은 내용의 취약점이 여러 지침서에서 발견되는 경우 우선순위가 높은 것만 유지
        """
        # 취약점을 키로 그룹화 (라인 번호 + 매치된 텍스트)
        vulnerability_groups = defaultdict(list)
        
        for vuln in vulnerabilities:
            # 중복 판단 키 생성
            key = (vuln.line, vuln.matched_text[:50], vuln.rule_id.split('-')[0])  # 룰 기본 ID 사용
            vulnerability_groups[key].append(vuln)
        
        deduplicated = []
        
        for key, group in vulnerability_groups.items():
            if len(group) == 1:
                # 중복 없음
                deduplicated.append(group[0])
            else:
                # 중복 있음 - 우선순위가 높은 지침서 선택
                best_vuln = min(group, key=lambda v: self._get_framework_priority(
                    framework_mapping.get(getattr(v, 'combinedRuleId', v.rule_id), 'UNKNOWN')
                ))
                
                # 중복 정보 추가
                best_vuln_dict = best_vuln.to_dict()
                best_vuln_dict['duplicateInfo'] = {
                    'isDuplicate': True,
                    'duplicateCount': len(group),
                    'alternativeFrameworks': [
                        framework_mapping.get(getattr(v, 'combinedRuleId', v.rule_id), 'UNKNOWN') 
                        for v in group if v != best_vuln
                    ]
                }
                
                enhanced_vuln = VulnerabilityIssue.from_dict(best_vuln_dict)
                deduplicated.append(enhanced_vuln)
        
        return sorted(deduplicated, key=lambda v: (v.line, v.rule_id))
    
    def _get_framework_priority(self, framework: str) -> int:
        """지침서 우선순위 반환 (낮을수록 높은 우선순위)"""
        priority_map = {
            "KISA": 0,   # 최고 우선순위
            "CIS": 1,
            "NIST": 2
        }
        return priority_map.get(framework, 999)
    
    def _generate_combined_statistics(
        self, 
        vulnerabilities: List[VulnerabilityIssue], 
        rules: Dict[str, SecurityRule],
        frameworks: List[str]
    ) -> AnalysisStatistics:
        """조합 분석 통계 생성"""
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
    
    def _generate_framework_statistics(
        self, 
        vulnerabilities: List[VulnerabilityIssue], 
        rules: Dict[str, SecurityRule]
    ) -> AnalysisStatistics:
        """개별 지침서 통계 생성"""
        return self._generate_combined_statistics(vulnerabilities, rules, [])
    
    def _generate_comparison_analysis(
        self, 
        framework_results: Dict[str, Dict]
    ) -> Dict[str, Any]:
        """비교 분석 결과 생성"""
        # 각 지침서별 취약점 심각도 분포
        severity_comparison = {}
        issue_overlap = {}
        
        for framework, result in framework_results.items():
            if "error" not in result:
                stats = result.get("statistics", {})
                severity_comparison[framework] = {
                    "high": stats.get("highSeverityIssues", 0),
                    "medium": stats.get("mediumSeverityIssues", 0),
                    "low": stats.get("lowSeverityIssues", 0),
                    "total": result.get("issuesFound", 0)
                }
        
        # 지침서 간 취약점 중복도 계산
        frameworks = list(framework_results.keys())
        for i, fw1 in enumerate(frameworks):
            for fw2 in frameworks[i+1:]:
                if "error" not in framework_results[fw1] and "error" not in framework_results[fw2]:
                    overlap = self._calculate_issue_overlap(
                        framework_results[fw1]["results"],
                        framework_results[fw2]["results"]
                    )
                    issue_overlap[f"{fw1}-{fw2}"] = overlap
        
        return {
            "severityComparison": severity_comparison,
            "issueOverlap": issue_overlap,
            "recommendations": self._generate_comparison_recommendations(framework_results)
        }
    
    def _calculate_issue_overlap(self, results1: List[Dict], results2: List[Dict]) -> Dict[str, Any]:
        """두 지침서 결과 간 중복도 계산"""
        # 간단한 중복도 계산 (라인 번호 기준)
        lines1 = set(r["line"] for r in results1)
        lines2 = set(r["line"] for r in results2)
        
        common_lines = lines1 & lines2
        total_lines = lines1 | lines2
        
        overlap_percentage = (len(common_lines) / len(total_lines) * 100) if total_lines else 0
        
        return {
            "commonIssues": len(common_lines),
            "totalUniqueIssues": len(total_lines),
            "overlapPercentage": round(overlap_percentage, 1)
        }
    
    def _generate_comparison_recommendations(self, framework_results: Dict) -> List[str]:
        """비교 분석 기반 추천사항 생성"""
        recommendations = []
        
        successful_frameworks = [fw for fw, result in framework_results.items() if "error" not in result]
        
        if len(successful_frameworks) > 1:
            # 가장 엄격한 지침서 찾기
            strictest = max(successful_frameworks, 
                          key=lambda fw: framework_results[fw]["issuesFound"])
            recommendations.append(f"{strictest} 지침서가 가장 엄격한 보안 기준을 적용했습니다")
            
            # 모든 지침서에서 공통으로 발견된 취약점에 우선 대응 권장
            recommendations.append("모든 지침서에서 공통으로 발견된 취약점을 우선적으로 해결하세요")
            
            # 조합 분석 권장
            recommendations.append("더 포괄적인 보안 점검을 위해 조합 분석(combined mode)을 권장합니다")
        
        return recommendations
    
    def _validate_frameworks(self, frameworks: List[str]) -> List[str]:
        """지침서 유효성 검증"""
        valid_frameworks = []
        
        for framework in frameworks:
            framework = framework.upper()
            try:
                load_rules(framework)
                valid_frameworks.append(framework)
            except (ValueError, NotImplementedError):
                self.logger.warning(f"지침서 {framework}는 사용할 수 없습니다")
        
        return valid_frameworks
    
    def _get_framework_analysis_details(self, frameworks: List[str], rules: Dict) -> Dict:
        """지침서별 분석 상세 정보"""
        details = {}
        
        for framework in frameworks:
            framework_rules = [rule_id for rule_id in rules.keys() if rule_id.startswith(framework)]
            details[framework] = {
                "rulesApplied": len(framework_rules),
                "weight": self.framework_weights.get(framework, 1.0),
                "status": "active"
            }
        
        return details
    
    def _get_unique_issues(self, vulnerabilities: List[VulnerabilityIssue]) -> List[VulnerabilityIssue]:
        """고유한 취약점 목록 반환"""
        seen = set()
        unique = []
        
        for vuln in vulnerabilities:
            key = (vuln.line, vuln.matched_text[:50])
            if key not in seen:
                seen.add(key)
                unique.append(vuln)
        
        return unique
    
    def _get_most_strict_framework(self, framework_results: Dict) -> str:
        """가장 엄격한 지침서 반환"""
        max_issues = 0
        strictest = None
        
        for framework, result in framework_results.items():
            if "error" not in result and result["issuesFound"] > max_issues:
                max_issues = result["issuesFound"]
                strictest = framework
        
        return strictest or "Unknown"
    
    def _get_consensus_issues(self, framework_results: Dict) -> int:
        """모든 지침서에서 공통으로 발견된 취약점 수"""
        # 간단한 구현 - 실제로는 더 정교한 매칭 필요
        successful_results = [r for r in framework_results.values() if "error" not in r]
        
        if len(successful_results) < 2:
            return 0
        
        # 모든 결과에서 공통 라인 찾기
        common_lines = set(r["line"] for r in successful_results[0]["results"])
        
        for result in successful_results[1:]:
            result_lines = set(r["line"] for r in result["results"])
            common_lines &= result_lines
        
        return len(common_lines)
    
    def get_analysis_statistics(self) -> Dict[str, Any]:
        """분석 통계 반환"""
        return {
            "analysisStats": dict(self.analysis_stats),
            "supportedFrameworks": self.supported_frameworks,
            "frameworkWeights": self.framework_weights
        }


# 기존 호환성을 위한 별칭
EnhancedConfigAnalyzer = MultiFrameworkAnalyzer
ConfigAnalyzer = MultiFrameworkAnalyzer