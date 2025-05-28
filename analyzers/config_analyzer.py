# -*- coding: utf-8 -*-
"""
analyzers/config_analyzer.py (Enhanced Version - Multi-Framework Support)
네트워크 장비 설정 파일 분석 엔진 - 논리 기반 분석 강화 및 다중 지침서 지원

기존 정규식 매칭과 논리 기반 판단을 결합한 고도화된 분석 엔진
복잡한 조건 분석 및 컨텍스트 기반 취약점 탐지 지원
KISA, CIS, NIST 등 다중 지침서 지원
"""

import re
import time
from typing import List, Dict, Optional, Tuple, Any
import logging

# 새로운 룰 로더 시스템 import
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


class EnhancedConfigAnalyzer:
    """네트워크 장비 설정 파일 분석기 - 논리 기반 분석 강화 및 다중 지침서 지원"""
    
    def __init__(self, default_framework: str = "KISA"):
        """
        분석기 초기화
        
        Args:
            default_framework: 기본 사용할 지침서 (KISA, CIS, NIST 등)
        """
        self.logger = logging.getLogger(__name__)
        self.default_framework = default_framework.upper()
        
        # 기본 지침서 룰 로드
        try:
            self.rules = load_rules(self.default_framework)
            self.logger.info(f"기본 지침서 '{self.default_framework}' 룰 로드 완료: {len(self.rules)}개")
        except (ValueError, NotImplementedError) as e:
            self.logger.warning(f"기본 지침서 '{self.default_framework}' 로드 실패: {e}")
            # KISA로 폴백
            self.default_framework = "KISA"
            self.rules = load_rules("KISA")
            self.logger.info(f"KISA 지침서로 폴백: {len(self.rules)}개 룰 로드")
        
        # 분석 통계
        self.analysis_stats = {
            'total_analyses': 0,
            'logical_analyses': 0,
            'pattern_analyses': 0,
            'hybrid_analyses': 0,
            'framework_usage': {}
        }
        
    def analyze_config(self, request: AnalysisRequest, framework: Optional[str] = None) -> AnalysisResult:
        """
        설정 파일 분석 메인 함수 - 다중 지침서 지원
        
        Args:
            request: 분석 요청 객체
            framework: 사용할 지침서 (None이면 기본 지침서 사용)
            
        Returns:
            AnalysisResult: 분석 결과
        """
        start_time = time.time()
        
        # 사용할 지침서 결정
        target_framework = framework or self.default_framework
        target_framework = target_framework.upper()
        
        # 지침서 룰셋 로드
        try:
            applicable_rules = self._get_applicable_rules(request, target_framework)
        except (ValueError, NotImplementedError) as e:
            self.logger.error(f"지침서 '{target_framework}' 룰 로드 실패: {e}")
            # 기본 지침서로 폴백
            target_framework = self.default_framework
            applicable_rules = self._get_applicable_rules(request, target_framework)
        
        # 설정 컨텍스트 파싱 (논리 기반 분석을 위한 사전 처리)
        config_context = parse_config_context(request.config_text, request.device_type)
        
        # 하이브리드 분석 실행
        vulnerabilities = self._hybrid_analyze_config(
            request.get_config_lines(), 
            applicable_rules,
            config_context,
            request.options
        )
        
        # 분석 시간 계산
        analysis_time = time.time() - start_time
        
        # 통계 정보 생성
        statistics = self._generate_statistics(vulnerabilities, applicable_rules)
        
        # 분석 통계 업데이트
        self.analysis_stats['total_analyses'] += 1
        self.analysis_stats['framework_usage'][target_framework] = \
            self.analysis_stats['framework_usage'].get(target_framework, 0) + 1
        
        self.logger.info(
            f"다중 지침서 분석 완료 - 지침서: {target_framework}, "
            f"장비: {request.device_type}, "
            f"적용 룰: {len(applicable_rules)}개, "
            f"발견 취약점: {len(vulnerabilities)}개, "
            f"분석 시간: {analysis_time:.2f}초"
        )
        
        return AnalysisResult(
            vulnerabilities=vulnerabilities,
            analysis_time=analysis_time,
            statistics=statistics
        )
    
    def _hybrid_analyze_config(
        self, 
        config_lines: List[str], 
        rules: Dict[str, SecurityRule],
        config_context: ConfigContext,
        options
    ) -> List[VulnerabilityIssue]:
        """하이브리드 분석: 논리 기반 + 패턴 매칭"""
        vulnerabilities = []
        
        for rule_id, rule in rules.items():
            rule_vulnerabilities = []
            
            # 1. 논리 기반 분석 (우선순위)
            if rule.logical_check_function:
                logical_vulns = self._perform_logical_analysis(rule, config_context, options)
                rule_vulnerabilities.extend(logical_vulns)
                self.analysis_stats['logical_analyses'] += 1
            
            # 2. 기본 패턴 매칭 분석 (논리 기반이 없는 경우)
            elif rule.patterns:
                pattern_vulns = self._perform_pattern_analysis(rule, config_lines, config_context, options)
                rule_vulnerabilities.extend(pattern_vulns)
                self.analysis_stats['pattern_analyses'] += 1
            
            # 3. 하이브리드 분석 (둘 다 있는 경우)
            else:
                # 논리 기반과 패턴 매칭 결과를 결합
                logical_vulns = self._perform_logical_analysis(rule, config_context, options) if rule.logical_check_function else []
                pattern_vulns = self._perform_pattern_analysis(rule, config_lines, config_context, options) if rule.patterns else []
                
                # 중복 제거하면서 결합
                combined_vulns = self._merge_vulnerability_results(logical_vulns, pattern_vulns)
                rule_vulnerabilities.extend(combined_vulns)
                self.analysis_stats['hybrid_analyses'] += 1
            
            vulnerabilities.extend(rule_vulnerabilities)
        
        # 전역 분석 (설정 누락 검사)
        global_vulnerabilities = self._perform_global_analysis(config_context, rules, options)
        vulnerabilities.extend(global_vulnerabilities)
        
        # 중복 제거 및 정렬
        unique_vulnerabilities = self._remove_duplicates(vulnerabilities)
        
        return unique_vulnerabilities
    
    def _perform_logical_analysis(
        self, 
        rule: SecurityRule, 
        context: ConfigContext, 
        options
    ) -> List[VulnerabilityIssue]:
        """논리 기반 분석 수행"""
        vulnerabilities = []
        
        try:
            # 논리 기반 체크 함수 호출
            logical_results = rule.logical_check_function("", 0, context)
            
            for result in logical_results:
                issue = VulnerabilityIssue(
                    rule_id=rule.rule_id,
                    severity=rule.severity,
                    line=result.get('line', 0),
                    matched_text=result.get('matched_text', ''),
                    description=self._enhance_description(rule.description, result.get('details', {})),
                    recommendation=self._get_device_specific_recommendation(rule, context.device_type),
                    reference=rule.reference,
                    category=rule.category.value,
                    raw_match=result.get('matched_text') if options.return_raw_matches else None
                )
                
                vulnerabilities.append(issue)
                
        except Exception as e:
            self.logger.error(f"논리 기반 분석 오류 (룰 {rule.rule_id}): {e}")
        
        return vulnerabilities
    
    def _perform_pattern_analysis(
        self, 
        rule: SecurityRule, 
        config_lines: List[str], 
        context: ConfigContext, 
        options
    ) -> List[VulnerabilityIssue]:
        """기존 패턴 매칭 분석 수행"""
        vulnerabilities = []
        
        for line_num, line in enumerate(config_lines, 1):
            # 빈 라인이나 주석 라인 스킵
            if not line.strip() or line.strip().startswith('!'):
                continue
            
            # negative 패턴 확인 (양호한 상태)
            is_safe = False
            for neg_pattern in rule.compiled_negative_patterns:
                if neg_pattern.search(line):
                    is_safe = True
                    break
            
            if is_safe:
                continue
            
            # 취약점 패턴 확인
            for pattern in rule.compiled_patterns:
                match = pattern.search(line)
                if match:
                    # 장비별 특화 검증
                    if self._is_device_specific_vulnerable(line, rule, context.device_type):
                        matched_text = match.group(0)
                        
                        issue = VulnerabilityIssue(
                            rule_id=rule.rule_id,
                            severity=rule.severity,
                            line=line_num,
                            matched_text=matched_text,
                            description=rule.description,
                            recommendation=self._get_device_specific_recommendation(rule, context.device_type),
                            reference=rule.reference,
                            category=rule.category.value,
                            raw_match=line.strip() if options.return_raw_matches else None
                        )
                        
                        vulnerabilities.append(issue)
                        break  # 첫 번째 매치만 보고
        
        return vulnerabilities
    
    def _perform_global_analysis(
        self, 
        context: ConfigContext, 
        rules: Dict[str, SecurityRule], 
        options
    ) -> List[VulnerabilityIssue]:
        """전역 분석 (설정 누락 등)"""
        vulnerabilities = []
        
        # 필수 설정 누락 검사
        missing_config_rules = {
            "N-18": self._check_banner_missing,
            "N-19": self._check_logging_server_missing,
            "N-22": self._check_ntp_missing,
            "N-23": self._check_timestamp_missing,
        }
        
        for rule_id, check_func in missing_config_rules.items():
            if rule_id in rules:
                rule = rules[rule_id]
                try:
                    missing_issues = check_func(context, rule)
                    vulnerabilities.extend(missing_issues)
                except Exception as e:
                    self.logger.error(f"전역 분석 오류 (룰 {rule_id}): {e}")
        
        return vulnerabilities
    
    def _merge_vulnerability_results(
        self, 
        logical_vulns: List[VulnerabilityIssue], 
        pattern_vulns: List[VulnerabilityIssue]
    ) -> List[VulnerabilityIssue]:
        """논리 기반과 패턴 매칭 결과 병합"""
        # 논리 기반 결과를 우선하되, 패턴 매칭에서만 발견된 것도 포함
        merged = list(logical_vulns)
        
        for pattern_vuln in pattern_vulns:
            # 같은 라인에서 같은 룰로 이미 발견되지 않았으면 추가
            is_duplicate = any(
                logical_vuln.rule_id == pattern_vuln.rule_id and 
                logical_vuln.line == pattern_vuln.line
                for logical_vuln in logical_vulns
            )
            
            if not is_duplicate:
                merged.append(pattern_vuln)
        
        return merged
    
    def _enhance_description(self, base_description: str, details: Dict[str, Any]) -> str:
        """상세 정보를 포함하여 설명 강화"""
        if not details:
            return base_description
        
        enhanced = base_description
        
        # 세부 정보 추가
        if 'interface_name' in details:
            enhanced += f" (인터페이스: {details['interface_name']})"
        
        if 'reason' in details:
            enhanced += f" - {details['reason']}"
        
        if 'password_type' in details:
            enhanced += f" (패스워드 타입: {details['password_type']})"
        
        return enhanced
    
    def _check_banner_missing(self, context: ConfigContext, rule: SecurityRule) -> List[VulnerabilityIssue]:
        """배너 설정 누락 검사"""
        vulnerabilities = []
        
        if context.device_type == "Cisco":
            if not re.search(r"banner\s+(motd|login|exec)", context.full_config, re.IGNORECASE):
                vulnerabilities.append(VulnerabilityIssue(
                    rule_id=rule.rule_id,
                    severity=rule.severity,
                    line=0,
                    matched_text="배너 설정 누락",
                    description="로그온 시 경고 메시지가 설정되지 않음",
                    recommendation=rule.recommendation,
                    reference=rule.reference,
                    category=rule.category.value
                ))
        
        return vulnerabilities
    
    def _check_logging_server_missing(self, context: ConfigContext, rule: SecurityRule) -> List[VulnerabilityIssue]:
        """로깅 서버 설정 누락 검사"""
        vulnerabilities = []
        
        if context.device_type == "Cisco":
            if not re.search(r"logging\s+\d+\.\d+\.\d+\.\d+", context.full_config, re.IGNORECASE):
                vulnerabilities.append(VulnerabilityIssue(
                    rule_id=rule.rule_id,
                    severity=rule.severity,
                    line=0,
                    matched_text="원격 로그서버 설정 누락",
                    description="원격 로그서버가 설정되지 않음",
                    recommendation=rule.recommendation,
                    reference=rule.reference,
                    category=rule.category.value
                ))
        
        return vulnerabilities
    
    def _check_ntp_missing(self, context: ConfigContext, rule: SecurityRule) -> List[VulnerabilityIssue]:
        """NTP 서버 설정 누락 검사"""
        vulnerabilities = []
        
        if context.device_type == "Cisco":
            if not re.search(r"ntp\s+server", context.full_config, re.IGNORECASE):
                vulnerabilities.append(VulnerabilityIssue(
                    rule_id=rule.rule_id,
                    severity=rule.severity,
                    line=0,
                    matched_text="NTP 서버 설정 누락",
                    description="NTP 서버가 설정되지 않음",
                    recommendation=rule.recommendation,
                    reference=rule.reference,
                    category=rule.category.value
                ))
        
        return vulnerabilities
    
    def _check_timestamp_missing(self, context: ConfigContext, rule: SecurityRule) -> List[VulnerabilityIssue]:
        """타임스탬프 설정 누락 검사"""
        vulnerabilities = []
        
        if context.device_type == "Cisco":
            if not re.search(r"service\s+timestamps", context.full_config, re.IGNORECASE):
                vulnerabilities.append(VulnerabilityIssue(
                    rule_id=rule.rule_id,
                    severity=rule.severity,
                    line=0,
                    matched_text="타임스탬프 설정 누락",
                    description="로그 타임스탬프가 설정되지 않음",
                    recommendation=rule.recommendation,
                    reference=rule.reference,
                    category=rule.category.value
                ))
        
        return vulnerabilities
    
    def _get_applicable_rules(self, request: AnalysisRequest, framework: str = None) -> Dict[str, SecurityRule]:
        """요청에 적용 가능한 룰셋 반환 (다중 지침서 지원)"""
        target_framework = framework or self.default_framework
        
        if request.options.check_all_rules:
            return get_rules_by_device_type(target_framework, request.device_type)
        else:
            specific_rules = {}
            for rule_id in request.options.specific_rule_ids or []:
                rule = get_rule_by_id(target_framework, rule_id)
                if rule and request.device_type in rule.device_types:
                    specific_rules[rule_id] = rule
            return specific_rules
    
    def _is_device_specific_vulnerable(self, line: str, rule: SecurityRule, device_type: str) -> bool:
        """장비별 특화 취약점 검증"""
        
        # N-04 (VTY ACL) - 장비별 다른 검증 로직
        if rule.rule_id == "N-04":
            if device_type == "Cisco":
                return "access-class" not in line.lower()
            elif device_type == "Juniper":
                return "filter" not in line.lower()
        
        # N-16 (SSH) - 장비별 다른 명령어
        if rule.rule_id == "N-16":
            if device_type == "Cisco":
                return "transport input" in line.lower() and "ssh" not in line.lower()
            elif device_type == "Juniper":
                return "telnet" in line.lower()
        
        return True
    
    def _get_device_specific_recommendation(self, rule: SecurityRule, device_type: str) -> str:
        """장비별 특화 권고사항 반환"""
        device_specific_recommendations = {
            "N-04": {
                "Cisco": "line vty 0 4 -> access-class <ACL번호> in 명령어 사용",
                "Juniper": "firewall filter를 설정하고 lo0 인터페이스에 적용",
                "default": rule.recommendation
            },
            "N-16": {
                "Cisco": "line vty 0 4 -> transport input ssh 명령어 사용",
                "Juniper": "set system services ssh, delete system services telnet",
                "default": rule.recommendation
            }
        }
        
        if rule.rule_id in device_specific_recommendations:
            device_recs = device_specific_recommendations[rule.rule_id]
            return device_recs.get(device_type, device_recs["default"])
        
        return rule.recommendation
    
    def _remove_duplicates(self, vulnerabilities: List[VulnerabilityIssue]) -> List[VulnerabilityIssue]:
        """중복 취약점 제거"""
        seen = set()
        unique_vulnerabilities = []
        
        for vuln in vulnerabilities:
            # 룰 ID, 라인 번호, 매치된 텍스트로 중복 판단
            key = (vuln.rule_id, vuln.line, vuln.matched_text[:50])  # 텍스트는 50자까지만
            if key not in seen:
                seen.add(key)
                unique_vulnerabilities.append(vuln)
        
        # 라인 번호순으로 정렬
        return sorted(unique_vulnerabilities, key=lambda v: (v.line, v.rule_id))
    
    def _generate_statistics(
        self, 
        vulnerabilities: List[VulnerabilityIssue], 
        applicable_rules: Dict[str, SecurityRule]
    ) -> AnalysisStatistics:
        """분석 통계 정보 생성"""
        severity_counts = {"상": 0, "중": 0, "하": 0}
        
        for vuln in vulnerabilities:
            if vuln.severity in severity_counts:
                severity_counts[vuln.severity] += 1
        
        # 실패한 룰 수 (취약점이 발견된 룰)
        failed_rule_ids = set(vuln.rule_id for vuln in vulnerabilities)
        rules_failed = len(failed_rule_ids)
        rules_passed = len(applicable_rules) - rules_failed
        
        return AnalysisStatistics(
            total_rules_checked=len(applicable_rules),
            rules_passed=rules_passed,
            rules_failed=rules_failed,
            high_severity_issues=severity_counts["상"],
            medium_severity_issues=severity_counts["중"],
            low_severity_issues=severity_counts["하"]
        )
    
    # ==================== 확장된 API 메서드들 (다중 지침서 지원) ====================
    
    def get_available_rules(self, framework: str = None) -> List[Dict]:
        """사용 가능한 룰 목록 반환 (다중 지침서 지원)"""
        target_framework = framework or self.default_framework
        
        try:
            rules_dict = load_rules(target_framework)
        except (ValueError, NotImplementedError):
            rules_dict = self.rules
        
        rules_list = []
        for rule_id, rule in rules_dict.items():
            rule_info = {
                "ruleId": rule.rule_id,
                "title": rule.title,
                "description": rule.description,
                "severity": rule.severity,
                "category": rule.category.value,
                "deviceTypes": rule.device_types,
                "reference": rule.reference,
                "hasLogicalAnalysis": rule.logical_check_function is not None,
                "framework": target_framework,
                "vulnerabilityExamples": rule.vulnerability_examples,
                "safeExamples": rule.safe_examples,
                "heuristicRules": rule.heuristic_rules
            }
            rules_list.append(rule_info)
        
        return sorted(rules_list, key=lambda x: x["ruleId"])
    
    def get_rule_detail(self, rule_id: str, framework: str = None) -> Optional[Dict]:
        """특정 룰의 상세 정보 반환 (다중 지침서 지원)"""
        target_framework = framework or self.default_framework
        
        try:
            rule = get_rule_by_id(target_framework, rule_id)
        except (ValueError, NotImplementedError):
            rule = get_rule_by_id("KISA", rule_id)
            target_framework = "KISA"
        
        if not rule:
            return None
        
        return {
            "ruleId": rule.rule_id,
            "title": rule.title,
            "description": rule.description,
            "severity": rule.severity,
            "category": rule.category.value,
            "deviceTypes": rule.device_types,
            "patterns": rule.patterns,
            "negativePatterns": rule.negative_patterns,
            "recommendation": rule.recommendation,
            "reference": rule.reference,
            "framework": target_framework,
            "hasLogicalAnalysis": rule.logical_check_function is not None,
            "vulnerabilityExamples": rule.vulnerability_examples,
            "safeExamples": rule.safe_examples,
            "heuristicRules": rule.heuristic_rules,
            "logicalConditions": [
                {
                    "name": condition.name,
                    "description": condition.description,
                    "examples": condition.examples
                } for condition in rule.logical_conditions
            ] if rule.logical_conditions else []
        }
    
    def get_supported_device_types(self, framework: str = None) -> List[str]:
        """지원되는 장비 타입 목록 반환 (다중 지침서 지원)"""
        target_framework = framework or self.default_framework
        
        try:
            rules_dict = load_rules(target_framework)
        except (ValueError, NotImplementedError):
            rules_dict = self.rules
        
        device_types = set()
        for rule in rules_dict.values():
            device_types.update(rule.device_types)
        return sorted(list(device_types))
    
    def get_supported_frameworks(self) -> List[str]:
        """지원되는 지침서 목록 반환"""
        return list(get_supported_sources().keys())
    
    def get_analysis_statistics(self) -> Dict[str, Any]:
        """분석 엔진 통계 반환 (다중 지침서 지원)"""
        return {
            "analysisStats": self.analysis_stats,
            "defaultFramework": self.default_framework,
            "supportedFrameworks": self.get_supported_frameworks(),
            "totalRules": len(self.rules),
            "logicalRules": sum(1 for rule in self.rules.values() if rule.logical_check_function),
            "patternRules": sum(1 for rule in self.rules.values() if rule.patterns and not rule.logical_check_function),
            "hybridRules": sum(1 for rule in self.rules.values() if rule.patterns and rule.logical_check_function)
        }
    
    def validate_config_syntax(self, config_text: str, device_type: str) -> List[str]:
        """설정 파일 기본 문법 검증 (강화된 버전)"""
        errors = []
        
        try:
            # 컨텍스트 파싱을 통한 문법 검증
            context = parse_config_context(config_text, device_type)
            
            # 기본 구조 검증
            if device_type == "Cisco":
                errors.extend(self._validate_cisco_syntax(context))
            elif device_type == "Juniper":
                errors.extend(self._validate_juniper_syntax(context))
                
        except Exception as e:
            errors.append(f"설정 파싱 오류: {e}")
        
        return errors
    
    def _validate_cisco_syntax(self, context: ConfigContext) -> List[str]:
        """Cisco 설정 문법 검증"""
        errors = []
        
        # 인터페이스 블록 완성도 검사
        for interface_name, interface_config in context.parsed_interfaces.items():
            if not interface_config['config_lines']:
                errors.append(f"인터페이스 {interface_name}: 설정이 비어있음")
        
        # 글로벌 설정 일관성 검사
        if context.parsed_services.get('password-encryption') and not context.global_settings.get('enable_password_type'):
            errors.append("password-encryption이 활성화되었지만 enable 패스워드가 설정되지 않음")
        
        return errors
    
    def _validate_juniper_syntax(self, context: ConfigContext) -> List[str]:
        """Juniper 설정 문법 검증"""
        errors = []
        
        # Juniper 특화 문법 검증 로직
        # (구현 필요)
        
        return errors
    
    def analyze_single_line(self, line: str, device_type: str, rule_ids: Optional[List[str]] = None, framework: str = None) -> List[VulnerabilityIssue]:
        """단일 라인 분석 (디버깅/테스트용) - 다중 지침서 지원"""
        target_framework = framework or self.default_framework
        
        try:
            applicable_rules = get_rules_by_device_type(target_framework, device_type)
        except (ValueError, NotImplementedError):
            applicable_rules = get_rules_by_device_type("KISA", device_type)
        
        if rule_ids:
            applicable_rules = {
                rule_id: rule for rule_id, rule in applicable_rules.items()
                if rule_id in rule_ids
            }
        
        # 단일 라인을 위한 컨텍스트 생성
        dummy_config = line
        context = parse_config_context(dummy_config, device_type)
        
        class DummyOptions:
            return_raw_matches = True
        
        vulnerabilities = []
        
        for rule_id, rule in applicable_rules.items():
            # 논리 기반 분석
            if rule.logical_check_function:
                try:
                    logical_vulns = self._perform_logical_analysis(rule, context, DummyOptions())
                    vulnerabilities.extend(logical_vulns)
                except:
                    pass  # 단일 라인 분석에서는 오류 무시
            
            # 패턴 매칭 분석
            else:
                pattern_vulns = self._perform_pattern_analysis(rule, [line], context, DummyOptions())
                vulnerabilities.extend(pattern_vulns)
        
        return vulnerabilities
    
    def switch_framework(self, framework: str):
        """기본 지침서 변경"""
        try:
            new_rules = load_rules(framework.upper())
            self.default_framework = framework.upper()
            self.rules = new_rules
            self.logger.info(f"기본 지침서를 '{self.default_framework}'로 변경: {len(self.rules)}개 룰")
        except (ValueError, NotImplementedError) as e:
            self.logger.error(f"지침서 '{framework}' 변경 실패: {e}")
            raise


# 기존 호환성을 위한 별칭
ConfigAnalyzer = EnhancedConfigAnalyzer