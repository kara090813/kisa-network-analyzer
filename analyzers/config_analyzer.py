# -*- coding: utf-8 -*-
"""
analyzers/config_analyzer.py
네트워크 장비 설정 파일 분석 엔진

KISA 가이드 기반 보안 취약점 탐지 및 분석 로직 구현
"""

import re
import time
from typing import List, Dict, Optional, Tuple
import logging

from rules.security_rules import (
    get_all_rules, get_rules_by_device_type, get_rule_by_id,
    SecurityRule, RuleCategory
)
from models.analysis_request import AnalysisRequest
from models.analysis_response import (
    VulnerabilityIssue, AnalysisResult, AnalysisStatistics
)


class ConfigAnalyzer:
    """네트워크 장비 설정 파일 분석기"""
    
    def __init__(self):
        """분석기 초기화"""
        self.logger = logging.getLogger(__name__)
        self.rules = get_all_rules()
        
    def analyze_config(self, request: AnalysisRequest) -> AnalysisResult:
        """
        설정 파일 분석 메인 함수
        
        Args:
            request: 분석 요청 객체
            
        Returns:
            AnalysisResult: 분석 결과
        """
        start_time = time.time()
        
        # 장비 타입에 맞는 룰셋 선택
        applicable_rules = self._get_applicable_rules(request)
        
        # 설정 라인별 분석
        vulnerabilities = self._analyze_config_lines(
            request.get_config_lines(), 
            applicable_rules,
            request.options
        )
        
        # 분석 시간 계산
        analysis_time = time.time() - start_time
        
        # 통계 정보 생성
        statistics = self._generate_statistics(vulnerabilities, applicable_rules)
        
        self.logger.info(
            f"분석 완료 - 장비: {request.device_type}, "
            f"적용 룰: {len(applicable_rules)}개, "
            f"발견 취약점: {len(vulnerabilities)}개, "
            f"분석 시간: {analysis_time:.2f}초"
        )
        
        return AnalysisResult(
            vulnerabilities=vulnerabilities,
            analysis_time=analysis_time,
            statistics=statistics
        )
    
    def _get_applicable_rules(self, request: AnalysisRequest) -> Dict[str, SecurityRule]:
        """요청에 적용 가능한 룰셋 반환"""
        if request.options.check_all_rules:
            # 모든 룰 중 해당 장비 타입에 적용 가능한 것들
            return get_rules_by_device_type(request.device_type)
        else:
            # 특정 룰들만
            specific_rules = {}
            for rule_id in request.options.specific_rule_ids or []:
                rule = get_rule_by_id(rule_id)
                if rule and request.device_type in rule.device_types:
                    specific_rules[rule_id] = rule
            return specific_rules
    
    def _analyze_config_lines(
        self, 
        config_lines: List[str], 
        rules: Dict[str, SecurityRule],
        options
    ) -> List[VulnerabilityIssue]:
        """설정 라인별 취약점 분석"""
        vulnerabilities = []
        
        for line_num, line in enumerate(config_lines, 1):
            # 빈 라인이나 주석 라인 스킵
            if not line.strip() or line.strip().startswith('!'):
                continue
                
            # 각 룰에 대해 검사
            for rule_id, rule in rules.items():
                issues = self._check_line_against_rule(line, line_num, rule, options)
                vulnerabilities.extend(issues)
        
        # 중복 제거 (같은 라인에서 같은 룰로 여러 번 탐지된 경우)
        unique_vulnerabilities = self._remove_duplicates(vulnerabilities)
        
        return unique_vulnerabilities
    
    def _check_line_against_rule(
        self, 
        line: str, 
        line_num: int, 
        rule: SecurityRule,
        options
    ) -> List[VulnerabilityIssue]:
        """특정 라인을 특정 룰에 대해 검사"""
        issues = []
        
        # 먼저 negative 패턴 확인 (양호한 상태)
        for neg_pattern in rule.compiled_negative_patterns:
            if neg_pattern.search(line):
                # 양호한 상태이므로 취약점이 아님
                return []
        
        # 취약점 패턴 확인
        for pattern in rule.compiled_patterns:
            match = pattern.search(line)
            if match:
                # 취약점 발견
                matched_text = match.group(0)
                
                issue = VulnerabilityIssue(
                    rule_id=rule.rule_id,
                    severity=rule.severity,
                    line=line_num,
                    matched_text=matched_text,
                    description=rule.description,
                    recommendation=rule.recommendation,
                    reference=rule.reference,
                    category=rule.category.value,
                    raw_match=line.strip() if options.return_raw_matches else None
                )
                
                issues.append(issue)
                
                # 첫 번째 매치만 보고하도록 제한
                break
        
        # 커스텀 체크 함수가 있다면 실행
        if rule.check_function:
            custom_issues = rule.check_function(line, line_num, rule)
            if custom_issues:
                issues.extend(custom_issues)
        
        return issues
    
    def _remove_duplicates(self, vulnerabilities: List[VulnerabilityIssue]) -> List[VulnerabilityIssue]:
        """중복 취약점 제거"""
        seen = set()
        unique_vulnerabilities = []
        
        for vuln in vulnerabilities:
            # 룰 ID, 라인 번호, 매치된 텍스트로 중복 판단
            key = (vuln.rule_id, vuln.line, vuln.matched_text)
            if key not in seen:
                seen.add(key)
                unique_vulnerabilities.append(vuln)
        
        return unique_vulnerabilities
    
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
    
    def get_available_rules(self) -> List[Dict]:
        """사용 가능한 룰 목록 반환"""
        rules_list = []
        for rule_id, rule in self.rules.items():
            rules_list.append({
                "ruleId": rule.rule_id,
                "title": rule.title,
                "description": rule.description,
                "severity": rule.severity,
                "category": rule.category.value,
                "deviceTypes": rule.device_types,
                "reference": rule.reference
            })
        return sorted(rules_list, key=lambda x: x["ruleId"])
    
    def get_rule_detail(self, rule_id: str) -> Optional[Dict]:
        """특정 룰의 상세 정보 반환"""
        rule = get_rule_by_id(rule_id)
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
            "reference": rule.reference
        }
    
    def get_supported_device_types(self) -> List[str]:
        """지원되는 장비 타입 목록 반환"""
        device_types = set()
        for rule in self.rules.values():
            device_types.update(rule.device_types)
        return sorted(list(device_types))
    
    def analyze_single_line(self, line: str, device_type: str, rule_ids: Optional[List[str]] = None) -> List[VulnerabilityIssue]:
        """단일 라인 분석 (디버깅/테스트용)"""
        applicable_rules = get_rules_by_device_type(device_type)
        
        if rule_ids:
            applicable_rules = {
                rule_id: rule for rule_id, rule in applicable_rules.items()
                if rule_id in rule_ids
            }
        
        class DummyOptions:
            return_raw_matches = True
        
        return self._check_line_against_rule(line, 1, applicable_rules, DummyOptions())
    
    def validate_config_syntax(self, config_text: str, device_type: str) -> List[str]:
        """설정 파일 기본 문법 검증"""
        errors = []
        lines = config_text.splitlines()
        
        # 기본적인 문법 오류 검사
        for line_num, line in enumerate(lines, 1):
            line = line.strip()
            if not line or line.startswith('!'):
                continue
            
            # Cisco 설정 기본 검증
            if device_type == "Cisco":
                # 기본 명령어 구조 검증
                if line and not self._is_valid_cisco_command(line):
                    errors.append(f"라인 {line_num}: 알 수 없는 명령어 구조 - {line}")
        
        return errors
    
    def _is_valid_cisco_command(self, line: str) -> bool:
        """Cisco 명령어 유효성 기본 검사"""
        # 매우 기본적인 검사만 수행
        known_commands = [
            'interface', 'router', 'line', 'access-list', 'ip', 'no',
            'enable', 'username', 'service', 'snmp-server', 'logging',
            'ntp', 'banner', 'hostname', 'version', 'boot', 'clock',
            'cdp', 'spanning-tree', 'vlan', 'switchport', 'exit', 'end'
        ]
        
        first_word = line.split()[0] if line.split() else ""
        return any(line.startswith(cmd) for cmd in known_commands) or line.startswith(' ')
