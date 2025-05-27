
# -*- coding: utf-8 -*-
"""
analyzers/config_analyzer.py (개선된 버전)
네트워크 장비 설정 파일 분석 엔진

KISA 가이드 기반 보안 취약점 탐지 및 분석 로직 구현
장비별 특화 로직 강화
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
            request.device_type,
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
        device_type: str,
        options
    ) -> List[VulnerabilityIssue]:
        """설정 라인별 취약점 분석 (장비별 특화 로직 추가)"""
        vulnerabilities = []
        
        # 전체 설정을 하나의 문자열로 합치기 (멀티라인 분석용)
        full_config = "\n".join(config_lines)
        
        for line_num, line in enumerate(config_lines, 1):
            # 빈 라인이나 주석 라인 스킵
            if not line.strip() or line.strip().startswith('!'):
                continue
                
            # 각 룰에 대해 검사
            for rule_id, rule in rules.items():
                issues = self._check_line_against_rule(
                    line, line_num, rule, device_type, options, full_config
                )
                vulnerabilities.extend(issues)
        
        # 설정이 없는 경우의 취약점 검사 (전역 분석)
        global_issues = self._check_missing_configurations(
            full_config, rules, device_type, options
        )
        vulnerabilities.extend(global_issues)
        
        # 중복 제거 (같은 라인에서 같은 룰로 여러 번 탐지된 경우)
        unique_vulnerabilities = self._remove_duplicates(vulnerabilities)
        
        return unique_vulnerabilities
    
    def _check_line_against_rule(
        self, 
        line: str, 
        line_num: int, 
        rule: SecurityRule,
        device_type: str,
        options,
        full_config: str
    ) -> List[VulnerabilityIssue]:
        """특정 라인을 특정 룰에 대해 검사 (장비별 특화)"""
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
                # 장비별 특화 검증
                if self._is_device_specific_vulnerable(line, rule, device_type):
                    matched_text = match.group(0)
                    
                    issue = VulnerabilityIssue(
                        rule_id=rule.rule_id,
                        severity=rule.severity,
                        line=line_num,
                        matched_text=matched_text,
                        description=rule.description,
                        recommendation=self._get_device_specific_recommendation(rule, device_type),
                        reference=rule.reference,
                        category=rule.category.value,
                        raw_match=line.strip() if options.return_raw_matches else None
                    )
                    
                    issues.append(issue)
                    break  # 첫 번째 매치만 보고
        
        # 커스텀 체크 함수가 있다면 실행
        if rule.check_function:
            custom_issues = rule.check_function(line, line_num, rule, device_type)
            if custom_issues:
                issues.extend(custom_issues)
        
        return issues
    
    def _check_missing_configurations(
        self,
        full_config: str,
        rules: Dict[str, SecurityRule],
        device_type: str,
        options
    ) -> List[VulnerabilityIssue]:
        """설정이 누락된 경우의 취약점 검사"""
        issues = []
        
        # 특정 설정이 없는 경우를 검사하는 룰들
        missing_config_rules = {
            "N-18": self._check_banner_missing,
            "N-19": self._check_logging_server_missing,
            "N-22": self._check_ntp_missing,
            "N-23": self._check_timestamp_missing,
        }
        
        for rule_id, check_func in missing_config_rules.items():
            if rule_id in rules:
                rule = rules[rule_id]
                missing_issues = check_func(full_config, rule, device_type)
                issues.extend(missing_issues)
        
        return issues
    
    def _check_banner_missing(self, config: str, rule: SecurityRule, device_type: str) -> List[VulnerabilityIssue]:
        """배너 설정 누락 검사"""
        if device_type == "Cisco":
            if not re.search(r"banner\s+(motd|login|exec)", config, re.IGNORECASE):
                return [VulnerabilityIssue(
                    rule_id=rule.rule_id,
                    severity=rule.severity,
                    line=0,
                    matched_text="배너 설정 누락",
                    description="로그온 시 경고 메시지가 설정되지 않음",
                    recommendation=rule.recommendation,
                    reference=rule.reference,
                    category=rule.category.value
                )]
        return []
    
    def _check_logging_server_missing(self, config: str, rule: SecurityRule, device_type: str) -> List[VulnerabilityIssue]:
        """로깅 서버 설정 누락 검사"""
        if device_type == "Cisco":
            if not re.search(r"logging\s+\d+\.\d+\.\d+\.\d+", config, re.IGNORECASE):
                return [VulnerabilityIssue(
                    rule_id=rule.rule_id,
                    severity=rule.severity,
                    line=0,
                    matched_text="원격 로그서버 설정 누락",
                    description="원격 로그서버가 설정되지 않음",
                    recommendation=rule.recommendation,
                    reference=rule.reference,
                    category=rule.category.value
                )]
        return []
    
    def _check_ntp_missing(self, config: str, rule: SecurityRule, device_type: str) -> List[VulnerabilityIssue]:
        """NTP 서버 설정 누락 검사"""
        if device_type == "Cisco":
            if not re.search(r"ntp\s+server", config, re.IGNORECASE):
                return [VulnerabilityIssue(
                    rule_id=rule.rule_id,
                    severity=rule.severity,
                    line=0,
                    matched_text="NTP 서버 설정 누락",
                    description="NTP 서버가 설정되지 않음",
                    recommendation=rule.recommendation,
                    reference=rule.reference,
                    category=rule.category.value
                )]
        return []
    
    def _check_timestamp_missing(self, config: str, rule: SecurityRule, device_type: str) -> List[VulnerabilityIssue]:
        """타임스탬프 설정 누락 검사"""
        if device_type == "Cisco":
            if not re.search(r"service\s+timestamps", config, re.IGNORECASE):
                return [VulnerabilityIssue(
                    rule_id=rule.rule_id,
                    severity=rule.severity,
                    line=0,
                    matched_text="타임스탬프 설정 누락",
                    description="로그 타임스탬프가 설정되지 않음",
                    recommendation=rule.recommendation,
                    reference=rule.reference,
                    category=rule.category.value
                )]
        return []
    
    def _is_device_specific_vulnerable(self, line: str, rule: SecurityRule, device_type: str) -> bool:
        """장비별 특화 취약점 검증"""
        
        # N-04 (VTY ACL) - 장비별 다른 검증 로직
        if rule.rule_id == "N-04":
            if device_type == "Cisco":
                # Cisco의 경우 access-class 확인
                return "access-class" not in line.lower()
            elif device_type == "Juniper":
                # Juniper의 경우 firewall filter 확인
                return "filter" not in line.lower()
        
        # N-16 (SSH) - 장비별 다른 명령어
        if rule.rule_id == "N-16":
            if device_type == "Cisco":
                return "transport input" in line.lower() and "ssh" not in line.lower()
            elif device_type == "Juniper":
                return "telnet" in line.lower()
        
        # 기본적으로는 패턴 매치된 경우 취약함
        return True
    
    def _get_device_specific_recommendation(self, rule: SecurityRule, device_type: str) -> str:
        """장비별 특화 권고사항 반환"""
        
        # 장비별 특화 권고사항이 있는 경우
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