# -*- coding: utf-8 -*-
"""
models/analysis_response.py (개선된 버전)
분석 응답 데이터 모델 - 상세 정보 보존 및 통과 항목 포함

KISA 네트워크 장비 취약점 분석 결과를 위한 데이터 구조 정의
"""

from dataclasses import dataclass
from typing import List, Optional, Dict, Any, Union
from datetime import datetime
from enum import Enum


class Severity(Enum):
    """취약점 심각도"""
    HIGH = "상"      # 상급
    MEDIUM = "중"    # 중급
    LOW = "하"       # 하급


class RuleStatus(Enum):
    """룰 검사 상태"""
    FAILED = "failed"      # 취약점 발견
    PASSED = "passed"      # 통과
    SKIPPED = "skipped"    # 건너뜀
    ERROR = "error"        # 오류


@dataclass
class VulnerabilityIssue:
    """발견된 취약점 정보 - 상세 정보 포함"""
    rule_id: str
    severity: str
    line: int
    matched_text: str
    description: str
    recommendation: str
    reference: str
    category: Optional[str] = None
    raw_match: Optional[str] = None
    # 🔥 새로운 필드: 상세 정보 보존
    affected_items: Optional[List[Dict[str, Any]]] = None  # 영향받는 인터페이스/설정들
    summary_info: Optional[Dict[str, Any]] = None  # 요약 정보
    analysis_details: Optional[Dict[str, Any]] = None  # 분석 상세 내용
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'VulnerabilityIssue':
        """딕셔너리로부터 VulnerabilityIssue 객체 생성"""
        return cls(
            rule_id=data['ruleId'],
            severity=data['severity'],
            line=data['line'],
            matched_text=data['matchedText'],
            description=data['description'],
            recommendation=data['recommendation'],
            reference=data['reference'],
            category=data.get('category'),
            raw_match=data.get('rawMatch'),
            affected_items=data.get('affectedItems'),
            summary_info=data.get('summaryInfo'),
            analysis_details=data.get('analysisDetails')
        )
    
    def to_dict(self) -> Dict[str, Any]:
        """딕셔너리로 변환 - 상세 정보 포함"""
        result = {
            'ruleId': self.rule_id,
            'severity': self.severity,
            'line': self.line,
            'matchedText': self.matched_text,
            'description': self.description,
            'recommendation': self.recommendation,
            'reference': self.reference,
            'status': 'failed'  # 취약점이므로 failed
        }
        
        if self.category:
            result['category'] = self.category
        if self.raw_match:
            result['rawMatch'] = self.raw_match
        if self.affected_items:
            result['affectedItems'] = self.affected_items
        if self.summary_info:
            result['summaryInfo'] = self.summary_info
        if self.analysis_details:
            result['analysisDetails'] = self.analysis_details
            
        return result
    
    def get_display_summary(self) -> str:
        """사용자에게 표시할 요약 정보 생성"""
        if self.summary_info:
            if self.summary_info.get('total_affected', 0) > 1:
                affected_type = self.summary_info.get('affected_type', 'items')
                total = self.summary_info.get('total_affected', 0)
                items = self.summary_info.get('affected_list', [])
                
                # 처음 3개만 보여주고 나머지는 개수로 표시
                display_items = items[:3] if len(items) > 3 else items
                remaining = len(items) - 3 if len(items) > 3 else 0
                
                items_str = ", ".join(display_items)
                if remaining > 0:
                    items_str += f" (+{remaining} more)"
                
                return f"{total} {affected_type} affected: {items_str}"
        
        return self.matched_text


@dataclass
class PassedRule:
    """🔥 새로운 클래스: 통과된 룰 정보"""
    rule_id: str
    title: str
    description: str
    severity: str
    category: str
    reference: str
    reason: str = "Configuration compliant"  # 통과 이유
    checked_items: Optional[List[Dict[str, Any]]] = None  # 검사된 항목들
    analysis_details: Optional[Dict[str, Any]] = None
    
    def to_dict(self) -> Dict[str, Any]:
        """딕셔너리로 변환"""
        result = {
            'ruleId': self.rule_id,
            'title': self.title,
            'description': self.description,
            'severity': self.severity,
            'category': self.category,
            'reference': self.reference,
            'status': 'passed',
            'reason': self.reason
        }
        
        if self.checked_items:
            result['checkedItems'] = self.checked_items
        if self.analysis_details:
            result['analysisDetails'] = self.analysis_details
            
        return result


@dataclass
class SkippedRule:
    """🔥 새로운 클래스: 건너뛴 룰 정보"""
    rule_id: str
    title: str
    description: str
    severity: str
    category: str
    reference: str
    reason: str  # 건너뛴 이유
    
    def to_dict(self) -> Dict[str, Any]:
        """딕셔너리로 변환"""
        return {
            'ruleId': self.rule_id,
            'title': self.title,
            'description': self.description,
            'severity': self.severity,
            'category': self.category,
            'reference': self.reference,
            'status': 'skipped',
            'reason': self.reason
        }


@dataclass
class AnalysisStatistics:
    """분석 통계 정보"""
    total_rules_checked: int
    rules_passed: int
    rules_failed: int
    rules_skipped: int = 0  # 🔥 새로운 필드
    high_severity_issues: int = 0
    medium_severity_issues: int = 0
    low_severity_issues: int = 0
    # 🔥 새로운 필드: 상세 통계
    total_individual_findings: Optional[int] = None  # 개별 발견 사항 총 개수
    consolidated_rules: Optional[int] = None  # 통합된 룰 개수
    
    def to_dict(self) -> Dict[str, Any]:
        """딕셔너리로 변환"""
        result = {
            'totalRulesChecked': self.total_rules_checked,
            'rulesPassed': self.rules_passed,
            'rulesFailed': self.rules_failed,
            'rulesSkipped': self.rules_skipped,
            'highSeverityIssues': self.high_severity_issues,
            'mediumSeverityIssues': self.medium_severity_issues,
            'lowSeverityIssues': self.low_severity_issues,
            'complianceRate': round((self.rules_passed / max(self.total_rules_checked, 1)) * 100, 2)  # 🔥 컴플라이언스 비율
        }
        
        if self.total_individual_findings is not None:
            result['totalIndividualFindings'] = self.total_individual_findings
        if self.consolidated_rules is not None:
            result['consolidatedRules'] = self.consolidated_rules
            
        return result


@dataclass
class AnalysisResult:
    """분석 결과"""
    vulnerabilities: List[VulnerabilityIssue]
    passed_rules: List[PassedRule] = None  # 🔥 새로운 필드
    skipped_rules: List[SkippedRule] = None  # 🔥 새로운 필드
    analysis_time: float = 0.0
    statistics: Optional[AnalysisStatistics] = None
    
    def __post_init__(self):
        if self.passed_rules is None:
            self.passed_rules = []
        if self.skipped_rules is None:
            self.skipped_rules = []
    
    def get_issues_by_severity(self, severity: str) -> List[VulnerabilityIssue]:
        """특정 심각도의 취약점들만 반환"""
        return [issue for issue in self.vulnerabilities if issue.severity == severity]
    
    def get_issues_by_rule(self, rule_id: str) -> List[VulnerabilityIssue]:
        """특정 룰의 취약점들만 반환"""
        return [issue for issue in self.vulnerabilities if issue.rule_id == rule_id]
    
    def get_all_results_by_status(self, status: str) -> List[Dict[str, Any]]:
        """🔥 새로운 메서드: 상태별 모든 결과 반환"""
        if status == 'failed':
            return [vuln.to_dict() for vuln in self.vulnerabilities]
        elif status == 'passed':
            return [rule.to_dict() for rule in self.passed_rules]
        elif status == 'skipped':
            return [rule.to_dict() for rule in self.skipped_rules]
        else:
            return []


@dataclass
class AnalysisResponse:
    """분석 응답"""
    device_type: str
    total_lines: int
    issues_found: int
    analysis_time: float
    results: List[VulnerabilityIssue]
    passed_rules: List[PassedRule] = None  # 🔥 새로운 필드
    skipped_rules: List[SkippedRule] = None  # 🔥 새로운 필드
    statistics: Optional[AnalysisStatistics] = None
    timestamp: Optional[str] = None
    
    def __post_init__(self):
        """초기화 후 처리"""
        if self.timestamp is None:
            self.timestamp = datetime.now().isoformat()
        if self.passed_rules is None:
            self.passed_rules = []
        if self.skipped_rules is None:
            self.skipped_rules = []
    
    def to_dict(self, include_passed: bool = False, include_skipped: bool = False) -> Dict[str, Any]:
        """🔥 개선된 딕셔너리 변환 - 옵션으로 통과/건너뛴 항목 포함"""
        response = {
            'success': True,
            'deviceType': self.device_type,
            'totalLines': self.total_lines,
            'issuesFound': self.issues_found,
            'analysisTime': self.analysis_time,
            'timestamp': self.timestamp,
            'results': {
                'failed': [issue.to_dict() for issue in self.results]
            }
        }
        
        # 🔥 통과된 룰 포함 (옵션)
        if include_passed and self.passed_rules:
            response['results']['passed'] = [rule.to_dict() for rule in self.passed_rules]
            response['passedRulesCount'] = len(self.passed_rules)
        
        # 🔥 건너뛴 룰 포함 (옵션)
        if include_skipped and self.skipped_rules:
            response['results']['skipped'] = [rule.to_dict() for rule in self.skipped_rules]
            response['skippedRulesCount'] = len(self.skipped_rules)
        
        if self.statistics:
            response['statistics'] = self.statistics.to_dict()
            
        return response
    
    def get_summary_by_severity(self) -> Dict[str, int]:
        """심각도별 취약점 개수 요약"""
        summary = {
            Severity.HIGH.value: 0,
            Severity.MEDIUM.value: 0,
            Severity.LOW.value: 0
        }
        
        for issue in self.results:
            if issue.severity in summary:
                summary[issue.severity] += 1
                
        return summary
    
    def get_rules_summary(self) -> Dict[str, int]:
        """룰별 취약점 개수 요약"""
        summary = {}
        for issue in self.results:
            if issue.rule_id not in summary:
                summary[issue.rule_id] = 0
            summary[issue.rule_id] += 1
        return summary
    
    def filter_by_severity(self, severity: str) -> 'AnalysisResponse':
        """특정 심각도의 취약점만 포함하는 새로운 응답 객체 생성"""
        filtered_results = [issue for issue in self.results if issue.severity == severity]
        
        return AnalysisResponse(
            device_type=self.device_type,
            total_lines=self.total_lines,
            issues_found=len(filtered_results),
            analysis_time=self.analysis_time,
            results=filtered_results,
            passed_rules=self.passed_rules,
            skipped_rules=self.skipped_rules,
            statistics=self.statistics,
            timestamp=self.timestamp
        )


def create_consolidated_vulnerability(rule_id: str, individual_vulnerabilities: List[VulnerabilityIssue]) -> VulnerabilityIssue:
    """
    🔥 개별 취약점들을 하나의 통합 취약점으로 생성 - 상세 정보 보존
    """
    if not individual_vulnerabilities:
        raise ValueError("No vulnerabilities to consolidate")
    
    # 가장 높은 심각도 선택
    severity_order = {'상': 3, 'High': 3, '중': 2, 'Medium': 2, '하': 1, 'Low': 1}
    primary_vuln = max(individual_vulnerabilities, 
                      key=lambda v: severity_order.get(v.severity, 0))
    
    # 영향받는 항목들 추출
    affected_items = []
    affected_list = []
    affected_type = "items"
    
    for vuln in individual_vulnerabilities:
        item_info = {
            'line': vuln.line,
            'matchedText': vuln.matched_text,
            'severity': vuln.severity
        }
        
        # 분석 상세 정보에서 추가 정보 추출
        if vuln.analysis_details:
            details = vuln.analysis_details
            
            # 인터페이스 관련 정보
            if 'interface_name' in details:
                item_info['interfaceName'] = details['interface_name']
                affected_list.append(details['interface_name'])
                affected_type = "interfaces"
            
            # 사용자 관련 정보
            if 'username' in details:
                item_info['username'] = details['username']
                affected_list.append(details['username'])
                affected_type = "users"
            
            # 서비스 관련 정보
            if 'service_name' in details:
                item_info['serviceName'] = details['service_name']
                affected_list.append(details['service_name'])
                affected_type = "services"
            
            # SNMP 커뮤니티 관련 정보
            if 'community' in details:
                item_info['community'] = details['community']
                affected_list.append(details['community'])
                affected_type = "SNMP communities"
        
        affected_items.append(item_info)
    
    # 중복 제거
    affected_list = list(set(affected_list))
    
    # 요약 정보 생성
    summary_info = {
        'total_affected': len(individual_vulnerabilities),
        'affected_type': affected_type,
        'affected_list': affected_list,
        'severity_breakdown': {}
    }
    
    # 심각도별 개수 계산
    for vuln in individual_vulnerabilities:
        severity = vuln.severity
        summary_info['severity_breakdown'][severity] = summary_info['severity_breakdown'].get(severity, 0) + 1
    
    # 통합된 매치 텍스트 생성
    if len(individual_vulnerabilities) > 1:
        if affected_type == "interfaces" and len(affected_list) > 0:
            matched_text = f"{len(affected_list)} interfaces affected: {', '.join(affected_list[:3])}"
            if len(affected_list) > 3:
                matched_text += f" (+{len(affected_list) - 3} more)"
        else:
            matched_text = f"{len(individual_vulnerabilities)} instances found"
    else:
        matched_text = primary_vuln.matched_text
    
    # 통합된 추천사항 생성
    if len(set(v.recommendation for v in individual_vulnerabilities)) == 1:
        # 모든 추천사항이 동일한 경우
        recommendation = primary_vuln.recommendation
    else:
        # 추천사항이 다른 경우 통합
        recommendation = f"Apply security configuration for {len(individual_vulnerabilities)} items. See details for specific recommendations."
    
    # 첫 번째 취약점의 라인 또는 가장 작은 라인 번호 사용
    line_numbers = [v.line for v in individual_vulnerabilities if v.line > 0]
    primary_line = min(line_numbers) if line_numbers else individual_vulnerabilities[0].line
    
    return VulnerabilityIssue(
        rule_id=rule_id,
        severity=primary_vuln.severity,
        line=primary_line,
        matched_text=matched_text,
        description=primary_vuln.description,
        recommendation=recommendation,
        reference=primary_vuln.reference,
        category=primary_vuln.category,
        affected_items=affected_items,
        summary_info=summary_info,
        analysis_details={
            'consolidation_type': 'multiple_instances',
            'total_instances': len(individual_vulnerabilities),
            'primary_severity': primary_vuln.severity,
            'line_numbers': [v.line for v in individual_vulnerabilities],
            'affected_items_detail': affected_list
        }
    )


def calculate_consolidated_statistics(vulnerabilities: List[VulnerabilityIssue]) -> Dict[str, Any]:
    """
    🔥 개선된 통합 통계 계산 - 상세 정보 보존
    
    룰별로 통합하되, 개별 발견 사항의 상세 정보는 보존
    """
    if not vulnerabilities:
        return {
            'consolidated_vulnerabilities': [],
            'statistics': {
                'total_vulnerabilities': 0,
                'total_individual_findings': 0,
                'high_severity': 0,
                'medium_severity': 0,
                'low_severity': 0,
                'consolidated_rules': 0
            }
        }
    
    # 룰별로 그룹화
    rule_groups = {}
    for vuln in vulnerabilities:
        rule_id = vuln.rule_id
        if rule_id not in rule_groups:
            rule_groups[rule_id] = []
        rule_groups[rule_id].append(vuln)
    
    # 룰별로 통합된 취약점 생성
    consolidated_vulnerabilities = []
    
    for rule_id, rule_vulns in rule_groups.items():
        if len(rule_vulns) == 1:
            # 단일 취약점인 경우 그대로 사용
            consolidated_vulnerabilities.append(rule_vulns[0])
        else:
            # 다중 취약점인 경우 통합
            consolidated_vuln = create_consolidated_vulnerability(rule_id, rule_vulns)
            consolidated_vulnerabilities.append(consolidated_vuln)
    
    # 통계 계산
    total_rules = len(consolidated_vulnerabilities)
    total_individual = len(vulnerabilities)
    severity_counts = {'상': 0, 'High': 0, '중': 0, 'Medium': 0, '하': 0, 'Low': 0}
    
    for vuln in consolidated_vulnerabilities:
        if vuln.severity in severity_counts:
            severity_counts[vuln.severity] += 1
    
    return {
        'consolidated_vulnerabilities': consolidated_vulnerabilities,
        'statistics': {
            'total_vulnerabilities': total_rules,
            'total_individual_findings': total_individual,
            'high_severity': severity_counts['상'] + severity_counts['High'],
            'medium_severity': severity_counts['중'] + severity_counts['Medium'],
            'low_severity': severity_counts['하'] + severity_counts['Low'],
            'consolidated_rules': total_rules
        }
    }


def find_actual_line_number(config_lines: List[str], search_patterns: List[str], 
                          interface_name: str = None, context_lines: int = 5) -> int:
    """
    🔥 실제 설정 라인 번호를 정확하게 찾는 헬퍼 함수
    
    Args:
        config_lines: 설정 파일 라인들
        search_patterns: 검색할 패턴들
        interface_name: 인터페이스 이름 (인터페이스 관련 설정인 경우)
        context_lines: 컨텍스트 라인 범위
    
    Returns:
        실제 라인 번호 (1-based), 찾지 못하면 0
    """
    if not config_lines or not search_patterns:
        return 0
    
    # 인터페이스 관련 설정인 경우
    if interface_name:
        in_interface_section = False
        interface_start_line = 0
        
        for i, line in enumerate(config_lines):
            line_clean = line.strip()
            original_line = line
            
            # 인터페이스 시작
            if line_clean.startswith(f'interface {interface_name}'):
                in_interface_section = True
                interface_start_line = i + 1
                continue
            
            # 인터페이스 섹션 내부
            elif in_interface_section and original_line.startswith(' '):
                # 패턴 매칭
                for pattern in search_patterns:
                    if pattern.lower() in line_clean.lower():
                        return i + 1
                        
            # 다른 섹션 시작하면 인터페이스 섹션 종료
            elif in_interface_section and not original_line.startswith(' ') and line_clean:
                in_interface_section = False
        
        # 인터페이스 섹션에서 찾지 못한 경우 인터페이스 시작 라인 반환
        if interface_start_line > 0:
            return interface_start_line
    
    # 전역 설정에서 검색
    for i, line in enumerate(config_lines):
        line_clean = line.strip()
        for pattern in search_patterns:
            if pattern.lower() in line_clean.lower():
                return i + 1
    
    # 찾지 못한 경우
    return 0


def enhance_vulnerability_with_line_info(vuln: VulnerabilityIssue, 
                                       config_lines: List[str]) -> VulnerabilityIssue:
    """
    🔥 취약점에 정확한 라인 정보 추가
    """
    if vuln.line > 0:
        return vuln  # 이미 라인 정보가 있음
    
    # 분석 상세 정보에서 검색 패턴 추출
    search_patterns = []
    interface_name = None
    
    if vuln.analysis_details:
        details = vuln.analysis_details
        
        # 인터페이스 이름
        if 'interface_name' in details:
            interface_name = details['interface_name']
            search_patterns.append(f"interface {interface_name}")
        
        # 매치된 텍스트에서 패턴 추출
        if vuln.matched_text and vuln.matched_text != 'Configuration check required':
            # 간단한 키워드 추출
            keywords = vuln.matched_text.split()
            for keyword in keywords:
                if len(keyword) > 3 and not keyword.isdigit():
                    search_patterns.append(keyword)
    
    # 룰 ID 기반 패턴 추가
    rule_patterns = _get_search_patterns_by_rule(vuln.rule_id)
    search_patterns.extend(rule_patterns)
    
    # 실제 라인 번호 찾기
    if search_patterns:
        actual_line = find_actual_line_number(config_lines, search_patterns, interface_name)
        if actual_line > 0:
            vuln.line = actual_line
    
    return vuln


def _get_search_patterns_by_rule(rule_id: str) -> List[str]:
    """룰 ID별 검색 패턴 반환"""
    patterns = {
        'N-07': ['snmp-server', 'snmp'],
        'N-11': ['service tftp', 'tftp'],
        'N-25': ['service finger', 'finger'],
        'N-26': ['ip http server', 'http server'],
        'N-27': ['service tcp-small-servers', 'service udp-small-servers'],
        'N-29': ['cdp run'],
        'N-31': ['ip source-route'],
        'N-35': ['ip domain-lookup', 'ip domain lookup'],
        'N-36': ['service pad'],
        'NW-16': ['snmp-server', 'snmp'],
        'NW-20': ['service tftp', 'tftp'],
        'NW-25': ['service finger', 'finger'],
        'NW-26': ['ip http server', 'http server'],
        'NW-27': ['service tcp-small-servers', 'service udp-small-servers'],
        'NW-29': ['cdp run'],
        'NW-31': ['ip source-route'],
        'NW-35': ['ip domain-lookup', 'ip domain lookup'],
        'NW-36': ['service pad'],
    }
    
    return patterns.get(rule_id, [])