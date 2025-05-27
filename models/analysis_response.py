# -*- coding: utf-8 -*-
"""
models/analysis_response.py
분석 응답 데이터 모델

KISA 네트워크 장비 취약점 분석 결과를 위한 데이터 구조 정의
"""

from dataclasses import dataclass
from typing import List, Optional, Dict, Any
from datetime import datetime
from enum import Enum


class Severity(Enum):
    """취약점 심각도"""
    HIGH = "상"      # 상급
    MEDIUM = "중"    # 중급
    LOW = "하"       # 하급


@dataclass
class VulnerabilityIssue:
    """발견된 취약점 정보"""
    rule_id: str
    severity: str
    line: int
    matched_text: str
    description: str
    recommendation: str
    reference: str
    category: Optional[str] = None
    raw_match: Optional[str] = None
    
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
            raw_match=data.get('rawMatch')
        )
    
    def to_dict(self) -> Dict[str, Any]:
        """딕셔너리로 변환"""
        result = {
            'ruleId': self.rule_id,
            'severity': self.severity,
            'line': self.line,
            'matchedText': self.matched_text,
            'description': self.description,
            'recommendation': self.recommendation,
            'reference': self.reference
        }
        
        if self.category:
            result['category'] = self.category
        if self.raw_match:
            result['rawMatch'] = self.raw_match
            
        return result


@dataclass
class AnalysisStatistics:
    """분석 통계 정보"""
    total_rules_checked: int
    rules_passed: int
    rules_failed: int
    high_severity_issues: int
    medium_severity_issues: int
    low_severity_issues: int
    
    def to_dict(self) -> Dict[str, Any]:
        """딕셔너리로 변환"""
        return {
            'totalRulesChecked': self.total_rules_checked,
            'rulesPassed': self.rules_passed,
            'rulesFailed': self.rules_failed,
            'highSeverityIssues': self.high_severity_issues,
            'mediumSeverityIssues': self.medium_severity_issues,
            'lowSeverityIssues': self.low_severity_issues
        }


@dataclass
class AnalysisResult:
    """분석 결과"""
    vulnerabilities: List[VulnerabilityIssue]
    analysis_time: float
    statistics: Optional[AnalysisStatistics] = None
    
    def get_issues_by_severity(self, severity: str) -> List[VulnerabilityIssue]:
        """특정 심각도의 취약점들만 반환"""
        return [issue for issue in self.vulnerabilities if issue.severity == severity]
    
    def get_issues_by_rule(self, rule_id: str) -> List[VulnerabilityIssue]:
        """특정 룰의 취약점들만 반환"""
        return [issue for issue in self.vulnerabilities if issue.rule_id == rule_id]


@dataclass
class AnalysisResponse:
    """분석 응답"""
    device_type: str
    total_lines: int
    issues_found: int
    analysis_time: float
    results: List[VulnerabilityIssue]
    statistics: Optional[AnalysisStatistics] = None
    timestamp: Optional[str] = None
    
    def __post_init__(self):
        """초기화 후 처리"""
        if self.timestamp is None:
            self.timestamp = datetime.now().isoformat()
    
    def to_dict(self) -> Dict[str, Any]:
        """딕셔너리로 변환"""
        response = {
            'success': True,
            'deviceType': self.device_type,
            'totalLines': self.total_lines,
            'issuesFound': self.issues_found,
            'analysisTime': self.analysis_time,
            'timestamp': self.timestamp,
            'results': [issue.to_dict() for issue in self.results]
        }
        
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
            statistics=self.statistics,
            timestamp=self.timestamp
        )
