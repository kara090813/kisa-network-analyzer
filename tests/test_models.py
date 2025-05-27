# ================================
# tests/test_models.py
# -*- coding: utf-8 -*-
"""
단위 테스트 - 데이터 모델 테스트
"""

import unittest
from models.analysis_request import AnalysisRequest, AnalysisOptions
from models.analysis_response import VulnerabilityIssue, AnalysisResponse


class TestDataModels(unittest.TestCase):
    """데이터 모델 테스트"""
    
    def test_analysis_request_validation(self):
        """분석 요청 검증 테스트"""
        # 유효한 요청
        valid_request = AnalysisRequest(
            device_type="Cisco",
            config_text="hostname Router",
            options=AnalysisOptions()
        )
        errors = valid_request.validate()
        self.assertEqual(len(errors), 0)
        
        # 무효한 요청 - 빈 장비 타입
        invalid_request = AnalysisRequest(
            device_type="",
            config_text="hostname Router",
            options=AnalysisOptions()
        )
        errors = invalid_request.validate()
        self.assertGreater(len(errors), 0)
    
    def test_vulnerability_issue_creation(self):
        """취약점 이슈 생성 테스트"""
        issue = VulnerabilityIssue(
            rule_id="N-01",
            severity="상",
            line=10,
            matched_text="enable password cisco",
            description="기본 패스워드 사용",
            recommendation="보안 패스워드로 변경",
            reference="KISA 가이드 N-01"
        )
        
        issue_dict = issue.to_dict()
        self.assertEqual(issue_dict["ruleId"], "N-01")
        self.assertEqual(issue_dict["severity"], "상")
        self.assertEqual(issue_dict["line"], 10)
    
    def test_analysis_response_serialization(self):
        """분석 응답 직렬화 테스트"""
        response = AnalysisResponse(
            device_type="Cisco",
            total_lines=100,
            issues_found=2,
            analysis_time=1.5,
            results=[]
        )
        
        response_dict = response.to_dict()
        self.assertTrue(response_dict["success"])
        self.assertEqual(response_dict["deviceType"], "Cisco")
        self.assertEqual(response_dict["totalLines"], 100)