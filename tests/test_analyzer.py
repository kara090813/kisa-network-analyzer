# tests/test_analyzer.py
# -*- coding: utf-8 -*-
"""
단위 테스트 - 분석 엔진 테스트
"""

import unittest
from analyzers.config_analyzer import ConfigAnalyzer
from models.analysis_request import AnalysisRequest, AnalysisOptions
from rules.security_rules import get_rule_by_id


class TestConfigAnalyzer(unittest.TestCase):
    """설정 분석기 테스트"""
    
    def setUp(self):
        """테스트 설정"""
        self.analyzer = ConfigAnalyzer()
    
    def test_cisco_basic_password_detection(self):
        """Cisco 기본 패스워드 탐지 테스트"""
        config = "enable password cisco123"
        request = AnalysisRequest(
            device_type="Cisco",
            config_text=config,
            options=AnalysisOptions(specific_rule_ids=["N-01"])
        )
        
        result = self.analyzer.analyze_config(request)
        self.assertEqual(len(result.vulnerabilities), 1)
        self.assertEqual(result.vulnerabilities[0].rule_id, "N-01")
    
    def test_cisco_secure_password(self):
        """Cisco 보안 패스워드 테스트"""
        config = "enable secret $1$mERr$9cTjUIlM1MHmBpJl6bYKj1"
        request = AnalysisRequest(
            device_type="Cisco",
            config_text=config,
            options=AnalysisOptions(specific_rule_ids=["N-01"])
        )
        
        result = self.analyzer.analyze_config(request)
        self.assertEqual(len(result.vulnerabilities), 0)
    
    def test_snmp_community_detection(self):
        """SNMP 커뮤니티 탐지 테스트"""
        config = """
snmp-server community public RO
snmp-server community private RW
        """
        request = AnalysisRequest(
            device_type="Cisco",
            config_text=config,
            options=AnalysisOptions(specific_rule_ids=["N-08"])
        )
        
        result = self.analyzer.analyze_config(request)
        self.assertEqual(len(result.vulnerabilities), 2)
    
    def test_multiple_device_types(self):
        """다중 장비 타입 지원 테스트"""
        supported_types = self.analyzer.get_supported_device_types()
        expected_types = ["Cisco", "Juniper", "Radware", "Passport", "Piolink"]
        
        for device_type in expected_types:
            self.assertIn(device_type, supported_types)
    
    def test_rule_availability(self):
        """룰 가용성 테스트"""
        rules = self.analyzer.get_available_rules()
        self.assertGreater(len(rules), 0)
        
        # 필수 룰들 존재 확인
        essential_rules = ["N-01", "N-04", "N-08", "N-16"]
        available_rule_ids = [rule["ruleId"] for rule in rules]
        
        for rule_id in essential_rules:
            self.assertIn(rule_id, available_rule_ids)