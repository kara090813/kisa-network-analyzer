#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
test_api.py
KISA 네트워크 장비 취약점 분석 API 테스트 스크립트

API의 기본 기능들을 테스트하는 스크립트
"""

import requests
import json
import time
from typing import Dict, Any


class APITester:
    """API 테스트 클래스"""
    
    def __init__(self, base_url: str = "http://localhost:5000"):
        self.base_url = base_url.rstrip('/')
        self.session = requests.Session()
        
    def test_health_check(self) -> bool:
        """헬스 체크 테스트"""
        print("=== 헬스 체크 테스트 ===")
        try:
            response = self.session.get(f"{self.base_url}/api/v1/health")
            response.raise_for_status()
            
            data = response.json()
            print(f"✓ 상태: {data.get('status')}")
            print(f"✓ 버전: {data.get('version')}")
            print(f"✓ 서비스: {data.get('service')}")
            return True
            
        except Exception as e:
            print(f"✗ 헬스 체크 실패: {e}")
            return False
    
    def test_get_rules(self) -> bool:
        """룰 목록 조회 테스트"""
        print("\n=== 룰 목록 조회 테스트 ===")
        try:
            response = self.session.get(f"{self.base_url}/api/v1/rules")
            response.raise_for_status()
            
            data = response.json()
            print(f"✓ 성공: {data.get('success')}")
            print(f"✓ 총 룰 수: {data.get('totalRules')}")
            
            if data.get('rules'):
                print("✓ 첫 번째 룰 예시:")
                first_rule = data['rules'][0]
                print(f"  - ID: {first_rule.get('ruleId')}")
                print(f"  - 제목: {first_rule.get('title')}")
                print(f"  - 심각도: {first_rule.get('severity')}")
            
            return True
            
        except Exception as e:
            print(f"✗ 룰 목록 조회 실패: {e}")
            return False
    
    def test_get_device_types(self) -> bool:
        """지원 장비 타입 조회 테스트"""
        print("\n=== 지원 장비 타입 조회 테스트 ===")
        try:
            response = self.session.get(f"{self.base_url}/api/v1/device-types")
            response.raise_for_status()
            
            data = response.json()
            print(f"✓ 성공: {data.get('success')}")
            print(f"✓ 지원 장비 타입: {', '.join(data.get('deviceTypes', []))}")
            
            return True
            
        except Exception as e:
            print(f"✗ 장비 타입 조회 실패: {e}")
            return False
    
    def test_config_analysis(self) -> bool:
        """설정 분석 테스트"""
        print("\n=== 설정 분석 테스트 ===")
        
        # 테스트용 Cisco 설정 (취약점 포함)
        test_config = """
version 15.1
service timestamps debug datetime msec
service timestamps log datetime msec
no service password-encryption
!
hostname TestRouter
!
boot-start-marker
boot-end-marker
!
enable password cisco123
!
no aaa new-model
!
ip domain name test.local
ip name-server 8.8.8.8
!
interface FastEthernet0/0
 ip address 192.168.1.1 255.255.255.0
 no shutdown
!
interface FastEthernet0/1
 shutdown
!
line con 0
line vty 0 4
 password telnet123
 login
 transport input all
!
snmp-server community public RO
snmp-server community private RW
!
service finger
ip http server
service tcp-small-servers
service udp-small-servers
cdp run
!
end
"""
        
        # 분석 요청 데이터
        request_data = {
            "deviceType": "Cisco",
            "configText": test_config,
            "options": {
                "checkAllRules": True,
                "returnRawMatches": True,
                "includeRecommendations": True
            }
        }
        
        try:
            print("요청 전송 중...")
            start_time = time.time()
            
            response = self.session.post(
                f"{self.base_url}/api/v1/config-analyze",
                json=request_data,
                headers={'Content-Type': 'application/json'}
            )
            response.raise_for_status()
            
            end_time = time.time()
            analysis_time = end_time - start_time
            
            data = response.json()
            print(f"✓ 성공: {data.get('success')}")
            print(f"✓ 장비 타입: {data.get('deviceType')}")
            print(f"✓ 총 라인 수: {data.get('totalLines')}")
            print(f"✓ 발견된 취약점: {data.get('issuesFound')}개")
            print(f"✓ 분석 시간: {analysis_time:.2f}초")
            
            # 취약점 상세 정보 출력
            if data.get('results'):
                print("\n발견된 취약점들:")
                for i, issue in enumerate(data['results'][:5], 1):  # 최대 5개만 출력
                    print(f"  {i}. [{issue.get('severity')}] {issue.get('ruleId')}")
                    print(f"     라인 {issue.get('line')}: {issue.get('matchedText')}")
                    print(f"     설명: {issue.get('description')}")
                    if len(data['results']) > 5:
                        print(f"  ... 외 {len(data['results']) - 5}개")
                        break
            
            # 통계 정보 출력
            if data.get('statistics'):
                stats = data['statistics']
                print(f"\n분석 통계:")
                print(f"  - 검사된 룰: {stats.get('totalRulesChecked')}개")
                print(f"  - 통과: {stats.get('rulesPassed')}개")
                print(f"  - 실패: {stats.get('rulesFailed')}개")
                print(f"  - 상급 취약점: {stats.get('highSeverityIssues')}개")
                print(f"  - 중급 취약점: {stats.get('mediumSeverityIssues')}개")
                print(f"  - 하급 취약점: {stats.get('lowSeverityIssues')}개")
            
            return True
            
        except Exception as e:
            print(f"✗ 설정 분석 실패: {e}")
            if hasattr(e, 'response') and e.response:
                print(f"응답 내용: {e.response.text}")
            return False
    
    def test_specific_rules(self) -> bool:
        """특정 룰만 분석 테스트"""
        print("\n=== 특정 룰 분석 테스트 ===")
        
        test_config = """
enable password cisco123
snmp-server community public RO
line vty 0 4
 password simple
 transport input telnet
"""
        
        request_data = {
            "deviceType": "Cisco",
            "configText": test_config,
            "options": {
                "checkAllRules": False,
                "specificRuleIds": ["N-01", "N-08", "N-16"],
                "returnRawMatches": True
            }
        }
        
        try:
            response = self.session.post(
                f"{self.base_url}/api/v1/config-analyze",
                json=request_data,
                headers={'Content-Type': 'application/json'}
            )
            response.raise_for_status()
            
            data = response.json()
            print(f"✓ 특정 룰 분석 성공")
            print(f"✓ 발견된 취약점: {data.get('issuesFound')}개")
            
            rule_counts = {}
            for issue in data.get('results', []):
                rule_id = issue.get('ruleId')
                rule_counts[rule_id] = rule_counts.get(rule_id, 0) + 1
            
            print(f"✓ 룰별 취약점: {rule_counts}")
            
            return True
            
        except Exception as e:
            print(f"✗ 특정 룰 분석 실패: {e}")
            return False
    
    def test_invalid_requests(self) -> bool:
        """잘못된 요청 테스트"""
        print("\n=== 잘못된 요청 테스트 ===")
        
        # 빈 요청
        try:
            response = self.session.post(f"{self.base_url}/api/v1/config-analyze")
            if response.status_code == 400:
                print("✓ 빈 요청 거부됨")
            else:
                print("✗ 빈 요청이 승인됨 (문제)")
        except:
            pass
        
        # 잘못된 장비 타입
        try:
            response = self.session.post(
                f"{self.base_url}/api/v1/config-analyze",
                json={
                    "deviceType": "InvalidDevice",
                    "configText": "test config"
                }
            )
            if response.status_code == 400:
                print("✓ 잘못된 장비 타입 거부됨")
            else:
                print("✗ 잘못된 장비 타입이 승인됨 (문제)")
        except:
            pass
        
        # 빈 설정 텍스트
        try:
            response = self.session.post(
                f"{self.base_url}/api/v1/config-analyze",
                json={
                    "deviceType": "Cisco",
                    "configText": ""
                }
            )
            if response.status_code == 400:
                print("✓ 빈 설정 텍스트 거부됨")
            else:
                print("✗ 빈 설정 텍스트가 승인됨 (문제)")
        except:
            pass
        
        return True
    
    def run_all_tests(self) -> Dict[str, bool]:
        """모든 테스트 실행"""
        print("KISA 네트워크 장비 취약점 분석 API 테스트 시작\n")
        
        tests = {
            'health_check': self.test_health_check,
            'get_rules': self.test_get_rules,
            'get_device_types': self.test_get_device_types,
            'config_analysis': self.test_config_analysis,
            'specific_rules': self.test_specific_rules,
            'invalid_requests': self.test_invalid_requests
        }
        
        results = {}
        for test_name, test_func in tests.items():
            try:
                results[test_name] = test_func()
            except Exception as e:
                print(f"✗ {test_name} 테스트 중 예외 발생: {e}")
                results[test_name] = False
        
        # 결과 요약
        print("\n" + "="*50)
        print("테스트 결과 요약")
        print("="*50)
        
        passed = sum(results.values())
        total = len(results)
        
        for test_name, result in results.items():
            status = "✓ PASS" if result else "✗ FAIL"
            print(f"{test_name:20} : {status}")
        
        print(f"\n총 {total}개 테스트 중 {passed}개 통과 ({passed/total*100:.1f}%)")
        
        return results


def main():
    """메인 함수"""
    import argparse
    
    parser = argparse.ArgumentParser(description='KISA API 테스트')
    parser.add_argument(
        '--url', 
        default='http://localhost:5000',
        help='API 서버 URL (기본: http://localhost:5000)'
    )
    parser.add_argument(
        '--test',
        choices=['health', 'rules', 'device-types', 'analyze', 'specific', 'invalid', 'all'],
        default='all',
        help='실행할 테스트 선택'
    )
    
    args = parser.parse_args()
    
    tester = APITester(args.url)
    
    # 개별 테스트 실행
    if args.test == 'all':
        tester.run_all_tests()
    elif args.test == 'health':
        tester.test_health_check()
    elif args.test == 'rules':
        tester.test_get_rules()
    elif args.test == 'device-types':
        tester.test_get_device_types()
    elif args.test == 'analyze':
        tester.test_config_analysis()
    elif args.test == 'specific':
        tester.test_specific_rules()
    elif args.test == 'invalid':
        tester.test_invalid_requests()


if __name__ == '__main__':
    main()
