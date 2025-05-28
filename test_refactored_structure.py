#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
test_refactored_structure.py
리팩토링된 구조 테스트 스크립트

새로운 다중 지침서 지원 구조가 제대로 작동하는지 테스트
기존 API와의 호환성 및 새로운 기능 테스트
"""

import sys
import os
import traceback
from typing import Dict, List, Any

# 프로젝트 루트 디렉토리를 sys.path에 추가
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

def test_rules_import():
    """룰 import 테스트"""
    print("=== 룰 Import 테스트 ===")
    
    try:
        # 1. 새로운 loader 시스템 테스트
        from rules.loader import (
            load_rules, 
            get_supported_sources, 
            get_source_info,
            get_statistics
        )
        
        print("✅ rules.loader import 성공")
        
        # 2. 지원되는 지침서 확인
        sources = get_supported_sources()
        print(f"✅ 지원 지침서: {list(sources.keys())}")
        
        # 3. KISA 룰 로드 테스트
        kisa_rules = load_rules("KISA")
        print(f"✅ KISA 룰 로드: {len(kisa_rules)}개")
        
        # 4. 통계 정보 테스트
        stats = get_statistics("KISA")
        print(f"✅ KISA 통계: 총 {stats['totalRules']}개, 논리분석 {stats['logicalRules']}개")
        
        # 5. 기존 호환성 테스트
        from rules import get_all_rules, get_rules_by_device_type
        
        all_rules = get_all_rules()
        cisco_rules = get_rules_by_device_type("Cisco")
        
        print(f"✅ 기존 호환성: 전체 {len(all_rules)}개, Cisco {len(cisco_rules)}개")
        
        return True
        
    except Exception as e:
        print(f"❌ 룰 import 실패: {e}")
        traceback.print_exc()
        return False


def test_logical_checks_import():
    """논리적 검증 함수 import 테스트"""
    print("\n=== 논리적 검증 함수 Import 테스트 ===")
    
    try:
        from rules.checks_kisa import (
            check_basic_password_usage,
            check_password_complexity,
            check_vty_access_control,
            check_snmp_security
        )
        
        print("✅ 논리적 검증 함수 import 성공")
        
        # 간단한 실행 테스트
        from rules.kisa_rules import ConfigContext
        
        # 더미 컨텍스트 생성
        test_context = ConfigContext(
            full_config="enable password cisco123",
            config_lines=["enable password cisco123"],
            device_type="Cisco"
        )
        test_context.global_settings = {
            'enable_password_type': 'password',
            'enable_password_value': 'cisco123'
        }
        
        # N-01 룰 테스트
        vulnerabilities = check_basic_password_usage("", 1, test_context)
        print(f"✅ N-01 논리적 검증 테스트: {len(vulnerabilities)}개 취약점 발견")
        
        return True
        
    except Exception as e:
        print(f"❌ 논리적 검증 함수 테스트 실패: {e}")
        traceback.print_exc()
        return False


def test_analyzer_integration():
    """분석기 통합 테스트"""
    print("\n=== 분석기 통합 테스트 ===")
    
    try:
        from analyzers.config_analyzer import EnhancedConfigAnalyzer
        from models.analysis_request import AnalysisRequest, AnalysisOptions
        
        # 분석기 초기화
        analyzer = EnhancedConfigAnalyzer()
        print("✅ 분석기 초기화 성공")
        
        # 테스트 설정
        test_config = """
version 15.1
hostname TestRouter
enable password cisco123
snmp-server community public RO
line vty 0 4
 password simple
 transport input telnet
end
"""
        
        # 분석 요청 생성
        request = AnalysisRequest(
            device_type="Cisco",
            config_text=test_config,
            options=AnalysisOptions(check_all_rules=True)
        )
        
        # 분석 실행
        result = analyzer.analyze_config(request)
        
        print(f"✅ 분석 완료: {len(result.vulnerabilities)}개 취약점 발견")
        print(f"   - 분석 시간: {result.analysis_time:.2f}초")
        
        # 발견된 취약점 출력
        if result.vulnerabilities:
            print("   발견된 취약점:")
            for vuln in result.vulnerabilities[:3]:  # 처음 3개만 출력
                print(f"     - [{vuln.severity}] {vuln.rule_id}: {vuln.description}")
        
        return True
        
    except Exception as e:
        print(f"❌ 분석기 통합 테스트 실패: {e}")
        traceback.print_exc()
        return False


def test_api_compatibility():
    """기존 API 호환성 테스트"""
    print("\n=== 기존 API 호환성 테스트 ===")
    
    try:
        # 기존 방식으로 룰 접근
        from rules.security_rules import get_all_rules, get_rule_by_id
        
        # 이것은 실패해야 함 (파일이 분리되었으므로)
        print("⚠️  기존 security_rules.py import 테스트...")
        
    except ImportError:
        print("✅ 예상된 동작: security_rules.py가 분리됨")
        
        # 새로운 방식으로 테스트
        try:
            from rules import get_all_rules, get_rule_by_id
            
            all_rules = get_all_rules()
            rule_n01 = get_rule_by_id("N-01")
            
            print(f"✅ 새로운 import 경로로 성공: 전체 {len(all_rules)}개 룰")
            print(f"   N-01 룰: {rule_n01.title if rule_n01 else 'None'}")
            
            return True
            
        except Exception as e:
            print(f"❌ 새로운 import 경로 실패: {e}")
            return False
    
    except Exception as e:
        print(f"❌ 호환성 테스트 중 예외 발생: {e}")
        return False


def test_multi_framework_support():
    """다중 지침서 지원 테스트"""
    print("\n=== 다중 지침서 지원 테스트 ===")
    
    try:
        from rules.loader import load_rules, get_supported_sources
        
        sources = get_supported_sources()
        print(f"✅ 지원 지침서: {list(sources.keys())}")
        
        # KISA 로드 테스트
        kisa_rules = load_rules("KISA")
        print(f"✅ KISA 로드 성공: {len(kisa_rules)}개 룰")
        
        # CIS 로드 테스트 (구현되지 않음)
        try:
            cis_rules = load_rules("CIS")
            print(f"✅ CIS 로드 성공: {len(cis_rules)}개 룰")
        except NotImplementedError:
            print("✅ 예상된 동작: CIS는 아직 구현되지 않음")
        
        # 잘못된 지침서 테스트
        try:
            invalid_rules = load_rules("INVALID")
            print(f"❌ 예상치 못한 성공: {len(invalid_rules)}개 룰")
        except ValueError:
            print("✅ 예상된 동작: 잘못된 지침서 거부")
        
        return True
        
    except Exception as e:
        print(f"❌ 다중 지침서 테스트 실패: {e}")
        traceback.print_exc()
        return False


def test_specific_rules():
    """특정 룰들의 동작 테스트"""
    print("\n=== 특정 룰 동작 테스트 ===")
    
    try:
        from rules import get_rule_by_id
        from rules.kisa_rules import parse_config_context
        
        # N-01 룰 테스트
        rule_n01 = get_rule_by_id("N-01")
        if rule_n01:
            print(f"✅ N-01 룰: {rule_n01.title}")
            print(f"   논리 분석: {'있음' if rule_n01.logical_check_function else '없음'}")
            
            # 논리 분석 실행 테스트
            if rule_n01.logical_check_function:
                test_config = "enable password cisco123"
                context = parse_config_context(test_config, "Cisco")
                context.global_settings = {
                    'enable_password_type': 'password',
                    'enable_password_value': 'cisco123'
                }
                
                vulns = rule_n01.logical_check_function("", 1, context)
                print(f"   논리 분석 결과: {len(vulns)}개 취약점")
        
        # N-08 룰 테스트
        rule_n08 = get_rule_by_id("N-08")
        if rule_n08:
            print(f"✅ N-08 룰: {rule_n08.title}")
            print(f"   논리 분석: {'있음' if rule_n08.logical_check_function else '없음'}")
        
        return True
        
    except Exception as e:
        print(f"❌ 특정 룰 테스트 실패: {e}")
        traceback.print_exc()
        return False


def main():
    """메인 테스트 함수"""
    print("🚀 리팩토링된 구조 테스트 시작")
    print("=" * 50)
    
    tests = [
        ("룰 Import", test_rules_import),
        ("논리적 검증 함수", test_logical_checks_import),
        ("분석기 통합", test_analyzer_integration),
        ("API 호환성", test_api_compatibility),
        ("다중 지침서 지원", test_multi_framework_support),
        ("특정 룰 동작", test_specific_rules)
    ]
    
    results = {}
    
    for test_name, test_func in tests:
        try:
            results[test_name] = test_func()
        except Exception as e:
            print(f"❌ {test_name} 테스트 중 예외 발생: {e}")
            results[test_name] = False
    
    # 결과 요약
    print("\n" + "=" * 50)
    print("🎯 테스트 결과 요약")
    print("=" * 50)
    
    passed = sum(results.values())
    total = len(results)
    
    for test_name, result in results.items():
        status = "✅ PASS" if result else "❌ FAIL"
        print(f"{test_name:20} : {status}")
    
    print(f"\n📊 총 {total}개 테스트 중 {passed}개 통과 ({passed/total*100:.1f}%)")
    
    if passed == total:
        print("🎉 모든 테스트 통과! 리팩토링이 성공적으로 완료되었습니다.")
    else:
        print("⚠️  일부 테스트 실패. 코드를 점검해주세요.")
    
    return results


if __name__ == "__main__":
    main()