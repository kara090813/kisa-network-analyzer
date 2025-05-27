#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
파일을 사용한 KISA API 테스트 스크립트
"""

import requests
import json
import os

def test_config_file(filename, device_type="Cisco"):
    """설정 파일을 사용해서 API 테스트"""
    
    # 파일 존재 확인
    if not os.path.exists(filename):
        print(f"❌ 파일을 찾을 수 없습니다: {filename}")
        return
    
    # 파일 읽기
    try:
        with open(filename, 'r', encoding='utf-8') as f:
            config_text = f.read()
    except Exception as e:
        print(f"❌ 파일 읽기 오류: {e}")
        return
    
    print(f"📄 파일: {filename}")
    print(f"📏 라인 수: {len(config_text.splitlines())}")
    print(f"🔧 장비 타입: {device_type}")
    
    # API 호출
    url = "http://localhost:5001/api/v1/config-analyze"
    data = {
        "deviceType": device_type,
        "configText": config_text,
        "options": {
            "checkAllRules": True,
            "includeRecommendations": True
        }
    }
    
    try:
        print("🚀 API 호출 중...")
        response = requests.post(url, json=data, headers={'Content-Type': 'application/json'})
        
        if response.status_code == 200:
            result = response.json()
            print("✅ 분석 성공!")
            print(f"📊 총 라인 수: {result.get('totalLines', 0)}")
            print(f"🚨 발견된 취약점: {result.get('issuesFound', 0)}개")
            
            if result.get('results'):
                print("\n🔍 발견된 취약점들:")
                for i, issue in enumerate(result['results'][:5], 1):  # 최대 5개만 표시
                    print(f"  {i}. [{issue.get('severity')}] {issue.get('ruleId')}")
                    print(f"     라인 {issue.get('line')}: {issue.get('matchedText')}")
                    print(f"     📝 {issue.get('description')}")
                    print(f"     💡 권고: {issue.get('recommendation')}")
                    print()
                
                if len(result['results']) > 5:
                    print(f"  ... 외 {len(result['results']) - 5}개")
            else:
                print("✅ 취약점이 발견되지 않았습니다!")
        
        else:
            print(f"❌ API 오류 (코드: {response.status_code})")
            try:
                error_data = response.json()
                print(f"오류 내용: {error_data.get('error', 'Unknown error')}")
                if 'details' in error_data:
                    print(f"상세: {error_data['details']}")
            except:
                print(f"응답: {response.text}")
    
    except requests.exceptions.ConnectionError:
        print("❌ 서버에 연결할 수 없습니다. 서버가 실행 중인지 확인하세요.")
    except Exception as e:
        print(f"❌ 오류 발생: {e}")

def main():
    """메인 함수"""
    print("=== KISA 네트워크 설정 파일 분석 테스트 ===\n")
    
    # 1. 헬스 체크
    try:
        response = requests.get("http://localhost:5001/api/v1/health")
        if response.status_code == 200:
            print("✅ 서버 연결 성공\n")
        else:
            print("❌ 서버 응답 오류\n")
            return
    except:
        print("❌ 서버에 연결할 수 없습니다. 서버가 실행 중인지 확인하세요.\n")
        return
    
    # 2. 예제 파일들 테스트
    test_files = [
        "examples/cisco_vulnerable.cfg",
        "examples/cisco_secure.cfg"
    ]
    
    for filename in test_files:
        print("-" * 50)
        test_config_file(filename)
        print()

if __name__ == "__main__":
    main()