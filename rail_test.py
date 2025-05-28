#!/usr/bin/env python3
"""
배포된 KISA API 테스트 스크립트
사용법: python test_deployed_api.py https://your-app.railway.app
"""

import requests
import sys
import json
import time

def test_deployed_api(base_url):
    """배포된 API 테스트"""
    
    print(f"🧪 KISA API 테스트 시작: {base_url}")
    print("=" * 50)
    
    # 1. 헬스 체크
    print("1️⃣ 헬스 체크...")
    try:
        response = requests.get(f"{base_url}/api/v1/health", timeout=10)
        if response.status_code == 200:
            print("✅ 헬스 체크 성공")
            print(f"   응답: {response.json()}")
        else:
            print(f"❌ 헬스 체크 실패: {response.status_code}")
            return False
    except Exception as e:
        print(f"❌ 헬스 체크 오류: {e}")
        return False
    
    # 2. 룰 목록 조회
    print("\n2️⃣ 룰 목록 조회...")
    try:
        response = requests.get(f"{base_url}/api/v1/rules", timeout=10)
        if response.status_code == 200:
            data = response.json()
            print(f"✅ 룰 목록 조회 성공: 총 {data.get('totalRules', 0)}개 룰")
        else:
            print(f"❌ 룰 목록 조회 실패: {response.status_code}")
    except Exception as e:
        print(f"❌ 룰 목록 조회 오류: {e}")
    
    # 3. 취약한 설정 분석 테스트
    print("\n3️⃣ 취약한 설정 분석 테스트...")
    vulnerable_config = """
version 15.1
hostname TestRouter
!
enable password cisco123
!
snmp-server community public RO
snmp-server community private RW
!
service finger
ip http server
service tcp-small-servers
cdp run
ip source-route
!
line vty 0 4
 password simple123
 transport input telnet
!
end
"""
    
    test_request = {
        "deviceType": "Cisco",
        "configText": vulnerable_config,
        "options": {
            "checkAllRules": True,
            "includeRecommendations": True,
            "returnRawMatches": True
        }
    }
    
    try:
        start_time = time.time()
        response = requests.post(
            f"{base_url}/api/v1/config-analyze",
            json=test_request,
            headers={'Content-Type': 'application/json'},
            timeout=30
        )
        end_time = time.time()
        
        if response.status_code == 200:
            result = response.json()
            print(f"✅ 설정 분석 성공")
            print(f"   분석 시간: {end_time - start_time:.2f}초")
            print(f"   총 라인: {result.get('totalLines')}")
            print(f"   발견된 취약점: {result.get('issuesFound')}개")
            
            # 취약점 상세 정보 출력 (최대 5개)
            if result.get('results'):
                print("\n   발견된 취약점들:")
                for i, issue in enumerate(result['results'][:5], 1):
                    print(f"     {i}. [{issue.get('severity')}] {issue.get('ruleId')}")
                    print(f"        라인 {issue.get('line')}: {issue.get('matchedText')}")
                    print(f"        설명: {issue.get('description')}")
                
                if len(result['results']) > 5:
                    print(f"     ... 외 {len(result['results']) - 5}개")
            
            return True
        else:
            print(f"❌ 설정 분석 실패: {response.status_code}")
            print(f"   응답: {response.text}")
            return False
            
    except Exception as e:
        print(f"❌ 설정 분석 오류: {e}")
        return False
    
    # 4. 보안 설정 분석 테스트
    print("\n4️⃣ 보안 설정 분석 테스트...")
    secure_config = """
version 15.1
service timestamps debug datetime msec localtime show-timezone
service timestamps log datetime msec localtime show-timezone
service password-encryption
security passwords min-length 8
!
hostname SecureRouter
!
enable secret $1$mERr$9cTjUIlM1MHmBpJl6bYKj1
!
no snmp-server
no ip http server
no service finger
no service tcp-small-servers
no service udp-small-servers
no cdp run
no ip source-route
no ip domain-lookup
!
ip ssh version 2
access-list 10 permit 192.168.1.100
access-list 10 deny any log
!
line vty 0 4
 access-class 10 in
 exec-timeout 5 0
 login local
 transport input ssh
!
end
"""
    
    secure_request = {
        "deviceType": "Cisco",
        "configText": secure_config,
        "options": {
            "checkAllRules": True
        }
    }
    
    try:
        response = requests.post(
            f"{base_url}/api/v1/config-analyze",
            json=secure_request,
            headers={'Content-Type': 'application/json'},
            timeout=30
        )
        
        if response.status_code == 200:
            result = response.json()
            print(f"✅ 보안 설정 분석 성공")
            print(f"   발견된 취약점: {result.get('issuesFound')}개")
            if result.get('issuesFound') == 0:
                print("   🎉 완벽한 보안 설정!")
        else:
            print(f"❌ 보안 설정 분석 실패: {response.status_code}")
            
    except Exception as e:
        print(f"❌ 보안 설정 분석 오류: {e}")

def main():
    if len(sys.argv) != 2:
        print("사용법: python test_deployed_api.py <API_URL>")
        print("예시: python test_deployed_api.py https://your-app.railway.app")
        sys.exit(1)
    
    base_url = sys.argv[1].rstrip('/')
    
    success = test_deployed_api(base_url)
    
    print("\n" + "=" * 50)
    if success:
        print("🎉 모든 테스트 통과! API가 정상적으로 동작합니다.")
        print(f"\n📝 API 사용 예시:")
        print(f"curl -X POST {base_url}/api/v1/config-analyze \\")
        print(f'  -H "Content-Type: application/json" \\')
        print(f"  -d '{{\"deviceType\": \"Cisco\", \"configText\": \"enable password cisco123\", \"options\": {{\"checkAllRules\": true}}}}'")
    else:
        print("❌ 일부 테스트 실패. 로그를 확인해주세요.")

if __name__ == "__main__":
    main()