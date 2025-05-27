# ================================
# examples/README.md
# 예제 설정 파일 설명

이 디렉토리에는 KISA 네트워크 장비 보안 분석을 위한 다양한 예제 설정 파일들이 포함되어 있습니다.

## 파일 목록

### Cisco 설정 파일
- `cisco_vulnerable.cfg`: 다양한 취약점이 포함된 Cisco 설정
- `cisco_secure.cfg`: 보안 권고사항이 적용된 Cisco 설정
- `worst_case_cisco.cfg`: 최악의 보안 상태 (모든 취약점 포함)
- `medium_case_cisco.cfg`: 중간 수준의 보안 상태
- `perfect_case_cisco.cfg`: 완벽한 보안 설정

### Juniper 설정 파일  
- `juniper_vulnerable.conf`: 취약점이 포함된 Juniper 설정
- `juniper_secure.conf`: 보안이 강화된 Juniper 설정

## 사용법

### API 테스트
```bash
# 취약한 설정 분석
curl -X POST http://localhost:5000/api/v1/config-analyze \
  -H "Content-Type: application/json" \
  -d "{
    \"deviceType\": \"Cisco\",
    \"configText\": \"$(cat examples/cisco_vulnerable.cfg)\",
    \"options\": {\"checkAllRules\": true}
  }"

# 보안 설정 분석  
curl -X POST http://localhost:5000/api/v1/config-analyze \
  -H "Content-Type: application/json" \
  -d "{
    \"deviceType\": \"Cisco\", 
    \"configText\": \"$(cat examples/cisco_secure.cfg)\",
    \"options\": {\"checkAllRules\": true}
  }"
```

### Python 스크립트
```python
import requests

# 파일 읽기
with open('examples/cisco_vulnerable.cfg', 'r') as f:
    config = f.read()

# 분석 요청
response = requests.post('http://localhost:5000/api/v1/config-analyze', 
    json={
        'deviceType': 'Cisco',
        'configText': config,
        'options': {'checkAllRules': True}
    })

print(f"취약점 발견: {response.json()['issuesFound']}개")
```

## 예상 결과

### cisco_vulnerable.cfg 분석 결과
- 예상 취약점: 8-10개
- 주요 발견사항:
  - N-01: 기본 패스워드 사용
  - N-04: VTY 접근 제한 없음
  - N-08: SNMP 기본 커뮤니티
  - N-16: Telnet 사용
  - N-25: Finger 서비스 활성화
  - N-26: HTTP 서비스 활성화
  - N-27: Small 서비스 활성화
  - N-29: CDP 활성화

### cisco_secure.cfg 분석 결과
- 예상 취약점: 0개
- 모든 보안 권고사항 적용됨

이 예제들을 통해 API의 정확성과 KISA 가이드 준수 여부를 확인할 수 있습니다.