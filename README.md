# KISA 네트워크 장비 취약점 분석 API

KISA(한국인터넷진흥원) 네트워크 장비 보안 가이드를 기반으로 네트워크 장비 설정 파일의 보안 취약점을 자동으로 탐지하는 REST API입니다.

## 📋 목차

- [프로젝트 개요](#-프로젝트-개요)
- [주요 기능](#-주요-기능)
- [지원 장비](#-지원-장비)
- [설치 및 실행](#-설치-및-실행)
- [API 사용법](#-api-사용법)
- [예제](#-예제)
- [개발 환경 설정](#-개발-환경-설정)
- [기여 방법](#-기여-방법)

## 🎯 프로젝트 개요

이 프로젝트는 네트워크 관리자들이 장비 설정의 보안 취약점을 빠르고 정확하게 식별할 수 있도록 도와주는 도구입니다. KISA 주요정보통신기반시설 기술적 취약점 분석·평가 방법 상세가이드를 기반으로 38개의 보안 점검 항목을 자동화했습니다.

### 주요 특징

- **KISA 가이드 완전 준수**: 공식 보안 가이드라인 기반 룰셋
- **다중 장비 지원**: Cisco, Juniper, Radware 등 주요 벤더 지원
- **실시간 분석**: 설정 파일 업로드 즉시 취약점 탐지
- **상세한 권고사항**: 각 취약점별 구체적인 해결방법 제시
- **REST API**: 다양한 시스템과 쉬운 연동 가능

## ✨ 주요 기능

### 보안 점검 항목 (38개 룰)

#### 🔐 계정 관리 (상급)
- **N-01**: 기본 패스워드 변경 여부
- **N-02**: 패스워드 복잡성 설정
- **N-03**: 암호화된 패스워드 사용

#### 🛡️ 접근 관리 (상급/중급)
- **N-04**: VTY 접근 제한 (ACL) 설정
- **N-05**: Session Timeout 설정
- **N-16**: VTY 안전한 프로토콜 (SSH) 사용

#### 🔧 기능 관리 (상급/중급)
- **N-07**: SNMP 서비스 차단
- **N-08**: SNMP Community String 복잡성
- **N-11**: TFTP 서비스 차단
- **N-25**: Finger 서비스 차단
- **N-26**: 웹 서비스 차단
- **N-27**: TCP/UDP Small 서비스 차단
- **N-29**: CDP 서비스 차단
- **N-31**: Source 라우팅 차단
- **N-35**: Domain Lookup 차단

#### 📊 로그 관리 (중급/하급)
- **N-19**: 원격 로그서버 사용
- **N-22**: NTP 서버 연동
- **N-23**: Timestamp 로그 설정

## 🔧 지원 장비

| 벤더 | 모델 | 지원 버전 |
|------|------|-----------|
| Cisco | IOS/IOS-XE | 12.x, 15.x |
| Juniper | Junos | 모든 버전 |
| Radware | Alteon | 28.x, 29.x |
| Nortel | Passport | 7.x |
| Piolink | PLOS | 모든 버전 |

## 🚀 설치 및 실행

### 요구사항

- Python 3.8 이상
- pip 패키지 관리자

### 설치

```bash
# 저장소 복제
git clone https://github.com/your-org/kisa-network-analyzer.git
cd kisa-network-analyzer

# 가상환경 생성 및 활성화
python -m venv venv
source venv/bin/activate  # Windows: venv\Scripts\activate

# 의존성 설치
pip install -r requirements.txt
```

### 실행

```bash
# 개발 서버 실행
python main.py

# 또는 Flask 명령어 사용
export FLASK_APP=main.py
export FLASK_ENV=development
flask run
```

서버가 실행되면 `http://localhost:5000`에서 API를 사용할 수 있습니다.

## 📡 API 사용법

### 기본 엔드포인트

| Method | Endpoint | 설명 |
|--------|----------|------|
| GET | `/api/v1/health` | 서비스 상태 확인 |
| GET | `/api/v1/rules` | 사용 가능한 룰 목록 |
| GET | `/api/v1/device-types` | 지원 장비 타입 |
| POST | `/api/v1/config-analyze` | 설정 파일 분석 |

### 설정 분석 API

**요청 (POST `/api/v1/config-analyze`)**

```json
{
  "deviceType": "Cisco",
  "configText": "version 15.1\nhostname Router\nenable password cisco123\n...",
  "options": {
    "checkAllRules": true,
    "specificRuleIds": ["N-01", "N-04"],
    "returnRawMatches": false,
    "includeRecommendations": true
  }
}
```

**응답 (200 OK)**

```json
{
  "success": true,
  "deviceType": "Cisco",
  "totalLines": 120,
  "issuesFound": 3,
  "analysisTime": 0.45,
  "timestamp": "2024-01-15T10:30:00Z",
  "results": [
    {
      "ruleId": "N-01",
      "severity": "상",
      "line": 15,
      "matchedText": "enable password cisco123",
      "description": "기본 패스워드를 변경하지 않고 사용",
      "recommendation": "enable secret 명령어로 암호화된 패스워드 설정 필요",
      "reference": "KISA 가이드 N-01 (상) 1.1 패스워드 설정",
      "category": "계정 관리"
    }
  ],
  "statistics": {
    "totalRulesChecked": 25,
    "rulesPassed": 22,
    "rulesFailed": 3,
    "highSeverityIssues": 2,
    "mediumSeverityIssues": 1,
    "lowSeverityIssues": 0
  }
}
```

## 📝 예제

### Python 클라이언트

```python
import requests

# 설정 파일 읽기
with open('router_config.txt', 'r') as f:
    config_text = f.read()

# API 요청
response = requests.post('http://localhost:5000/api/v1/config-analyze', json={
    "deviceType": "Cisco",
    "configText": config_text,
    "options": {
        "checkAllRules": True,
        "includeRecommendations": True
    }
})

# 결과 처리
if response.status_code == 200:
    result = response.json()
    print(f"발견된 취약점: {result['issuesFound']}개")
    
    for issue in result['results']:
        print(f"[{issue['severity']}] {issue['ruleId']}: {issue['description']}")
        print(f"  라인 {issue['line']}: {issue['matchedText']}")
        print(f"  권고: {issue['recommendation']}")
        print()
```

### JavaScript/Node.js 클라이언트

```javascript
const axios = require('axios');
const fs = require('fs');

async function analyzeConfig() {
    try {
        const configText = fs.readFileSync('router_config.txt', 'utf8');
        
        const response = await axios.post('http://localhost:5000/api/v1/config-analyze', {
            deviceType: 'Cisco',
            configText: configText,
            options: {
                checkAllRules: true,
                includeRecommendations: true
            }
        });
        
        const result = response.data;
        console.log(`발견된 취약점: ${result.issuesFound}개`);
        
        result.results.forEach(issue => {
            console.log(`[${issue.severity}] ${issue.ruleId}: ${issue.description}`);
            console.log(`  라인 ${issue.line}: ${issue.matchedText}`);
            console.log(`  권고: ${issue.recommendation}`);
        });
        
    } catch (error) {
        console.error('분석 실패:', error.message);
    }
}

analyzeConfig();
```

### curl 명령어

```bash
# 설정 파일 분석
curl -X POST http://localhost:5000/api/v1/config-analyze \
  -H "Content-Type: application/json" \
  -d '{
    "deviceType": "Cisco",
    "configText": "version 15.1\nhostname Router\nenable password cisco123",
    "options": {
      "checkAllRules": true
    }
  }'

# 특정 룰만 검사
curl -X POST http://localhost:5000/api/v1/config-analyze \
  -H "Content-Type: application/json" \
  -d '{
    "deviceType": "Cisco", 
    "configText": "enable password cisco123\nsnmp-server community public RO",
    "options": {
      "checkAllRules": false,
      "specificRuleIds": ["N-01", "N-08"]
    }
  }'
```

## 🛠️ 개발 환경 설정

### 환경 변수

```bash
# .env 파일 생성
FLASK_ENV=development
LOG_LEVEL=DEBUG
API_PORT=5000
MAX_CONTENT_LENGTH=52428800  # 50MB
```

### 테스트 실행

```bash
# 단위 테스트
python -m pytest tests/

# API 테스트
python test_api.py

# 특정 테스트만 실행
python test_api.py --test analyze
```

### 코드 품질 검사

```bash
# 코드 포맷팅
black .

# 린트 검사
flake8 .

# 타입 검사
mypy .

# 보안 검사
bandit -r .
```

## 🐳 Docker 실행

```bash
# Docker 이미지 빌드
docker build -t kisa-network-analyzer .

# 컨테이너 실행
docker run -p 5000:5000 kisa-network-analyzer

# Docker Compose 사용
docker-compose up -d
```

## 📊 성능 및 제한사항

### 성능 지표
- **처리 속도**: 1,000라인 기준 ~0.1초
- **메모리 사용량**: 설정 파일 크기의 약 3-5배
- **동시 처리**: 기본 설정에서 최대 10개 요청

### 제한사항
- **최대 파일 크기**: 50MB
- **최대 라인 수**: 50,000줄
- **요청 제한**: 분당 100회

## 🔍 주요 취약점 탐지 예시

### 기본 패스워드 사용
```cisco
! 취약한 설정
enable password cisco
username admin password admin

! 권장 설정  
enable secret $1$mERr$9cTjUIlM1MHmBpJl6bYKj1
username admin secret $1$mERr$9cTjUIlM1MHmBpJl6bYKj1
```

### VTY 접근 제한 미설정
```cisco
! 취약한 설정
line vty 0 4
 password simple
 login

! 권장 설정
access-list 10 permit 192.168.1.100
line vty 0 4
 password complex_password
 access-class 10 in
 transport input ssh
```

### SNMP 기본 Community String
```cisco
! 취약한 설정
snmp-server community public RO
snmp-server community private RW

! 권장 설정
snmp-server community complex_readonly_string RO
! RW 커뮤니티는 가능한 제거
```

## 🤝 기여 방법

1. **이슈 리포트**: 버그나 개선사항을 Issues에 등록
2. **풀 리퀘스트**: 코드 기여시 PR 제출
3. **룰셋 확장**: 새로운 보안 룰 추가
4. **문서 개선**: README나 코드 주석 개선

### 개발 가이드라인

- 코드 스타일: PEP 8 준수
- 커밋 메시지: Conventional Commits 형식
- 테스트: 새 기능에 대한 테스트 필수
- 문서화: 공개 API에 대한 docstring 필수

## 📄 라이선스

이 프로젝트는 MIT 라이선스 하에 배포됩니다. 자세한 내용은 [LICENSE](LICENSE) 파일을 참조하세요.

## 📞 문의 및 지원

- **이메일**: security@example.com
- **이슈 트래커**: [GitHub Issues](https://github.com/your-org/kisa-network-analyzer/issues)
- **문서**: [위키](https://github.com/your-org/kisa-network-analyzer/wiki)

## 📈 버전 히스토리

- **v1.0.0** (2024-01-15): 초기 릴리스
  - KISA 가이드 기반 38개 룰 구현
  - 5개 주요 벤더 지원
  - REST API 제공

---

⚠️ **보안 주의사항**: 이 도구는 보안 취약점 탐지를 위한 것으로, 실제 운영 환경의 설정 변경 전에는 반드시 전문가의 검토를 받으시기 바랍니다.
