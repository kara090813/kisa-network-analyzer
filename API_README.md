# 네트워크 장비 취약점 진단 API 명세서

## 📋 개요

**API 버전**: 1.4.0  
**분석 엔진**: Enhanced Multi-Framework 1.1  
**Base URL**: `https://kisa-network-analyzer-production.up.railway.app`  
**Content-Type**: `application/json`  
**인코딩**: UTF-8

## 🛡️ 지원 기능

### 핵심 기능
- ✅ **다중 지침서 지원**: KISA, NW, CIS 보안 지침서
- ✅ **상세 정보 보존**: 어느 인터페이스/설정에 문제가 있는지 명확히 표시
- ✅ **정확한 라인 번호**: 실제 설정 라인 번호 제공
- ✅ **통합 통계**: 개별 취약점과 통합 취약점 선택 가능
- ✅ **IOS 버전 감지**: Cisco IOS 버전 정보 자동 감지
- ✅ **논리 기반 분석**: 패턴 매칭 + 컨텍스트 기반 스마트 분석
- ✅ **다양한 장비 지원**: Cisco, Juniper, Piolink, HP, Alcatel 등

### 지원 장비 타입
- **Cisco**: IOS 버전 감지, 전체 기능 지원
- **Juniper**: JunOS 설정 분석
- **Piolink**: 로드밸런서 보안 설정
- **HP/Alcatel/Extreme/Dasan**: 기본 보안 설정 점검

---

## 🔗 API 엔드포인트

### 1. 헬스 체크

#### `GET /api/v1/health`

시스템 상태 및 기본 정보를 확인합니다.

**Response 200:**
```json
{
  "status": "healthy",
  "version": "1.4.0",
  "engineVersion": "Enhanced Multi-Framework 1.1",
  "timestamp": "2025-06-07T12:00:00.000Z",
  "service": "KISA Network Security Config Analyzer (Enhanced Multi-Framework)",
  "features": {
    "logicalAnalysis": true,
    "patternMatching": true,
    "multiFrameworkSupport": true,
    "frameworkComparison": true,
    "contextualParsing": true,
    "detailedReporting": true,
    "accurateLineNumbers": true,
    "consolidatedStatistics": true,
    "iosVersionDetection": true
  },
  "supportedFrameworks": ["KISA", "NW", "CIS", "NIST"],
  "implementedFrameworks": ["KISA", "NW", "CIS"],
  "frameworkDetails": {
    "KISA": {
      "name": "KISA 네트워크 장비 보안 가이드",
      "description": "한국인터넷진흥원(KISA) 네트워크 장비 보안 점검 가이드라인",
      "version": "2021",
      "total_rules": 38,
      "categories": ["계정 관리", "접근 관리", "패치 관리", "로그 관리", "기능 관리"]
    }
  }
}
```

---

### 2. 지침서 목록 조회

#### `GET /api/v1/frameworks`

지원되는 보안 지침서 목록을 조회합니다.

**Response 200:**
```json
{
  "success": true,
  "totalFrameworks": 4,
  "implementedFrameworks": 3,
  "frameworks": [
    {
      "id": "KISA",
      "name": "KISA 네트워크 장비 보안 가이드",
      "description": "한국인터넷진흥원(KISA) 네트워크 장비 보안 점검 가이드라인",
      "version": "2021",
      "rules_count": 38,
      "categories": ["계정 관리", "접근 관리", "패치 관리", "로그 관리", "기능 관리"],
      "statistics": {
        "totalRules": 38,
        "severityBreakdown": {"상": 14, "중": 20, "하": 4},
        "categoryBreakdown": {
          "계정 관리": 4,
          "접근 관리": 6,
          "패치 관리": 1,
          "로그 관리": 7,
          "기능 관리": 20
        },
        "supportedDeviceTypes": ["Cisco", "Juniper", "Alteon", "Piolink"],
        "logicalRules": 35,
        "patternRules": 3
      },
      "isImplemented": true,
      "status": "active"
    }
  ]
}
```

---

### 3. 메인 설정 분석

#### `POST /api/v1/config-analyze`

네트워크 장비 설정 파일을 분석하여 보안 취약점을 검사합니다.

**Request Body:**
```json
{
  "deviceType": "Cisco",
  "configText": "version 15.1\nhostname TestRouter\nenable password cisco\n...",
  "framework": "KISA",
  "options": {
    "checkAllRules": true,
    "specificRuleIds": ["N-01", "N-04"],
    "returnRawMatches": false,
    "enableLogicalAnalysis": true,
    "includeRecommendations": true,
    "useConsolidation": true,
    "showDetailedInfo": true
  }
}
```

**Request Parameters:**

| 필드 | 타입 | 필수 | 설명 | 기본값 |
|------|------|------|------|--------|
| `deviceType` | string | ✅ | 장비 타입 (Cisco, Juniper, Piolink 등) | - |
| `configText` | string | ✅ | 설정 파일 전체 텍스트 (최대 10MB) | - |
| `framework` | string | ❌ | 사용할 지침서 (KISA, NW, CIS) | "KISA" |
| `options.checkAllRules` | boolean | ❌ | 모든 룰 검사 여부 | true |
| `options.specificRuleIds` | array | ❌ | 특정 룰 ID 목록 (checkAllRules가 false일 때 필수) | null |
| `options.returnRawMatches` | boolean | ❌ | 원본 매치 텍스트 포함 여부 | false |
| `options.enableLogicalAnalysis` | boolean | ❌ | 논리 기반 분석 활성화 | true |
| `options.includeRecommendations` | boolean | ❌ | 권고사항 포함 여부 | true |
| `options.useConsolidation` | boolean | ❌ | 통합 통계 사용 여부 | true |
| `options.showDetailedInfo` | boolean | ❌ | 상세 정보 표시 여부 | true |

**Response 200:**
```json
{
  "success": true,
  "deviceType": "Cisco (15.1)",
  "totalLines": 156,
  "issuesFound": 8,
  "analysisTime": 0.45,
  "timestamp": "2025-06-07T12:00:00.000Z",
  "framework": "KISA",
  "frameworkInfo": {
    "name": "KISA 네트워크 장비 보안 가이드",
    "version": "2021",
    "total_rules": 38
  },
  "engineVersion": "Enhanced Multi-Framework 1.1",
  "contextInfo": {
    "totalInterfaces": 4,
    "activeInterfaces": 2,
    "configuredServices": 3,
    "globalSettings": 8,
    "iosVersion": "15.1",
    "deviceType": "Cisco",
    "configComplexity": "Medium",
    "hasVtyLines": true,
    "hasSnmpCommunities": false,
    "totalUsers": 1
  },
  "deviceInfo": {
    "originalDeviceType": "Cisco",
    "deviceTypeWithVersion": "Cisco (15.1)",
    "iosVersion": "15.1",
    "isVersionDetected": true
  },
  "analysisOptions": {
    "useConsolidation": true,
    "showDetailedInfo": true,
    "framework": "KISA"
  },
  "validationWarnings": [
    "설정 파일이 너무 짧습니다. 완전한 설정인지 확인하세요."
  ],
  "analysisDetails": {
    "rulesApplied": 32,
    "consolidationUsed": true,
    "individualFindings": 12,
    "consolidatedRules": 8,
    "logicalRulesUsed": 28,
    "patternRulesUsed": 4
  },
  "detailedSummary": {
    "interfaceIssues": {
      "FastEthernet0/0": [
        {
          "ruleId": "N-32",
          "severity": "중",
          "issue": "proxy_arp_enabled",
          "line": 45
        }
      ]
    },
    "userIssues": {
      "admin": [
        {
          "ruleId": "N-01",
          "severity": "상",
          "issue": "weak_password",
          "line": 12
        }
      ]
    },
    "serviceIssues": {
      "http_server": [
        {
          "ruleId": "N-26",
          "severity": "중",
          "issue": "service_enabled",
          "line": 78
        }
      ]
    },
    "globalIssues": [
      {
        "ruleId": "N-07",
        "severity": "상",
        "issue": "snmp_service_enabled",
        "line": 89
      }
    ],
    "summary": {
      "affectedInterfaces": 1,
      "affectedUsers": 1,
      "affectedServices": 1,
      "globalConfigurationIssues": 1
    }
  },
  "results": [
    {
      "ruleId": "N-01",
      "severity": "상",
      "line": 12,
      "matchedText": "enable password cisco",
      "description": "기본 패스워드를 변경하지 않고 사용하는지 점검",
      "recommendation": "enable secret 명령어를 사용하여 암호화된 패스워드 설정 필요",
      "reference": "KISA 가이드 N-01 (상) 1.1 패스워드 설정",
      "category": "계정 관리",
      "affectedItems": [
        {
          "type": "global",
          "name": "enable_password",
          "line": 12,
          "matchedText": "enable password cisco",
          "severity": "상"
        }
      ],
      "summaryInfo": {
        "total_affected": 1,
        "affected_type": "global_settings",
        "affected_list": ["enable_password"],
        "severity_breakdown": {"상": 1}
      },
      "analysisDetails": {
        "analysis_type": "logical",
        "framework": "KISA",
        "rule_category": "계정 관리",
        "original_line": 12,
        "vulnerability": "weak_enable_password",
        "password_value": "cisco",
        "is_default_password": true,
        "encryption_type": "plaintext"
      }
    }
  ],
  "statistics": {
    "totalRulesChecked": 32,
    "rulesPassed": 24,
    "rulesFailed": 8,
    "highSeverityIssues": 3,
    "mediumSeverityIssues": 4,
    "lowSeverityIssues": 1,
    "totalIndividualFindings": 12,
    "consolidatedRules": 8
  }
}
```

**Error Responses:**

**400 Bad Request - 잘못된 요청:**
```json
{
  "success": false,
  "error": "요청 데이터 검증 실패",
  "details": [
    "deviceType은 비어있을 수 없습니다",
    "configText는 비어있을 수 없습니다"
  ],
  "warnings": []
}
```

**501 Not Implemented - 구현되지 않은 지침서:**
```json
{
  "success": false,
  "error": "NIST 지침서는 아직 구현되지 않았습니다.",
  "details": "NIST framework is not yet implemented",
  "implementedFrameworks": ["KISA", "NW", "CIS"]
}
```

---

### 4. 상세 분석 (개별 취약점)

#### `POST /api/v1/config-analyze/detailed`

통합하지 않은 모든 개별 취약점을 반환합니다.

**Request Body:** `config-analyze`와 동일

**Response:** 기본 분석과 동일하지만 `useConsolidation: false`로 처리되어 모든 개별 취약점이 반환됩니다.

---

### 5. 요약 분석 (통합 통계만)

#### `POST /api/v1/config-analyze/summary`

통합된 통계 정보만 반환합니다.

**Request Body:** `config-analyze`와 동일

**Response:** 기본 분석과 동일하지만 `useConsolidation: true`, `showDetailedInfo: false`로 처리됩니다.

---

### 6. 룰셋 목록 조회

#### `GET /api/v1/rules`

특정 지침서의 보안 룰 목록을 조회합니다.

**Query Parameters:**

| 파라미터 | 타입 | 필수 | 설명 | 기본값 |
|----------|------|------|------|--------|
| `framework` | string | ❌ | 지침서 (KISA, NW, CIS) | "KISA" |
| `deviceType` | string | ❌ | 장비 타입 필터 | null |
| `severity` | string | ❌ | 심각도 필터 (상, 중, 하) | null |
| `includeExamples` | boolean | ❌ | 예제 포함 여부 | false |

**Response 200:**
```json
{
  "success": true,
  "framework": "KISA",
  "totalRules": 38,
  "filters": {
    "deviceType": "Cisco",
    "severity": null,
    "includeExamples": false
  },
  "engineInfo": {
    "logicalRules": 35,
    "patternRules": 3
  },
  "rules": [
    {
      "ruleId": "N-01",
      "title": "기본 패스워드 변경",
      "description": "기본 패스워드를 변경하지 않고 사용하는지 점검",
      "severity": "상",
      "category": "계정 관리",
      "deviceTypes": ["Cisco", "Alteon", "Passport", "Juniper", "Piolink"],
      "reference": "KISA 가이드 N-01 (상) 1.1 패스워드 설정",
      "hasLogicalAnalysis": true,
      "framework": "KISA"
    }
  ]
}
```

---

### 7. 지원 장비 타입 조회

#### `GET /api/v1/device-types`

지원되는 장비 타입 목록을 조회합니다.

**Query Parameters:**

| 파라미터 | 타입 | 필수 | 설명 | 기본값 |
|----------|------|------|------|--------|
| `framework` | string | ❌ | 지침서 (KISA, NW, CIS) | "KISA" |

**Response 200:**
```json
{
  "success": true,
  "framework": "KISA",
  "deviceTypes": [
    "Cisco", "Juniper", "Alteon", "Passport", "Piolink", 
    "HP", "Alcatel", "Extreme", "Dasan", "Radware"
  ],
  "deviceInfo": {
    "Cisco": {
      "supportedRules": 38,
      "logicalAnalysisRules": 35,
      "framework": "KISA",
      "features": {
        "contextParsing": true,
        "interfaceAnalysis": true,
        "serviceAnalysis": true,
        "iosVersionDetection": true
      }
    },
    "Juniper": {
      "supportedRules": 25,
      "logicalAnalysisRules": 22,
      "framework": "KISA",
      "features": {
        "contextParsing": true,
        "interfaceAnalysis": true,
        "serviceAnalysis": true,
        "iosVersionDetection": false
      }
    }
  },
  "totalDeviceTypes": 10
}
```

---

### 8. 분석 엔진 통계

#### `GET /api/v1/statistics`

분석 엔진의 통계 정보를 조회합니다.

**Query Parameters:**

| 파라미터 | 타입 | 필수 | 설명 | 기본값 |
|----------|------|------|------|--------|
| `framework` | string | ❌ | 지침서 (KISA, NW, CIS) | "KISA" |

**Response 200:**
```json
{
  "success": true,
  "framework": "KISA",
  "engineStatistics": {
    "analysisStats": {
      "total_analyses": 1250,
      "framework_usage": {
        "KISA": 850,
        "NW": 300,
        "CIS": 100
      }
    },
    "supportedFrameworks": ["KISA", "NW", "CIS", "NIST"],
    "defaultFramework": "KISA",
    "frameworkDetails": {
      "KISA": {
        "name": "KISA 네트워크 장비 보안 가이드",
        "version": "2021",
        "total_rules": 38
      }
    }
  },
  "ruleStatistics": {
    "totalRules": 38,
    "severityStats": {"상": 14, "중": 20, "하": 4},
    "categoryStats": {
      "계정 관리": 4,
      "접근 관리": 6,
      "패치 관리": 1,
      "로그 관리": 7,
      "기능 관리": 20
    },
    "deviceStats": {
      "Cisco": 38,
      "Juniper": 25,
      "Piolink": 20
    },
    "logicalRules": 35,
    "patternRules": 3
  },
  "timestamp": "2025-06-07T12:00:00.000Z"
}
```

---

## 🚨 오류 코드

| HTTP 코드 | 설명 | 해결 방법 |
|-----------|------|----------|
| 400 | 잘못된 요청 (필수 필드 누락, 유효하지 않은 데이터) | 요청 형식 및 필수 필드 확인 |
| 404 | 요청한 리소스를 찾을 수 없음 | API 경로 확인 |
| 500 | 내부 서버 오류 | 서버 관리자에게 문의 |
| 501 | 구현되지 않은 기능 (예: NIST 지침서) | 지원되는 지침서 사용 |

## 📋 사용 예제

### Python 예제

```python
import requests
import json

# API 설정
BASE_URL = "https://kisa-network-analyzer-production.up.railway.app"
headers = {"Content-Type": "application/json"}

# 설정 파일 읽기
with open("router_config.txt", "r") as f:
    config_text = f.read()

# 분석 요청
payload = {
    "deviceType": "Cisco",
    "configText": config_text,
    "framework": "KISA",
    "options": {
        "checkAllRules": True,
        "enableLogicalAnalysis": True,
        "includeRecommendations": True,
        "useConsolidation": True,
        "showDetailedInfo": True
    }
}

response = requests.post(
    f"{BASE_URL}/api/v1/config-analyze", 
    headers=headers, 
    json=payload
)

if response.status_code == 200:
    result = response.json()
    print(f"취약점 발견: {result['issuesFound']}개")
    print(f"분석 시간: {result['analysisTime']}초")
    
    # 고위험 취약점만 출력
    for issue in result['results']:
        if issue['severity'] == '상':
            print(f"[{issue['ruleId']}] {issue['description']}")
            print(f"라인 {issue['line']}: {issue['matchedText']}")
            print(f"권고사항: {issue['recommendation']}")
            print("-" * 50)
else:
    print(f"오류: {response.status_code}")
    print(response.json())
```

### cURL 예제

```bash
# 헬스 체크
curl -X GET "https://kisa-network-analyzer-production.up.railway.app/api/v1/health"

# 설정 분석
curl -X POST "https://kisa-network-analyzer-production.up.railway.app/api/v1/config-analyze" \
  -H "Content-Type: application/json" \
  -d '{
    "deviceType": "Cisco",
    "configText": "version 15.1\nhostname TestRouter\nenable password cisco\n",
    "framework": "KISA",
    "options": {
      "checkAllRules": true,
      "useConsolidation": true
    }
  }'

# 룰 목록 조회
curl -X GET "https://kisa-network-analyzer-production.up.railway.app/api/v1/rules?framework=KISA&deviceType=Cisco"
```

## 📊 응답 데이터 구조

### 취약점 객체 (VulnerabilityIssue)

```json
{
  "ruleId": "N-01",
  "severity": "상",
  "line": 12,
  "matchedText": "enable password cisco",
  "description": "기본 패스워드를 변경하지 않고 사용하는지 점검",
  "recommendation": "enable secret 명령어를 사용하여 암호화된 패스워드 설정 필요",
  "reference": "KISA 가이드 N-01 (상) 1.1 패스워드 설정",
  "category": "계정 관리",
  "affectedItems": [
    {
      "type": "global|interface|user|service",
      "name": "enable_password",
      "line": 12
    }
  ],
  "summaryInfo": {
    "total_affected": 1,
    "affected_type": "global_settings",
    "affected_list": ["enable_password"]
  },
  "analysisDetails": {
    "analysis_type": "logical|pattern",
    "framework": "KISA",
    "vulnerability": "weak_enable_password",
    "interface_name": "FastEthernet0/0",
    "username": "admin",
    "service_name": "http_server"
  }
}
```

### 통계 객체 (AnalysisStatistics)

```json
{
  "totalRulesChecked": 32,
  "rulesPassed": 24,
  "rulesFailed": 8,
  "highSeverityIssues": 3,
  "mediumSeverityIssues": 4,
  "lowSeverityIssues": 1,
  "totalIndividualFindings": 12,
  "consolidatedRules": 8
}
```

## 🔍 고급 기능

### 1. 통합 vs 상세 분석

- **통합 분석** (`useConsolidation: true`): 같은 룰의 여러 위반 사항을 하나로 통합
- **상세 분석** (`useConsolidation: false`): 모든 개별 위반 사항을 별도로 표시

### 2. IOS 버전 감지

Cisco 장비의 경우 설정에서 IOS 버전을 자동 감지하여 `deviceType`에 포함시킵니다.
예: `"Cisco"` → `"Cisco (15.1)"`

### 3. 컨텍스트 기반 분석

단순 패턴 매칭이 아닌 설정 파일의 전체 컨텍스트를 이해하여 더 정확한 분석을 제공합니다.

### 4. 다중 지침서 지원

- **KISA**: 한국인터넷진흥원 보안 가이드 (38개 룰)
- **NW**: 자체 네트워크 보안 가이드 (42개 룰)  
- **CIS**: Center for Internet Security 벤치마크 (89개 룰)
- **NIST**: 구현 예정

---

## 📞 지원 및 문의

- **GitHub**: [프로젝트 리포지토리]
- **이슈 리포트**: [GitHub Issues]
- **문서**: [Wiki 페이지]

---

**⚡ 빠른 시작**: 위의 Python 예제를 복사하여 바로 사용해보세요!