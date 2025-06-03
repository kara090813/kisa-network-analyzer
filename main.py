#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
KISA 네트워크 장비 취약점 분석 API (Fixed Multi-Framework Version)
main.py - Flask 애플리케이션 메인 파일

수정사항:
- 실제 지침서 선택 기능 활성화
- API 호출 시 framework 파라미터 처리
- 기존 호환성 완전 유지
"""

import os
from flask import Flask, request, jsonify
from flask_cors import CORS
import json
import logging
from datetime import datetime
import traceback
from typing import Dict, List, Any, Optional

# 수정된 분석기 import
from analyzers.config_analyzer import MultiFrameworkAnalyzer
from models.analysis_request import AnalysisRequest
from models.analysis_response import AnalysisResponse
from utils.validation import validate_request
from utils.logger import setup_logger

# 새로운 룰 로더 시스템 import
from rules.loader import (
    load_rules, 
    get_supported_sources, 
    get_source_info,
    get_statistics as get_rule_statistics
)

# Flask 애플리케이션 초기화
app = Flask(__name__)
CORS(app)

# 로깅 설정
logger = setup_logger(__name__)

# Multi-Framework Analyzer 인스턴스 생성
analyzer = MultiFrameworkAnalyzer()

# API 버전 정보
API_VERSION = "1.4.0"  # 실제 다중 지침서 지원으로 버전 업데이트
ANALYSIS_ENGINE_VERSION = "Multi-Framework 1.1"


@app.route('/api/v1/health', methods=['GET'])
def health_check():
    """API 상태 확인 엔드포인트"""
    try:
        analysis_stats = analyzer.get_analysis_statistics()
        supported_sources = get_supported_sources()
        
        # 실제 구현된 지침서 확인
        implemented_frameworks = []
        for framework in supported_sources.keys():
            try:
                rules = load_rules(framework)
                if rules:
                    implemented_frameworks.append(framework)
            except:
                pass
        
        return jsonify({
            "status": "healthy",
            "version": API_VERSION,
            "engineVersion": ANALYSIS_ENGINE_VERSION,
            "timestamp": datetime.now().isoformat(),
            "service": "KISA Network Security Config Analyzer (Enhanced Multi-Framework)",
            "features": {
                "logicalAnalysis": True,
                "patternMatching": True,
                "multiFrameworkSupport": True,
                "frameworkComparison": True,
                "contextualParsing": True,
                "detailedReporting": True,  # 🔥 새로운 기능
                "accurateLineNumbers": True,  # 🔥 새로운 기능
                "consolidatedStatistics": True  # 🔥 새로운 기능
            },
            "supportedFrameworks": list(supported_sources.keys()),
            "implementedFrameworks": implemented_frameworks,
            "frameworkDetails": supported_sources,
            "statistics": analysis_stats
        })
    except Exception as e:
        logger.error(f"헬스 체크 중 오류 발생: {str(e)}")
        return jsonify({
            "status": "error",
            "version": API_VERSION,
            "error": str(e)
        }), 500


@app.route('/api/v1/frameworks', methods=['GET'])
def get_frameworks():
    """지원되는 보안 지침서 목록 조회"""
    try:
        supported_sources = get_supported_sources()
        frameworks_info = []
        
        for source, info in supported_sources.items():
            try:
                stats = get_rule_statistics(source)
                framework_info = {
                    "id": source,
                    **info,
                    "statistics": stats,
                    "isImplemented": stats["totalRules"] > 0,
                    "status": "active" if stats["totalRules"] > 0 else "planned"
                }
            except (NotImplementedError, ValueError):
                framework_info = {
                    "id": source,
                    **info,
                    "statistics": {"totalRules": 0},
                    "isImplemented": False,
                    "status": "planned"
                }
            
            frameworks_info.append(framework_info)
        
        return jsonify({
            "success": True,
            "totalFrameworks": len(frameworks_info),
            "implementedFrameworks": sum(1 for f in frameworks_info if f["isImplemented"]),
            "frameworks": frameworks_info
        })
        
    except Exception as e:
        logger.error(f"지침서 목록 조회 중 오류 발생: {str(e)}")
        return jsonify({
            "success": False,
            "error": "지침서 목록 조회 실패",
            "details": str(e)
        }), 500


@app.route('/api/v1/config-analyze', methods=['POST'])
def analyze_config():
    """
    🔥 개선된 네트워크 장비 설정 파일 분석 메인 엔드포인트
    
    Request Body:
    {
        "deviceType": "Cisco",
        "configText": "<config 파일 전체 텍스트>",
        "framework": "KISA",  // 지침서 선택 (기본값: KISA)
        "options": {
            "checkAllRules": true,
            "specificRuleIds": ["N-01", "N-04"],
            "returnRawMatches": false,
            "enableLogicalAnalysis": true,
            "includeRecommendations": true,
            "useConsolidation": true,  // 🔥 새로운 옵션: 통합 통계 사용 여부
            "showDetailedInfo": true   // 🔥 새로운 옵션: 상세 정보 표시 여부
        }
    }
    """
    try:
        # 요청 데이터 검증
        if not request.json:
            return jsonify({
                "success": False,
                "error": "JSON 데이터가 필요합니다"
            }), 400
        
        # 지침서 파라미터 처리
        framework = request.json.get('framework', 'KISA').upper()
        
        # 🔥 새로운 옵션들 처리
        use_consolidation = request.json.get('options', {}).get('useConsolidation', True)
        show_detailed_info = request.json.get('options', {}).get('showDetailedInfo', True)
        
        # 지침서 유효성 검증
        try:
            framework_rules = load_rules(framework)
            logger.info(f"지침서 '{framework}' 로드 성공 - {len(framework_rules)}개 룰")
        except ValueError as e:
            return jsonify({
                "success": False,
                "error": f"지원되지 않는 지침서입니다: {framework}",
                "supportedFrameworks": list(get_supported_sources().keys()),
                "details": str(e)
            }), 400
        except NotImplementedError as e:
            return jsonify({
                "success": False,
                "error": f"{framework} 지침서는 아직 구현되지 않았습니다.",
                "details": str(e),
                "implementedFrameworks": [f for f in get_supported_sources().keys() 
                                        if f in ["KISA", "NW", "CIS"]]
            }), 501
        
        # 요청 객체 생성 및 검증
        try:
            analysis_request = AnalysisRequest.from_dict(request.json)
            validation_result = validate_request(analysis_request)
            if not validation_result.is_valid:
                return jsonify({
                    "success": False,
                    "error": "요청 데이터 검증 실패",
                    "details": validation_result.errors,
                    "warnings": validation_result.warnings
                }), 400
        except Exception as e:
            return jsonify({
                "success": False,
                "error": "요청 데이터 파싱 실패",
                "details": str(e)
            }), 400
        
        # 로깅
        config_lines_count = len(analysis_request.config_text.splitlines())
        logger.info(f"분석 요청 수신 - 지침서: {framework}, "
                   f"장비 타입: {analysis_request.device_type}, "
                   f"설정 라인 수: {config_lines_count}")
        
        # 🔥 개선된 분석 수행
        analysis_result = analyzer.analyze_config(
            analysis_request, 
            framework=framework,
            use_consolidation=use_consolidation
        )
        
        # 컨텍스트 정보 추가
        context_info = _extract_context_info(analysis_request.config_text, analysis_request.device_type)
        
        # 🔥 개선된 응답 생성
        response = AnalysisResponse(
            device_type=analysis_request.device_type,
            total_lines=config_lines_count,
            issues_found=len(analysis_result.vulnerabilities),
            analysis_time=analysis_result.analysis_time,
            results=analysis_result.vulnerabilities,
            statistics=analysis_result.statistics
        )
        
        # 응답 딕셔너리 생성 및 상세 정보 추가
        response_dict = response.to_dict()
        response_dict.update({
            "framework": framework,
            "frameworkInfo": get_source_info(framework),
            "engineVersion": ANALYSIS_ENGINE_VERSION,
            "contextInfo": context_info,
            "analysisOptions": {
                "useConsolidation": use_consolidation,
                "showDetailedInfo": show_detailed_info,
                "framework": framework
            },
            "validationWarnings": validation_result.warnings if hasattr(validation_result, 'warnings') else [],
            "analysisDetails": {
                "rulesApplied": analysis_result.statistics.total_rules_checked if analysis_result.statistics else 0,
                "consolidationUsed": use_consolidation,
                "individualFindings": getattr(analysis_result.statistics, 'total_individual_findings', None),
                "consolidatedRules": getattr(analysis_result.statistics, 'consolidated_rules', None),
                "logicalRulesUsed": sum(1 for v in analysis_result.vulnerabilities 
                                      if v.analysis_details and v.analysis_details.get('analysis_type') == 'logical'),
                "patternRulesUsed": sum(1 for v in analysis_result.vulnerabilities 
                                      if v.analysis_details and v.analysis_details.get('analysis_type') == 'pattern')
            }
        })
        
        # 🔥 상세 정보 표시 옵션에 따른 처리
        if show_detailed_info:
            # 상세 정보를 포함한 요약 생성
            detailed_summary = _generate_detailed_summary(analysis_result.vulnerabilities)
            response_dict["detailedSummary"] = detailed_summary
        
        logger.info(f"분석 완료 - 지침서: {framework}, "
                   f"발견된 취약점: {response.issues_found}개, "
                   f"분석 시간: {analysis_result.analysis_time:.2f}초, "
                   f"통합 통계: {use_consolidation}")
        
        return jsonify(response_dict)
    
    except Exception as e:
        logger.error(f"설정 분석 중 오류 발생: {str(e)}")
        logger.error(f"스택 트레이스: {traceback.format_exc()}")
        return jsonify({
            "success": False,
            "error": "설정 분석 실패",
            "details": str(e),
            "engineVersion": ANALYSIS_ENGINE_VERSION,
            "framework": request.json.get('framework', 'KISA') if request.json else None
        }), 500

@app.route('/api/v1/config-analyze/detailed', methods=['POST'])
def analyze_config_detailed():
    """
    🔥 새로운 엔드포인트: 상세 분석 (통합하지 않은 개별 취약점들)
    """
    try:
        # 기본 분석 수행하되 통합 통계를 사용하지 않음
        original_request = request.json.copy()
        if 'options' not in original_request:
            original_request['options'] = {}
        original_request['options']['useConsolidation'] = False
        original_request['options']['showDetailedInfo'] = True
        
        # 임시로 request.json 수정
        request.json = original_request
        
        return analyze_config()
    
    except Exception as e:
        logger.error(f"상세 분석 중 오류 발생: {str(e)}")
        return jsonify({
            "success": False,
            "error": "상세 분석 실패",
            "details": str(e)
        }), 500


@app.route('/api/v1/config-analyze/summary', methods=['POST'])
def analyze_config_summary():
    """
    🔥 새로운 엔드포인트: 요약 분석 (통합 통계만)
    """
    try:
        # 기본 분석 수행하되 통합 통계를 사용
        original_request = request.json.copy()
        if 'options' not in original_request:
            original_request['options'] = {}
        original_request['options']['useConsolidation'] = True
        original_request['options']['showDetailedInfo'] = False
        
        # 임시로 request.json 수정
        request.json = original_request
        
        return analyze_config()
    
    except Exception as e:
        logger.error(f"요약 분석 중 오류 발생: {str(e)}")
        return jsonify({
            "success": False,
            "error": "요약 분석 실패",
            "details": str(e)
        }), 500


def _generate_detailed_summary(vulnerabilities: List) -> Dict[str, Any]:
    """🔥 상세 요약 정보 생성"""
    
    # 인터페이스별 문제 집계
    interface_issues = {}
    service_issues = {}
    user_issues = {}
    global_issues = []
    
    for vuln in vulnerabilities:
        if vuln.analysis_details:
            details = vuln.analysis_details
            
            # 인터페이스 관련 문제
            if 'interface_name' in details:
                interface_name = details['interface_name']
                if interface_name not in interface_issues:
                    interface_issues[interface_name] = []
                interface_issues[interface_name].append({
                    'ruleId': vuln.rule_id,
                    'severity': vuln.severity,
                    'issue': details.get('vulnerability', 'configuration_issue'),
                    'line': vuln.line
                })
            
            # 사용자 관련 문제
            elif 'username' in details:
                username = details['username']
                if username not in user_issues:
                    user_issues[username] = []
                user_issues[username].append({
                    'ruleId': vuln.rule_id,
                    'severity': vuln.severity,
                    'issue': details.get('vulnerability', 'user_configuration_issue'),
                    'line': vuln.line
                })
            
            # 서비스 관련 문제
            elif 'service_name' in details:
                service_name = details['service_name']
                if service_name not in service_issues:
                    service_issues[service_name] = []
                service_issues[service_name].append({
                    'ruleId': vuln.rule_id,
                    'severity': vuln.severity,
                    'issue': details.get('vulnerability', 'service_configuration_issue'),
                    'line': vuln.line
                })
            
            # 전역 설정 문제
            else:
                global_issues.append({
                    'ruleId': vuln.rule_id,
                    'severity': vuln.severity,
                    'issue': details.get('vulnerability', 'global_configuration_issue'),
                    'line': vuln.line
                })
    
    return {
        "interfaceIssues": interface_issues,
        "userIssues": user_issues,
        "serviceIssues": service_issues,
        "globalIssues": global_issues,
        "summary": {
            "affectedInterfaces": len(interface_issues),
            "affectedUsers": len(user_issues),
            "affectedServices": len(service_issues),
            "globalConfigurationIssues": len(global_issues)
        }
    }

@app.route('/api/v1/rules', methods=['GET'])
def get_rules():
    """룰셋 목록 조회 (다중 지침서 지원)"""
    try:
        # 쿼리 파라미터 처리
        include_examples = request.args.get('includeExamples', 'false').lower() == 'true'
        device_type = request.args.get('deviceType')
        severity = request.args.get('severity')
        framework = request.args.get('framework', 'KISA').upper()
        
        # 지침서별 룰 로드
        try:
            rules_dict = load_rules(framework)
        except ValueError as e:
            return jsonify({
                "success": False,
                "error": str(e),
                "supportedFrameworks": list(get_supported_sources().keys())
            }), 404
        except NotImplementedError as e:
            return jsonify({
                "success": False,
                "error": f"{framework} 지침서는 아직 구현되지 않았습니다.",
                "details": str(e)
            }), 501
        
        rules = []
        for rule_id, rule in rules_dict.items():
            rule_info = {
                "ruleId": rule.rule_id,
                "title": rule.title,
                "description": rule.description,
                "severity": rule.severity,
                "category": rule.category.value,
                "deviceTypes": rule.device_types,
                "reference": rule.reference,
                "hasLogicalAnalysis": rule.logical_check_function is not None,
                "framework": framework
            }
            
            if include_examples:
                rule_info.update({
                    "vulnerabilityExamples": rule.vulnerability_examples,
                    "safeExamples": rule.safe_examples,
                    "patterns": rule.patterns,
                    "negativePatterns": rule.negative_patterns
                })
            
            rules.append(rule_info)
        
        # 필터 적용
        if device_type:
            rules = [rule for rule in rules if device_type in rule['deviceTypes']]
        
        if severity:
            rules = [rule for rule in rules if rule['severity'] == severity]
        
        return jsonify({
            "success": True,
            "framework": framework,
            "totalRules": len(rules),
            "filters": {
                "deviceType": device_type,
                "severity": severity,
                "includeExamples": include_examples
            },
            "engineInfo": {
                "logicalRules": sum(1 for rule in rules if rule.get('hasLogicalAnalysis')),
                "patternRules": sum(1 for rule in rules if not rule.get('hasLogicalAnalysis'))
            },
            "rules": rules
        })
    except Exception as e:
        logger.error(f"룰셋 조회 중 오류 발생: {str(e)}")
        return jsonify({
            "success": False,
            "error": "룰셋 조회 실패",
            "details": str(e)
        }), 500


@app.route('/api/v1/device-types', methods=['GET'])
def get_supported_device_types():
    """지원되는 장비 타입 목록 조회"""
    try:
        framework = request.args.get('framework', 'KISA').upper()
        
        # 분석기에서 지원 장비 타입 조회
        device_types = analyzer.get_supported_device_types(framework)
        
        # 각 장비 타입별 상세 정보
        device_info = {}
        try:
            rules_dict = load_rules(framework)
            for device_type in device_types:
                applicable_rules = len([rule for rule in rules_dict.values() 
                                     if device_type in rule.device_types])
                logical_rules = len([rule for rule in rules_dict.values() 
                                   if device_type in rule.device_types and rule.logical_check_function])
                
                device_info[device_type] = {
                    "supportedRules": applicable_rules,
                    "logicalAnalysisRules": logical_rules,
                    "framework": framework,
                    "features": {
                        "contextParsing": device_type in ["Cisco", "Juniper"],
                        "interfaceAnalysis": device_type in ["Cisco", "Juniper", "Piolink"],
                        "serviceAnalysis": True
                    }
                }
        except:
            # 기본 정보 제공
            for device_type in device_types:
                device_info[device_type] = {
                    "supportedRules": 0,
                    "logicalAnalysisRules": 0,
                    "framework": framework
                }
        
        return jsonify({
            "success": True,
            "framework": framework,
            "deviceTypes": device_types,
            "deviceInfo": device_info,
            "totalDeviceTypes": len(device_types)
        })
    except Exception as e:
        logger.error(f"지원 장비 타입 조회 중 오류 발생: {str(e)}")
        return jsonify({
            "success": False,
            "error": "지원 장비 타입 조회 실패",
            "details": str(e)
        }), 500


@app.route('/api/v1/frameworks/<framework_id>/rules', methods=['GET'])
def get_framework_rules(framework_id):
    """특정 지침서의 룰 목록 조회"""
    try:
        framework = framework_id.upper()
        include_examples = request.args.get('includeExamples', 'false').lower() == 'true'
        device_type = request.args.get('deviceType')
        
        # 지침서별 룰 로드
        try:
            rules_dict = load_rules(framework)
        except ValueError as e:
            return jsonify({
                "success": False,
                "error": f"지원되지 않는 지침서: {framework}",
                "supportedFrameworks": list(get_supported_sources().keys())
            }), 404
        except NotImplementedError as e:
            return jsonify({
                "success": False,
                "error": f"{framework} 지침서는 아직 구현되지 않았습니다."
            }), 501
        
        rules = analyzer.get_available_rules(framework)
        
        # 필터 적용
        if device_type:
            rules = [rule for rule in rules if device_type in rule['deviceTypes']]
        
        return jsonify({
            "success": True,
            "framework": framework,
            "totalRules": len(rules),
            "rules": rules
        })
        
    except Exception as e:
        logger.error(f"지침서 룰 조회 중 오류 발생: {str(e)}")
        return jsonify({
            "success": False,
            "error": "지침서 룰 조회 실패",
            "details": str(e)
        }), 500


@app.route('/api/v1/statistics', methods=['GET'])
def get_analysis_statistics():
    """분석 엔진 통계 정보 조회"""
    try:
        framework = request.args.get('framework', 'KISA').upper()
        
        # 분석 엔진 통계
        engine_stats = analyzer.get_analysis_statistics()
        
        # 지침서별 룰 통계
        try:
            rule_stats = get_rule_statistics(framework)
        except (ValueError, NotImplementedError):
            rule_stats = {"totalRules": 0}
        
        return jsonify({
            "success": True,
            "framework": framework,
            "engineStatistics": engine_stats,
            "ruleStatistics": rule_stats,
            "timestamp": datetime.now().isoformat()
        })
        
    except Exception as e:
        logger.error(f"통계 조회 중 오류 발생: {str(e)}")
        return jsonify({
            "success": False,
            "error": "통계 조회 실패",
            "details": str(e)
        }), 500


@app.route('/api/v1/analyze-line', methods=['POST'])
def analyze_single_line():
    """단일 라인 분석 엔드포인트"""
    try:
        if not request.json:
            return jsonify({
                "success": False,
                "error": "JSON 데이터가 필요합니다"
            }), 400
        
        line = request.json.get('line')
        device_type = request.json.get('deviceType')
        rule_ids = request.json.get('ruleIds')
        framework = request.json.get('framework', 'KISA').upper()
        
        if not line or not device_type:
            return jsonify({
                "success": False,
                "error": "line과 deviceType이 필요합니다"
            }), 400
        
        # 단일 라인 분석 실행
        vulnerabilities = analyzer.analyze_single_line(line, device_type, rule_ids, framework)
        
        return jsonify({
            "success": True,
            "framework": framework,
            "line": line,
            "deviceType": device_type,
            "appliedRules": rule_ids or "all",
            "issuesFound": len(vulnerabilities),
            "results": [vuln.to_dict() for vuln in vulnerabilities]
        })
        
    except Exception as e:
        logger.error(f"단일 라인 분석 중 오류 발생: {str(e)}")
        return jsonify({
            "success": False,
            "error": "단일 라인 분석 실패",
            "details": str(e)
        }), 500


def _extract_context_info(config_text: str, device_type: str) -> Dict[str, Any]:
    """설정 파일에서 컨텍스트 정보 추출"""
    try:
        from rules.kisa_rules import parse_config_context
        context = parse_config_context(config_text, device_type)
        
        return {
            "totalInterfaces": len(context.parsed_interfaces),
            "activeInterfaces": sum(1 for iface in context.parsed_interfaces.values() 
                                  if not iface.get('is_shutdown', False)),
            "configuredServices": len(context.parsed_services),
            "globalSettings": len(context.global_settings),
            "deviceType": device_type,
            "configComplexity": _calculate_config_complexity(context),
            "hasVtyLines": len(context.vty_lines) > 0,
            "hasSnmpCommunities": len(context.snmp_communities) > 0,
            "totalUsers": len(context.parsed_users)
        }
    except Exception as e:
        logger.warning(f"컨텍스트 정보 추출 실패: {e}")
        return {
            "totalLines": len(config_text.splitlines()),
            "deviceType": device_type,
            "extractionError": str(e)
        }


def _calculate_config_complexity(context) -> str:
    """설정 복잡도 계산"""
    interface_count = len(context.parsed_interfaces)
    service_count = len(context.parsed_services)
    global_settings_count = len(context.global_settings)
    
    total_complexity = interface_count + service_count + global_settings_count
    
    if total_complexity < 10:
        return "Simple"
    elif total_complexity < 30:
        return "Medium"
    else:
        return "Complex"


@app.errorhandler(404)
def not_found(error):
    """404 에러 핸들러"""
    return jsonify({
        "success": False,
        "error": "요청한 리소스를 찾을 수 없습니다",
        "path": request.path,
        "engineVersion": ANALYSIS_ENGINE_VERSION
    }), 404


@app.errorhandler(500)
def internal_error(error):
    """500 에러 핸들러"""
    logger.error(f"내부 서버 오류: {str(error)}")
    return jsonify({
        "success": False,
        "error": "내부 서버 오류가 발생했습니다",
        "engineVersion": ANALYSIS_ENGINE_VERSION
    }), 500


if __name__ == '__main__':
    # 환경변수에서 포트 가져오기
    port = int(os.environ.get('PORT', 5002))
    debug = os.environ.get('FLASK_ENV') != 'production'
    
    # 시작 로그
    logger.info(f"KISA 네트워크 보안 분석 API 시작 - Enhanced Multi-Framework Version {API_VERSION}")
    logger.info(f"분석 엔진: {ANALYSIS_ENGINE_VERSION}")
    logger.info(f"새로운 기능: 상세 정보 보존, 정확한 라인 번호, 통합 통계 옵션")
    
    try:
        # 지원 지침서 확인
        supported = get_supported_sources()
        implemented = []
        for fw in supported.keys():
            try:
                rules = load_rules(fw)
                if rules:
                    implemented.append(fw)
                    logger.info(f"✅ {fw} 지침서: {len(rules)}개 룰 로드됨")
            except NotImplementedError:
                logger.info(f"⏳ {fw} 지침서: 구현 예정")
            except Exception as e:
                logger.warning(f"❌ {fw} 지침서 로드 실패: {e}")
        
        logger.info(f"구현된 지침서: {', '.join(implemented)}")
        logger.info(f"추가 엔드포인트: /api/v1/config-analyze/detailed, /api/v1/config-analyze/summary")
        
    except Exception as e:
        logger.error(f"지침서 초기화 중 오류: {e}")
    
    logger.info(f"포트: {port}, 디버그 모드: {debug}")
    
    app.run(
        host='0.0.0.0',
        port=port,
        debug=debug
    )