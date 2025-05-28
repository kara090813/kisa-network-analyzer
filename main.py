#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
KISA 네트워크 장비 취약점 분석 API (Enhanced Version)
main.py - Flask 애플리케이션 메인 파일

기능:
- 논리 기반 분석을 포함한 고도화된 네트워크 장비 설정 파일 분석
- 기존 정규식 매칭 + 새로운 논리 기반 판단 하이브리드 분석
- KISA 가이드 기반 보안 취약점 탐지
- REST API 형태로 서비스 제공
"""

import os
from flask import Flask, request, jsonify
from flask_cors import CORS
import json
import logging
from datetime import datetime
import traceback
from typing import Dict, List, Any, Optional  # ✅ 타입 힌트 import 추가

# 강화된 분석기 import
from analyzers.config_analyzer import EnhancedConfigAnalyzer
from models.analysis_request import AnalysisRequest
from models.analysis_response import AnalysisResponse
from utils.validation import validate_request
from utils.logger import setup_logger

# Flask 애플리케이션 초기화
app = Flask(__name__)
CORS(app)  # CORS 설정 (프론트엔드 연동을 위해)

# 로깅 설정
logger = setup_logger(__name__)

# Enhanced ConfigAnalyzer 인스턴스 생성
analyzer = EnhancedConfigAnalyzer()

# API 버전 정보
API_VERSION = "1.1.0"  # 논리 기반 분석 추가로 버전 업데이트
ANALYSIS_ENGINE_VERSION = "Enhanced 2.0"


@app.route('/api/v1/health', methods=['GET'])
def health_check():
    """
    API 상태 확인 엔드포인트 (강화된 정보 포함)
    """
    try:
        analysis_stats = analyzer.get_analysis_statistics()
        
        return jsonify({
            "status": "healthy",
            "version": API_VERSION,
            "engineVersion": ANALYSIS_ENGINE_VERSION,
            "timestamp": datetime.now().isoformat(),
            "service": "KISA Network Security Config Analyzer (Enhanced)",
            "features": {
                "logicalAnalysis": True,
                "patternMatching": True,
                "hybridAnalysis": True,
                "contextualParsing": True
            },
            "statistics": analysis_stats
        })
    except Exception as e:
        logger.error(f"헬스 체크 중 오류 발생: {str(e)}")
        return jsonify({
            "status": "error",
            "version": API_VERSION,
            "engineVersion": ANALYSIS_ENGINE_VERSION,
            "timestamp": datetime.now().isoformat(),
            "service": "KISA Network Security Config Analyzer (Enhanced)",
            "error": str(e)
        }), 500


@app.route('/api/v1/rules', methods=['GET'])
def get_rules():
    """
    사용 가능한 룰셋 목록 조회 (강화된 정보 포함)
    """
    try:
        # 쿼리 파라미터 처리
        include_examples = request.args.get('includeExamples', 'false').lower() == 'true'
        device_type = request.args.get('deviceType')
        severity = request.args.get('severity')
        
        rules = analyzer.get_available_rules()
        
        # 필터 적용
        if device_type:
            rules = [rule for rule in rules if device_type in rule['deviceTypes']]
        
        if severity:
            rules = [rule for rule in rules if rule['severity'] == severity]
        
        # 예제 정보 제거 (요청하지 않은 경우)
        if not include_examples:
            for rule in rules:
                rule.pop('vulnerabilityExamples', None)
                rule.pop('safeExamples', None)
                rule.pop('heuristicRules', None)
        
        return jsonify({
            "success": True,
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


@app.route('/api/v1/config-analyze', methods=['POST'])
def analyze_config():
    """
    네트워크 장비 설정 파일 분석 메인 엔드포인트 (강화된 분석)
    
    Request Body:
    {
        "deviceType": "Cisco",
        "configText": "<config 파일 전체 텍스트>",
        "options": {
            "checkAllRules": true,
            "specificRuleIds": ["N-01", "N-04"],
            "returnRawMatches": false,
            "enableLogicalAnalysis": true,
            "includeRecommendations": true,
            "analysisMode": "hybrid"  // "pattern", "logical", "hybrid"
        }
    }
    
    Response:
    {
        "deviceType": "Cisco",
        "totalLines": 120,  
        "issuesFound": 3,
        "engineVersion": "Enhanced 2.0",
        "analysisMode": "hybrid",
        "analysisTime": 0.45,
        "results": [...],
        "statistics": {...},
        "contextInfo": {...}
    }
    """
    try:
        # 요청 데이터 검증
        if not request.json:
            return jsonify({
                "success": False,
                "error": "JSON 데이터가 필요합니다"
            }), 400
        
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
        
        # 분석 옵션 확인
        analysis_mode = request.json.get('options', {}).get('analysisMode', 'hybrid')
        enable_logical = request.json.get('options', {}).get('enableLogicalAnalysis', True)
        
        # 로깅
        config_lines_count = len(analysis_request.config_text.splitlines())
        logger.info(f"강화된 분석 요청 수신 - 장비 타입: {analysis_request.device_type}, "
                   f"설정 라인 수: {config_lines_count}, 분석 모드: {analysis_mode}")
        
        # 설정 파일 분석 실행 (강화된 분석기 사용)
        analysis_result = analyzer.analyze_config(analysis_request)
        
        # 컨텍스트 정보 추가 (강화된 정보)
        context_info = _extract_context_info(analysis_request.config_text, analysis_request.device_type)
        
        # 응답 생성 (강화된 정보 포함)
        response = AnalysisResponse(
            device_type=analysis_request.device_type,
            total_lines=config_lines_count,
            issues_found=len(analysis_result.vulnerabilities),
            analysis_time=analysis_result.analysis_time,
            results=analysis_result.vulnerabilities,
            statistics=analysis_result.statistics
        )
        
        # 응답 딕셔너리 생성 및 강화된 정보 추가
        response_dict = response.to_dict()
        response_dict.update({
            "engineVersion": ANALYSIS_ENGINE_VERSION,
            "analysisMode": analysis_mode,
            "contextInfo": context_info,
            "validationWarnings": validation_result.warnings if hasattr(validation_result, 'warnings') else []
        })
        
        logger.info(f"강화된 분석 완료 - 발견된 취약점: {response.issues_found}개, "
                   f"분석 시간: {analysis_result.analysis_time:.2f}초")
        
        return jsonify(response_dict)
    
    except Exception as e:
        logger.error(f"설정 분석 중 오류 발생: {str(e)}")
        logger.error(f"스택 트레이스: {traceback.format_exc()}")
        return jsonify({
            "success": False,
            "error": "설정 분석 실패",
            "details": str(e),
            "engineVersion": ANALYSIS_ENGINE_VERSION
        }), 500


@app.route('/api/v1/rules/<rule_id>', methods=['GET'])
def get_rule_detail(rule_id):
    """
    특정 룰의 상세 정보 조회 (강화된 정보 포함)
    """
    try:
        include_examples = request.args.get('includeExamples', 'true').lower() == 'true'
        
        rule_detail = analyzer.get_rule_detail(rule_id)
        if rule_detail:
            # 예제 정보 제거 (요청하지 않은 경우)
            if not include_examples:
                rule_detail.pop('vulnerabilityExamples', None)
                rule_detail.pop('safeExamples', None)
                rule_detail.pop('heuristicRules', None)
                rule_detail.pop('logicalConditions', None)
            
            return jsonify({
                "success": True,
                "rule": rule_detail,
                "enhancedInfo": {
                    "hasLogicalAnalysis": rule_detail.get('hasLogicalAnalysis', False),
                    "complexityLevel": "High" if rule_detail.get('logicalConditions') else "Medium"
                }
            })
        else:
            return jsonify({
                "success": False,
                "error": f"룰 '{rule_id}'를 찾을 수 없습니다"
            }), 404
    except Exception as e:
        logger.error(f"룰 상세정보 조회 중 오류 발생: {str(e)}")
        return jsonify({
            "success": False,
            "error": "룰 상세정보 조회 실패",
            "details": str(e)
        }), 500


@app.route('/api/v1/device-types', methods=['GET'])
def get_supported_device_types():
    """
    지원되는 장비 타입 목록 조회 (강화된 정보 포함)
    """
    try:
        device_types = analyzer.get_supported_device_types()
        
        # 각 장비 타입별 지원 기능 정보
        device_info = {}
        for device_type in device_types:
            applicable_rules = len([rule for rule in analyzer.get_available_rules() 
                                 if device_type in rule['deviceTypes']])
            logical_rules = len([rule for rule in analyzer.get_available_rules() 
                               if device_type in rule['deviceTypes'] and rule.get('hasLogicalAnalysis')])
            
            device_info[device_type] = {
                "supportedRules": applicable_rules,
                "logicalAnalysisRules": logical_rules,
                "features": {
                    "contextParsing": device_type in ["Cisco", "Juniper"],
                    "interfaceAnalysis": device_type in ["Cisco", "Juniper", "Piolink"],
                    "serviceAnalysis": True
                }
            }
        
        return jsonify({
            "success": True,
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


@app.route('/api/v1/config-validate', methods=['POST'])
def validate_config():
    """
    설정 파일 문법 검증 엔드포인트 (새로운 기능)
    
    Request Body:
    {
        "deviceType": "Cisco",
        "configText": "<config 파일 전체 텍스트>"
    }
    """
    try:
        if not request.json:
            return jsonify({
                "success": False,
                "error": "JSON 데이터가 필요합니다"
            }), 400
        
        device_type = request.json.get('deviceType')
        config_text = request.json.get('configText')
        
        if not device_type or not config_text:
            return jsonify({
                "success": False,
                "error": "deviceType과 configText가 필요합니다"
            }), 400
        
        # 문법 검증 실행
        syntax_errors = analyzer.validate_config_syntax(config_text, device_type)
        
        return jsonify({
            "success": True,
            "isValid": len(syntax_errors) == 0,
            "errorCount": len(syntax_errors),
            "errors": syntax_errors,
            "deviceType": device_type,
            "totalLines": len(config_text.splitlines())
        })
        
    except Exception as e:
        logger.error(f"설정 검증 중 오류 발생: {str(e)}")
        return jsonify({
            "success": False,
            "error": "설정 검증 실패",
            "details": str(e)
        }), 500


@app.route('/api/v1/analyze-line', methods=['POST'])
def analyze_single_line():
    """
    단일 라인 분석 엔드포인트 (디버깅/테스트용)
    
    Request Body:
    {
        "line": "enable password cisco",
        "deviceType": "Cisco",
        "ruleIds": ["N-01"]  // 선택사항
    }
    """
    try:
        if not request.json:
            return jsonify({
                "success": False,
                "error": "JSON 데이터가 필요합니다"
            }), 400
        
        line = request.json.get('line')
        device_type = request.json.get('deviceType')
        rule_ids = request.json.get('ruleIds')
        
        if not line or not device_type:
            return jsonify({
                "success": False,
                "error": "line과 deviceType이 필요합니다"
            }), 400
        
        # 단일 라인 분석 실행
        vulnerabilities = analyzer.analyze_single_line(line, device_type, rule_ids)
        
        return jsonify({
            "success": True,
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


@app.route('/api/v1/statistics', methods=['GET'])
def get_analysis_statistics():
    """
    분석 엔진 통계 정보 조회 (새로운 기능)
    """
    try:
        stats = analyzer.get_analysis_statistics()
        
        return jsonify({
            "success": True,
            "statistics": stats,
            "timestamp": datetime.now().isoformat()
        })
        
    except Exception as e:
        logger.error(f"통계 조회 중 오류 발생: {str(e)}")
        return jsonify({
            "success": False,
            "error": "통계 조회 실패",
            "details": str(e)
        }), 500


def _extract_context_info(config_text: str, device_type: str) -> Dict[str, Any]:
    """설정 파일에서 컨텍스트 정보 추출"""
    try:
        from rules.security_rules import parse_config_context
        context = parse_config_context(config_text, device_type)
        
        return {
            "totalInterfaces": len(context.parsed_interfaces),
            "activeInterfaces": sum(1 for iface in context.parsed_interfaces.values() 
                                  if not iface.get('is_shutdown', False)),
            "configuredServices": len(context.parsed_services),
            "globalSettings": len(context.global_settings),
            "deviceType": device_type,
            "configComplexity": _calculate_config_complexity(context)
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


@app.errorhandler(413)
def payload_too_large(error):
    """413 에러 핸들러 (파일 크기 초과)"""
    return jsonify({
        "success": False,
        "error": "업로드된 파일이 너무 큽니다",
        "maxSize": "50MB",
        "engineVersion": ANALYSIS_ENGINE_VERSION
    }), 413


if __name__ == '__main__':
    # 환경변수에서 포트 가져오기 (Railway 호환)
    port = int(os.environ.get('PORT', 5002))
    debug = os.environ.get('FLASK_ENV') != 'production'
    
    # 시작 로그
    logger.info(f"KISA 네트워크 보안 분석 API 시작 - Enhanced Version {API_VERSION}")
    logger.info(f"분석 엔진: {ANALYSIS_ENGINE_VERSION}")
    logger.info(f"포트: {port}, 디버그 모드: {debug}")
    
    app.run(
        host='0.0.0.0',
        port=port,
        debug=debug
    )