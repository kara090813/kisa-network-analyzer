#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
KISA 네트워크 장비 취약점 분석 API
main.py - Flask 애플리케이션 메인 파일

기능:
- 네트워크 장비 설정 파일 업로드 및 분석
- KISA 가이드 기반 보안 취약점 탐지
- REST API 형태로 서비스 제공
"""

from flask import Flask, request, jsonify
from flask_cors import CORS
import json
import logging
from datetime import datetime
import traceback

from analyzers.config_analyzer import ConfigAnalyzer
from models.analysis_request import AnalysisRequest
from models.analysis_response import AnalysisResponse
from utils.validation import validate_request
from utils.logger import setup_logger

# Flask 애플리케이션 초기화
app = Flask(__name__)
CORS(app)  # CORS 설정 (프론트엔드 연동을 위해)

# 로깅 설정
logger = setup_logger(__name__)

# ConfigAnalyzer 인스턴스 생성
analyzer = ConfigAnalyzer()


@app.route('/api/v1/health', methods=['GET'])
def health_check():
    """
    API 상태 확인 엔드포인트
    """
    return jsonify({
        "status": "healthy",
        "version": "1.0.0",
        "timestamp": datetime.now().isoformat(),
        "service": "KISA Network Security Config Analyzer"
    })


@app.route('/api/v1/rules', methods=['GET'])
def get_rules():
    """
    사용 가능한 룰셋 목록 조회
    """
    try:
        rules = analyzer.get_available_rules()
        return jsonify({
            "success": True,
            "totalRules": len(rules),
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
    네트워크 장비 설정 파일 분석 메인 엔드포인트
    
    Request Body:
    {
        "deviceType": "Cisco",
        "configText": "<config 파일 전체 텍스트>",
        "options": {
            "checkAllRules": true,
            "specificRuleIds": ["N-01", "N-04"],
            "returnRawMatches": false
        }
    }
    
    Response:
    {
        "deviceType": "Cisco",
        "totalLines": 120,
        "issuesFound": 3,
        "results": [...]
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
                    "details": validation_result.errors
                }), 400
        except Exception as e:
            return jsonify({
                "success": False,
                "error": "요청 데이터 파싱 실패",
                "details": str(e)
            }), 400
        
        # 로깅
        logger.info(f"분석 요청 수신 - 장비 타입: {analysis_request.device_type}, "
                   f"설정 라인 수: {len(analysis_request.config_text.splitlines())}")
        
        # 설정 파일 분석 실행
        analysis_result = analyzer.analyze_config(analysis_request)
        
        # 응답 생성
        response = AnalysisResponse(
            device_type=analysis_request.device_type,
            total_lines=len(analysis_request.config_text.splitlines()),
            issues_found=len(analysis_result.vulnerabilities),
            analysis_time=analysis_result.analysis_time,
            results=analysis_result.vulnerabilities
        )
        
        logger.info(f"분석 완료 - 발견된 취약점: {response.issues_found}개")
        
        return jsonify(response.to_dict())
    
    except Exception as e:
        logger.error(f"설정 분석 중 오류 발생: {str(e)}")
        logger.error(f"스택 트레이스: {traceback.format_exc()}")
        return jsonify({
            "success": False,
            "error": "설정 분석 실패",
            "details": str(e)
        }), 500


@app.route('/api/v1/rules/<rule_id>', methods=['GET'])
def get_rule_detail(rule_id):
    """
    특정 룰의 상세 정보 조회
    """
    try:
        rule_detail = analyzer.get_rule_detail(rule_id)
        if rule_detail:
            return jsonify({
                "success": True,
                "rule": rule_detail
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
    지원되는 장비 타입 목록 조회
    """
    try:
        device_types = analyzer.get_supported_device_types()
        return jsonify({
            "success": True,
            "deviceTypes": device_types
        })
    except Exception as e:
        logger.error(f"지원 장비 타입 조회 중 오류 발생: {str(e)}")
        return jsonify({
            "success": False,
            "error": "지원 장비 타입 조회 실패",
            "details": str(e)
        }), 500


@app.errorhandler(404)
def not_found(error):
    """404 에러 핸들러"""
    return jsonify({
        "success": False,
        "error": "요청한 리소스를 찾을 수 없습니다",
        "path": request.path
    }), 404


@app.errorhandler(500)
def internal_error(error):
    """500 에러 핸들러"""
    logger.error(f"내부 서버 오류: {str(error)}")
    return jsonify({
        "success": False,
        "error": "내부 서버 오류가 발생했습니다"
    }), 500


if __name__ == '__main__':
    # 환경변수에서 포트 가져오기 (Railway 호환)
    port = int(os.environ.get('PORT', 5000))
    debug = os.environ.get('FLASK_ENV') != 'production'
    
    app.run(
        host='0.0.0.0',
        port=port,
        debug=debug
    )