# -*- coding: utf-8 -*-
"""
utils/logger.py
로깅 설정 유틸리티

애플리케이션 전체의 로깅 설정 및 관리
"""

import logging
import logging.handlers
import os
import sys
from datetime import datetime
from typing import Optional


def setup_logger(
    name: str,
    level: str = "INFO",
    log_file: Optional[str] = None,
    max_bytes: int = 10 * 1024 * 1024,  # 10MB
    backup_count: int = 5
) -> logging.Logger:
    """
    로거 설정 및 반환
    
    Args:
        name: 로거 이름
        level: 로그 레벨 (DEBUG, INFO, WARNING, ERROR, CRITICAL)
        log_file: 로그 파일 경로 (None이면 콘솔만)
        max_bytes: 로그 파일 최대 크기
        backup_count: 백업 파일 개수
        
    Returns:
        logging.Logger: 설정된 로거
    """
    logger = logging.getLogger(name)
    
    # 기존 핸들러 제거 (중복 방지)
    for handler in logger.handlers[:]:
        logger.removeHandler(handler)
    
    # 로그 레벨 설정
    log_level = getattr(logging, level.upper(), logging.INFO)
    logger.setLevel(log_level)
    
    # 로그 포맷 설정
    formatter = logging.Formatter(
        '%(asctime)s - %(name)s - %(levelname)s - %(funcName)s:%(lineno)d - %(message)s',
        datefmt='%Y-%m-%d %H:%M:%S'
    )
    
    # 콘솔 핸들러 설정
    console_handler = logging.StreamHandler(sys.stdout)
    console_handler.setLevel(log_level)
    console_handler.setFormatter(formatter)
    logger.addHandler(console_handler)
    
    # 파일 핸들러 설정 (파일 경로가 지정된 경우)
    if log_file:
        # 로그 디렉토리 생성
        log_dir = os.path.dirname(log_file)
        if log_dir and not os.path.exists(log_dir):
            os.makedirs(log_dir, exist_ok=True)
        
        # 로테이팅 파일 핸들러
        file_handler = logging.handlers.RotatingFileHandler(
            log_file,
            maxBytes=max_bytes,
            backupCount=backup_count,
            encoding='utf-8'
        )
        file_handler.setLevel(log_level)
        file_handler.setFormatter(formatter)
        logger.addHandler(file_handler)
    
    return logger


def setup_api_logger() -> logging.Logger:
    """API 전용 로거 설정"""
    log_dir = os.environ.get('LOG_DIR', 'logs')
    log_file = os.path.join(log_dir, 'api.log')
    log_level = os.environ.get('LOG_LEVEL', 'INFO')
    
    return setup_logger(
        name='kisa_network_api',
        level=log_level,
        log_file=log_file
    )


def setup_analysis_logger() -> logging.Logger:
    """분석 엔진 전용 로거 설정"""
    log_dir = os.environ.get('LOG_DIR', 'logs')
    log_file = os.path.join(log_dir, 'analysis.log')
    log_level = os.environ.get('LOG_LEVEL', 'INFO')
    
    return setup_logger(
        name='kisa_network_analyzer',
        level=log_level,
        log_file=log_file
    )


class RequestLogger:
    """요청 로깅을 위한 컨텍스트 매니저"""
    
    def __init__(self, logger: logging.Logger, request_id: str):
        self.logger = logger
        self.request_id = request_id
        self.start_time = None
    
    def __enter__(self):
        self.start_time = datetime.now()
        self.logger.info(f"[{self.request_id}] 요청 시작")
        return self
    
    def __exit__(self, exc_type, exc_val, exc_tb):
        end_time = datetime.now()
        duration = (end_time - self.start_time).total_seconds()
        
        if exc_type is None:
            self.logger.info(f"[{self.request_id}] 요청 완료 - 소요시간: {duration:.2f}초")
        else:
            self.logger.error(
                f"[{self.request_id}] 요청 실패 - 소요시간: {duration:.2f}초, "
                f"오류: {exc_type.__name__}: {exc_val}"
            )
    
    def log_step(self, step: str, details: str = ""):
        """단계별 로그 기록"""
        self.logger.info(f"[{self.request_id}] {step}" + (f" - {details}" if details else ""))


def log_analysis_result(logger: logging.Logger, request_id: str, result_summary: dict):
    """분석 결과 로깅"""
    logger.info(
        f"[{request_id}] 분석 결과: "
        f"장비타입={result_summary.get('device_type')}, "
        f"총라인수={result_summary.get('total_lines')}, "
        f"취약점수={result_summary.get('issues_found')}, "
        f"분석시간={result_summary.get('analysis_time', 0):.2f}초"
    )


def log_security_event(logger: logging.Logger, event_type: str, details: dict):
    """보안 이벤트 로깅"""
    logger.warning(
        f"보안 이벤트: {event_type} - "
        f"세부정보: {details}"
    )


def log_performance_metric(logger: logging.Logger, metric_name: str, value: float, unit: str = ""):
    """성능 지표 로깅"""
    logger.info(
        f"성능지표: {metric_name}={value}{unit}"
    )


class AnalysisMetrics:
    """분석 성능 지표 수집"""
    
    def __init__(self, logger: logging.Logger):
        self.logger = logger
        self.metrics = {}
        self.start_times = {}
    
    def start_timer(self, name: str):
        """타이머 시작"""
        self.start_times[name] = datetime.now()
    
    def end_timer(self, name: str):
        """타이머 종료 및 지표 기록"""
        if name in self.start_times:
            elapsed = (datetime.now() - self.start_times[name]).total_seconds()
            self.metrics[name] = elapsed
            log_performance_metric(self.logger, name, elapsed, "초")
            del self.start_times[name]
            return elapsed
        return 0
    
    def record_metric(self, name: str, value: float, unit: str = ""):
        """지표 직접 기록"""
        self.metrics[name] = value
        log_performance_metric(self.logger, name, value, unit)
    
    def get_metrics(self) -> dict:
        """수집된 지표 반환"""
        return self.metrics.copy()


def configure_werkzeug_logging():
    """Werkzeug (Flask) 로깅 설정"""
    # Werkzeug 로그 레벨 조정 (개발 환경에서 너무 상세한 로그 방지)
    logging.getLogger('werkzeug').setLevel(logging.WARNING)


def configure_root_logging():
    """루트 로거 설정"""
    # 루트 로거의 기본 레벨 설정
    root_logger = logging.getLogger()
    root_logger.setLevel(logging.WARNING)  # 외부 라이브러리 로그 최소화


# 환경별 로깅 설정
def setup_production_logging():
    """프로덕션 환경 로깅 설정"""
    configure_root_logging()
    configure_werkzeug_logging()
    
    # 프로덕션에서는 INFO 레벨 이상만 로깅
    os.environ.setdefault('LOG_LEVEL', 'INFO')


def setup_development_logging():
    """개발 환경 로깅 설정"""
    configure_werkzeug_logging()
    
    # 개발에서는 DEBUG 레벨까지 로깅
    os.environ.setdefault('LOG_LEVEL', 'DEBUG')


# 초기화 함수
def initialize_logging(environment: str = 'development'):
    """로깅 시스템 초기화"""
    if environment == 'production':
        setup_production_logging()
    else:
        setup_development_logging()
    
    # 로그 디렉토리 생성
    log_dir = os.environ.get('LOG_DIR', 'logs')
    if not os.path.exists(log_dir):
        os.makedirs(log_dir, exist_ok=True)
