# -*- coding: utf-8 -*-
"""
config.py
애플리케이션 설정 관리

환경별 설정 및 전역 설정 값들을 관리
"""

import os
from dataclasses import dataclass
from typing import Optional, List


@dataclass
class DatabaseConfig:
    """데이터베이스 설정 (향후 확장용)"""
    url: Optional[str] = None
    pool_size: int = 5
    max_overflow: int = 10
    pool_timeout: int = 30


@dataclass
class SecurityConfig:
    """보안 설정"""
    secret_key: str = "kisa-network-security-analyzer-secret-key-change-in-production"
    max_content_length: int = 50 * 1024 * 1024  # 50MB
    rate_limit: str = "100 per minute"
    allowed_origins: List[str] = None
    
    def __post_init__(self):
        if self.allowed_origins is None:
            self.allowed_origins = ["*"]


@dataclass
class LoggingConfig:
    """로깅 설정"""
    level: str = "INFO"
    format: str = "%(asctime)s - %(name)s - %(levelname)s - %(funcName)s:%(lineno)d - %(message)s"
    file_path: Optional[str] = None
    max_bytes: int = 10 * 1024 * 1024  # 10MB
    backup_count: int = 5
    enable_console: bool = True
    enable_file: bool = True


@dataclass
class AnalysisConfig:
    """분석 엔진 설정"""
    max_config_size: int = 10 * 1024 * 1024  # 10MB
    max_lines: int = 50000
    timeout_seconds: int = 300  # 5분
    cache_enabled: bool = False
    cache_ttl: int = 3600  # 1시간
    parallel_analysis: bool = False
    max_workers: int = 4


@dataclass
class APIConfig:
    """API 설정"""
    host: str = "0.0.0.0"
    port: int = 5000
    debug: bool = False
    testing: bool = False
    threaded: bool = True
    processes: int = 1


class Config:
    """기본 설정 클래스"""
    
    def __init__(self):
        self.security = SecurityConfig()
        self.logging = LoggingConfig()
        self.analysis = AnalysisConfig()
        self.api = APIConfig()
        self.database = DatabaseConfig()
        
        # 환경변수에서 설정 로드
        self._load_from_environment()
    
    def _load_from_environment(self):
        """환경변수에서 설정 로드"""
        # Security 설정
        if os.getenv('SECRET_KEY'):
            self.security.secret_key = os.getenv('SECRET_KEY')
        
        if os.getenv('MAX_CONTENT_LENGTH'):
            self.security.max_content_length = int(os.getenv('MAX_CONTENT_LENGTH'))
        
        if os.getenv('ALLOWED_ORIGINS'):
            self.security.allowed_origins = os.getenv('ALLOWED_ORIGINS').split(',')
        
        # Logging 설정
        if os.getenv('LOG_LEVEL'):
            self.logging.level = os.getenv('LOG_LEVEL').upper()
        
        if os.getenv('LOG_FILE'):
            self.logging.file_path = os.getenv('LOG_FILE')
        
        # Analysis 설정
        if os.getenv('MAX_CONFIG_SIZE'):
            self.analysis.max_config_size = int(os.getenv('MAX_CONFIG_SIZE'))
        
        if os.getenv('ANALYSIS_TIMEOUT'):
            self.analysis.timeout_seconds = int(os.getenv('ANALYSIS_TIMEOUT'))
        
        if os.getenv('ENABLE_CACHE'):
            self.analysis.cache_enabled = os.getenv('ENABLE_CACHE').lower() == 'true'
        
        # API 설정
        if os.getenv('API_HOST'):
            self.api.host = os.getenv('API_HOST')
        
        if os.getenv('API_PORT'):
            self.api.port = int(os.getenv('API_PORT'))
        
        if os.getenv('API_DEBUG'):
            self.api.debug = os.getenv('API_DEBUG').lower() == 'true'


class DevelopmentConfig(Config):
    """개발 환경 설정"""
    
    def __init__(self):
        super().__init__()
        self.api.debug = True
        self.logging.level = "DEBUG"
        self.logging.enable_console = True
        self.analysis.cache_enabled = False


class ProductionConfig(Config):
    """프로덕션 환경 설정"""
    
    def __init__(self):
        super().__init__()
        self.api.debug = False
        self.logging.level = "WARNING"
        self.logging.file_path = "/var/log/kisa-analyzer/app.log"
        self.analysis.cache_enabled = True
        self.analysis.parallel_analysis = True
        
        # 프로덕션에서는 보안 강화
        self.security.allowed_origins = [
            "https://yourdomain.com",
            "https://admin.yourdomain.com"
        ]


class TestingConfig(Config):
    """테스트 환경 설정"""
    
    def __init__(self):
        super().__init__()
        self.api.testing = True
        self.api.debug = True
        self.logging.level = "DEBUG"
        self.logging.enable_file = False
        self.analysis.timeout_seconds = 60
        self.analysis.cache_enabled = False


# 설정 팩토리
def get_config(environment: str = None) -> Config:
    """
    환경에 따른 설정 객체 반환
    
    Args:
        environment: 환경 이름 (development, production, testing)
        
    Returns:
        Config: 설정 객체
    """
    if environment is None:
        environment = os.getenv('FLASK_ENV', 'development')
    
    config_map = {
        'development': DevelopmentConfig,
        'production': ProductionConfig,
        'testing': TestingConfig
    }
    
    config_class = config_map.get(environment, DevelopmentConfig)
    return config_class()


# 전역 상수
class Constants:
    """애플리케이션 상수"""
    
    # API 버전
    API_VERSION = "v1"
    
    # 지원되는 장비 타입
    SUPPORTED_DEVICE_TYPES = [
        "Cisco",
        "Juniper", 
        "Radware",
        "Passport",
        "Piolink"
    ]
    
    # 심각도 레벨
    SEVERITY_LEVELS = ["상", "중", "하"]
    
    # 최대 파일 크기 (MB)
    MAX_FILE_SIZE_MB = 50
    
    # 기본 타임아웃 (초)
    DEFAULT_TIMEOUT = 300
    
    # 지원되는 파일 확장자
    ALLOWED_EXTENSIONS = ['.txt', '.cfg', '.conf', '.config']
    
    # 룰 카테고리
    RULE_CATEGORIES = [
        "계정 관리",
        "접근 관리", 
        "패치 관리",
        "로그 관리",
        "기능 관리"
    ]
    
    # HTTP 상태 코드 메시지
    STATUS_MESSAGES = {
        200: "성공",
        400: "잘못된 요청",
        404: "리소스를 찾을 수 없음", 
        500: "내부 서버 오류"
    }


class ErrorMessages:
    """에러 메시지 상수"""
    
    INVALID_DEVICE_TYPE = "지원되지 않는 장비 타입입니다"
    EMPTY_CONFIG_TEXT = "설정 파일 내용이 비어있습니다"
    CONFIG_TOO_LARGE = "설정 파일이 너무 큽니다"
    INVALID_RULE_ID = "존재하지 않는 룰 ID입니다"
    ANALYSIS_TIMEOUT = "분석 시간이 초과되었습니다"
    INVALID_JSON = "유효하지 않은 JSON 형식입니다"
    MISSING_REQUIRED_FIELD = "필수 필드가 누락되었습니다"
    INTERNAL_ERROR = "내부 서버 오류가 발생했습니다"


class SuccessMessages:
    """성공 메시지 상수"""
    
    ANALYSIS_COMPLETED = "분석이 성공적으로 완료되었습니다"
    RULES_RETRIEVED = "룰 목록을 성공적으로 조회했습니다"
    DEVICE_TYPES_RETRIEVED = "지원 장비 타입을 성공적으로 조회했습니다"


# 환경 변수 검증
def validate_environment():
    """환경 변수 검증"""
    required_vars = []
    missing_vars = []
    
    for var in required_vars:
        if not os.getenv(var):
            missing_vars.append(var)
    
    if missing_vars:
        raise ValueError(f"필수 환경 변수가 설정되지 않았습니다: {', '.join(missing_vars)}")


# 설정 로드 및 검증
def load_and_validate_config(environment: str = None) -> Config:
    """설정 로드 및 검증"""
    validate_environment()
    config = get_config(environment)
    
    # 추가 검증 로직
    if config.analysis.max_config_size <= 0:
        raise ValueError("max_config_size는 0보다 커야 합니다")
    
    if config.analysis.timeout_seconds <= 0:
        raise ValueError("timeout_seconds는 0보다 커야 합니다")
    
    if config.api.port < 1 or config.api.port > 65535:
        raise ValueError("port는 1-65535 범위여야 합니다")
    
    return config


# 기본 설정 인스턴스
default_config = get_config()
