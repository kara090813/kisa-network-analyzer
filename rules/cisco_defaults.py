# =============================================================================
# 📁 rules/cisco_defaults.py 
# 용도: Cisco IOS 기본값 관리
# =============================================================================
"""
Cisco IOS 기본값 정의 및 관리
버전별, 플랫폼별 기본 동작 정의
"""

from typing import Dict, Any, Optional
import re

class CiscoDefaults:
    """Cisco IOS 기본값 관리 클래스"""
    
    # IOS 버전별 기본값 정의
    DEFAULT_VALUES = {
        'domain_lookup': True,           # 기본 enabled
        'source_route': True,           # 기본 enabled
        'proxy_arp': True,              # 기본 enabled
        'redirects': True,              # 기본 enabled  
        'unreachables': True,           # 기본 enabled
        'mask_reply': {                 # 버전별 차이
            'pre_12.4': True,
            'post_12.4': False
        },
        'directed_broadcast': {         # 버전별 차이
            'pre_12.0': True,
            'post_12.0': False
        },
        'cdp': True,                    # 기본 enabled
        'finger': False,                # 기본 disabled
        'tcp_small_servers': False,     # 기본 disabled
        'udp_small_servers': False,     # 기본 disabled
        'bootp_server': False,          # 기본 disabled
        'http_server': False,           # 기본 disabled
        'identd': False,                # 기본 disabled
        'pad': False                    # 기본 disabled
    }
    
    @classmethod
    def get_default_value(cls, service_name: str, ios_version: Optional[str] = None) -> bool:
        """서비스의 기본값 반환"""
        default = cls.DEFAULT_VALUES.get(service_name)
        
        if isinstance(default, dict):
            # 버전별 기본값 처리
            if ios_version:
                version_num = cls._extract_version_number(ios_version)
                if service_name == 'mask_reply':
                    return default['pre_12.4'] if version_num < 12.4 else default['post_12.4']
                elif service_name == 'directed_broadcast':
                    return default['pre_12.0'] if version_num < 12.0 else default['post_12.0']
            # 버전 정보 없으면 최신 기준
            return list(default.values())[-1]
        
        return default
    
    @classmethod
    def _extract_version_number(cls, version_string: str) -> float:
        """버전 문자열에서 숫자 추출"""
        match = re.search(r'(\d+\.\d+)', version_string)
        if match:
            return float(match.group(1))
        return 15.0  # 기본값으로 최신 버전 가정
