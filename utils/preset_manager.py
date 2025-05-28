# -*- coding: utf-8 -*-
"""
utils/preset_manager.py
사용자 프리셋 관리 시스템

기능:
- 분석 설정 프리셋 저장/로드
- 지침서 조합 프리셋
- 사용자별 기본 설정
- 프리셋 공유 및 가져오기
"""

import json
import os
from typing import Dict, List, Optional, Any
from datetime import datetime
from dataclasses import dataclass, asdict, field
from pathlib import Path
import logging


@dataclass
class AnalysisPreset:
    """분석 프리셋 정의"""
    id: str
    name: str
    description: str
    frameworks: List[str]
    analysis_mode: str  # single, comparison, combined
    device_types: List[str]
    options: Dict[str, Any]
    created_at: str
    updated_at: str
    usage_count: int = 0
    is_favorite: bool = False
    tags: List[str] = field(default_factory=list)
    author: str = "user"
    
    def to_dict(self) -> Dict[str, Any]:
        """딕셔너리로 변환"""
        return asdict(self)
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'AnalysisPreset':
        """딕셔너리에서 생성"""
        return cls(**data)


@dataclass 
class UserSettings:
    """사용자 설정"""
    default_framework: str = "KISA"
    default_analysis_mode: str = "single"
    favorite_frameworks: List[str] = field(default_factory=lambda: ["KISA"])
    default_options: Dict[str, Any] = field(default_factory=lambda: {
        "checkAllRules": True,
        "enableLogicalAnalysis": True,
        "includeRecommendations": True,
        "returnRawMatches": False
    })
    ui_preferences: Dict[str, Any] = field(default_factory=dict)
    notification_settings: Dict[str, bool] = field(default_factory=lambda: {
        "analysis_complete": True,
        "new_frameworks": True,
        "preset_shared": False
    })
    
    def to_dict(self) -> Dict[str, Any]:
        """딕셔너리로 변환"""
        return asdict(self)
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'UserSettings':
        """딕셔너리에서 생성"""
        return cls(**data)


class PresetManager:
    """프리셋 관리자"""
    
    def __init__(self, storage_dir: str = "user_data"):
        """
        프리셋 관리자 초기화
        
        Args:
            storage_dir: 사용자 데이터 저장 디렉토리
        """
        self.logger = logging.getLogger(__name__)
        self.storage_dir = Path(storage_dir)
        self.presets_file = self.storage_dir / "presets.json"
        self.settings_file = self.storage_dir / "user_settings.json"
        
        # 디렉토리 생성
        self.storage_dir.mkdir(exist_ok=True)
        
        # 데이터 로드
        self.presets: Dict[str, AnalysisPreset] = self._load_presets()
        self.user_settings: UserSettings = self._load_user_settings()
        
        # 기본 프리셋 생성
        self._create_default_presets()
        
        self.logger.info(f"프리셋 관리자 초기화 완료 - 프리셋: {len(self.presets)}개")
    
    def _load_presets(self) -> Dict[str, AnalysisPreset]:
        """저장된 프리셋 로드"""
        if not self.presets_file.exists():
            return {}
        
        try:
            with open(self.presets_file, 'r', encoding='utf-8') as f:
                data = json.load(f)
                presets = {}
                for preset_id, preset_data in data.items():
                    presets[preset_id] = AnalysisPreset.from_dict(preset_data)
                return presets
        except Exception as e:
            self.logger.error(f"프리셋 로드 실패: {e}")
            return {}
    
    def _load_user_settings(self) -> UserSettings:
        """사용자 설정 로드"""
        if not self.settings_file.exists():
            return UserSettings()
        
        try:
            with open(self.settings_file, 'r', encoding='utf-8') as f:
                data = json.load(f)
                return UserSettings.from_dict(data)
        except Exception as e:
            self.logger.error(f"사용자 설정 로드 실패: {e}")
            return UserSettings()
    
    def _save_presets(self):
        """프리셋 저장"""
        try:
            data = {preset_id: preset.to_dict() for preset_id, preset in self.presets.items()}
            with open(self.presets_file, 'w', encoding='utf-8') as f:
                json.dump(data, f, ensure_ascii=False, indent=2)
        except Exception as e:
            self.logger.error(f"프리셋 저장 실패: {e}")
            raise
    
    def _save_user_settings(self):
        """사용자 설정 저장"""
        try:
            with open(self.settings_file, 'w', encoding='utf-8') as f:
                json.dump(self.user_settings.to_dict(), f, ensure_ascii=False, indent=2)
        except Exception as e:
            self.logger.error(f"사용자 설정 저장 실패: {e}")
            raise
    
    def _create_default_presets(self):
        """기본 프리셋 생성"""
        default_presets = [
            {
                "id": "kisa_comprehensive",
                "name": "KISA 종합 점검",
                "description": "KISA 가이드의 모든 룰을 적용한 종합적인 보안 점검",
                "frameworks": ["KISA"],
                "analysis_mode": "single",
                "device_types": ["Cisco", "Juniper", "Piolink"],
                "options": {
                    "checkAllRules": True,
                    "enableLogicalAnalysis": True,
                    "includeRecommendations": True,
                    "returnRawMatches": False
                },
                "tags": ["comprehensive", "standard", "kisa"],
                "author": "system"
            },
            {
                "id": "kisa_critical_only",
                "name": "KISA 상급 취약점만",
                "description": "KISA 가이드의 상급(높은 위험도) 취약점만 점검",
                "frameworks": ["KISA"],
                "analysis_mode": "single", 
                "device_types": ["Cisco", "Juniper", "Piolink"],
                "options": {
                    "checkAllRules": False,
                    "specificRuleIds": ["N-01", "N-02", "N-03", "N-04", "N-05", "N-06", "N-07", "N-08", "N-09", "N-10", "N-11", "N-12", "N-13", "N-14"],
                    "enableLogicalAnalysis": True,
                    "includeRecommendations": True
                },
                "tags": ["critical", "high-risk", "kisa"],
                "author": "system"
            },
            {
                "id": "multi_framework_comparison",
                "name": "다중 지침서 비교",
                "description": "KISA와 CIS 지침서를 비교하여 각각의 결과를 확인",
                "frameworks": ["KISA", "CIS"],
                "analysis_mode": "comparison",
                "device_types": ["Cisco"],
                "options": {
                    "checkAllRules": True,
                    "enableLogicalAnalysis": True,
                    "includeRecommendations": True,
                    "compareFrameworks": True
                },
                "tags": ["comparison", "multi-framework", "comprehensive"],
                "author": "system"
            },
            {
                "id": "combined_comprehensive",
                "name": "통합 종합 점검",
                "description": "KISA와 CIS 지침서를 조합하여 가장 포괄적인 보안 점검",
                "frameworks": ["KISA", "CIS"],
                "analysis_mode": "combined",
                "device_types": ["Cisco"],
                "options": {
                    "checkAllRules": True,
                    "enableLogicalAnalysis": True,
                    "includeRecommendations": True,
                    "returnRawMatches": False
                },
                "tags": ["combined", "comprehensive", "multi-framework"],
                "author": "system"
            },
            {
                "id": "quick_cisco_check",
                "name": "Cisco 빠른 점검",
                "description": "Cisco 장비 대상 필수 보안 항목 빠른 점검",
                "frameworks": ["KISA"],
                "analysis_mode": "single",
                "device_types": ["Cisco"],
                "options": {
                    "checkAllRules": False,
                    "specificRuleIds": ["N-01", "N-03", "N-04", "N-05", "N-16", "N-26"],
                    "enableLogicalAnalysis": True,
                    "includeRecommendations": True
                },
                "tags": ["quick", "cisco", "essential"],
                "author": "system"
            }
        ]
        
        now = datetime.now().isoformat()
        
        for preset_data in default_presets:
            if preset_data["id"] not in self.presets:
                preset_data.update({
                    "created_at": now,
                    "updated_at": now,
                    "usage_count": 0,
                    "is_favorite": False
                })
                
                self.presets[preset_data["id"]] = AnalysisPreset.from_dict(preset_data)
        
        self._save_presets()
    
    def create_preset(self, preset_data: Dict[str, Any]) -> str:
        """새 프리셋 생성"""
        # 필수 필드 검증
        required_fields = ["name", "frameworks", "analysis_mode", "device_types"]
        for field in required_fields:
            if field not in preset_data:
                raise ValueError(f"필수 필드 누락: {field}")
        
        # ID 생성
        preset_id = f"user_{int(datetime.now().timestamp())}"
        
        # 프리셋 객체 생성
        now = datetime.now().isoformat()
        preset = AnalysisPreset(
            id=preset_id,
            name=preset_data["name"],
            description=preset_data.get("description", ""),
            frameworks=preset_data["frameworks"],
            analysis_mode=preset_data["analysis_mode"],
            device_types=preset_data["device_types"],
            options=preset_data.get("options", {}),
            created_at=now,
            updated_at=now,
            usage_count=0,
            is_favorite=preset_data.get("is_favorite", False),
            tags=preset_data.get("tags", []),
            author=preset_data.get("author", "user")
        )
        
        self.presets[preset_id] = preset
        self._save_presets()
        
        self.logger.info(f"새 프리셋 생성: {preset.name} (ID: {preset_id})")
        return preset_id
    
    def get_preset(self, preset_id: str) -> Optional[AnalysisPreset]:
        """프리셋 조회"""
        return self.presets.get(preset_id)
    
    def get_all_presets(self, include_system: bool = True, tags: Optional[List[str]] = None) -> List[AnalysisPreset]:
        """모든 프리셋 조회"""
        presets = list(self.presets.values())
        
        # 시스템 프리셋 필터링
        if not include_system:
            presets = [p for p in presets if p.author != "system"]
        
        # 태그 필터링
        if tags:
            presets = [p for p in presets if any(tag in p.tags for tag in tags)]
        
        # 사용 빈도순 정렬
        return sorted(presets, key=lambda p: (p.is_favorite, p.usage_count), reverse=True)
    
    def update_preset(self, preset_id: str, updates: Dict[str, Any]) -> bool:
        """프리셋 업데이트"""
        if preset_id not in self.presets:
            return False
        
        preset = self.presets[preset_id]
        
        # 업데이트 가능한 필드들
        updatable_fields = ["name", "description", "frameworks", "analysis_mode", 
                           "device_types", "options", "is_favorite", "tags"]
        
        for field, value in updates.items():
            if field in updatable_fields:
                setattr(preset, field, value)
        
        preset.updated_at = datetime.now().isoformat()
        self._save_presets()
        
        self.logger.info(f"프리셋 업데이트: {preset.name} (ID: {preset_id})")
        return True
    
    def delete_preset(self, preset_id: str) -> bool:
        """프리셋 삭제"""
        if preset_id in self.presets:
            preset_name = self.presets[preset_id].name
            del self.presets[preset_id]
            self._save_presets()
            
            self.logger.info(f"프리셋 삭제: {preset_name} (ID: {preset_id})")
            return True
        return False
    
    def use_preset(self, preset_id: str) -> Optional[Dict[str, Any]]:
        """프리셋 사용 - 사용 횟수 증가 및 분석 요청 데이터 반환"""
        if preset_id not in self.presets:
            return None
        
        preset = self.presets[preset_id]
        preset.usage_count += 1
        self._save_presets()
        
        # 분석 요청 형태로 변환
        return {
            "frameworks": preset.frameworks,
            "analysisMode": preset.analysis_mode,
            "options": preset.options,
            "deviceTypes": preset.device_types,
            "presetInfo": {
                "id": preset.id,
                "name": preset.name,
                "description": preset.description
            }
        }
    
    def get_user_settings(self) -> UserSettings:
        """사용자 설정 조회"""
        return self.user_settings
    
    def update_user_settings(self, updates: Dict[str, Any]) -> bool:
        """사용자 설정 업데이트"""
        try:
            # 업데이트 가능한 필드들
            updatable_fields = ["default_framework", "default_analysis_mode", 
                               "favorite_frameworks", "default_options", 
                               "ui_preferences", "notification_settings"]
            
            for field, value in updates.items():
                if field in updatable_fields and hasattr(self.user_settings, field):
                    setattr(self.user_settings, field, value)
            
            self._save_user_settings()
            self.logger.info("사용자 설정 업데이트 완료")
            return True
        except Exception as e:
            self.logger.error(f"사용자 설정 업데이트 실패: {e}")
            return False
    
    def export_presets(self, preset_ids: Optional[List[str]] = None) -> Dict[str, Any]:
        """프리셋 내보내기"""
        if preset_ids:
            export_presets = {pid: self.presets[pid].to_dict() 
                            for pid in preset_ids if pid in self.presets}
        else:
            export_presets = {pid: preset.to_dict() 
                            for pid, preset in self.presets.items() 
                            if preset.author == "user"}
        
        return {
            "export_date": datetime.now().isoformat(),
            "version": "1.0",
            "presets": export_presets
        }
    
    def import_presets(self, import_data: Dict[str, Any], overwrite: bool = False) -> Dict[str, Any]:
        """프리셋 가져오기"""
        results = {"imported": [], "skipped": [], "errors": []}
        
        presets_data = import_data.get("presets", {})
        
        for preset_id, preset_data in presets_data.items():
            try:
                # 기존 프리셋 확인
                if preset_id in self.presets and not overwrite:
                    results["skipped"].append(preset_id)
                    continue
                
                # 프리셋 생성/업데이트
                preset_data["author"] = "imported"
                preset_data["updated_at"] = datetime.now().isoformat()
                
                self.presets[preset_id] = AnalysisPreset.from_dict(preset_data)
                results["imported"].append(preset_id)
                
            except Exception as e:
                results["errors"].append({"preset_id": preset_id, "error": str(e)})
        
        if results["imported"]:
            self._save_presets()
        
        return results
    
    def get_statistics(self) -> Dict[str, Any]:
        """프리셋 사용 통계"""
        total_presets = len(self.presets)
        user_presets = len([p for p in self.presets.values() if p.author == "user"])
        system_presets = len([p for p in self.presets.values() if p.author == "system"])
        favorite_presets = len([p for p in self.presets.values() if p.is_favorite])
        
        # 가장 많이 사용된 프리셋
        most_used = max(self.presets.values(), key=lambda p: p.usage_count, default=None)
        
        # 지침서별 프리셋 수
        framework_usage = {}
        for preset in self.presets.values():
            for framework in preset.frameworks:
                framework_usage[framework] = framework_usage.get(framework, 0) + 1
        
        return {
            "totalPresets": total_presets,
            "userPresets": user_presets,
            "systemPresets": system_presets,
            "favoritePresets": favorite_presets,
            "mostUsedPreset": {
                "name": most_used.name,
                "usageCount": most_used.usage_count
            } if most_used else None,
            "frameworkUsage": framework_usage,
            "userSettings": self.user_settings.to_dict()
        }