# ================================
# scripts/rule_validator.py
# -*- coding: utf-8 -*-
"""
룰셋 검증 스크립트
"""

import re
from rules.security_rules import get_all_rules


def validate_rules():
    """모든 룰의 유효성 검증"""
    rules = get_all_rules()
    errors = []
    warnings = []
    
    for rule_id, rule in rules.items():
        # 필수 필드 검증
        if not rule.rule_id:
            errors.append(f"{rule_id}: rule_id가 비어있음")
        
        if not rule.title:
            errors.append(f"{rule_id}: title이 비어있음")
        
        if not rule.description:
            errors.append(f"{rule_id}: description이 비어있음")
        
        if rule.severity not in ["상", "중", "하"]:
            errors.append(f"{rule_id}: 잘못된 severity: {rule.severity}")
        
        # 패턴 검증
        for i, pattern in enumerate(rule.patterns):
            try:
                re.compile(pattern, re.IGNORECASE)
            except re.error as e:
                errors.append(f"{rule_id}: 패턴 {i} 컴파일 오류: {e}")
        
        for i, pattern in enumerate(rule.negative_patterns):
            try:
                re.compile(pattern, re.IGNORECASE)
            except re.error as e:
                errors.append(f"{rule_id}: negative 패턴 {i} 컴파일 오류: {e}")
        
        # 장비 타입 검증
        valid_devices = ["Cisco", "Juniper", "Radware", "Passport", "Piolink"]
        for device in rule.device_types:
            if device not in valid_devices:
                warnings.append(f"{rule_id}: 알 수 없는 장비 타입: {device}")
        
        # 권고사항 길이 검증
        if len(rule.recommendation) < 10:
            warnings.append(f"{rule_id}: 권고사항이 너무 짧음")
    
    # 결과 출력
    print(f"=== 룰셋 검증 결과 ===")
    print(f"총 룰 수: {len(rules)}")
    print(f"오류: {len(errors)}개")
    print(f"경고: {len(warnings)}개")
    
    if errors:
        print("\n=== 오류 목록 ===")
        for error in errors:
            print(f"ERROR: {error}")
    
    if warnings:
        print("\n=== 경고 목록 ===")
        for warning in warnings:
            print(f"WARNING: {warning}")
    
    return len(errors) == 0


def generate_rule_report():
    """룰셋 리포트 생성"""
    rules = get_all_rules()
    
    # 통계 수집
    severity_count = {"상": 0, "중": 0, "하": 0}
    category_count = {}
    device_count = {}
    
    for rule in rules.values():
        severity_count[rule.severity] += 1
        
        category = rule.category.value
        category_count[category] = category_count.get(category, 0) + 1
        
        for device in rule.device_types:
            device_count[device] = device_count.get(device, 0) + 1
    
    # 리포트 출력
    print("=== KISA 네트워크 장비 보안 룰셋 리포트 ===")
    print(f"총 룰 수: {len(rules)}")
    print()
    
    print("심각도별 분포:")
    for severity, count in severity_count.items():
        percentage = (count / len(rules)) * 100
        print(f"  {severity}: {count}개 ({percentage:.1f}%)")
    print()
    
    print("카테고리별 분포:")
    for category, count in category_count.items():
        percentage = (count / len(rules)) * 100
        print(f"  {category}: {count}개 ({percentage:.1f}%)")
    print()
    
    print("장비별 지원 룰 수:")
    for device, count in sorted(device_count.items()):
        percentage = (count / len(rules)) * 100
        print(f"  {device}: {count}개 ({percentage:.1f}%)")


if __name__ == "__main__":
    validate_rules()
    print()
    generate_rule_report()