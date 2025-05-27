# ================================
# scripts/benchmark.py
# -*- coding: utf-8 -*-
"""
성능 벤치마크 스크립트
"""

import time
import statistics
from analyzers.config_analyzer import ConfigAnalyzer
from models.analysis_request import AnalysisRequest, AnalysisOptions


def generate_large_config(lines=1000):
    """대용량 설정 파일 생성"""
    config_lines = [
        "version 15.1",
        "hostname BenchmarkRouter",
        "enable secret $1$test$hash123456789"
    ]
    
    # 인터페이스 설정 반복 생성
    for i in range(lines):
        config_lines.extend([
            f"interface FastEthernet0/{i}",
            f" ip address 192.168.{i//254}.{i%254} 255.255.255.0",
            " no shutdown"
        ])
    
    config_lines.append("end")
    return "\n".join(config_lines)


def benchmark_analyzer():
    """분석기 성능 벤치마크"""
    analyzer = ConfigAnalyzer()
    
    # 다양한 크기의 설정 파일로 테스트
    test_sizes = [100, 500, 1000, 2000, 5000]
    results = {}
    
    for size in test_sizes:
        print(f"테스트 중: {size} 라인 설정...")
        
        config = generate_large_config(size)
        request = AnalysisRequest(
            device_type="Cisco",
            config_text=config,
            options=AnalysisOptions(check_all_rules=True)
        )
        
        # 5회 반복 측정
        times = []
        for _ in range(5):
            start_time = time.time()
            result = analyzer.analyze_config(request)
            end_time = time.time()
            times.append(end_time - start_time)
        
        # 통계 계산
        avg_time = statistics.mean(times)
        min_time = min(times)
        max_time = max(times)
        std_dev = statistics.stdev(times) if len(times) > 1 else 0
        
        results[size] = {
            'avg_time': avg_time,
            'min_time': min_time,
            'max_time': max_time,
            'std_dev': std_dev,
            'lines_per_second': size / avg_time
        }
        
        print(f"  평균: {avg_time:.3f}초")
        print(f"  초당 처리 라인: {size / avg_time:.0f}")
        print()
    
    # 결과 출력
    print("=== 벤치마크 결과 ===")
    print("크기(라인) | 평균시간(초) | 초당라인 | 표준편차")
    print("-" * 50)
    
    for size, stats in results.items():
        print(f"{size:8d} | {stats['avg_time']:9.3f} | {stats['lines_per_second']:7.0f} | {stats['std_dev']:7.3f}")
    
    return results


if __name__ == "__main__":
    benchmark_analyzer()