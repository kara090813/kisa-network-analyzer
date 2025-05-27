# ================================
# Makefile
# 프로젝트 관리용 Makefile

.PHONY: help install test lint format run docker-build docker-run clean

help:  ## 도움말 표시
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | sort | awk 'BEGIN {FS = ":.*?## "}; {printf "\033[36m%-20s\033[0m %s\n", $$1, $$2}'

install:  ## 의존성 설치
	pip install -r requirements.txt

install-dev:  ## 개발용 의존성 설치
	pip install -r requirements.txt
	pip install pytest pytest-cov black flake8 mypy

test:  ## 테스트 실행
	python -m pytest tests/ -v

test-cov:  ## 커버리지 포함 테스트
	python -m pytest tests/ --cov=. --cov-report=html

lint:  ## 코드 린트 검사
	flake8 . --max-line-length=100 --exclude=venv,__pycache__
	mypy . --ignore-missing-imports

format:  ## 코드 포맷팅
	black . --line-length=100

run:  ## 개발 서버 실행
	python main.py

run-prod:  ## 프로덕션 서버 실행
	gunicorn --bind 0.0.0.0:5000 --workers 4 main:app

docker-build:  ## Docker 이미지 빌드
	docker build -t kisa-network-analyzer .

docker-run:  ## Docker 컨테이너 실행
	docker run -p 5000:5000 kisa-network-analyzer

docker-compose-up:  ## Docker Compose 실행
	docker-compose up -d

docker-compose-down:  ## Docker Compose 정지
	docker-compose down

benchmark:  ## 성능 벤치마크 실행
	python scripts/benchmark.py

validate-rules:  ## 룰셋 검증
	python scripts/rule_validator.py

generate-configs:  ## 테스트 설정 생성
	python scripts/config_generator.py

clean:  ## 임시 파일 정리
	find . -type f -name "*.pyc" -delete
	find . -type d -name "__pycache__" -delete
	rm -rf .pytest_cache/
	rm -rf .coverage
	rm -rf htmlcov/
	rm -rf logs/*.log

api-test:  ## API 테스트 실행
	python test_api.py

setup:  ## 초기 설정
	mkdir -p logs
	mkdir -p tests
	mkdir -p examples
	chmod +x scripts/*.sh

all: install lint test  ## 전체 검증 실행