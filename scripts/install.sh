# ================================
# scripts/install.sh
#!/bin/bash

# KISA 네트워크 장비 취약점 분석 API 설치 스크립트

set -e

echo "=== KISA 네트워크 장비 취약점 분석 API 설치 ==="

# Python 버전 확인
python_version=$(python3 --version 2>&1 | cut -d' ' -f2 | cut -d'.' -f1-2)
required_version="3.8"

if [ "$(printf '%s\n' "$required_version" "$python_version" | sort -V | head -n1)" != "$required_version" ]; then
    echo "오류: Python 3.8 이상이 필요합니다. 현재 버전: $python_version"
    exit 1
fi

echo "✓ Python 버전 확인: $python_version"

# 가상환경 생성
if [ ! -d "venv" ]; then
    echo "가상환경 생성 중..."
    python3 -m venv venv
    echo "✓ 가상환경 생성 완료"
else
    echo "✓ 기존 가상환경 사용"
fi

# 가상환경 활성화
source venv/bin/activate

# pip 업그레이드
echo "pip 업그레이드 중..."
pip install --upgrade pip

# 의존성 설치
echo "의존성 설치 중..."
pip install -r requirements.txt

# 디렉토리 생성
echo "필요한 디렉토리 생성 중..."
mkdir -p logs
mkdir -p config
mkdir -p examples

# 환경변수 파일 생성
if [ ! -f ".env" ]; then
    echo "환경변수 파일 생성 중..."
    cp .env.example .env
    echo "✓ .env 파일이 생성되었습니다. 필요에 따라 수정하세요."
fi

# 스크립트 실행 권한 부여
chmod +x scripts/*.sh

# 설치 완료 메시지
echo ""
echo "=== 설치 완료 ==="
echo "다음 명령어로 서버를 시작할 수 있습니다:"
echo ""
echo "  source venv/bin/activate  # 가상환경 활성화"
echo "  python main.py            # 개발 서버 실행"
echo ""
echo "또는 Make를 사용하여:"
echo "  make run                  # 개발 서버 실행"
echo "  make test                 # 테스트 실행"
echo "  make api-test            # API 테스트 실행"
echo ""
echo "서버가 실행되면 https://kisa-network-analyzer-production.up.railway.app/api/v1/health 에서 상태를 확인할 수 있습니다."
