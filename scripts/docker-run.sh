# ================================
# scripts/docker-run.sh
#!/bin/bash

# Docker 컨테이너 실행 스크립트

set -e

# 변수 설정
IMAGE_NAME="kisa-network-analyzer"
TAG=${1:-latest}
CONTAINER_NAME="kisa-analyzer"
PORT=${2:-5000}

echo "Running Docker container: ${IMAGE_NAME}:${TAG}"

# 기존 컨테이너 정리
if [ $(docker ps -aq -f name=${CONTAINER_NAME}) ]; then
    echo "Stopping and removing existing container..."
    docker stop ${CONTAINER_NAME} || true
    docker rm ${CONTAINER_NAME} || true
fi

# 로그 디렉토리 생성
mkdir -p logs

# 컨테이너 실행
docker run -d \
    --name ${CONTAINER_NAME} \
    -p ${PORT}:5000 \
    -v $(pwd)/logs:/app/logs \
    -e FLASK_ENV=production \
    -e LOG_LEVEL=INFO \
    --restart unless-stopped \
    ${IMAGE_NAME}:${TAG}

echo "Container started successfully!"
echo "API available at: http://localhost:${PORT}/api/v1/health"

# 컨테이너 상태 확인
sleep 5
docker ps -f name=${CONTAINER_NAME}