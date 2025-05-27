# ================================
# scripts/docker-build.sh
#!/bin/bash

# Docker 이미지 빌드 스크립트

set -e

# 변수 설정
IMAGE_NAME="kisa-network-analyzer"
TAG=${1:-latest}
REGISTRY=${REGISTRY:-""}

echo "Building Docker image: ${IMAGE_NAME}:${TAG}"

# 이미지 빌드
docker build -t ${IMAGE_NAME}:${TAG} .

# 레지스트리가 설정된 경우 태그 추가
if [ ! -z "$REGISTRY" ]; then
    echo "Tagging for registry: ${REGISTRY}/${IMAGE_NAME}:${TAG}"
    docker tag ${IMAGE_NAME}:${TAG} ${REGISTRY}/${IMAGE_NAME}:${TAG}
fi

echo "Build completed successfully!"

# 이미지 크기 확인
echo "Image size:"
docker images ${IMAGE_NAME}:${TAG}