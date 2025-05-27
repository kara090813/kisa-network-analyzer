# ================================
# scripts/docker-deploy.sh
#!/bin/bash

# Docker 배포 스크립트

set -e

# 변수 설정
IMAGE_NAME="kisa-network-analyzer"
TAG=${1:-latest}
REGISTRY=${REGISTRY:-""}
ENVIRONMENT=${2:-production}

echo "Deploying ${IMAGE_NAME}:${TAG} to ${ENVIRONMENT}"

# 환경별 설정
case $ENVIRONMENT in
    "production")
        COMPOSE_FILE="docker-compose.yml"
        ;;
    "development")
        COMPOSE_FILE="docker-compose.dev.yml"
        ;;
    *)
        echo "Unknown environment: $ENVIRONMENT"
        exit 1
        ;;
esac

# 이미지 빌드
./scripts/docker-build.sh $TAG

# 레지스트리에 푸시 (설정된 경우)
if [ ! -z "$REGISTRY" ]; then
    echo "Pushing to registry..."
    docker push ${REGISTRY}/${IMAGE_NAME}:${TAG}
fi

# Docker Compose로 배포
echo "Deploying with docker-compose..."
docker-compose -f $COMPOSE_FILE down
docker-compose -f $COMPOSE_FILE up -d

echo "Deployment completed!"

# 서비스 상태 확인
echo "Checking service health..."
sleep 10
curl -f http://localhost:5000/api/v1/health || echo "Health check failed"