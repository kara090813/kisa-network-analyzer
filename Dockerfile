# Dockerfile
FROM python:3.9-slim

# 작업 디렉토리 설정
WORKDIR /app

# 시스템 패키지 업데이트 및 필요한 패키지 설치
RUN apt-get update && \
    apt-get install -y --no-install-recommends \
    gcc \
    && rm -rf /var/lib/apt/lists/*

# Python 의존성 파일 복사 및 설치
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# 애플리케이션 소스 복사
COPY . .

# 로그 디렉토리 생성
RUN mkdir -p logs

# 비root 유저 생성 및 권한 설정
RUN useradd -r -s /bin/false appuser && \
    chown -R appuser:appuser /app
USER appuser

# 포트 노출
EXPOSE 5000

# 환경변수 설정
ENV FLASK_APP=main.py
ENV FLASK_ENV=production
ENV PYTHONPATH=/app

# Health check
HEALTHCHECK --interval=30s --timeout=30s --start-period=5s --retries=3 \
  CMD curl -f http://localhost:5000/api/v1/health || exit 1

# 애플리케이션 실행
CMD ["sh", "-c", "gunicorn --bind 0.0.0.0:$PORT --workers 4 --timeout 300 main:app"]

