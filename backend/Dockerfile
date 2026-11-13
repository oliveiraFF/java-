# 构建上下文：仓库根目录（需要同时拷贝 backend 与 detector）
FROM python:3.11-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1

WORKDIR /app

COPY backend/requirements.txt backend/requirements-dev.txt backend/
RUN pip install -r backend/requirements-dev.txt

COPY detector detector
RUN pip install ./detector

COPY backend backend

RUN useradd --create-home --uid 1000 app \
    && mkdir -p /data/rawmail \
    && chown -R app:app /data /app
USER app

WORKDIR /app/backend
EXPOSE 8000
