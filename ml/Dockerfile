# 训练与实验环境（不进生产）。构建上下文：仓库根目录。
FROM python:3.11-slim
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1 PIP_NO_CACHE_DIR=1 PIP_DISABLE_PIP_VERSION_CHECK=1
WORKDIR /work
COPY ml/requirements.txt /tmp/ml-requirements.txt
RUN pip install -r /tmp/ml-requirements.txt
COPY detector /opt/detector
RUN pip install /opt/detector
