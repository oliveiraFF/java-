# PhishGuard · 基于语义表征的钓鱼邮件检测方法研究与系统实现

毕业设计项目，同时按商业 MVP 的标准开发。设计文档见 [docs/开发文档.md](docs/开发文档.md)。

## 目录

| 目录 | 内容 |
|---|---|
| `backend/` | FastAPI 接口、Celery 任务、数据库模型与迁移 |
| `detector/` | 检测引擎（独立 Python 包）：邮件解析、规则、模型、融合打分 |
| `frontend/` | Vue 3 工作台，生产环境由 Nginx 托管并反向代理 `/api` |
| `ml/` | 数据清洗、训练与实验脚本；`ml/data/`、`ml/artifacts/` 不入库 |
| `docs/` | 开发文档、任务书 |

## 启动

```bash
cp .env.example .env      # 修改其中的密码和密钥
docker compose up -d --build
```

打开 http://localhost:8080 查看服务状态。管理员账号和初始密码在 `.env` 的 `ADMIN_USERNAME` / `ADMIN_PASSWORD`。

## 数据与训练

原始数据放在 `ml/data/raw/`（Kaggle Phishing Email Dataset 的 6 个子集 CSV），然后：

```bash
docker compose --profile ml run --rm ml python -I ml/scripts/prepare_data.py
```

输出 `ml/data/processed/emails.csv`（含 `kind`：phishing / fraud / spam / ham，以及 `split`：train / val / test）和 `stats.json`。

## 测试

```bash
docker compose run --rm --no-deps api pytest -q
docker compose run --rm --no-deps api sh -c "cd /app/detector && pytest -q tests"
```
