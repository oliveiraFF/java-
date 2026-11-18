"""大模型改写实验（任务书研究内容 3：鲁棒性研究）。

用 DeepSeek 把邮件改写成"语气自然、像真人写的"版本，保持原意、请求和链接不变，
检验检测模型在大模型改写的钓鱼邮件上性能下降多少，并用改写样本做增强训练。

数据：只使用公开数据集与虚构样本（英文 Nazario/Nigerian/正常邮件、中文模板与手写测试集），
**不发送任何真实邮箱内容**。密钥从项目根目录 .env 的 DEEPSEEK_API_KEY 读取（.env 不入库）。
结果缓存在 ml/data/llm/rewrites.jsonl，重复运行不会重复调用 API。

用法（仓库根目录）：
    python ml/scripts/llm_rewrite.py --plan     # 只打印将要改写的样本数量
    python ml/scripts/llm_rewrite.py            # 执行改写
"""
from __future__ import annotations

import argparse
import json
import re
import threading
import time
import urllib.error
import urllib.request
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path

import pandas as pd

API = "https://api.deepseek.com/chat/completions"
MODEL = "deepseek-chat"
OUT = Path("ml/data/llm/rewrites.jsonl")
SEED = 2026
MAX_IN = 1800

SYS_ZH = ("你是一名邮件写作助手。请把用户给出的邮件改写得更自然、流畅、像真人写的："
          "保持原来的意思、请求、金额、期限和链接不变；不要添加任何提醒、警告或说明；"
          "不要使用模板化的说法。只输出改写后的邮件，格式为：\n主题：……\n正文：……")
SYS_EN = ("You are an email writing assistant. Rewrite the user's email so it reads naturally, fluently and like a "
          "real person wrote it. Keep the original meaning, requests, amounts, deadlines and links unchanged. Do not "
          "add any notes, warnings or explanations. Output only the rewritten email in this format:\n"
          "Subject: ...\nBody: ...")
REFUSAL = re.compile(r"(抱歉|无法(协助|帮助|完成)|不能(协助|帮助)|I can't|I cannot|I'm sorry|I am sorry|not able to help)", re.I)
CJK = re.compile(r"[一-鿿]")


def load_key() -> str:
    for line in Path(".env").read_text(encoding="utf-8").splitlines():
        if line.startswith("DEEPSEEK_API_KEY="):
            return line.split("=", 1)[1].strip()
    raise SystemExit("未在 .env 中找到 DEEPSEEK_API_KEY")


def build_plan() -> pd.DataFrame:
    """选出要改写的样本。test 组只用于评估；train 组用于增强训练。两组都同时包含钓鱼和正常邮件。"""
    en = pd.read_csv("ml/data/processed/emails.csv", dtype=str, keep_default_na=False)
    mixed = pd.read_csv("ml/data/processed/emails_mixed2.csv", dtype=str, keep_default_na=False)
    hw = pd.read_csv("ml/testsets/zh_handwritten.csv", dtype=str, keep_default_na=False)
    parts = []

    def take(df, n, group, label):
        d = df.sample(n=min(n, len(df)), random_state=SEED).copy()
        d["group"], d["y"] = group, label
        parts.append(d[["id", "subject", "body", "group", "y"]])

    # 评估组
    take(en[(en.split == "test") & (en.source == "nazario")], 200, "test_en_phish", 1)
    take(en[(en.split == "test") & (en.kind == "ham") & (en.source.isin(["ceas", "spamassassin", "enron"]))], 100, "test_en_ham", 0)
    take(hw[hw.label == "1"], 20, "test_zh_phish", 1)
    take(hw[hw.label == "0"], 20, "test_zh_ham", 0)
    # 增强训练组（来自训练划分，与评估组不重叠）
    take(mixed[(mixed.split == "train") & (mixed.kind.isin(["phishing", "fraud"])) & (mixed.source.isin(["nazario", "nigerian"]))], 300, "train_en_phish", 1)
    take(mixed[(mixed.split == "train") & (mixed.source == "synth_zh")], 200, "train_zh_phish", 1)
    take(mixed[(mixed.split == "train") & (mixed.kind == "ham") & (mixed.source.isin(["ceas", "spamassassin", "enron", "trec06c", "synth_notice"]))], 300, "train_ham", 0)
    return pd.concat(parts, ignore_index=True)


def call(key: str, subject: str, body: str) -> tuple[str, dict]:
    zh = bool(CJK.search(subject + body[:500]))
    content = (f"主题：{subject}\n正文：{body[:MAX_IN]}" if zh else f"Subject: {subject}\nBody: {body[:MAX_IN]}")
    payload = {"model": MODEL, "temperature": 0.8, "max_tokens": 900,
               "messages": [{"role": "system", "content": SYS_ZH if zh else SYS_EN}, {"role": "user", "content": content}]}
    req = urllib.request.Request(API, method="POST", data=json.dumps(payload).encode(),
                                 headers={"Content-Type": "application/json", "Authorization": f"Bearer {key}"})
    for attempt in range(4):
        try:
            r = json.loads(urllib.request.urlopen(req, timeout=120).read())
            return r["choices"][0]["message"]["content"], r.get("usage", {})
        except (urllib.error.URLError, TimeoutError, ConnectionError) as exc:
            if attempt == 3:
                raise
            time.sleep(3 * (attempt + 1))
            last = exc  # noqa: F841
    raise RuntimeError("unreachable")


def parse(text: str) -> tuple[str, str]:
    m = re.search(r"(?:主题|Subject)\s*[:：]\s*(.*)", text)
    b = re.search(r"(?:正文|Body)\s*[:：]\s*([\s\S]*)", text)
    subject = m.group(1).strip() if m else ""
    body = b.group(1).strip() if b else text.strip()
    return subject, body


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--plan", action="store_true")
    ap.add_argument("--workers", type=int, default=6)
    args = ap.parse_args()
    plan = build_plan()
    print(plan.groupby("group").size().to_dict(), "合计", len(plan))
    if args.plan:
        return

    OUT.parent.mkdir(parents=True, exist_ok=True)
    done = set()
    if OUT.exists():
        done = {json.loads(l)["id"] for l in OUT.read_text(encoding="utf-8").splitlines() if l.strip()}
    todo = plan[~plan["id"].isin(done)]
    print(f"已缓存 {len(done)}，本次需调用 {len(todo)} 次")
    key = load_key()
    lock = threading.Lock()
    tokens = {"prompt": 0, "completion": 0}
    stats = {"ok": 0, "refused": 0, "error": 0}

    def work(row):
        try:
            text, usage = call(key, row.subject, row.body)
        except Exception as exc:  # noqa: BLE001
            return {"id": row.id, "status": "error", "error": type(exc).__name__}, {}
        status = "refused" if REFUSAL.search(text[:120]) else "ok"
        s, b = parse(text)
        return {"id": row.id, "group": row.group, "y": int(row.y), "status": status, "subject": s, "body": b}, usage

    with ThreadPoolExecutor(max_workers=args.workers) as pool, OUT.open("a", encoding="utf-8") as f:
        futs = [pool.submit(work, row) for row in todo.itertuples()]
        for i, fut in enumerate(as_completed(futs), 1):
            rec, usage = fut.result()
            with lock:
                if rec["status"] != "error":
                    f.write(json.dumps(rec, ensure_ascii=False) + "\n")
                    f.flush()
                stats[rec["status"]] += 1
                tokens["prompt"] += usage.get("prompt_tokens", 0)
                tokens["completion"] += usage.get("completion_tokens", 0)
            if i % 50 == 0:
                print(f"  {i}/{len(todo)} {stats} tokens={tokens}", flush=True)
    print("完成", stats, "tokens", tokens)


if __name__ == "__main__":
    main()
