"""公开数据集清洗与划分。

输入：ml/data/raw/ 下 Kaggle "Phishing Email Dataset" 的 6 个子集 CSV
输出：ml/data/processed/emails.csv 和 stats.json

要点：
- 不用合并版 phishing_email.csv：它只有一列文本，丢失了发件人、URL 等结构字段，
  且与 6 个子集重复。
- 原始标签 1 混合了垃圾邮件、诈骗邮件和钓鱼邮件，这里用 kind 列区分：
  Nazario → phishing，Nigerian_Fraud → fraud，其余子集的 1 → spam，0 → ham。
- 先去重再划分，避免同一封邮件同时出现在训练集和测试集（数据泄露）。
- 同一文本在不同来源中标签冲突时整组丢弃。

用法（仓库根目录）：
    docker compose --profile ml run --rm ml python -I ml/scripts/prepare_data.py
"""
from __future__ import annotations

import argparse
import hashlib
import json
import sys
from pathlib import Path

import numpy as np
import pandas as pd

from phishguard_detector import parse_text

SOURCES = {
    "CEAS_08.csv": "ceas",
    "Enron.csv": "enron",
    "Ling.csv": "ling",
    "Nazario.csv": "nazario",
    "Nigerian_Fraud.csv": "nigerian",
    "SpamAssasin.csv": "spamassassin",
}
POSITIVE_KIND = {"nazario": "phishing", "nigerian": "fraud"}
MAX_BODY = 20_000
MIN_CHARS = 20
SPLIT = (0.7, 0.1, 0.2)
SEED = 42


def load(raw_dir: Path) -> pd.DataFrame:
    frames = []
    for fname, source in SOURCES.items():
        p = raw_dir / fname
        if not p.exists():
            sys.exit(f"缺少数据文件：{p}")
        # C 引擎：支持带引号的多行字段，且没有 python 引擎 128KB 的单字段上限
        df = pd.read_csv(p, dtype=str, keep_default_na=False, encoding="utf-8", encoding_errors="replace", engine="c", on_bad_lines="warn")
        for col in ("sender", "receiver", "date", "subject", "body", "urls", "label"):
            if col not in df.columns:
                df[col] = ""
        df = df[["sender", "date", "subject", "body", "label"]].copy()
        df["source"] = source
        df["has_header"] = source not in ("enron", "ling")
        frames.append(df)
        print(f"  读取 {fname:<20} {len(df):>7} 行")
    return pd.concat(frames, ignore_index=True)


def clean(df: pd.DataFrame) -> tuple[pd.DataFrame, dict]:
    stats: dict = {"raw_rows": int(len(df))}

    df = df[df["label"].isin(["0", "1"])].copy()
    df["label"] = df["label"].astype(int)
    stats["after_valid_label"] = int(len(df))

    parsed = [parse_text(s, b[:MAX_BODY * 2], snd) for s, b, snd in zip(df["subject"], df["body"], df["sender"])]
    df["subject"] = [p.subject for p in parsed]
    df["body"] = [p.text[:MAX_BODY] for p in parsed]
    df["sender"] = [p.from_addr for p in parsed]
    df["n_urls"] = [len(p.urls) for p in parsed]

    df = df[(df["subject"].str.len() + df["body"].str.len()) >= MIN_CHARS]
    stats["after_min_length"] = int(len(df))

    key = (df["subject"].str.lower().str.strip() + "\n" + df["body"].str.lower().str.split().str.join(" "))
    df["text_hash"] = [hashlib.sha1(k.encode("utf-8")).hexdigest() for k in key]

    label_per_hash = df.groupby("text_hash")["label"].nunique()
    conflict = set(label_per_hash[label_per_hash > 1].index)
    stats["conflicting_label_rows_dropped"] = int(df["text_hash"].isin(conflict).sum())
    df = df[~df["text_hash"].isin(conflict)]

    before = len(df)
    df = df.drop_duplicates("text_hash", keep="first")
    stats["duplicate_rows_dropped"] = int(before - len(df))
    stats["final_rows"] = int(len(df))

    df["kind"] = np.where(df["label"] == 0, "ham", df["source"].map(POSITIVE_KIND).fillna("spam"))
    return df, stats


def split(df: pd.DataFrame) -> pd.DataFrame:
    rng = np.random.default_rng(SEED)
    df = df.copy()
    df["split"] = ""
    for _, idx in df.groupby(["source", "label"]).groups.items():
        idx = np.array(list(idx))
        rng.shuffle(idx)
        n = len(idx)
        n_train, n_val = int(round(n * SPLIT[0])), int(round(n * SPLIT[1]))
        df.loc[idx[:n_train], "split"] = "train"
        df.loc[idx[n_train:n_train + n_val], "split"] = "val"
        df.loc[idx[n_train + n_val:], "split"] = "test"
    return df


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--raw", default="ml/data/raw")
    ap.add_argument("--out", default="ml/data/processed")
    args = ap.parse_args()
    raw_dir, out_dir = Path(args.raw), Path(args.out)
    out_dir.mkdir(parents=True, exist_ok=True)

    print("[1/3] 读取原始数据")
    df = load(raw_dir)
    print("[2/3] 清洗与去重")
    df, stats = clean(df)
    print("[3/3] 划分训练/验证/测试集")
    df = split(df)

    df = df.reset_index(drop=True)
    df.insert(0, "id", [f"e{i:06d}" for i in range(len(df))])
    cols = ["id", "source", "kind", "label", "split", "has_header", "sender", "date", "n_urls", "subject", "body"]
    df[cols].to_csv(out_dir / "emails.csv", index=False, encoding="utf-8")

    stats["by_split_label"] = {f"{s}/{l}": int(n) for (s, l), n in df.groupby(["split", "label"]).size().items()}
    stats["by_source_kind"] = {f"{s}/{k}": int(n) for (s, k), n in df.groupby(["source", "kind"]).size().items()}
    stats["by_kind"] = {k: int(n) for k, n in df["kind"].value_counts().items()}
    (out_dir / "stats.json").write_text(json.dumps(stats, ensure_ascii=False, indent=2), encoding="utf-8")
    print(json.dumps(stats, ensure_ascii=False, indent=2))
    print(f"已写入 {out_dir / 'emails.csv'}")


if __name__ == "__main__":
    main()
