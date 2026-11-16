"""用已训练好的 DistilBERT 给指定数据子集打分，输出 id,score 的 CSV。

用法（仓库根目录）：
    ml/.venv/Scripts/python ml/scripts/predict_distilbert.py \
        --model-dir ml/artifacts/distilbert_unseen_nazario --split val --exclude-source nazario \
        --out ml/artifacts/scores/distilbert_unseen_nazario_val.csv
"""
from __future__ import annotations

import argparse
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

import pandas as pd  # noqa: E402
import torch  # noqa: E402
from transformers import AutoModelForSequenceClassification, AutoTokenizer  # noqa: E402

from common import load_emails  # noqa: E402
from train_distilbert import make_loader, predict  # noqa: E402


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--model-dir", required=True)
    ap.add_argument("--split", default="val", choices=["train", "val", "test"])
    ap.add_argument("--exclude-source", default=None)
    ap.add_argument("--max-len", type=int, default=256)
    ap.add_argument("--out", required=True)
    args = ap.parse_args()

    device = torch.device("cuda" if torch.cuda.is_available() else "cpu")
    df = load_emails()
    df = df[df["split"] == args.split]
    if args.exclude_source:
        df = df[df["source"] != args.exclude_source]
    df = df.reset_index(drop=True)

    tok = AutoTokenizer.from_pretrained(args.model_dir)
    model = AutoModelForSequenceClassification.from_pretrained(args.model_dir).to(device)
    scores = predict(model, make_loader(df, tok, args.max_len, 64, shuffle=False), device)
    Path(args.out).parent.mkdir(parents=True, exist_ok=True)
    pd.DataFrame({"id": df["id"], "score": scores}).to_csv(args.out, index=False)
    print(f"已为 {len(df)} 封邮件打分：{args.out}")


if __name__ == "__main__":
    main()
