"""合并中英文数据，生成混合训练集。

组成：
- 英文公开数据（emails.csv）：ham / spam / phishing / fraud
- trec06c 中文语料（zh_trec06c.csv）：ham / spam
- 中文钓鱼模板合成（synth/zh_phish.csv）：phishing
- （--with-notices）现代通知类正常邮件合成（synth/notice_ham.csv）：ham，实验 7

"钓鱼 vs 非钓鱼"目标下：phishing、fraud 为正样本；ham、spam 为负样本。
不包含任何真实邮箱数据；真实邮箱和手写测试集只用于评估。

用法（仓库根目录）：
    python ml/scripts/build_mixed.py                                   # → emails_mixed.csv（实验 6）
    python ml/scripts/build_mixed.py --with-notices --out emails_mixed2.csv   # 实验 7
"""
from __future__ import annotations

import argparse
import sys
from pathlib import Path

import pandas as pd

P = Path("ml/data/processed")
S = Path("ml/data/synth")
COLS = ["id", "source", "kind", "label", "split", "has_header", "sender", "date", "n_urls", "subject", "body"]


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--with-notices", action="store_true", help="加入现代通知类正常邮件合成样本")
    ap.add_argument("--out", default="emails_mixed.csv")
    args = ap.parse_args()
    sources = [P / "emails.csv", P / "zh_trec06c.csv", S / "zh_phish.csv"]
    if args.with_notices:
        sources.append(S / "notice_ham.csv")
    parts = []
    for path in sources:
        if not path.exists():
            sys.exit(f"缺少 {path}，请先运行对应的准备脚本")
        df = pd.read_csv(path, dtype=str, keep_default_na=False)
        for c in COLS:
            if c not in df.columns:
                df[c] = ""
        parts.append(df[COLS])
        print(f"{path.name:<20} {len(df):>7} 封  {df['kind'].value_counts().to_dict()}")
    mixed = pd.concat(parts, ignore_index=True)
    mixed.to_csv(P / args.out, index=False, encoding="utf-8")
    print(f"合计 {len(mixed)} 封 → {P / args.out}")
    print(mixed.groupby(["split", "kind"]).size().unstack(fill_value=0))


if __name__ == "__main__":
    main()
