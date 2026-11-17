"""合并中英文数据，生成混合训练集 ml/data/processed/emails_mixed.csv。

组成：
- 英文公开数据（emails.csv）：ham / spam / phishing / fraud
- trec06c 中文语料（zh_trec06c.csv）：ham / spam
- 中文钓鱼模板合成（synth/zh_phish.csv）：phishing

"钓鱼 vs 非钓鱼"目标下：phishing、fraud 为正样本；ham、spam 为负样本。
不包含任何真实邮箱数据；真实邮箱和手写测试集只用于评估。

用法（仓库根目录）：python ml/scripts/build_mixed.py
"""
from __future__ import annotations

import sys
from pathlib import Path

import pandas as pd

P = Path("ml/data/processed")
COLS = ["id", "source", "kind", "label", "split", "has_header", "sender", "date", "n_urls", "subject", "body"]


def main() -> None:
    parts = []
    for path, need in ((P / "emails.csv", True), (P / "zh_trec06c.csv", True), (Path("ml/data/synth/zh_phish.csv"), True)):
        if not path.exists():
            if need:
                sys.exit(f"缺少 {path}，请先运行对应的准备脚本")
            continue
        df = pd.read_csv(path, dtype=str, keep_default_na=False)
        for c in COLS:
            if c not in df.columns:
                df[c] = ""
        parts.append(df[COLS])
        print(f"{path.name:<20} {len(df):>7} 封  {df['kind'].value_counts().to_dict()}")
    mixed = pd.concat(parts, ignore_index=True)
    mixed.to_csv(P / "emails_mixed.csv", index=False, encoding="utf-8")
    print(f"合计 {len(mixed)} 封 → {P / 'emails_mixed.csv'}")
    print(mixed.groupby(["split", "kind"]).size().unstack(fill_value=0))


if __name__ == "__main__":
    main()
