"""导入 TREC 2006 中文垃圾邮件语料（trec06c）。

输入：ml/data/raw/ 下的 trec06c 压缩包（.tgz / .tar.gz / .zip）或解压后的 trec06c/ 目录。
     语料结构：data/xxx/yyy 为邮件原文，full/index 为标签（每行 "spam ../data/000/000"）。
输出：ml/data/processed/zh_trec06c.csv（列与 emails.csv 一致，kind 为 ham / spam）。

要点：
- 邮件大多是 GB2312/GBK，部分没有声明字符集。先按邮件声明解码，乱码过多时整体改用 GB18030。
- trec06c 的 spam 主要是中文广告。在"钓鱼 vs 非钓鱼"的目标下它是负样本，
  正好教模型"中文营销邮件不是钓鱼"，针对真实邮箱中的误报问题。
- 先去重再按 kind 分层划分 70/10/20，与英文数据的做法一致。

用法（仓库根目录）：python ml/scripts/prepare_trec06c.py [--src 路径]
"""
from __future__ import annotations

import argparse
import hashlib
import re
import sys
import tarfile
import zipfile
from email.header import decode_header, make_header
from pathlib import Path

import numpy as np
import pandas as pd

from phishguard_detector import parse_bytes

SEED = 42
MAX_BODY = 20_000
RAW = Path("ml/data/raw")
_CJK = re.compile(r"[一-鿿]")


def find_source(explicit: str | None) -> Path:
    if explicit:
        return Path(explicit)
    cands = sorted(p for p in RAW.glob("*trec06c*") if p.is_dir() or p.suffix in (".tgz", ".gz", ".zip"))
    if not cands:
        sys.exit("没有在 ml/data/raw/ 下找到 trec06c 压缩包或目录，请用 --src 指定路径")
    return cands[0]


def extract(src: Path) -> Path:
    """返回包含 full/index 的语料根目录；压缩包解压到 ml/data/raw/trec06c_extracted/。"""
    if src.is_dir():
        root = src
    else:
        out = RAW / "trec06c_extracted"
        if not out.exists():
            print(f"解压 {src.name} ...")
            out.mkdir(parents=True)
            if src.suffix == ".zip":
                with zipfile.ZipFile(src) as z:
                    for m in z.infolist():  # 防止压缩包内的路径跳出目标目录
                        if ".." in Path(m.filename).parts or Path(m.filename).is_absolute():
                            sys.exit(f"压缩包中有不安全的路径：{m.filename}")
                    z.extractall(out)
            else:
                with tarfile.open(src) as t:
                    t.extractall(out, filter="data")
        root = out
    idx = next(root.rglob("full/index"), None)
    if idx is None:
        sys.exit(f"在 {root} 中找不到 full/index 标签文件")
    return idx.parent.parent


def garbled(s: str) -> bool:
    if not s:
        return False
    bad = s.count("�") + len(re.findall(r"[\x80-\xff]", s))
    return bad / max(1, len(s)) > 0.02


def decode_subject(raw_header: bytes) -> str:
    m = re.search(rb"^Subject:(.*(?:\r?\n[ \t].*)*)", raw_header, re.I | re.M)
    if not m:
        return ""
    v = m.group(1).strip()
    try:
        s = str(make_header(decode_header(v.decode("ascii"))))
    except (UnicodeDecodeError, LookupError, ValueError):
        s = v.decode("gb18030", errors="replace")
    return s.strip()


def read_email(path: Path) -> tuple[str, str, str]:
    raw = path.read_bytes()
    pe = parse_bytes(raw)
    subject, body, sender = pe.subject, pe.text, pe.from_addr
    if garbled(body) or not _CJK.search(body + subject):
        # 未声明字符集的 GBK 邮件：整体按 GB18030 重新解码
        sep = re.search(rb"\r?\n\r?\n", raw)
        head, rest = (raw[:sep.start()], raw[sep.end():]) if sep else (raw, b"")
        body = rest.decode("gb18030", errors="replace")
        subject = decode_subject(head) if garbled(subject) or not subject else subject
    return subject, body, sender


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--src")
    ap.add_argument("--out", default="ml/data/processed/zh_trec06c.csv")
    args = ap.parse_args()
    root = extract(find_source(args.src))
    lines = (root / "full" / "index").read_text(encoding="ascii", errors="ignore").split()
    pairs = list(zip(lines[0::2], lines[1::2]))
    print(f"语料根目录 {root}，标签 {len(pairs)} 条")

    rows, skipped = [], 0
    for i, (lab, rel) in enumerate(pairs):
        p = (root / "full" / rel).resolve()
        if not p.is_file() or root.resolve() not in p.parents:
            skipped += 1
            continue
        try:
            subject, body, sender = read_email(p)
        except Exception:  # noqa: BLE001 - 个别损坏邮件跳过
            skipped += 1
            continue
        rows.append({"subject": subject.strip(), "body": body[:MAX_BODY], "sender": sender,
                     "kind": "spam" if lab.lower() == "spam" else "ham"})
        if (i + 1) % 10000 == 0:
            print(f"  已读取 {i + 1}")
    df = pd.DataFrame(rows)
    stats = {"index": len(pairs), "read": len(df), "skipped": skipped}

    df = df[(df["subject"].str.len() + df["body"].str.len()) >= 20]
    df["garbled"] = [garbled(s + b) for s, b in zip(df["subject"], df["body"])]
    stats["garbled_dropped"] = int(df["garbled"].sum())
    df = df[~df["garbled"]].drop(columns="garbled")
    key = df["subject"].str.strip() + "\n" + df["body"].str.split().str.join(" ")
    df["h"] = [hashlib.sha1(k.encode("utf-8")).hexdigest() for k in key]
    before = len(df)
    df = df.drop_duplicates("h")
    stats["duplicates_dropped"] = before - len(df)

    rng = np.random.default_rng(SEED)
    df["split"] = ""
    for _, idx in df.groupby("kind").groups.items():
        idx = np.array(list(idx))
        rng.shuffle(idx)
        n = len(idx)
        a, b = int(round(n * 0.7)), int(round(n * 0.8))
        df.loc[idx[:a], "split"], df.loc[idx[a:b], "split"], df.loc[idx[b:], "split"] = "train", "val", "test"
    df = df.reset_index(drop=True)
    df.insert(0, "id", [f"zt{i:06d}" for i in range(len(df))])
    df["source"], df["has_header"], df["date"], df["n_urls"] = "trec06c", True, "", 0
    df["label"] = (df["kind"] == "spam").astype(int)  # 原始定义：恶意（含垃圾）= 1
    cols = ["id", "source", "kind", "label", "split", "has_header", "sender", "date", "n_urls", "subject", "body"]
    Path(args.out).parent.mkdir(parents=True, exist_ok=True)
    df[cols].to_csv(args.out, index=False, encoding="utf-8")
    stats["final"] = len(df)
    stats["by_kind"] = df["kind"].value_counts().to_dict()
    print(stats)
    print(f"已写入 {args.out}")


if __name__ == "__main__":
    main()
