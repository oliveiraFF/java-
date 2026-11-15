"""DistilBERT 语义表征模型微调与评估。

与 train_baseline.py 使用同一份数据划分和同一套指标（common.py），结果可直接对比。

用法（仓库根目录，使用 ml/.venv）：
    ml/.venv/Scripts/python ml/scripts/train_distilbert.py                 # 标准划分
    ml/.venv/Scripts/python ml/scripts/train_distilbert.py --holdout enron # 留一来源
    ml/.venv/Scripts/python ml/scripts/train_distilbert.py --limit 2000    # 小样本冒烟测试
"""
from __future__ import annotations

import argparse
import math
import random
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

import numpy as np  # noqa: E402
import torch  # noqa: E402
from torch.utils.data import DataLoader  # noqa: E402
from transformers import AutoModelForSequenceClassification, AutoTokenizer, get_linear_schedule_with_warmup  # noqa: E402

from common import SEED, TARGET_FPR, fmt, load_emails, metrics, model_input, save_json, threshold_at_fpr  # noqa: E402

PRE_TRUNCATE_CHARS = 4000  # 分词前先截断字符，加速；256 token 远用不到这么多字符


def set_seed(seed: int) -> None:
    random.seed(seed)
    np.random.seed(seed)
    torch.manual_seed(seed)
    torch.cuda.manual_seed_all(seed)


class Collator:
    def __init__(self, tok, max_len: int):
        self.tok, self.max_len = tok, max_len

    def __call__(self, batch):
        texts, labels = zip(*batch)
        enc = self.tok(list(texts), truncation=True, max_length=self.max_len, padding=True, return_tensors="pt")
        enc["labels"] = torch.tensor(labels, dtype=torch.long)
        return enc


def make_loader(df, tok, max_len, bs, shuffle):
    texts = model_input(df, PRE_TRUNCATE_CHARS).tolist()
    data = list(zip(texts, df["label"].astype(int).tolist()))
    return DataLoader(data, batch_size=bs, shuffle=shuffle, collate_fn=Collator(tok, max_len), num_workers=0)


@torch.no_grad()
def predict(model, loader, device) -> np.ndarray:
    model.eval()
    out = []
    for batch in loader:
        batch = {k: v.to(device, non_blocking=True) for k, v in batch.items() if k != "labels"}
        with torch.autocast(device_type=device.type, dtype=torch.float16, enabled=device.type == "cuda"):
            logits = model(**batch).logits
        out.append(torch.softmax(logits.float(), dim=-1)[:, 1].cpu().numpy())
    return np.concatenate(out) if out else np.array([])


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--model", default="distilbert-base-multilingual-cased")
    ap.add_argument("--max-len", type=int, default=256)
    ap.add_argument("--epochs", type=int, default=2)
    ap.add_argument("--bs", type=int, default=16)
    ap.add_argument("--eval-bs", type=int, default=64)
    ap.add_argument("--lr", type=float, default=3e-5)
    ap.add_argument("--warmup", type=float, default=0.06)
    ap.add_argument("--holdout", default=None, help="留一来源实验：训练时排除该来源，并在该来源全部邮件上测试")
    ap.add_argument("--limit", type=int, default=0, help="只用前 N 条训练数据（冒烟测试）")
    ap.add_argument("--tag", default=None)
    args = ap.parse_args()

    set_seed(SEED)
    device = torch.device("cuda" if torch.cuda.is_available() else "cpu")
    tag = args.tag or ("standard" if not args.holdout else f"loso_{args.holdout}") + (f"_limit{args.limit}" if args.limit else "")
    print(f"设备 {device}{' · ' + torch.cuda.get_device_name(0) if device.type == 'cuda' else ''}，实验 {tag}")

    df = load_emails()
    tr, va, te = (df[df["split"] == s] for s in ("train", "val", "test"))
    if args.holdout:
        tr, va = tr[tr["source"] != args.holdout], va[va["source"] != args.holdout]
        te = df[df["source"] == args.holdout]
    if args.limit:
        tr = tr.sample(n=min(args.limit, len(tr)), random_state=SEED)
        va = va.sample(n=min(max(args.limit // 5, 200), len(va)), random_state=SEED)
        te = te.sample(n=min(max(args.limit // 2, 500), len(te)), random_state=SEED)
    tr, va, te = (x.reset_index(drop=True) for x in (tr, va, te))
    print(f"训练 {len(tr)} / 验证 {len(va)} / 测试 {len(te)}")

    tok = AutoTokenizer.from_pretrained(args.model)
    model = AutoModelForSequenceClassification.from_pretrained(args.model, num_labels=2).to(device)

    train_loader = make_loader(tr, tok, args.max_len, args.bs, shuffle=True)
    val_loader = make_loader(va, tok, args.max_len, args.eval_bs, shuffle=False)
    test_loader = make_loader(te, tok, args.max_len, args.eval_bs, shuffle=False)

    optim = torch.optim.AdamW(model.parameters(), lr=args.lr, weight_decay=0.01)
    total = len(train_loader) * args.epochs
    sched = get_linear_schedule_with_warmup(optim, int(total * args.warmup), total)
    scaler = torch.amp.GradScaler("cuda", enabled=device.type == "cuda")

    out_dir = Path("ml/artifacts") / f"distilbert_{tag}"
    best_f1, history = -1.0, []
    t_train = time.perf_counter()
    step = 0
    for epoch in range(1, args.epochs + 1):
        model.train()
        t_ep, running = time.perf_counter(), 0.0
        for batch in train_loader:
            batch = {k: v.to(device, non_blocking=True) for k, v in batch.items()}
            with torch.autocast(device_type=device.type, dtype=torch.float16, enabled=device.type == "cuda"):
                loss = model(**batch).loss
            optim.zero_grad(set_to_none=True)
            scaler.scale(loss).backward()
            scaler.unscale_(optim)
            torch.nn.utils.clip_grad_norm_(model.parameters(), 1.0)
            scaler.step(optim)
            scaler.update()
            sched.step()
            step += 1
            running += loss.item()
            if step % 200 == 0:
                done = step / total
                eta = (time.perf_counter() - t_train) / done * (1 - done)
                print(f"  epoch {epoch} step {step}/{total} loss {running / 200:.4f} 剩余约 {eta / 60:.1f} 分钟", flush=True)
                running = 0.0
        sv = predict(model, val_loader, device)
        mv = metrics(va["label"].to_numpy(), sv, 0.5)
        history.append({"epoch": epoch, "val": mv, "seconds": round(time.perf_counter() - t_ep, 1)})
        print(f"epoch {epoch} 验证集 F1={mv['f1']:.4f} AUC={fmt(mv['roc_auc'])} 用时 {history[-1]['seconds']}s")
        if mv["f1"] > best_f1:
            best_f1 = mv["f1"]
            out_dir.mkdir(parents=True, exist_ok=True)
            model.save_pretrained(out_dir)
            tok.save_pretrained(out_dir)
    train_seconds = time.perf_counter() - t_train

    # 用最佳 checkpoint 评估
    model = AutoModelForSequenceClassification.from_pretrained(out_dir).to(device)
    sv = predict(model, val_loader, device)
    t = time.perf_counter()
    st = predict(model, test_loader, device)
    infer_ms = (time.perf_counter() - t) / max(len(te), 1) * 1000
    yte = te["label"].to_numpy()
    thr_low = threshold_at_fpr(va["label"].to_numpy(), sv, TARGET_FPR)

    res = {
        "tag": tag, "model": args.model, "max_len": args.max_len, "epochs": args.epochs, "bs": args.bs, "lr": args.lr,
        "holdout": args.holdout, "data": {"train": len(tr), "val": len(va), "test": len(te)},
        "train_seconds": round(train_seconds, 1), "infer_ms_per_email": round(infer_ms, 3),
        "history": history,
        "test": metrics(yte, st, 0.5),
        "val_threshold_fpr1": thr_low,
        "test_at_fpr1": metrics(yte, st, thr_low),
    }
    if not args.holdout:
        focus = te["kind"].isin(["phishing", "fraud", "ham"]).to_numpy()
        res["test_focus"] = metrics(yte[focus], st[focus], 0.5)
        res["per_kind_recall"] = {k: float((st[(te["kind"] == k).to_numpy()] >= 0.5).mean()) for k in ("phishing", "fraud", "spam") if (te["kind"] == k).any()}

    save_json(res, Path("ml/reports") / f"distilbert_{tag}.json")
    m = res["test"]
    print(f"测试集 F1={m['f1']:.4f} P={m['precision']:.4f} R={m['recall']:.4f} AUC={fmt(m['roc_auc'])} FPR={fmt(m['fpr'])}")
    if "test_focus" in res:
        print(f"钓鱼专项 F1={res['test_focus']['f1']:.4f}；FPR≤1% 时召回={res['test_at_fpr1']['recall']:.4f}")
    print(f"训练 {train_seconds / 60:.1f} 分钟，推理 {infer_ms:.2f} ms/封，模型保存在 {out_dir}")


if __name__ == "__main__":
    main()
