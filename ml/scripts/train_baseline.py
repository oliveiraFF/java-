"""TF-IDF + 传统机器学习基线。

在同一份 TF-IDF 特征上训练朴素贝叶斯、逻辑回归、线性 SVM、随机森林四个模型，
输出论文对比实验用的指标表，并保存效果最好的模型。

评估口径：
1. 全量测试集：恶意邮件（钓鱼 + 诈骗 + 垃圾）vs 正常邮件
2. 钓鱼专项测试集：只保留 kind 为 phishing / fraud 的正样本 + 全部正常邮件，
   避免"垃圾邮件好识别"把分数抬高
3. 低误报阈值：在验证集上选使 FPR ≤ 1% 的最低阈值，在测试集上报告召回率

用法（仓库根目录）：
    docker compose --profile ml run --rm ml python -I ml/scripts/train_baseline.py
"""
from __future__ import annotations

import argparse
import json
import time
from pathlib import Path

import joblib
import numpy as np
import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import (
    accuracy_score,
    average_precision_score,
    confusion_matrix,
    f1_score,
    precision_score,
    recall_score,
    roc_auc_score,
)
from sklearn.naive_bayes import MultinomialNB
from sklearn.svm import LinearSVC

SEED = 42
TARGET_FPR = 0.01


def model_input(df: pd.DataFrame) -> pd.Series:
    return (df["subject"].fillna("") + "\n" + df["body"].fillna("")).str.slice(0, 20_000)


def scores(model, X) -> np.ndarray:
    """统一成"越大越可能是恶意"的分数。"""
    if hasattr(model, "predict_proba"):
        return model.predict_proba(X)[:, 1]
    return model.decision_function(X)


def default_threshold(model) -> float:
    return 0.5 if hasattr(model, "predict_proba") else 0.0


def metrics(y: np.ndarray, s: np.ndarray, thr: float) -> dict:
    pred = (s >= thr).astype(int)
    tn, fp, fn, tp = confusion_matrix(y, pred, labels=[0, 1]).ravel()
    return {
        "accuracy": accuracy_score(y, pred),
        "precision": precision_score(y, pred, zero_division=0),
        "recall": recall_score(y, pred, zero_division=0),
        "f1": f1_score(y, pred, zero_division=0),
        "roc_auc": roc_auc_score(y, s),
        "pr_auc": average_precision_score(y, s),
        "fpr": fp / (fp + tn) if (fp + tn) else 0.0,
        "tp": int(tp), "fp": int(fp), "tn": int(tn), "fn": int(fn),
    }


def threshold_at_fpr(y: np.ndarray, s: np.ndarray, target: float) -> float:
    """返回使负样本误报率不超过 target 的最小阈值。"""
    neg = np.sort(s[y == 0])
    k = int(np.floor(target * len(neg)))
    # 阈值取第 (n-k) 大的负样本分数之上，保证最多 k 个负样本 >= 阈值
    idx = len(neg) - k - 1
    return float(np.nextafter(neg[idx], np.inf)) if idx >= 0 else float(neg.min())


def top_terms(model, vec: TfidfVectorizer, n: int = 20) -> dict | None:
    names = vec.get_feature_names_out()
    if hasattr(model, "coef_"):
        w = model.coef_.ravel()
    elif hasattr(model, "feature_log_prob_"):
        w = model.feature_log_prob_[1] - model.feature_log_prob_[0]
    elif hasattr(model, "feature_importances_"):
        imp = model.feature_importances_
        return {"important": [names[i] for i in np.argsort(imp)[::-1][:n]]}
    else:
        return None
    order = np.argsort(w)
    return {"malicious": [names[i] for i in order[::-1][:n]], "legit": [names[i] for i in order[:n]]}


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--data", default="ml/data/processed/emails.csv")
    ap.add_argument("--artifacts", default="ml/artifacts")
    ap.add_argument("--reports", default="ml/reports")
    args = ap.parse_args()
    art, rep = Path(args.artifacts), Path(args.reports)
    art.mkdir(parents=True, exist_ok=True)
    rep.mkdir(parents=True, exist_ok=True)

    df = pd.read_csv(args.data, dtype={"subject": str, "body": str}, keep_default_na=False)
    tr, va, te = (df[df["split"] == s].reset_index(drop=True) for s in ("train", "val", "test"))
    print(f"训练 {len(tr)} / 验证 {len(va)} / 测试 {len(te)}")

    t0 = time.perf_counter()
    vec = TfidfVectorizer(
        lowercase=True, ngram_range=(1, 2), min_df=3, max_df=0.9, max_features=100_000,
        sublinear_tf=True, strip_accents="unicode", token_pattern=r"(?u)\b\w\w+\b", dtype=np.float32,
    )
    Xtr = vec.fit_transform(model_input(tr))
    Xva, Xte = vec.transform(model_input(va)), vec.transform(model_input(te))
    print(f"TF-IDF 词表 {len(vec.vocabulary_)}，耗时 {time.perf_counter() - t0:.1f}s")
    ytr, yva, yte = tr["label"].to_numpy(), va["label"].to_numpy(), te["label"].to_numpy()

    focus = te["kind"].isin(["phishing", "fraud", "ham"]).to_numpy()

    models = {
        "naive_bayes": MultinomialNB(alpha=0.1),
        "logistic_regression": LogisticRegression(C=8.0, max_iter=2000, solver="liblinear"),
        "linear_svm": LinearSVC(C=0.5),
        "random_forest": RandomForestClassifier(n_estimators=200, max_features="sqrt", n_jobs=-1, random_state=SEED),
    }

    results: dict = {
        "data": {"train": len(tr), "val": len(va), "test": len(te), "test_focus": int(focus.sum()), "vocab": len(vec.vocabulary_)},
        "models": {},
    }
    best_name, best_f1 = None, -1.0
    for name, model in models.items():
        t = time.perf_counter()
        model.fit(Xtr, ytr)
        fit_s = time.perf_counter() - t

        t = time.perf_counter()
        ste = scores(model, Xte)
        infer_ms = (time.perf_counter() - t) / len(te) * 1000
        sva = scores(model, Xva)

        thr0 = default_threshold(model)
        thr_low = threshold_at_fpr(yva, sva, TARGET_FPR)
        r = {
            "fit_seconds": round(fit_s, 1),
            "infer_ms_per_email": round(infer_ms, 4),
            "test": metrics(yte, ste, thr0),
            "test_focus": metrics(yte[focus], ste[focus], thr0),
            "val_threshold_fpr1": thr_low,
            "test_at_fpr1": metrics(yte, ste, thr_low),
            "per_kind_recall": {
                k: float(((ste[te["kind"] == k] >= thr0)).mean()) for k in ("phishing", "fraud", "spam")
            },
            "top_terms": top_terms(model, vec),
        }
        results["models"][name] = r
        m = r["test"]
        print(f"{name:<20} F1={m['f1']:.4f} P={m['precision']:.4f} R={m['recall']:.4f} AUC={m['roc_auc']:.4f} "
              f"| 钓鱼专项 F1={r['test_focus']['f1']:.4f} | FPR≤1% 时召回={r['test_at_fpr1']['recall']:.4f} "
              f"| 训练 {fit_s:.1f}s 推理 {infer_ms:.3f}ms/封")
        if m["f1"] > best_f1:
            best_name, best_f1 = name, m["f1"]

    results["best"] = best_name
    joblib.dump({"vectorizer": vec, "model": models[best_name], "name": best_name,
                 "threshold": default_threshold(models[best_name]),
                 "threshold_fpr1": results["models"][best_name]["val_threshold_fpr1"]},
                art / "baseline_tfidf.joblib", compress=3)

    def conv(o):
        if isinstance(o, (np.floating, np.integer)):
            return o.item()
        raise TypeError(type(o))

    (rep / "baseline_metrics.json").write_text(json.dumps(results, ensure_ascii=False, indent=2, default=conv), encoding="utf-8")
    write_report(results, rep / "baseline.md")
    print(f"最佳模型：{best_name}，已保存到 {art / 'baseline_tfidf.joblib'}")


def write_report(res: dict, path: Path) -> None:
    zh = {"naive_bayes": "朴素贝叶斯", "logistic_regression": "逻辑回归", "linear_svm": "线性 SVM", "random_forest": "随机森林"}
    d = res["data"]
    lines = [
        "# 基线实验结果：TF-IDF + 传统机器学习",
        "",
        f"数据：训练 {d['train']} / 验证 {d['val']} / 测试 {d['test']} 封；钓鱼专项测试子集 {d['test_focus']} 封；TF-IDF 词表 {d['vocab']}。",
        "特征：主题 + 正文，词级 1–2 gram，sublinear TF，max_features=100k。",
        "",
        "## 1. 全量测试集（恶意 vs 正常，默认阈值）",
        "",
        "| 模型 | 准确率 | 精确率 | 召回率 | F1 | ROC-AUC | PR-AUC | 误报率 | 训练耗时(s) | 推理(ms/封) |",
        "|---|---|---|---|---|---|---|---|---|---|",
    ]
    for k, r in res["models"].items():
        m = r["test"]
        lines.append(f"| {zh[k]} | {m['accuracy']:.4f} | {m['precision']:.4f} | {m['recall']:.4f} | {m['f1']:.4f} | "
                     f"{m['roc_auc']:.4f} | {m['pr_auc']:.4f} | {m['fpr']:.4f} | {r['fit_seconds']} | {r['infer_ms_per_email']} |")
    lines += ["", "## 2. 钓鱼专项测试子集（钓鱼 + 诈骗 vs 正常，默认阈值）", "",
              "| 模型 | 精确率 | 召回率 | F1 | ROC-AUC | 误报率 |", "|---|---|---|---|---|---|"]
    for k, r in res["models"].items():
        m = r["test_focus"]
        lines.append(f"| {zh[k]} | {m['precision']:.4f} | {m['recall']:.4f} | {m['f1']:.4f} | {m['roc_auc']:.4f} | {m['fpr']:.4f} |")
    lines += ["", "## 3. 低误报约束（验证集上选阈值使 FPR ≤ 1%，测试集结果）", "",
              "| 模型 | 测试集误报率 | 召回率 | 精确率 | F1 |", "|---|---|---|---|---|"]
    for k, r in res["models"].items():
        m = r["test_at_fpr1"]
        lines.append(f"| {zh[k]} | {m['fpr']:.4f} | {m['recall']:.4f} | {m['precision']:.4f} | {m['f1']:.4f} |")
    lines += ["", "## 4. 按类型的召回率（默认阈值）", "", "| 模型 | 钓鱼 phishing | 诈骗 fraud | 垃圾 spam |", "|---|---|---|---|"]
    for k, r in res["models"].items():
        p = r["per_kind_recall"]
        lines.append(f"| {zh[k]} | {p['phishing']:.4f} | {p['fraud']:.4f} | {p['spam']:.4f} |")
    lines += ["", "## 5. 模型最依赖的词（可解释性示例）", ""]
    for k, r in res["models"].items():
        t = r["top_terms"]
        if not t:
            continue
        lines.append(f"**{zh[k]}**")
        for side, words in t.items():
            label = {"malicious": "偏向恶意", "legit": "偏向正常", "important": "重要性最高"}[side]
            lines.append(f"- {label}：{'、'.join(words[:15])}")
        lines.append("")
    lines += [f"最佳模型（按全量测试集 F1）：**{zh[res['best']]}**", ""]
    path.write_text("\n".join(lines), encoding="utf-8")


if __name__ == "__main__":
    main()
