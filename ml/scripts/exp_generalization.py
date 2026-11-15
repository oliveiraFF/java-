"""泛化实验：检验 TF-IDF 基线是否依赖"数据来源捷径"。

实验 A · 留一来源（leave-one-source-out）
    依次把 CEAS / Enron / SpamAssassin / Ling 整个来源留出，只用其余来源的训练集训练，
    在留出来源的全部邮件上测试。对照组是标准划分下同一来源测试集的成绩。

实验 B · 捷径词屏蔽
    在训练集上用卡方检验找出最能区分"来自哪个语料库"的 N 个词（与是否恶意无关），
    加入停用词后重新训练，再做标准测试和实验 A。

用法（仓库根目录）：
    python ml/scripts/exp_generalization.py
"""
from __future__ import annotations

import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

import numpy as np  # noqa: E402
from sklearn.feature_extraction.text import CountVectorizer, TfidfVectorizer  # noqa: E402
from sklearn.feature_selection import chi2  # noqa: E402
from sklearn.linear_model import LogisticRegression  # noqa: E402
from sklearn.naive_bayes import MultinomialNB  # noqa: E402
from sklearn.svm import LinearSVC  # noqa: E402

from common import fmt, load_emails, metrics, model_input, save_json  # noqa: E402

HOLDOUT = ["ceas", "enron", "spamassassin", "ling"]
N_SHORTCUT = 1000
TOKEN = r"(?u)\b\w\w+\b"


def make_models():
    return {
        "naive_bayes": MultinomialNB(alpha=0.1),
        "logistic_regression": LogisticRegression(C=8.0, max_iter=2000, solver="liblinear"),
        "linear_svm": LinearSVC(C=0.5),
    }


def score(m, X):
    return m.predict_proba(X)[:, 1] if hasattr(m, "predict_proba") else m.decision_function(X)


def thr0(m):
    return 0.5 if hasattr(m, "predict_proba") else 0.0


def vectorizer(stop_words=None):
    return TfidfVectorizer(lowercase=True, ngram_range=(1, 2), min_df=3, max_df=0.9, max_features=100_000,
                           sublinear_tf=True, strip_accents="unicode", token_pattern=TOKEN,
                           stop_words=stop_words, dtype=np.float32)


def find_shortcut_words(train_df, n: int) -> list[str]:
    """卡方检验：哪些词最能区分邮件来自哪个语料库。

    只在正常邮件（ham）上计算。若在全部邮件上计算，Nazario / Nigerian 这类
    "整个来源都是恶意邮件"的语料会让 fund、bank、transfer 等真正的诈骗语义词
    被误判为来源词；而在正常邮件内部区分来源的词只可能是语料痕迹
    （公司名、人名、邮件列表名等），与是否恶意无关。
    """
    ham = train_df[train_df["label"] == 0]
    cv = CountVectorizer(lowercase=True, min_df=5, binary=True, token_pattern=TOKEN, strip_accents="unicode")
    X = cv.fit_transform(model_input(ham))
    chi, _ = chi2(X, ham["source"].to_numpy())
    chi = np.nan_to_num(chi)
    names = cv.get_feature_names_out()
    return [names[i] for i in np.argsort(chi)[::-1][:n]]


def run_setting(df, stop_words, tag: str) -> dict:
    out: dict = {"standard": {}, "loso": {}}
    tr, te = df[df["split"] == "train"], df[df["split"] == "test"]

    # 标准划分
    vec = vectorizer(stop_words)
    Xtr, Xte = vec.fit_transform(model_input(tr)), vec.transform(model_input(te))
    for name, m in make_models().items():
        m.fit(Xtr, tr["label"].to_numpy())
        s = score(m, Xte)
        out["standard"][name] = {
            "all": metrics(te["label"].to_numpy(), s, thr0(m)),
            "by_source": {src: metrics(te.loc[te["source"] == src, "label"].to_numpy(), s[(te["source"] == src).to_numpy()], thr0(m)) for src in HOLDOUT},
        }
        print(f"[{tag}] 标准划分 {name:<20} F1={out['standard'][name]['all']['f1']:.4f}")

    # 留一来源
    for src in HOLDOUT:
        tr_s = tr[tr["source"] != src]
        te_s = df[df["source"] == src]
        vec = vectorizer(stop_words)
        Xtr, Xte = vec.fit_transform(model_input(tr_s)), vec.transform(model_input(te_s))
        out["loso"][src] = {}
        for name, m in make_models().items():
            m.fit(Xtr, tr_s["label"].to_numpy())
            out["loso"][src][name] = metrics(te_s["label"].to_numpy(), score(m, Xte), thr0(m))
            r = out["loso"][src][name]
            print(f"[{tag}] 留出 {src:<13} {name:<20} F1={r['f1']:.4f} AUC={fmt(r['roc_auc'])} FPR={fmt(r['fpr'])}")
    return out


def write_report(res: dict, path: Path) -> None:
    zh = {"naive_bayes": "朴素贝叶斯", "logistic_regression": "逻辑回归", "linear_svm": "线性 SVM"}
    L = ["# 泛化实验：数据来源捷径对 TF-IDF 基线的影响", "",
         f"捷径词：在训练集的正常邮件上用卡方检验，选出最能区分语料来源的 {N_SHORTCUT} 个词"
         "（只用正常邮件，避免把诈骗语义词误判为来源词）。示例（前 40）：", "",
         "`" + "`、`".join(res["shortcut_words"][:40]) + "`", ""]

    L += ["## A. 留一来源 vs 标准划分（F1）", "",
          "标准划分 = 该来源的数据也参与训练，在该来源测试集上的成绩；留一来源 = 训练时完全没见过该来源。", "",
          "| 留出来源 | 模型 | 标准划分 F1 | 留一来源 F1 | 下降 | 留一来源 AUC | 留一来源误报率 |",
          "|---|---|---|---|---|---|---|"]
    base = res["original"]
    for src in HOLDOUT:
        for name in zh:
            a = base["standard"][name]["by_source"][src]["f1"]
            b = base["loso"][src][name]
            L.append(f"| {src} | {zh[name]} | {a:.4f} | {b['f1']:.4f} | {a - b['f1']:+.4f} | {fmt(b['roc_auc'])} | {fmt(b['fpr'])} |")

    L += ["", "## B. 屏蔽捷径词前后对比（F1）", "",
          "| 设定 | 模型 | 屏蔽前 | 屏蔽后 | 变化 |", "|---|---|---|---|---|"]
    msk = res["masked"]
    for name in zh:
        a, b = base["standard"][name]["all"]["f1"], msk["standard"][name]["all"]["f1"]
        L.append(f"| 标准划分 | {zh[name]} | {a:.4f} | {b:.4f} | {b - a:+.4f} |")
    for src in HOLDOUT:
        for name in zh:
            a, b = base["loso"][src][name]["f1"], msk["loso"][src][name]["f1"]
            L.append(f"| 留出 {src} | {zh[name]} | {a:.4f} | {b:.4f} | {b - a:+.4f} |")
    L.append("")
    path.write_text("\n".join(L), encoding="utf-8")


def main() -> None:
    t = time.perf_counter()
    df = load_emails()
    tr = df[df["split"] == "train"]
    shortcut = find_shortcut_words(tr, N_SHORTCUT)
    print("捷径词示例：", "、".join(shortcut[:30]))

    res = {"shortcut_words": shortcut,
           "original": run_setting(df, None, "原始"),
           "masked": run_setting(df, shortcut, "屏蔽")}
    rep = Path("ml/reports")
    save_json(res, rep / "generalization_metrics.json")
    write_report(res, rep / "generalization.md")
    print(f"完成，用时 {time.perf_counter() - t:.0f}s，报告：{rep / 'generalization.md'}")


if __name__ == "__main__":
    main()
