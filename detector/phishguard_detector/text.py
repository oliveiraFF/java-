"""文本切分：中英文混合。

英文、数字按词切分；中文没有空格，按单字和相邻两字（bigram）切分。
不依赖分词词典，对虚构的机构名、新词同样有效。

训练好的 TF-IDF 模型会引用这个函数，所以它必须放在检测引擎包里，
后端加载模型时才能找到。修改切分规则后需要重新训练模型。
"""
from __future__ import annotations

import re

_TOKEN = re.compile(r"[a-z0-9][a-z0-9_]+|[一-鿿]+")
_CJK_RUN = re.compile(r"[一-鿿]+")


def tokenize_mixed(text: str) -> list[str]:
    out: list[str] = []
    for tok in _TOKEN.findall(text.lower()):
        if _CJK_RUN.fullmatch(tok):
            out.extend(tok)  # 单字
            out.extend(tok[i:i + 2] for i in range(len(tok) - 1))  # 相邻两字
        else:
            out.append(tok)
    return out
