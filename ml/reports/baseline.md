# 基线实验结果：TF-IDF + 传统机器学习

数据：训练 57316 / 验证 8187 / 测试 16376 封；钓鱼专项测试子集 8819 封；TF-IDF 词表 100000。
特征：主题 + 正文，词级 1–2 gram，sublinear TF，max_features=100k。

## 1. 全量测试集（恶意 vs 正常，默认阈值）

| 模型 | 准确率 | 精确率 | 召回率 | F1 | ROC-AUC | PR-AUC | 误报率 | 训练耗时(s) | 推理(ms/封) |
|---|---|---|---|---|---|---|---|---|---|
| 朴素贝叶斯 | 0.9773 | 0.9961 | 0.9602 | 0.9778 | 0.9989 | 0.9991 | 0.0041 | 0.2 | 0.0048 |
| 逻辑回归 | 0.9920 | 0.9912 | 0.9934 | 0.9923 | 0.9997 | 0.9997 | 0.0096 | 7.1 | 0.0018 |
| 线性 SVM | 0.9930 | 0.9926 | 0.9940 | 0.9933 | 0.9998 | 0.9998 | 0.0080 | 2.1 | 0.0017 |
| 随机森林 | 0.9784 | 0.9809 | 0.9776 | 0.9793 | 0.9981 | 0.9980 | 0.0206 | 133.1 | 0.1687 |

## 2. 钓鱼专项测试子集（钓鱼 + 诈骗 vs 正常，默认阈值）

| 模型 | 精确率 | 召回率 | F1 | ROC-AUC | 误报率 |
|---|---|---|---|---|---|
| 朴素贝叶斯 | 0.9671 | 0.9711 | 0.9691 | 0.9993 | 0.0041 |
| 逻辑回归 | 0.9280 | 0.9969 | 0.9612 | 0.9999 | 0.0096 |
| 线性 SVM | 0.9388 | 0.9979 | 0.9675 | 0.9999 | 0.0080 |
| 随机森林 | 0.8547 | 0.9835 | 0.9146 | 0.9980 | 0.0206 |

## 3. 低误报约束（验证集上选阈值使 FPR ≤ 1%，测试集结果）

| 模型 | 测试集误报率 | 召回率 | 精确率 | F1 |
|---|---|---|---|---|
| 朴素贝叶斯 | 0.0079 | 0.9778 | 0.9926 | 0.9852 |
| 逻辑回归 | 0.0059 | 0.9892 | 0.9946 | 0.9919 |
| 线性 SVM | 0.0079 | 0.9940 | 0.9927 | 0.9934 |
| 随机森林 | 0.0066 | 0.9465 | 0.9936 | 0.9695 |

## 4. 按类型的召回率（默认阈值）

| 模型 | 钓鱼 phishing | 诈骗 fraud | 垃圾 spam |
|---|---|---|---|
| 朴素贝叶斯 | 0.9325 | 0.9894 | 0.9588 |
| 逻辑回归 | 0.9936 | 0.9985 | 0.9930 |
| 线性 SVM | 0.9936 | 1.0000 | 0.9935 |
| 随机森林 | 0.9614 | 0.9939 | 0.9768 |

## 5. 模型最依赖的词（可解释性示例）

**朴素贝叶斯**
- 偏向恶意：video partners、url video、partners email、email index、livefilestore com、livefilestore、custom alert、replica classics、alerts my、bay livefilestore、daily top、crime 2008、video crime、watches at、2008 crime
- 偏向正常：python org、mail python、python dev、enron、hou ect、ect ect、python 3000、opensuse、listinfo python、_______________________________________________ python、re python、hourahead、mailman options、options python、org mailman

**逻辑回归**
- 偏向恶意：your、2004、you、our、http、remove、here、2005、life、love、her、com、men、account、watches
- 偏向正常：enron、wrote、the、thanks、vince、louise、opensuse、on、2008、2001、713、university、edu、2007、to

**线性 SVM**
- 偏向恶意：your、2004、you、remove、http、2005、our、here、life、her、mobile、com、account、jose、sex
- 偏向正常：enron、wrote、thanks、vince、the、louise、opensuse、2008、713、on、fork、edu、uai、2001、tony

**随机森林**
- 重要性最高：your、re、wrote、the、enron、com、on、pm、http、thanks、our、2001、in、that、here

最佳模型（按全量测试集 F1）：**线性 SVM**
