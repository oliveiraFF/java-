# 基线实验结果：TF-IDF + 传统机器学习（目标：钓鱼 vs 非钓鱼）

数据：训练 57316 / 验证 8187 / 测试 16376 封；钓鱼专项测试子集 8819 封；TF-IDF 词表 100000。
特征：主题 + 正文，词级 1–2 gram，sublinear TF，max_features=100k。
正样本只有钓鱼与诈骗邮件；垃圾/营销邮件和正常邮件都是负样本；分类器使用类别平衡权重。

## 1. 全量测试集（钓鱼+诈骗 vs 其他，默认阈值）

| 模型 | 准确率 | 精确率 | 召回率 | F1 | ROC-AUC | PR-AUC | 误报率 | 训练耗时(s) | 推理(ms/封) |
|---|---|---|---|---|---|---|---|---|---|
| 朴素贝叶斯 | 0.9861 | 0.8293 | 0.9628 | 0.8911 | 0.9919 | 0.8273 | 0.0125 | 0.1 | 0.0016 |
| 逻辑回归 | 0.9893 | 0.8609 | 0.9773 | 0.9154 | 0.9963 | 0.9364 | 0.0099 | 4.3 | 0.0011 |
| 线性 SVM | 0.9894 | 0.8625 | 0.9773 | 0.9163 | 0.9963 | 0.9334 | 0.0098 | 2.2 | 0.0013 |
| 随机森林 | 0.9851 | 0.8894 | 0.8545 | 0.8716 | 0.9956 | 0.9162 | 0.0067 | 25.9 | 0.0381 |

## 2. 钓鱼专项测试子集（钓鱼 + 诈骗 vs 正常，默认阈值）

| 模型 | 精确率 | 召回率 | F1 | ROC-AUC | 误报率 |
|---|---|---|---|---|---|
| 朴素贝叶斯 | 0.9915 | 0.9628 | 0.9770 | 0.9984 | 0.0010 |
| 逻辑回归 | 0.9958 | 0.9773 | 0.9865 | 0.9991 | 0.0005 |
| 线性 SVM | 0.9968 | 0.9773 | 0.9870 | 0.9992 | 0.0004 |
| 随机森林 | 1.0000 | 0.8545 | 0.9215 | 0.9990 | 0.0000 |

## 3. 低误报约束（验证集上选阈值使 FPR ≤ 1%，测试集结果）

| 模型 | 测试集误报率 | 召回率 | 精确率 | F1 |
|---|---|---|---|---|
| 朴素贝叶斯 | 0.0087 | 0.6873 | 0.8325 | 0.7530 |
| 逻辑回归 | 0.0086 | 0.9577 | 0.8755 | 0.9147 |
| 线性 SVM | 0.0084 | 0.9639 | 0.8778 | 0.9188 |
| 随机森林 | 0.0083 | 0.9556 | 0.8786 | 0.9155 |

## 4. 各类邮件被判为正样本的比例（默认阈值）

钓鱼、诈骗两列越高越好；垃圾/营销、正常两列就是误报率，越低越好。

| 模型 | 钓鱼 phishing | 诈骗 fraud | 垃圾/营销 spam | 正常 ham |
|---|---|---|---|---|
| 朴素贝叶斯 | 0.9228 | 0.9818 | 0.0243 | 0.0010 |
| 逻辑回归 | 0.9646 | 0.9833 | 0.0197 | 0.0005 |
| 线性 SVM | 0.9646 | 0.9833 | 0.0196 | 0.0004 |
| 随机森林 | 0.7588 | 0.8997 | 0.0136 | 0.0000 |

## 5. 模型最依赖的词（可解释性示例）

**朴素贝叶斯**
- 偏向恶意：jose monkey、usaa、dear jose、wetransfer、usaa com、your usaa、hi jose、usaa security、you usaa、monkey org、account jose、your jose、de activation、5million、org account
- 偏向正常：python、replica、watches、2008、python org、enron、ect、replica watches、news network、cable news、com 2008、com video、html url、video partners、url video

**逻辑回归**
- 偏向恶意：account、dear、kindly、utf、monkey、jose、2016、your、your account、usaa、2022、2017、monkey org、payment、administrator
- 偏向正常：th、http、enron、2008、net、site、lottery、at、com、see、http www、free、linux、2005、ie

**线性 SVM**
- 偏向恶意：kindly、account、2016、2017、2022、utf、dear、jose、usaa、your account、monkey、payment、administrator、2018、https
- 偏向正常：th、enron、lottery、http、2008、site、net、ie、2005、linux ie、call、free、available、ilug、see

**随机森林**
- 重要性最高：account、your、your account、dear、monkey org、monkey、dollars、jose、jose monkey、to your、bank、security、sum、my、email

最佳模型（按全量测试集 F1）：**线性 SVM**
