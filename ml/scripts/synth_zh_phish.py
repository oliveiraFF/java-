"""中文钓鱼邮件场景模板合成。

公开的中文钓鱼邮件样本极少，这里按国内常见的 12 类钓鱼场景，把每封邮件拆成
"称呼 / 背景 / 制造紧迫 / 诱导动作 / 链接或联系方式 / 落款"几个部分，每部分有多种写法，
再随机填入机构名、金额、期限、仿冒域名、发件人身份等槽位，组合生成。

全部为虚构样本，不包含任何真实邮件内容。固定随机种子，可完全复现。
注意：模板生成的样本句式有限，只能用于训练；评估必须用独立手写的测试集
（ml/testsets/zh_phish_handwritten.csv），否则模型会因为"记住模板"而得到虚高的分数。

用法（仓库根目录）：python ml/scripts/synth_zh_phish.py --n 2000
"""
from __future__ import annotations

import argparse
import hashlib
import random
from pathlib import Path

import pandas as pd

SEED = 2026

BANKS = ["工商银行", "建设银行", "农业银行", "中国银行", "招商银行", "交通银行", "邮储银行", "浦发银行", "中信银行", "平安银行"]
PLATFORMS = ["支付宝", "微信支付", "淘宝", "京东", "拼多多", "美团", "抖音", "12306", "个人所得税APP", "国家医保服务平台"]
COURIERS = ["顺丰速运", "中通快递", "圆通速递", "韵达快递", "京东物流", "中国邮政 EMS"]
MAIL_SVC = ["企业邮箱", "腾讯企业邮", "阿里邮箱", "网易企业邮箱", "Coremail 邮件系统", "学校邮箱"]
DEPTS = ["财务部", "人力资源部", "行政部", "信息中心", "IT 运维部", "工会", "教务处", "网络中心"]
TITLES = ["王总", "李总", "张总", "刘总监", "陈经理", "赵董", "周总", "孙副总"]
TLDS = ["top", "xyz", "cc", "vip", "club", "icu", "shop", "online", "site", "cn-verify.com"]
FREEMAIL = ["163.com", "126.com", "qq.com", "sina.com", "foxmail.com", "gmail.com", "outlook.com"]
SHORT = ["t.cn", "url.cn", "dwz.cn", "suo.im", "bit.ly"]
PINYIN = {"工商银行": "icbc", "建设银行": "ccb", "农业银行": "abchina", "中国银行": "boc", "招商银行": "cmb",
          "交通银行": "bankcomm", "邮储银行": "psbc", "浦发银行": "spdb", "中信银行": "citic", "平安银行": "pingan",
          "支付宝": "alipay", "微信支付": "wxpay", "淘宝": "taobao", "京东": "jd", "拼多多": "pdd", "美团": "meituan",
          "抖音": "douyin", "12306": "12306", "个人所得税APP": "etax", "国家医保服务平台": "nhsa"}


def rnd_domain(r: random.Random, brand: str | None = None) -> str:
    base = PINYIN.get(brand or "", r.choice(["secure", "service", "account", "verify", "office", "mail"]))
    deco = r.choice(["-secure", "-verify", "-service", "-online", "safe", "-cn", "help", "-login", ""])
    return f"{base}{deco}{r.randint(1, 99) if r.random() < 0.3 else ''}.{r.choice(TLDS)}"


def rnd_url(r: random.Random, brand: str | None = None) -> str:
    if r.random() < 0.15:
        return f"http://{r.choice(SHORT)}/{''.join(r.choices('abcdefghjkmnpqrstuvwxyz23456789', k=6))}"
    if r.random() < 0.1:
        return f"http://{r.randint(45, 223)}.{r.randint(1, 254)}.{r.randint(1, 254)}.{r.randint(1, 254)}/login"
    path = r.choice(["login", "verify", "account/update", "auth", "index.html", "refund", "apply", "confirm"])
    return f"{r.choice(['http', 'https'])}://{rnd_domain(r, brand)}/{path}"


def deadline(r: random.Random) -> str:
    return r.choice(["24小时内", "48小时内", "今天下班前", "今日18:00前", "3个工作日内", "本周五前", "2小时内", "即日起"])


def money(r: random.Random) -> str:
    return r.choice([f"{r.randint(1, 98) * 100}元", f"{r.randint(2, 99)}800.00元", f"{r.randint(1, 30)}万元", f"￥{r.randint(3, 9)},{r.randint(100, 999)}.00"])


def scenario_bank(r):
    b = r.choice(BANKS)
    subj = r.choice([f"【{b}】您的账户存在异常，请尽快处理", f"{b}安全提醒：账户即将冻结", f"关于您{b}账户的重要通知", f"【{b}】账户安全验证通知"])
    body = [r.choice(["尊敬的客户：", "尊敬的用户您好：", "您好：", "亲爱的客户："]),
            r.choice(["系统检测到您的账户近期存在异地异常登录。", f"根据监管要求，我行正在对客户身份信息进行年度核验。", "您的银行卡因长时间未更新信息已被限制部分功能。", "我行风控系统发现您的账户存在可疑交易。"]),
            r.choice([f"请您务必在{deadline(r)}完成身份验证，", f"如未在{deadline(r)}内处理，", "逾期未处理的账户将被冻结，"]) + r.choice(["否则账户将被冻结。", "系统将暂停您的转账和支付功能。", "将影响您的正常使用。", "由此造成的损失需由本人承担。"]),
            r.choice(["请点击以下链接登录并核对您的银行卡号、密码及短信验证码：", "请通过以下安全通道重新验证身份：", "验证地址："]) + rnd_url(r, b),
            r.choice([f"{b}客户服务中心", f"{b}风险管理部", f"{b}"])]
    return subj, body, (f"{b}", f"service@{rnd_domain(r, b)}")


def scenario_ceo(r):
    t = r.choice(TITLES)
    subj = r.choice(["紧急", "急！请马上处理", "付款事宜", "在吗？", "有件事需要你帮忙", "今天务必办好"])
    body = [r.choice(["小李：", "小王，", "财务同事你好，", "在吗？", "你好，"]),
            r.choice(["我现在在开会，不方便接电话。", "我在外面出差，手机信号不好，用这个邮箱联系你。", "这件事比较急，先不要声张。"]),
            r.choice(["供应商那边的收款账户变更了，", "有一笔合同款需要马上支付，", "客户那边催得很紧，"]) + r.choice([f"麻烦你{deadline(r)}把{money(r)}转到新的收款账户。", f"请{deadline(r)}安排一笔{money(r)}的汇款。", "需要你先帮我垫付一下。"]),
            r.choice(["账户信息我稍后发给你，办完直接回复我。", "收款账号见附件，转完把回单截图发我。", "不要打电话问，直接按我说的办，回头我跟财务总监说。"]),
            r.choice([t, f"{t}（手机不方便，用邮箱联系）", ""])]
    return subj, body, (f"{t}", f"{r.choice(['ceo', 'boss', 'office', 'gm', 'zong'])}.{r.randint(100, 9999)}@{r.choice(FREEMAIL)}")


def scenario_mailbox(r):
    s = r.choice(MAIL_SVC)
    subj = r.choice([f"【{s}】您的邮箱容量已满", f"{s}账号即将过期", "邮箱升级通知", "您有 6 封邮件被系统拦截", f"{s}安全验证提醒"])
    body = [r.choice(["尊敬的用户：", "您好，", "各位同事："]),
            r.choice(["您的邮箱存储空间已超过 98%，新邮件将无法接收。", "因系统升级，所有账号需要重新验证。", "您有多封邮件被安全策略拦截，需手动释放。", "您的邮箱密码将于今日过期。"]),
            r.choice([f"请在{deadline(r)}完成验证，", "逾期未验证的账号将被停用，", "为避免邮件丢失，"]) + r.choice(["否则账号将被注销。", "请尽快处理。", "历史邮件将无法恢复。"]),
            r.choice(["请点击下方链接，输入邮箱账号和密码完成验证：", "请登录以下地址释放邮件：", "立即升级："]) + rnd_url(r),
            r.choice(["邮件系统管理员", f"{r.choice(DEPTS)}", "IT 服务台"])]
    return subj, body, (r.choice(["邮件系统管理员", "IT Helpdesk", "系统管理员"]), f"admin@{rnd_domain(r)}")


def scenario_tax(r):
    subj = r.choice(["个人所得税退税通知", f"{r.randint(2025, 2026)}年度个税汇算退税提醒", "您有一笔退税待领取", "【税务局】退税申领通知"])
    body = [r.choice(["纳税人您好：", "尊敬的纳税人：", "您好："]),
            f"经系统核算，您有一笔{money(r)}的个人所得税退税尚未领取。",
            r.choice([f"请于{deadline(r)}完成申领，", "退税申领通道即将关闭，", "逾期视为自动放弃，"]) + "过期不予办理。",
            r.choice(["请点击链接填写银行卡号、身份证号及交易密码完成申领：", "申领地址：", "请登录以下网址办理："]) + rnd_url(r, "个人所得税APP"),
            r.choice(["国家税务总局", "税务局纳税服务中心", "个人所得税服务平台"])]
    return subj, body, ("国家税务总局", f"notice@{rnd_domain(r)}")


def scenario_salary(r):
    d = r.choice(DEPTS)
    subj = r.choice(["关于发放季度补贴的通知", "工资调整通知", "年终奖发放确认", "社保补贴申领通知", "关于核对个人工资账户的通知"])
    body = [r.choice(["各位同事：", "全体员工：", "您好："]),
            r.choice(["本季度补贴已核算完毕，", "根据公司薪酬调整方案，", "年终奖金即将发放，"]) + f"您的应发金额为{money(r)}。",
            r.choice([f"请于{deadline(r)}登录系统核对个人银行账户信息，", "请尽快确认收款账户，"]) + r.choice(["逾期将视为放弃。", "未确认的将延后至下月发放。"]),
            r.choice(["核对地址：", "请点击此处确认：", "登录查看明细："]) + rnd_url(r),
            d]
    return subj, body, (d, f"{r.choice(['hr', 'finance', 'caiwu', 'xinchou'])}@{rnd_domain(r)}")


def scenario_courier(r):
    c = r.choice(COURIERS)
    subj = r.choice([f"【{c}】您的包裹派送失败", "快递地址异常，请重新确认", f"{c}理赔通知", "您有一个包裹待签收"])
    body = [r.choice(["您好：", "尊敬的客户："]),
            r.choice(["您的包裹因地址信息不完整无法派送。", "您的快递在运输中丢失，我们将为您办理理赔。", "您的包裹已到达网点，因未缴纳关税暂扣。"]),
            r.choice([f"请在{deadline(r)}内更新地址，", "请尽快处理，", f"理赔款{money(r)}需在{deadline(r)}内领取，"]) + r.choice(["否则包裹将被退回。", "逾期将无法补偿。"]),
            r.choice(["请点击链接填写信息并支付手续费：", "办理地址：", "请登录以下页面："]) + rnd_url(r),
            f"{c}客服中心"]
    return subj, body, (f"{c}", f"kefu@{rnd_domain(r)}")


def scenario_platform(r):
    p = r.choice(PLATFORMS)
    subj = r.choice([f"【{p}】账户安全提醒", f"{p}订单异常通知", f"{p}会员到期扣费提醒", f"关于您的{p}账号被限制的通知"])
    body = [r.choice(["亲爱的用户：", "您好："]),
            r.choice(["您的账户存在违规操作，已被临时限制。", f"您开通的会员服务将自动扣费{money(r)}。", "您购买的商品存在质量问题，可申请双倍赔偿。", "检测到您的账号在陌生设备登录。"]),
            r.choice([f"如非本人操作，请在{deadline(r)}内处理，", "如需取消，请尽快操作，", "请尽快申请，"]) + r.choice(["否则将无法退款。", "逾期将正常扣款。", "名额有限。"]),
            r.choice(["请点击链接登录并验证：", "取消地址：", "申请地址：", "联系在线客服："]) + rnd_url(r, p),
            f"{p}客服"]
    return subj, body, (f"{p}", f"no-reply@{rnd_domain(r, p)}")


def scenario_invoice(r):
    subj = r.choice(["发票已开具，请查收", "合同及付款通知单", "请确认对账单", "电子发票下载通知", "采购订单确认"])
    body = [r.choice(["您好：", "贵司财务：", "王经理您好："]),
            r.choice(["贵司本月的电子发票已开具，", "附件为本期对账单，", "双方合同款已到期，"]) + f"金额{money(r)}。",
            r.choice([f"请于{deadline(r)}内确认，", "请尽快核对，"]) + r.choice(["逾期将影响后续合作。", "如有疑问请及时联系。"]),
            r.choice(["请下载附件查看（解压密码 8866）。", "查看地址：" + rnd_url(r), "请点击下载：" + rnd_url(r)]),
            r.choice(["财务部", "商务部", "客户经理 陈"])]
    return subj, body, (r.choice(["财务部", "销售部"]), f"{r.choice(['fapiao', 'invoice', 'finance'])}@{rnd_domain(r)}")


def scenario_social_security(r):
    subj = r.choice(["医保卡异常通知", "社保信息核验通知", "您的医保账户存在异常", "关于医保个人账户清零的提醒"])
    body = [r.choice(["参保人您好：", "尊敬的参保人："]),
            r.choice(["您的医保卡存在异常消费记录，", "根据新政策，个人账户余额需在年底前转移，", "您的社保信息不完整，"]) + "需尽快核实。",
            r.choice([f"请在{deadline(r)}完成核验，", "逾期未处理的，"]) + r.choice(["账户将被冻结。", "余额将被清零。"]),
            "核验地址：" + rnd_url(r, "国家医保服务平台"),
            r.choice(["医疗保障局", "社保服务中心"])]
    return subj, body, ("医疗保障局", f"notice@{rnd_domain(r)}")


def scenario_prize(r):
    subj = r.choice(["恭喜您中奖", "您已获得年度幸运用户奖励", "积分即将清零，请尽快兑换", "您有一份礼品待领取"])
    body = [r.choice(["恭喜您！", "尊敬的用户："]),
            r.choice([f"您在本次活动中获得{money(r)}现金奖励。", "您的积分即将清零，可兑换价值千元的礼品。", "您被抽中为年度幸运用户，获得最新款手机一台。"]),
            r.choice([f"请在{deadline(r)}领取，", "名额有限，"]) + r.choice(["逾期作废。", "先到先得。"]),
            r.choice(["领取时需先缴纳少量手续费，请点击：", "领取地址：", "兑换地址："]) + rnd_url(r),
            r.choice(["活动组委会", "客服中心"])]
    return subj, body, ("活动组委会", f"event@{rnd_domain(r)}")


def scenario_account_school(r):
    subj = r.choice(["统一身份认证密码即将过期", "教务系统账号升级通知", "关于校园网账号安全检查的通知", "VPN 账号续期通知"])
    body = [r.choice(["各位老师、同学：", "同学你好：", "您好："]),
            r.choice(["因系统升级，所有统一身份认证账号需重新激活。", "您的校园网账号存在安全风险。", "您的 VPN 账号即将到期。"]),
            r.choice([f"请于{deadline(r)}完成激活，", "未完成的账号将被停用，"]) + "以免影响正常使用。",
            r.choice(["请点击链接，使用学号和密码登录：", "激活地址：", "续期地址："]) + rnd_url(r),
            r.choice(["网络信息中心", "信息化办公室", "教务处"])]
    return subj, body, (r.choice(["网络信息中心", "信息中心"]), f"nic@{rnd_domain(r)}")


def scenario_investment(r):
    subj = r.choice(["内部消息：稳赚不赔的项目", "专属理财名额", "高收益投资邀请", "导师带你炒股群邀请"])
    body = [r.choice(["您好：", "朋友您好："]),
            r.choice(["我们有一个内部投资项目，月收益稳定在 20% 以上。", "您获得了专属理财产品认购资格。", "我们的分析师团队带你精准抓牛股。"]),
            r.choice([f"名额仅剩 3 个，请在{deadline(r)}确认，", "机会难得，"]) + r.choice(["错过不再有。", "先到先得。"]),
            r.choice(["添加客服微信 ", "请点击注册：", "入群链接："]) + (f"vx{r.randint(10000, 99999)}" if r.random() < 0.3 else rnd_url(r)),
            r.choice(["投资顾问 张老师", "客服"])]
    return subj, body, ("投资顾问", f"vip{r.randint(1, 999)}@{r.choice(FREEMAIL)}")


SCENARIOS = [scenario_bank, scenario_ceo, scenario_mailbox, scenario_tax, scenario_salary, scenario_courier,
             scenario_platform, scenario_invoice, scenario_social_security, scenario_prize, scenario_account_school,
             scenario_investment]


def make(r: random.Random) -> dict:
    fn = r.choice(SCENARIOS)
    subj, parts, (name, addr) = fn(r)
    parts = [p for p in parts if p]
    if r.random() < 0.3:  # 部分邮件把正文合成一段
        body = "".join(parts[1:-1]) + "\n" + parts[-1]
        body = parts[0] + "\n" + body
    else:
        body = "\n".join(parts)
    return {"scenario": fn.__name__.removeprefix("scenario_"), "subject": subj, "body": body, "sender": f"{name} <{addr}>"}


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--n", type=int, default=2000)
    ap.add_argument("--out", default="ml/data/synth/zh_phish.csv")
    args = ap.parse_args()
    r = random.Random(SEED)
    rows, seen = [], set()
    while len(rows) < args.n:
        x = make(r)
        h = hashlib.sha1((x["subject"] + x["body"]).encode()).hexdigest()
        if h in seen:
            continue
        seen.add(h)
        # 按哈希稳定划分 train/val/test（模板样本的测试集只作参考，正式评估用手写测试集）
        bucket = int(h[:8], 16) % 10
        x.update(id=f"zp{len(rows):05d}", source="synth_zh", kind="phishing", label=1, has_header=False,
                 split="train" if bucket < 7 else "val" if bucket < 8 else "test")
        rows.append(x)
    df = pd.DataFrame(rows)
    Path(args.out).parent.mkdir(parents=True, exist_ok=True)
    df.to_csv(args.out, index=False, encoding="utf-8")
    print(f"生成 {len(df)} 封，场景分布：{df['scenario'].value_counts().to_dict()}")
    print(df.sample(3, random_state=1)[["subject", "body"]].to_string()[:1200])


if __name__ == "__main__":
    main()
