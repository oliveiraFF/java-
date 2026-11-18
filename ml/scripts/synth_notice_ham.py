"""现代通知类正常邮件模板合成（中文为主，含部分英文）。

实验 6 发现：TREC06C 采集于 2005 年，正常邮件以论坛讨论、私人通信为主，缺少现代平台发出的
验证码、登录提醒、账单、物流、会员续费、工资条等通知类邮件。这类邮件和钓鱼邮件共享大量词汇
（账户、验证、异常、金额），是真实邮箱中的主要误报来源。

这里合成的正常通知遵循真实平台的写法：链接指向平台官方域名或不带链接；提醒"不要把验证码告诉他人"；
"如非本人操作，请在 APP 内修改密码"，而不是"点击链接验证"；不以"24 小时内冻结"相威胁。

全部为虚构样本，固定随机种子。注意：手写测试集中的正常邮件也由作者编写，为避免评估虚高，
本文件刻意使用不同的句式；真实邮箱评估不受此影响。

用法（仓库根目录）：python ml/scripts/synth_notice_ham.py --n 3000
"""
from __future__ import annotations

import argparse
import hashlib
import random
from pathlib import Path

import pandas as pd

SEED = 7

PLATFORMS = [("阿里云", "aliyun.com"), ("腾讯云", "cloud.tencent.com"), ("京东", "jd.com"), ("淘宝", "taobao.com"),
             ("美团", "meituan.com"), ("携程", "ctrip.com"), ("网易", "163.com"), ("小红书", "xiaohongshu.com"),
             ("哔哩哔哩", "bilibili.com"), ("知乎", "zhihu.com"), ("钉钉", "dingtalk.com"), ("飞书", "feishu.cn"),
             ("Gitee", "gitee.com"), ("中国移动", "10086.cn"), ("滴滴出行", "didiglobal.com"), ("拼多多", "pinduoduo.com")]
BANKS = [("招商银行", "cmbchina.com"), ("工商银行", "icbc.com.cn"), ("建设银行", "ccb.com"), ("中国银行", "boc.cn"),
         ("交通银行", "bankcomm.com"), ("平安银行", "pingan.com")]
COURIERS = [("顺丰速运", "sf-express.com"), ("中通快递", "zto.com"), ("京东物流", "jdl.com"), ("圆通速递", "yto.net.cn")]
CITIES = ["北京", "上海", "广州", "深圳", "杭州", "成都", "南昌", "武汉", "长沙", "西安"]
ITEMS = ["蓝牙耳机", "保温杯", "机械键盘", "运动鞋", "台灯", "移动电源", "笔记本支架", "洗发水", "数据线", "书包"]
DEVICES = ["Windows 电脑", "iPhone", "安卓手机", "Mac", "iPad", "Chrome 浏览器"]
EN_SVC = [("GitHub", "github.com"), ("GitLab", "gitlab.com"), ("Google", "google.com"), ("Microsoft", "microsoft.com"),
          ("Steam", "steampowered.com"), ("Apple", "apple.com"), ("Notion", "notion.so"), ("Zoom", "zoom.us")]


def t(r):
    return f"{r.randint(1, 12)}月{r.randint(1, 28)}日 {r.randint(0, 23):02d}:{r.randint(0, 59):02d}"


def amt(r):
    return f"{r.randint(5, 9999)}.{r.randint(0, 99):02d}"


def code(r):
    return "".join(r.choices("0123456789", k=6))


def mask(r):
    return f"{r.randint(130, 199)}****{r.randint(1000, 9999)}"


def verify_code(r):
    p, d = r.choice(PLATFORMS)
    subj = r.choice([f"【{p}】验证码", f"{p}账号安全验证码", f"您的{p}登录验证码", f"{p}：邮箱验证码"])
    body = r.choice([f"本次操作的验证码是 {code(r)}，{r.choice([5, 10, 15, 30])} 分钟内有效。",
                     f"验证码：{code(r)}。您正在{r.choice(['登录', '绑定邮箱', '修改密码', '注册账号'])}，请在页面中输入。"]) + \
        r.choice(["验证码仅用于本人操作，工作人员不会向您索取，请勿转发。", "请勿将验证码透露给任何人。", "如果这不是您本人的操作，可以忽略本邮件，您的账号不会有任何变化。"])
    return subj, body, (p, f"no-reply@{d}")


def login_alert(r):
    p, d = r.choice(PLATFORMS)
    subj = r.choice([f"{p}：新设备登录提醒", f"您的{p}账号在新设备上登录", f"{p}登录通知"])
    body = (f"您的账号于 {t(r)} 在{r.choice(CITIES)}的一台{r.choice(DEVICES)}上登录。"
            + r.choice(["若是您本人操作，无需处理。", "如为本人登录，请忽略此提醒。"])
            + r.choice([f"若不是您本人，建议打开{p} APP，在“设置-账号与安全”中修改密码并退出其他设备。",
                        "如有疑问，可通过官方客服渠道咨询，我们不会通过邮件索取您的密码。",
                        f"您也可以访问 https://www.{d}/security 查看最近的登录记录。"]))
    return subj, body, (p, f"security@{d}")


def bill(r):
    b, d = r.choice(BANKS)
    subj = r.choice([f"{b}信用卡{r.randint(1, 12)}月电子账单", f"{b}：您的本期账单已出", f"{b}账单提醒"])
    body = (f"您好，您尾号 {r.randint(1000, 9999)} 的信用卡本期应还金额 {amt(r)} 元，最低还款额 {amt(r)} 元，"
            f"到期还款日为 {r.randint(1, 12)}月{r.randint(1, 28)}日。"
            + r.choice(["您可通过手机银行或官方网银查看明细并还款。", "已开通自动还款的客户将于到期日自动扣款，请保证账户余额充足。",
                        "本邮件为系统自动发送，请勿直接回复。"]))
    return subj, body, (b, f"estatement@{d}")


def shipping(r):
    c, d = r.choice(COURIERS)
    no = f"{r.choice(['SF', 'ZT', 'JD', 'YT'])}{r.randint(10 ** 11, 10 ** 12 - 1)}"
    subj = r.choice(["您的包裹已发出", "快件派送中", "您的快件已签收", f"{c}物流动态"])
    body = r.choice([f"您购买的{r.choice(ITEMS)}已由{c}揽收，运单号 {no}，预计 {r.randint(1, 3)} 天内送达。",
                     f"运单 {no} 正在派送，快递员电话 {mask(r)}，请保持电话畅通。",
                     f"运单 {no} 已于 {t(r)} 签收，签收人：{r.choice(['本人', '门卫', '快递柜', '家人'])}。"]) + \
        r.choice(["物流信息可在下单平台的订单详情中查看。", "感谢您的使用。", f"查询物流请访问 https://www.{d}。"])
    return subj, body, (c, f"notice@{d}")


def order(r):
    p, d = r.choice(PLATFORMS[:8] + PLATFORMS[15:])
    subj = r.choice(["订单支付成功", "您的订单已确认", "退款已到账", "订单完成，请评价"])
    body = r.choice([f"您在{p}购买的{r.choice(ITEMS)}已支付成功，实付 {amt(r)} 元，商家将尽快为您发货。",
                     f"您申请的退款 {amt(r)} 元已原路退回，预计 1-3 个工作日到账，具体以银行入账时间为准。",
                     f"订单已完成，欢迎在 APP 中对商品进行评价，评价可获得积分。"]) + \
        r.choice(["订单详情可在 APP 的“我的订单”中查看。", "本邮件由系统自动发送。", ""])
    return subj, body, (p, f"order@{d}")


def membership(r):
    p, d = r.choice(PLATFORMS)
    subj = r.choice([f"{p}会员即将到期", f"{p}自动续费提醒", f"{p}会员续费成功"])
    body = r.choice([f"您的会员将于 {r.randint(1, 12)}月{r.randint(1, 28)}日到期，到期后部分权益将无法使用，可在 APP 中自主续费。",
                     f"您开通了自动续费，将于下个扣费日扣除 {amt(r)} 元。如需取消，可在 APP“设置-自动续费管理”中关闭。",
                     f"会员续费成功，本次支付 {amt(r)} 元，有效期延长至明年同日。"])
    return subj, body, (p, f"vip@{d}")


def payroll(r):
    subj = r.choice([f"{r.randint(1, 12)}月工资条", "薪资发放通知", "个人所得税扣缴明细", "公积金缴存提醒"])
    body = r.choice([f"您本月工资已发放至工资卡，实发 {amt(r)} 元，明细请登录公司内网薪酬系统查看。如有疑问请联系人力资源部。",
                     "本月个税已按规定代扣代缴，扣缴明细可在个人所得税 APP 中查询。",
                     f"本月公积金已按时缴存，个人与单位合计 {amt(r)} 元。"])
    return subj, body, ("人力资源部", f"hr@corp{r.randint(1, 50)}.example")


def meeting(r):
    subj = r.choice(["会议邀请：项目周会", "日程提醒：评审会", "会议纪要", "会议时间调整"])
    body = r.choice([f"会议时间：{t(r)}，地点：{r.randint(2, 18)}楼{r.randint(1, 9)}号会议室，议题：项目进度同步，请提前准备材料。",
                     f"本周评审会改到周{r.choice('一二三四五')}下午，线上会议链接稍后通过日历邀请发送。",
                     "附件为本次会议纪要，主要结论：一、接口文档本周定稿；二、下周开始联调。请相关同事跟进。"])
    return subj, body, (r.choice(["项目组", "行政部", "张三", "李四"]), f"{r.choice(['pm', 'admin', 'zhangsan', 'lisi'])}@corp{r.randint(1, 50)}.example")


def campus(r):
    subj = r.choice(["选课结果公布", "图书到期提醒", "奖学金评定公示", "毕业设计中期检查安排", "体测时间安排"])
    body = r.choice(["本学期第二轮选课结果已公布，请登录教务系统查看，如有冲突请在补退选阶段调整。",
                     f"您借阅的图书将于 {r.randint(1, 12)}月{r.randint(1, 28)}日到期，可在图书馆网站或微信公众号办理续借。",
                     "本年度奖学金评定结果已公示，公示期为五个工作日，如有异议请联系学院办公室。",
                     "毕业设计中期检查将于下周进行，请各位同学准备中期报告及系统演示，具体时间以学院通知为准。"])
    return subj, body, (r.choice(["教务处", "图书馆", "学院办公室"]), f"{r.choice(['jwc', 'lib', 'xy'])}@university{r.randint(1, 9)}.edu.cn")


def marketing(r):
    p, d = r.choice(PLATFORMS)
    subj = r.choice([f"{p}双十一大促开启", "限时优惠券已到账", "新品上市", "会员日专享福利", "周末特惠"])
    body = r.choice([f"{p}年终大促现已开启，全场满 300 减 50，活动详情请打开 APP 首页查看。",
                     "您有一张 20 元无门槛优惠券已放入账户，有效期 7 天，可在下单时直接使用。",
                     "新品首发，会员享 9 折优惠，点击订阅新品上架提醒。"]) + \
        r.choice(["退订请回复 TD。", "如不想接收此类邮件，可在设置中关闭营销通知。", ""])
    return subj, body, (p, f"news@{d}")


def en_notice(r):
    s, d = r.choice(EN_SVC)
    subj = r.choice([f"[{s}] Sign-in from a new device", f"Your {s} verification code", f"[{s}] Please verify your email address",
                     f"{s}: receipt for your payment", f"[{s}] A new SSH key was added", f"{s} security alert"])
    body = r.choice([f"We noticed a new sign-in to your {s} account from {r.choice(DEVICES)}. If this was you, you can ignore this email. "
                     f"If not, review your account activity in your {s} settings.",
                     f"Your verification code is {code(r)}. It expires in 10 minutes. Never share this code with anyone.",
                     f"Thanks for signing up. Please confirm this email address to finish setting up your {s} account. "
                     f"If you did not create an account, no action is needed.",
                     f"Thanks for your payment of ${r.randint(3, 99)}.00. You can view your receipts at https://{d}/billing.",
                     "A new key was added to your account. If you did not add this key, remove it from your account settings."])
    return subj, body, (s, f"noreply@{d}")


TEMPLATES = [(verify_code, 3), (login_alert, 3), (bill, 2), (shipping, 2), (order, 2), (membership, 2),
             (payroll, 1), (meeting, 1), (campus, 1), (marketing, 2), (en_notice, 3)]


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--n", type=int, default=3000)
    ap.add_argument("--out", default="ml/data/synth/notice_ham.csv")
    args = ap.parse_args()
    r = random.Random(SEED)
    fns = [f for f, w in TEMPLATES for _ in range(w)]
    rows, seen = [], set()
    tries = 0
    while len(rows) < args.n and tries < args.n * 50:
        tries += 1
        fn = r.choice(fns)
        subj, body, (name, addr) = fn(r)
        h = hashlib.sha1((subj + body).encode()).hexdigest()
        if h in seen:
            continue
        seen.add(h)
        b = int(h[:8], 16) % 10
        rows.append({"id": f"nh{len(rows):05d}", "source": "synth_notice", "kind": "ham", "label": 0,
                     "split": "train" if b < 7 else "val" if b < 8 else "test", "has_header": False,
                     "sender": f"{name} <{addr}>", "date": "", "n_urls": 0, "subject": subj, "body": body,
                     "template": fn.__name__})
    df = pd.DataFrame(rows)
    Path(args.out).parent.mkdir(parents=True, exist_ok=True)
    df.to_csv(args.out, index=False, encoding="utf-8")
    print(f"生成 {len(df)} 封，模板分布：{df['template'].value_counts().to_dict()}")


if __name__ == "__main__":
    main()
