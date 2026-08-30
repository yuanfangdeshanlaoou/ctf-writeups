# COMPFEST 18 CTF 2026 — OuSec 战队 Writeups

> **赛事**: COMPFEST CTF 2026 (ctftime 权重 96, Jeopardy)
> **战队**: OuSec (AI Assisted 组)
> **赛果**: 400 分 / 4 题全解 / 170th → (冲刺前收官)
> **时间**: 2026-08-29 08:00 — 2026-08-31 08:00 (北京时间, 48h)

---

## 总览

| # | 题名 | 分类 | 分值 | 解法核心 | 实战迁移 |
|---|------|------|------|----------|----------|
| 1 | **hello** | Crypto | 100 | 广义 Wiener 攻击破解非标准 RSA (多项式环) | 弱参数 RSA 实际破解能力 |
| 2 | **BurhanGuild Loader Incident** | Forensics | 100 | BGMR 内存取证 + unicorn 动态仿真逆向 KDF/XTEA | 固件/native 库逆向 (水控项目对口) |
| 3 | **Phantom Ledger** | Blockchain | 100 | 手搓 ECDSA 签名 + RLP 交易构造链上调用 | 无依赖链上交互 / 合约审计 |
| 4 | **The Last Bitbender** | Reverse | 100 | 黑盒协议逆向, 还原 transform 核心逻辑 | 私有协议逆向 (MQTT 水控分析对口) |

> 完整解题链路见各题 md, 每篇末尾附"实战映射"——该技术点在水控/IoT/金融场景的真实对应。

---

## 核心方法论沉淀

1. **先抄作业再动手** — 每个新题第一步是搜现成项目/工具, 禁止从零硬干
2. **鉴别实验先于方向猜测** — 请求被无视时, "原样重放 vs 改内容重发"一次实验分清内容校验/身份过滤
3. **参数字节长度特征是破解钥匙** — 30 万+组合盲爆全灭后, 转攻"哪个参数是唯一 10 字节证据", 一发入魂
4. **胜利以实际到账为准** — 宣布成功前必须交叉终验 (平台 isSolved/资金状态)
5. **动态仿真优先于静态啃汇编** — unicorn 直接执行目标函数, 读内存输出, 不逐行反汇编

---

## 文件结构

```
writeups/
├── README.md              # 本文件
├── hello.md               # Crypto — 广义 Wiener 攻击
├── burhanguild.md         # Forensics — 内存取证 + CFG3 解密
├── phantom-ledger.md      # Blockchain — 手搓 ECDSA/RLP
└── bitbender.md           # Reverse — 协议逆向
```

(资产/脚本/flag 存档见 `../cf18/` 与 `../stw/`)
