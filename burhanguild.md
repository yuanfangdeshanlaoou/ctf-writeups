# BurhanGuild Loader Incident — Forensics (100 pts)

> 赛道: Forensics · 解法: 内存取证 (BGMR) + unicorn 动态仿真逆向 KDF/XTEA 解密 CFG3 配置

## 题目

给定一台被攻陷主机的多份内存快照（BGMR 格式），目标是还原攻击者的加载器（loader）配置（CFG3），并拼出符合 token_schema 的证明串（BGLPROOF{...}）。

## 攻击链路

### 阶段一：BGMR 快照解析 — 插件视图会截断证据

- 直接解析 BGMR 全部 record kind：1=meta / 2=procs / 3=env / 4=heap / 5=maps / 6=net / 7=files / 8=CVE / 9=loader / 10=supply。
- **关键认知**：图形插件只展示部分 kind，会漏证据——必须用 `records()` 拿全量。
- 5 份 capture = 攻击的 5 个快照：`java JNDI` → `pkexec PwnKit` → `kworker worker`。
- 其中 **A812 是唯一 orion-lab/gateway-transfer 真网关**（transfer.log 吻合），其余 staging-node 是诱饵。

### 阶段二：deleted_pages — 证据藏在被删页里

- 内存快照的 `deleted_pages`：8 页共 400KB 高熵数据，尾部藏着 **4 个完整 zip**（PK 魔数）。
- zip 内含 `case_fragment.json` + `transfer.log`，给出 sequence/host/collection 分类——这就是攻击链的分段证据。

### 阶段三：CFG3 解密 — 参数字节长度特征才是钥匙

CFG3 是 558 字节的加密配置，藏在 `.rodata 0x2028`。解密函数 `0x1500` 调用 KDF(`0x1100`) + XTEA(`0x13e0`)。

**KDF(0x1100, 728B)**：
- arg1 = rdi 字符串（读到 \0），arg2 = rsi 起 8B，arg3 = rdx 起 10B，盐 `"eir-v3"`(0x2000)
- 输出：4 个 dword bswap → 16B key

**XTEA(0x13e0)**：
- 输入 = keyid(4B) || 0x45000000（A812 末块 0x45 = 69）
- 输出 bswap 回写，XOR 密文出明文

**正确的种子组合（一发入魂）**：
```
seed1 = BG_MUTEX 值      → bguild-ce104cb0        (字符串)
arg2  = A812 堆 8B token → a01fb1f61e9116a6      (8字节)
arg3  = build_id 10字节  → 542715c2e46252e4d790   (10字节 ← 关键!)
```

### 阶段四：unicorn 动态仿真 — 修复模拟器 bug

**模拟器 bug（5054 组全灭根因）**：`0x1500` 里 `mov rcx, rbp`，KDF 的 rcx 必须指向 rbp 所在的栈地址（入口 RSP=R 时传 `R-0x20`），否则 KDF 把 key 写错位置 → XTEA 读到的 key 全零 → 所有种子都在用零 key 解密，白跑。

**unicorn 仿真要点**：
- `emu_start` 不压返回地址 → 栈顶预置 RETSTUB + map 可执行桩写 `0xC3`
- key 输出位置 = hook `0x1538` 时 rbp 的值

### 阶段五：按 token_schema 拼出证明

CFG3 明文 JSON 里有 `closure_contract.token_schema`：
```
BGLPROOF{orion-lab__cap-{capture_id}__loader-{loader_pid}__implant-{implant_id}__build-{build_id}__config-{config_sha256}__archive-{archive_sha256}__digest-{digest}}
```
把解密出的各项填进去，得到完整 flag（BGLPROOF{orion-lab__cap-A812__...}）。

## 关键教训

1. **30 万+组合盲爆 0 中 → 方向错了就该停**。不是继续加种子，而是转攻"参数字节的长度特征"——build_id 是唯一一个 10 字节的证据，答案就藏在这个特征里。
2. **动态仿真优先于静态啃汇编**：直接跑目标函数看内存输出，比逐条反汇编快一个数量级。
3. **模拟器也有 bug**，全灭不一定是思路错，先怀疑自己环境再怀疑目标。

## 实战映射

- **内存取证**：现实入侵调查里，进程内存 / 被删页 / 堆 token 是攻击者的"尸体"。BGMR 快照分析 = 事件响应里 volatility 分析的同款技能。
- **JNDI → pkexec → worker** 的链式提权：对应现实中 Log4Shell 之类 JNDI 注入 + 本地提权组合拳的检测。
- **unicorn 仿真逆向 native 库**：直接对口你水控项目——加固挡 Java 层但挡不住厂商自有 .so，用 unicorn 执行 JNI 导出函数、读内存输出，比 radare2 静态啃快得多。
- **KDF 参数长度特征**：真实固件里密钥派生函数的参数往往有固定字节数（MAC、ID、salt），"哪个参数是唯一 X 字节"这类指纹是逆向的捷径。

## 产物

- `brute_cfg3_v12.py`（最终版，seed 组合 + unicorn 仿真解密）
- `cfg3_plaintext_A812.json`（解密后的完整配置）
- `flag.txt`（BGLPROOF{...} 完整 flag）
- 提交链路：`nc 34.2.147.230 7010`（问卷服务，须看到 "✔ CORRECT" 才算对）
