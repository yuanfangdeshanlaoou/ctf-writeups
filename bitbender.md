# The Last Bitbender — Reverse (100 pts)

赛道：Reverse · 解法：shellcode 静态分析 + LCG 解密核心 + unicorn 仿真（Heaven's Gate）还原 transform 函数，黑盒服务自动应答

## 题目

一个 socket 服务（`nc 34.2.22.80 30097`），先发 token 认证，然后每轮给一个 32 字节 hex 请求，要求返回 `transform(请求)` 的结果。`transform` 藏在题目提供的 shellcode 里，一个"天国之门"（Heaven's Gate）风格的 32→64 位切换 shellcode。

## 攻击链路

### 阶段一：shellcode 静态分析

shellcode 开头是标准的 Heaven's Gate 序列：
```
mov ax, cs          ; 0x23
add eax, 0x10       ; -> 0x33 (64位代码段)
push eax
call $+5
add dword [esp], 5
retf                ; 远返回, 切到 64 位模式
```
这就是"从 32 位偷偷溜进 64 位"的经典手法。

### 阶段二：发现加密核心

- shellcode 中 `0xd4` 处有一段 0xc2 字节的加密核心，用 LCG 流密钥解密。
- 种子：`state = (0x46662de2ae713ee0 * 0xd1b54a32d192ed03) rol 0x11 ^ 0x6e7a5380f8318187`
- 每字节：`state = state * 0x9e6c63c6a3c4b1d1 + 0x2545f4914f6cdd1d; k = state >> 56; dec = enc ^ k`

### 阶段三：unicorn 仿真 + 手工还原

- 用 unicorn 逐指令 trace（`UC_HOOK_CODE`），按 CS 寄存器判断 32/64 位模式，capstone 反汇编。
- 还原出 transform 核心 = F + mixup 两级：

```
F(state):                          # 乘低32位 + 循环移位 + xor
    a, b = A&0xffffffff, B&0xffffffff
    A += a*b (low 64)
    B = rol(B, 13)
    A ^= B

mixup(x, y):                       # 雪崩扩散 (MurmurHash3 风格常数)
    y = rol(y + x, 29) * 0xff51afd7ed558ccd
    x = rol(x + y, 17)
```

- 输入先 `A ^= 0xa6f1c0d93b5e2748`（白化），输出 = `(A^B, A+B)` 两组字节。

### 阶段四：黑盒服务自动应答

`bitbender_solve.py`：socket 连上 → 收 token 认证 → 正则抓 32 字节请求 → `transform()` 算出响应 → 发回 → 收 flag。全自动，一轮秒回。

## 关键认知

1. Heaven's Gate 是恶意软件老手艺：32 位进程切 64 位代码段执行，常见于恶意 shellcode / 反调试。认得这个模式，这类样本直接破功。
2. 自解密核心（LCG + XOR）是 shellcode 最常见保护，解密完才是真逻辑，静态看完 shellcode 头就知道有货。
3. unicorn 仿真 > 纯静态：直接跑 trace 拿每步寄存器，比逐条啃汇编快。遇到 `retf` 切换段，靠 CS 判断模式就行。
4. 黑盒服务每轮换请求：逆向出 transform 后写成纯 Python，socket 自动应答即可，不用每次手算。

## 实战映射

- **Heaven's Gate 识别**：现实中带这种切换的样本基本是恶意加载器。能认出 + 仿真跑通，等于拿到一类 shellcode 分析的通解。
- **私有协议逆向**：服务端"给请求 → 要响应"的黑盒，直接对口水控项目，MQTT 私有协议、设备 challenge/response 认证，都是同一个"还原算法 → 自动应答"套路。逆向出的不是算法，是跟设备通信的能力。
- **LCG/流密码解密**：固件里大量用简单 LCG + XOR 藏关键数据，`state >> 56` 取高字节做 key 是常见廉价实现，可暴力或代数还原。
- **unicorn 全环境仿真**：沙箱里不用真跑 Windows 二进制，一个进程把 32/64 位混合代码全 trace 出来，是 .so 逆向流水线里最可复用的资产。

## 产物

- `shellcode.bin` + `decrypt_core.py` + `core.bin`（LCG 解密核心）
- `emu_trace.py` + `trace.log`（unicorn 全指令 trace, Heaven's Gate aware）
- `bitbender.py`（还原的 transform）+ `bitbender_solve.py`（自动应答）
