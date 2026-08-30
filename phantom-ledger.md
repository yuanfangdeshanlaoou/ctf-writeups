# Phantom Ledger — Blockchain (100 pts)

赛道：Blockchain · 解法：纯 Python 手搓 ECDSA 签名 + RLP 交易构造，链上调用 PhantomVault 合约

## 题目

一个本地 EVM 链（chain_id 31337，Foundry/Anvil 风格）+ PhantomVault 合约。玩家作为 relayer，要让 Setup 合约 `isSolved()` 返回 true。本质是权限控制缺陷：`transferCredit(from, to, amount)` 的调用者被当作 relayer，而 Setup 已授权给 relayer，于是玩家直接以 relayer 身份把 Setup 的 10 ETH 转给自己再 `withdraw`。

## 攻击链路

没有 web3.py / ethers，全用标准库 + pycryptodome，手搓三层：

### 1. 手搓 secp256k1 (ECDSA)
- 椭圆曲线点加/倍乘（Jacobian 坐标，模逆 `pow(a,-1,P)`）
- 公钥地址 = `keccak256(x||y)[-20:]`
- 签名：确定性 nonce `k = keccak(keccak(priv||hash))`，计算 r,s，低 s 归一化 + recovery id

### 2. 手搓 RLP 编码
- 整数字节序、短/长字符串、短/长列表的 RLP 前缀规则（`0x80+len` / `0xb7+len(lb)` / `0xc0` / `0xf7`）
- EIP-155：`v = chain_id*2 + 35 + recovery_id`，签名哈希 = `keccak(rlp(unsigned + [chain_id, '', '']))`

### 3. 交易提交
- `eth_getTransactionCount` 取 nonce → `eth_estimateGas` → `eth_gasPrice`
- `eth_sendRawTransaction` 提交 → 轮询 `eth_call` 验证

**核心调用序列**：
```
1. transferCredit(Setup -> player, 10 ETH)   # 玩家是 relayer，权限通过
2. withdraw(10 ETH)                          # 提走
3. eth_call isSolved() -> true               # 终验
```

## 关键认知

1. 没有库就是最好的库：手搓 ECDSA/RLP 全程无第三方依赖，链交互只走 `jsonrpc` HTTP，在沙箱 curl 受限的环境里是保命技能。
2. 权限模型审计：真正要解的题是"为什么玩家能调 transferCredit"，答案在合约的 access control（relayer 授权），不是密码学。
3. 终验不靠猜：`isSolved()` 必须看到 true，交易入块后还要交叉查 vault 余额，跟真实链上审计一个标准。

## 实战映射

- **链上合约审计**：transferCredit 的 relayer 权限缺陷 = 现实 DeFi 里常见的"谁可以调这个函数"审计点。审计重点永远是 access control + 外部调用重入，而不是花哨密码学。
- **无依赖链上交互**：在生产环境没有装好的 web3 库、或需要审计 SDK 行为时，能手搓签名/RLP 等于不依赖任何中间件直接操作链。对链上资金安全的终验（到账才算）也是真实交易的标准。
- **金融背景加成**：读合约资金流（Setup→Vault→player）跟读资产负债表一个思路，谁授权给谁、钱从哪流向哪、谁有权动，这些判断直接迁移自金融直觉。

## 产物

- `phantom_exploit.py`（完整 exploit，含非确定性 nonce 修复、低 s 归一化、recovery id）
- 提交：平台 challenge attempt → correct
