#!/usr/bin/env python3
# The Last Bitbender — transform 核心还原 (Heaven's Gate shellcode 逆向产物)
# 输入 16 字节 -> 输出 16 字节; 服务端黑盒: 给请求返回 transform(请求)
# 用法: 连接 socket 服务, 每轮抓 32 hex 请求 -> transform() 应答 -> 收 flag

M = (1 << 64) - 1

def rol64(x, n): return ((x << n) | (x >> (64 - n))) & M

def transform(inp16):
    """还原自 Heaven's Gate shellcode: 白化 + F(乘低32/rol13/xor) + mixup(MurmurHash3 常数)"""
    assert len(inp16) == 16
    A = int.from_bytes(inp16[0:8], 'little') ^ 0xa6f1c0d93b5e2748
    B = int.from_bytes(inp16[8:16], 'little')
    # core F: A += (A&0xffffffff)*(B&0xffffffff); B=rol(B,13); A^=B
    A = (A + ((A & 0xffffffff) * (B & 0xffffffff) & 0xffffffffffffffff)) & M
    B = rol64(B, 13)
    A ^= B
    # layer mixup: B=rol(B+A,29)*0xff51afd7ed558ccd; A=rol(A+B,17)
    B = (B + A) & M
    B = rol64(B, 29)
    B = (B * 0xff51afd7ed558ccd) & M
    A = (A + B) & M
    A = rol64(A, 17)
    out1 = ((A ^ B) & M).to_bytes(8, 'little')
    out2 = ((A + B) & M).to_bytes(8, 'little')
    return out1 + out2

if __name__ == '__main__':
    # 平台自检向量 (shellcode 内置)
    target = bytes.fromhex('023a3db6ab0ec7efd2babd484c91f80f')
    inp = bytes.fromhex('9c41e07db2f5361a8ad30c47e961b5f2')
    got = transform(inp)
    print('self-test:', got.hex(), 'MATCH' if got == target else 'FAIL')
