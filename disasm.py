from pwn import ELF
import capstone

e = ELF('pwn101', checksec=False)   # 讀取 ELF 檔案結構
for name, addr in sorted(e.symbols.items(), key=lambda x: x[1]):
    if 0x401000 <= addr < 0x402500 and name:
        print(hex(addr), name)
md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)  # x86-64 反組譯器

print('--- sakidaisuki ---')
code = e.read(0x4011fb, 0x24)       # 讀出這個位址的原始 bytes
for ins in md.disasm(code, 0x4011fb):
    print(f'{ins.address:#x}: {ins.mnemonic} {ins.op_str}') # 印出位址 + 組合語言指令

print('--- main ---')
code = e.read(0x40121f, 0x4d)       # main 到下一個 symbol (_fini) 之間的長度
for ins in md.disasm(code, 0x40121f):
    print(f'{ins.address:#x}: {ins.mnemonic} {ins.op_str}')