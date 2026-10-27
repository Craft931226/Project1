import capstone
from pwn import ELF

e = ELF('shellcode', checksec=False)
md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)


def dis(addr, size, name):
    print(f'--- {name} @ {hex(addr)} ---')
    code = e.read(addr, size)
    for ins in md.disasm(code, addr):
        print(f'{ins.address:#x}: {ins.mnemonic} {ins.op_str}')
    print()


def read_str(addr):
    data = e.read(addr, 128)
    return data.split(b'\x00')[0]


print('=== checksec ===')
print(e.checksec())

print()
print('=== symbol table (.text 範圍) ===')
for name, addr in sorted(e.symbols.items(), key=lambda x: x[1]):
    if 0x401000 <= addr < 0x401240 and name:
        print(hex(addr), name)

print()
dis(0x4011db, 0x40123c - 0x4011db, 'main')

print('=== 字串 ===')
print('banner', hex(0x402008), '->', read_str(0x402008))
