import capstone
from pwn import ELF

e = ELF('cheer_for_kotone', checksec=False)
md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)


def dis(addr, size, name):
    print(f'--- {name} @ {hex(addr)} ---')
    code = e.read(addr, size)
    for ins in md.disasm(code, addr):
        print(f'{ins.address:#x}: {ins.mnemonic} {ins.op_str}')


def read_str(addr):
    data = e.read(addr, 64)
    return data.split(b'\x00')[0]


print('=== symbol table (.text 範圍) ===')
for name, addr in sorted(e.symbols.items(), key=lambda x: x[1]):
    if 0x401000 <= addr < 0x401400 and name:
        print(hex(addr), name)

print()
dis(0x40125b, 0x401360 - 0x40125b, 'shukishukidaishuki')
print()
dis(0x40127f, 0x401360 - 0x40127f, 'main')

print()
print('=== 字串 (lea rax,[rip+off] 算出來的實際位址) ===')
strs = {
    'prompt1': 0x401295 + 7 + 0xd74,
    'prompt2': 0x4012a4 + 7 + 0xd85,
    'scanf_fmt': 0x4012ba + 7 + 0xd91,
    'errmsg_len1': 0x4012e0 + 7 + 0xd71,
    'errmsg_len2': 0x4012ef + 7 + 0x13fe,
    'errmsg_len3': 0x4012fe + 7 + 0x1405,
    'secret_string': 0x40131b + 7 + 0x13f6,
    'errmsg_cmp1': 0x401331 + 7 + 0x13f3,
    'errmsg_cmp2': 0x401340 + 7 + 0x1401,
    'shuki_bin_sh': 0x40126d + 7 + 0xd94,
}
for name, addr in strs.items():
    print(name, hex(addr), '->', read_str(addr))
