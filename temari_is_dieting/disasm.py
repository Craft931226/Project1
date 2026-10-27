import capstone
from pwn import ELF

e = ELF('temari_is_dieting', checksec=False)
md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)


def dis(addr, size, name):
    print(f'--- {name} @ {hex(addr)} ---')
    code = e.read(addr, size)
    for ins in md.disasm(code, addr):
        print(f'{ins.address:#x}: {ins.mnemonic} {ins.op_str}')


def read_str(addr):
    data = e.read(addr, 128)
    return data.split(b'\x00')[0]


print('=== checksec ===')
print(e.checksec())

print()
print('=== symbol table (.text 範圍) ===')
for name, addr in sorted(e.symbols.items(), key=lambda x: x[1]):
    if 0x401100 <= addr < 0x4014c0 and name:
        print(hex(addr), name)

print()
dis(0x4012bb, 0x4012dc - 0x4012bb, 'caught')
print()
dis(0x4012dc, 0x40130f - 0x4012dc, 'luna_say_maybe')
print()
dis(0x40130f, 0x401326 - 0x40130f, 'to_ulong')
print()
dis(0x401326, 0x4014b4 - 0x401326, 'main')

print()
print('=== 字串 (lea rax,[rip+off] 算出來的實際位址) ===')
strs = {
    'caught_msg':    0x4012ca + 0xd3e,
    'luna_banner':   0x4012eb + 0xd55,
    'luna_bin_sh':   0x401304 + 0xd7f,
    'main_banner1':  0x40133e + 0xd4d,
    'main_banner2':  0x40134d + 0xd53,
    'main_banner3':  0x40135c + 0xdbc,
    'main_prompt1':  0x40136e + 0xde5,
    'newline_sep':   0x4013ac + 0xdad,
    'secret_string': 0x4013c7 + 0xd94,
    'main_banner4':  0x4013e2 + 0xd86,
    'main_banner5':  0x4013f1 + 0xdb7,
    'main_prompt2':  0x401400 + 0xdd0,
    'scanf_fmt':     0x40141b + 0xdde,
    'err_scanf':     0x401434 + 0xdcc,
    'err_toolarge':  0x401455 + 0xdd3,
    'main_prompt3':  0x401473 + 0xde5,
    'main_final':    0x4014a5 + 0xdfa,
}
for name, addr in strs.items():
    print(name, hex(addr), '->', read_str(addr))
