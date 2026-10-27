import capstone
from pwn import ELF, context

e = ELF('son', checksec=False)
context.binary = e
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


print('=== checksec (son) ===')
print(e.checksec())

print()
print('=== symbol table（挑出題目自己的函式） ===')
for name, addr in sorted(e.symbols.items(), key=lambda x: x[1]):
    if 0x401200 <= addr < 0x4014c0 and name:
        print(hex(addr), name)

print()
dis(0x4012e2, 0x40130e - 0x4012e2, 'gadget')
dis(0x40130e, 0x4013a5 - 0x40130e, 'child')
dis(0x4013a5, 0x40141a - 0x4013a5, 'parent')
dis(0x40141a, 0x4014b4 - 0x40141a, 'main')

print('=== 字串 ===')
strs = {
    'child_banner1': 0x401330 + 0xcd4,
    'child_banner2': 0x40133f + 0xce2,
    'child_fmt1':    0x401364 + 0xcd0,
    'child_fmt2':    0x40137f + 0xcc2,
    'child_banner3': 0x401393 + 0xcb1,
    'parent_banner1': 0x4013c7 + 0xc7e,
    'parent_banner2': 0x4013d6 + 0xc4b,
    'parent_bye':     0x4013fb + 0xc62,
}
for name, addr in strs.items():
    print(name, hex(addr), '->', read_str(addr))

print()
print('=== PLT / GOT（ret2libc 會用到） ===')
print('plt.puts', hex(e.plt['puts']))
print('got.puts', hex(e.got['puts']))
print('plt.read', hex(e.plt['read']))
print('pop_rdi gadget（借用 gadget() 函式裡現成的）', hex(0x4012f5))
print('單獨的 ret gadget（gadget() 函式裡 pop_rdi 後面那個 byte）', hex(0x4012f6))
print('parent() 進入點（之後 ret2self 會用到）', hex(0x4013a5))

print()
print('=== libc.so.6（題目附帶，Ubuntu GLIBC 2.35） ===')
libc = ELF('libc.so.6', checksec=False)
print('system', hex(libc.symbols['system']))
print('puts', hex(libc.symbols['puts']))
binsh = next(libc.search(b'/bin/sh\x00'))
print('/bin/sh', hex(binsh))
