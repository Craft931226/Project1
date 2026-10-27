import capstone
from pwn import ELF, context

e = ELF('portal_gun', checksec=False)
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


print('=== checksec ===')
print(e.checksec())

print()
print('=== symbol table（挑出題目自己的函式與關鍵全域變數） ===')
for name, addr in sorted(e.symbols.items(), key=lambda x: x[1]):
    if 0x401200 <= addr < 0x4013a0 and name:
        print(hex(addr), name)
print('dimensions (.bss 全域陣列)', hex(e.symbols['dimensions']))

print()
dis(0x40125b, 0x4012a7 - 0x40125b, 'szechuan_sauce')
dis(0x4012a7, 0x40139c - 0x4012a7, 'main')

print('=== 字串 ===')
strs = {
    'szechuan_s1':   0x40126a + 0xd9e,
    'szechuan_s2':   0x401274 + 0xdd1,
    'szechuan_path': 0x40129c + 0xdac,
    'main_banner1':  0x4012d3 + 0xd7d,
    'main_banner2':  0x4012e2 + 0xdaa,
    'scanf_fmt1':    0x4012fd + 0xda7,
    'easter_egg':    0x401325 + 0xd83,
    'main_banner3':  0x401334 + 0xdbc,
    'scanf_fmt2':    0x401362 + 0xdba,
    'main_banner4':  0x401376 + 0xdb2,
}
for name, addr in strs.items():
    print(name, hex(addr), '->', read_str(addr))

print()
print('=== GOT（任意寫入要蓋的目標） ===')
print('got.puts', hex(e.got['puts']))
print('got.printf', hex(e.got['printf']))
print('szechuan_sauce (win function)', hex(0x40125b))

print()
print('=== 算出 "蓋 got.puts" 需要的 index n ===')
dims_base = e.symbols['dimensions']
got_puts = e.got['puts']
n = (got_puts - dims_base) // 8
print('dimensions base', hex(dims_base))
print('got.puts       ', hex(got_puts))
print('n =', n, ' (dimensions_base + n*8 == got.puts ?', hex(dims_base + n * 8) == hex(got_puts), ')')
print('要寫入的值 = szechuan_sauce 的位址，十進位 =', 0x40125b)
