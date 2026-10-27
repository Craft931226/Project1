import capstone
from pwn import ELF, context

e = ELF('shellcodeultimate', checksec=False)
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
print('=== symbol table ===')
for name, addr in sorted(e.symbols.items(), key=lambda x: x[1]):
    if 0x401100 <= addr < 0x4013b0 and name:
        print(hex(addr), name)

print()
dis(0x4011fb, 0x1a9, 'main')

print('=== 字串 ===')
strs = {
    'banner':      0x40121b + 0xded,
    'banner2':     0x40122a + 0xe0e,
    'err_nop':     0x40126f + 0xdf9,
    'err_syscall': 0x4012b3 + 0xddd,
    'err_int80':   0x4012f7 + 0xdc1,
    'err_marker':  0x40135c + 0xd84,
    'err_marker2': 0x40136b + 0xda0,
}
for name, addr in strs.items():
    print(name, hex(addr), '->', read_str(addr))

print()
print('''=== main() 的過濾邏輯整理（手動從上面反組譯讀出來）===

char buf[0x90];                       // 144 bytes
read(0, buf, 0x78);                   // 讀 120 bytes，buf 夠大，沒有 overflow

// 第一層過濾：掃過全部 120 bytes
for (i = 0; i <= 0x77; i++) {
    if (buf[i] == 0x90)                       exit_with("no NOP sled!!!");      // 禁止 NOP (0x90)
    if (i <= 0x76 && buf[i]==0x0f && buf[i+1]==0x05)
                                               exit_with("no syscall!!!");      // 禁止 0f 05 (syscall)
    if (i <= 0x76 && buf[i]==0xcd && buf[i+1]==0x80)
                                               exit_with("no int 0x80!!!");     // 禁止 cd 80 (int 0x80)
}

// 第二層過濾：每隔 6 bytes 檢查一組「魔法標記」
for (j = 0; j <= 9; j++) {
    idx = 6 * j;                              // 0, 6, 12, ..., 54
    if (!(buf[idx] == 0x0c && buf[idx+1] == 0x87))
                                               exit_with("missing marker!!!"); // 強制要求 or al,0x87
}

void (*fp)() = buf;
fp();                                           // 兩層過濾都通過才會執行 shellcode
''')
