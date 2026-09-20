# Hells Bells

**Category:** Pwn 
**Difficulty:** Medium 
**Author:** WubberDuckkie

## Description
Our breaching team keeps its charges in a little inventory manager — plant a charge, rewire it, inspect it, defuse it when you're done. The quartermaster swears you can't touch a charge once it's defused. He's wrong.

## Vulnerability
The challenge contains a use-after-free: freed objects can still be read and invoked, leaking libc and letting us reuse a freed chunk's function pointer.

## Exploitation
The vulnerability can be exploited by leaking libc through an unsorted-bin chunk, then reclaiming a freed object to overwrite its handler and call system("/bin/sh").

## Techniques
    Use-After-Free
    Unsorted-bin libc leak
    Heap chunk reuse
    Function-pointer hijack

