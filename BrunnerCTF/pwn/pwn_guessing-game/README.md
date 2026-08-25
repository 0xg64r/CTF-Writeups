# Guessing Game

**Category:** Pwn
**Difficulty:** Hard
**Author:** Vincent

## Description

A company is hosting a contest to win a new laptop, but despite winning the game, the prize is never paid out. The program is vulnerable and can be exploited to take control of the application.

## Vulnerabilities

The challenge relies on an **out-of-bounds memory access** in the guessing mechanism, allowing arbitrary memory values to be inferred and modified.

This can be leveraged to:

* Leak a **stack address**
* Leak a **libc address**
* Calculate the **libc base**
* Modify memory to construct a **ROP/one-gadget based control-flow hijack**

## Techniques

* Out-of-Bounds Memory Access
* Stack Leak
* Libc Leak
* Arbitrary Memory Write
* One Gadget
* ret2libc
