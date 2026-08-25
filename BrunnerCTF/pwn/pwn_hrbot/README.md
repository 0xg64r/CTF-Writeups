# HRBot

**Category:** Pwn
**Difficulty:** Beginner
**Author:** olexmeister

## Description

BrunnerCorp introduces **HRBot**, their automated HR system for handling employee cases.

## Vulnerability

The challenge contains a **stack-based buffer overflow** that allows us to overwrite the saved return address.

## Exploitation

The vulnerability can be exploited using a **ret2win** technique by overwriting the return address with the address of the `win()` function.

## Techniques

* Buffer Overflow
* ret2win
* Stack-based exploitation
