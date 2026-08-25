# Brunner Stocks

**Category:** Pwn
**Difficulty:** Easy-Medium
**Author:** Vincent

## Description

Brunnerne Inc. released an automated stock trading algorithm. After answering a survey about your investment preferences, you receive a customized trading algorithm.

## Vulnerability

The challenge contains a **stack-based buffer overflow** that allows us to overwrite the return address and control program execution.

## Exploitation

The vulnerability can be exploited using **ret2shellcode**, redirecting execution to shellcode placed in a controllable memory region.

## Techniques

* Buffer Overflow
* ret2shellcode
* Shellcode
