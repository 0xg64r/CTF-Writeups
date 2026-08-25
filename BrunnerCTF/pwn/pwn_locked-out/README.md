# Locked Out

**Category:** Pwn
**Difficulty:** Medium
**Authors:** Togby & Nissen

## Description

After Brunnerne Inc. refused to raise the bakers' wages, the workers went on strike. Management responded by locking everyone out and changing their PIN codes.

Unfortunately, there is still a piece of brunsviger waiting inside.

## Vulnerabilities

The challenge contains multiple vulnerabilities that can be chained together:

* Format String
* Buffer Overflow
* Canary Leak
* ret2win

## Exploitation

The format string vulnerability can be used to leak important stack values, including the **stack canary**. The canary can then be preserved while exploiting the buffer overflow to overwrite the return address and redirect execution to the `win()` function.

## Techniques

* Format String Leak
* Canary Leak
* Buffer Overflow
* ret2win
