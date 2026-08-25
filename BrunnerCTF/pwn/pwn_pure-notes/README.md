# Pure Notes

**Category:** Pwn
**Difficulty:** Medium-Hard
**Author:** Vincent

## Description

The existing note-taking solution wasn't productive or functional enough, so a new purely functional note-taking application was created.

## Vulnerabilities

The challenge involves a **heap use-after-free** vulnerability that can be exploited through **tcache poisoning**.

## Exploitation

By triggering a use-after-free condition, freed heap memory can be accessed and manipulated. This can then be leveraged to perform **tcache poisoning** and gain control over a target heap allocation.

## Techniques

* Heap Exploitation
* Use-After-Free
* Tcache Poisoning
* Haskell
