# Three memory-safety issues in Gurux GuruxDLMS.c, fixed in 9.0.2608.1701

**Author:** Adam Bedard, Security Researcher
**Product:** Gurux GuruxDLMS.c, the ANSI C DLMS/COSEM library (https://github.com/Gurux/GuruxDLMS.c)
**Affected:** versions before 9.0.2608.1701 (confirmed on commit `b14e6e0`)
**Fixed:** 9.0.2608.1701, commit [`4046d8bfc7`](https://github.com/Gurux/GuruxDLMS.c/commit/4046d8bfc70807992b6d310db24b8be2b307312f) (2026-08-17)
**Published:** 2026-11-11

If you build on GuruxDLMS.c, update to 9.0.2608.1701 or later. The repository has no release
tags; the fix is the commit above. The 9.0.2608.1701 release tip is the later commit `11a4fefe69`,
which contains the fix but does not change any of the affected code itself.

| # | CVE | Function | Type | CVSS 3.1 |
|---|---|---|---|---|
| 1 | Requested from MITRE | `cosem_setPushSetup()` | Heap buffer over-read and out-of-bounds write | 7.5 `AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H` |
| 2 | Requested from MITRE | `cosem_copyIP6Address()` | Heap buffer overflow | 9.1 `AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:H` |
| 3 | Requested from MITRE | `apdu_parsePDU()` | Out-of-bounds write inside the settings structure | 9.1 `AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:H` |

CVE IDs have been requested from MITRE and will be added here when assigned. Code execution was not
demonstrated for any of the three. The scores assume an unciphered deployment.

## 1. `cosem_setPushSetup()`: copy from the buffer struct instead of its data

`development/src/gxsetmalloc.c`, Push Setup (interface class 40) attribute 10, push protection
parameters. Each of the neighbouring copies reads from `tmp->byteArr->data`. The recipient system
title copy read from `tmp->byteArr`, the address of the `gxByteBuffer` structure itself:

```c
memcpy(p->recipientSystemTitle, tmp->byteArr, bb_size(tmp->byteArr));
```

The length comes from the message. `recipientSystemTitle` is 8 bytes, so a longer octet string
reads past the end of the buffer structure and writes past the end of the heap-allocated protection
parameters object. The bytes written come from adjacent heap memory, not from the message, so the
attacker controls the length but not the contents.

**Reach.** `notify_parsePush()` creates the object class named in an incoming DataNotification
and sets the requested attribute from message data, with no authentication on an unciphered push.
An application that parses pushes with it (typically a head-end or data concentrator) can be
driven into this copy by anything able to send it a push. The same function is reached by a SET
request on an established association. This path was traced in source; the proof below calls
`cosem_setPushSetup()` directly.

**Fix.** The copy now reads `tmp->byteArr->data`, and a length other than 8 is rejected. The same
check was added to the originator system title.

## 2. `cosem_copyIP6Address()`: no bound on the IPv6 address length

`development/src/gxsetmalloc.c`, called by `cosem_setIP6Setup()` for the IPv6 Setup (interface
class 48) address attributes. The destination is a 16-byte `IN6_ADDR` allocated per entry; the
copy used the length from the message:

```c
memset(target, 0, sizeof(IN6_ADDR));
memcpy(target, bb->data, bb->size);
```

An address octet string longer than 16 bytes overflows the heap allocation with bytes the
attacker supplies. The no-malloc variant in `gxsetignoremalloc.c` had the same copy.

**Reach.** A SET request on an established association. Because `notify_parsePush()` uses the same
`cosem_setValue()` dispatch as in issue 1, a push naming an IPv6 Setup object reaches it as well.
This path was traced in source; the proof below calls `cosem_setIP6Setup()` directly.

**Fix.** Both copies now reject any address that is not exactly 16 bytes.

## 3. `apdu_parsePDU()`: calling-AP-title length checked only when ciphered

`development/src/apdu.c`, server-side parsing of the calling-AP-title (tag `0xA6`) in an AARQ:

```c
if (ciphered && len != 8) { /* reject */ }
bb_get(buff, settings->sourceSystemTitle, len);
```

For an unciphered AARQ, which is what an unauthenticated client sends to open an association, the
check is skipped and up to 255 bytes are copied into the 8-byte `sourceSystemTitle`. The write
stays inside the `dlmsSettings` structure but overwrites the fields that follow it, including
security and ciphering state, before any association exists.

**Fix.** The length check now applies whether or not the AARQ is ciphered.

## How these were verified

Each issue was reproduced against the library built with its own makefile and AddressSanitizer,
calling the real library functions (`cosem_setPushSetup()`, `cosem_setIP6Setup()` and
`apdu_parsePDU()`). Issues 1 and 2 produce heap-buffer-overflow reports at the
copy. Issue 3 stays inside one structure, so AddressSanitizer does not flag it; it was shown by
filling the bytes after the field with a marker and confirming the message bytes overwrote
exactly the expected range. The fixes in 9.0.2608.1701 were reviewed in source.

## Timeline

| Date | Event |
|---|---|
| 2026-08-12 | Reported to Gurux by email; acknowledged the same day |
| 2026-08-17 | Fixes released in 9.0.2608.1701 (fix commit `4046d8bfc7`) |
| 2026-08-22 | Fixes reviewed by the reporter |
| 2026-11-11 | CVE IDs requested from MITRE (Gurux is not a CNA) |
| 2026-11-11 | This advisory published |

## Credit

Adam Bedard, Security Researcher
