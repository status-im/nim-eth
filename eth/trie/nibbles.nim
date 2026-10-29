# nimbus-eth1
# Copyright (c) 2023-2026 Status Research & Development GmbH
# Licensed under either of
#  * Apache License, version 2.0, ([LICENSE-APACHE](LICENSE-APACHE) or
#    http://www.apache.org/licenses/LICENSE-2.0)
#  * MIT license ([LICENSE-MIT](LICENSE-MIT) or
#    http://opensource.org/licenses/MIT)
# at your option. This file may not be copied, modified, or distributed
# except according to those terms.

{.push raises: [], gcsafe, inline.}

import stew/[arraybuf, bitops2, endians2, staticfor]

export arraybuf

type
  NibblesBuf* = object
    ## Allocation-free type for storing up to 64 4-bit nibbles, as seen in the
    ## Ethereum MPT
    bytes: array[32, byte]
      # Two nibbles per byte, grouped in 8-byte limbs of 16 nibbles each - for
      # buffers shorter than 64 nibbles we make sure the last limb holding any
      # data is zero-padded (so as to avoid UB on uninitialized reads) - for
      # example a buffer holding one nibble will have one fully initialized
      # limb and 3 uninitialized limbs.
    iend: uint8
      # Where valid nibbles can be found - we use indices here to avoid copies
      # wen slicing - iend not inclusive

  HexPrefixBuf* = ArrayBuf[33, byte]

const Limbs = 4

static:
  doAssert sizeof(NibblesBuf) == 33

func high*(T: type NibblesBuf): int =
  63

template limbOf(i: int | uint8): uint8 =
  # In which limb can nibble i be found?
  uint8(i) shr 4 # shr 4 = div 16 = 16 nibbles per limb

template shift(i: int | uint8): uint8 =
  # How many bits to shift to find nibble i within its limb?
  60 - ((uint8(i) mod 16) shl 2) # shl 2 = 4 bits per nibble

proc c_memcpy(dst, src: pointer, n: csize_t): pointer {.
  importc: "memcpy", header: "<string.h>", discardable, noSideEffect.}

template limbNative(r: NibblesBuf, i: untyped): uint64 =
  let pos = uint(i) shl 3
  discard r.bytes[pos + 7]
  var v {.noinit.}: uint64
  c_memcpy(addr v, unsafeAddr r.bytes[pos], csize_t sizeof(v))
  v

template limb(r: NibblesBuf, i: untyped): uint64 =
  toBE(r.limbNative(i))

template setLimbNative(r: var NibblesBuf, i: untyped, v: uint64) =
  let pos = uint(i) shl 3
  discard r.bytes[pos + 7]
  let val = v
  discard c_memcpy(addr r.bytes[pos], unsafeAddr val, csize_t sizeof(val))

template setLimb(r: var NibblesBuf, i: untyped, v: uint64) =
  r.setLimbNative(i, toBE(v))

template storeBE(dst: var array, pos: static int, v: uint64) =
  discard dst[pos + 7]
  let be = toBE(v)
  discard c_memcpy(addr dst[pos], unsafeAddr be, csize_t sizeof(be))

func nibble*(T: type NibblesBuf, nibble: byte): T {.noinit.} =
  result.setLimb(0, uint64(nibble) shl (64 - 4))
  result.iend = 1

func `[]`*(r: NibblesBuf, i: int): byte =
  (r.bytes[i shr 1] shr (4 - ((i and 1) shl 2))) and 0x0f

func `[]=`*(r: var NibblesBuf, i: int, v: byte) =
  let pos = i shr 1
  if (i and 1) == 0:
    r.bytes[pos] = ((v and 0x0f) shl 4) or (r.bytes[pos] and 0x0f)
  else:
    r.bytes[pos] = (r.bytes[pos] and 0xf0) or (v and 0x0f)

func fromBytes*(T: type NibblesBuf, bytes: openArray[byte]): T {.noinit.} =
  if bytes.len >= 32:
    result.iend = 64
    c_memcpy(addr result.bytes[0], unsafeAddr bytes[0], 32)
  else:
    let blen = bytes.len
    result.iend = uint8(blen * 2)
    result.setLimbNative(blen shr 3, 0'u64)
    if blen > 0:
      c_memcpy(addr result.bytes[0], unsafeAddr bytes[0], csize_t blen)

func len*(r: NibblesBuf): int =
  int(r.iend)

func `$`*(r: NibblesBuf): string =
  result = newStringOfCap(64)
  for i in 0 ..< r.len:
    const chars = "0123456789abcdef"
    result.add chars[r[i]]

func `==`*(lhs, rhs: NibblesBuf): bool =
  if lhs.iend != rhs.iend:
    return false

  staticFor i, 0 ..< Limbs:
    if uint8(i * 16) >= lhs.iend:
      return true
    if lhs.limbNative(i) != rhs.limbNative(i):
      return false
  true

func sharedPrefixLen*(lhs, rhs: NibblesBuf): int =
  let len = min(lhs.iend, rhs.iend)
  staticFor i, 0 ..< Limbs:
    const pos = i * 16

    let diff = lhs.limbNative(i) xor rhs.limbNative(i)
    if (pos + 16) >= len or diff != 0:
      return
        if pos < len:
          let mask =
            if len - pos >= 16:
              0'u64
            else:
              (not 0'u64) shr ((len - pos) * 4)
          pos + leadingZeros(toBE(diff) or mask) shr 2
        else:
          pos

  64

func startsWith*(lhs, rhs: NibblesBuf): bool =
  sharedPrefixLen(lhs, rhs) == rhs.len

func slice*(r: NibblesBuf, ibegin: int, iend = -1): NibblesBuf {.noinit.} =
  let e =
    if iend < 0:
      min(64, r.len + iend + 1)
    else:
      min(64, iend)

  # With noinit, we have to be careful not to read result.bytes
  result.iend = uint8(e - ibegin)

  var ilimb = ibegin.limbOf
  block done:
    let shift = (ibegin mod 16) shl 2
    if shift == 0: # Must be careful not to shift by 64 which is UB!
      staticFor i, 0 ..< Limbs:
        if uint8(i * 16) >= result.iend:
          break done
        result.setLimbNative(i, r.limbNative(ilimb))
        ilimb += 1
    else:
      var cur = r.limb(ilimb)
      staticFor i, 0 ..< Limbs:
        if uint8(i * 16) >= result.iend:
          break done

        ilimb += 1
        let next =
          if (ilimb * 16) < uint8 r.iend:
            r.limb(ilimb)
          else:
            0'u64

        result.setLimb(i, (cur shl shift) or (next shr (64 - shift)))
        cur = next

  if result.iend mod 16 > 0:
    # Clear last limb past iend so that we can compare full limbs
    let
      elimb = result.iend.limbOf
      eshift = result.iend.shift + 4
    result.setLimb(elimb, result.limb(elimb) and (0xffffffffffffffff'u64 shl eshift))

template copyshr(aend: uint8) =
  block adone: # copy aend nibbles of a
    staticFor i, 0 ..< Limbs:
      if uint8(i * 16) >= aend:
        break adone

      result.setLimbNative(i, a.limbNative(i))

  block bdone:
    let shift = (aend mod 16) shl 2

    var alimb = aend.limbOf

    if shift == 0:
      staticFor i, 0 ..< Limbs:
        if uint8(i * 16) >= b.iend:
          break bdone

        result.setLimbNative(alimb, b.limbNative(i))
        alimb += 1
    else:
      # remove the part of a that should be b from the last a limb
      var carry = result.limb(alimb) and ((not 0'u64) shl (64 - shift))

      staticFor i, 0 ..< Limbs:
        if uint8(i * 16) >= b.iend:
          if (alimb * 16) < result.iend:
            result.setLimb(alimb, carry)
          break bdone

        let cur = b.limb(i)
        result.setLimb(alimb, carry or cur shr shift)

        alimb += 1
        carry = cur shl (64 - shift)

      if (alimb * 16) < result.iend:
        result.setLimb(alimb, carry)

func `&`*(a, b: NibblesBuf): NibblesBuf {.noinit.} =
  result.iend = min(64'u8, a.iend + b.iend)

  let aend = a.iend
  copyshr(aend)

func replaceSuffix*(a, b: NibblesBuf): NibblesBuf {.noinit.} =
  if b.iend >= a.iend:
    result = b
  elif b.iend == 0:
    result = a
  else:
    result.iend = a.iend

    let aend = a.iend - b.iend
    copyshr(aend)

func toHexPrefix*(r: NibblesBuf, isLeaf = false): HexPrefixBuf {.noinit.} =
  # We'll adjust to the actual length below, but this hack allows us to write
  # full limbs

  result.n = 33 # careful with noinit, to not call setlen
  let
    limbs = (r.iend + 15).limbOf
    isOdd = (r.iend and 1) > 0

  result[0] = (byte(isLeaf) * 2 + byte(isOdd)) shl 4

  if isOdd:
    result[0] = result[0] or (r.bytes[0] shr 4)

    staticFor i, 0 ..< Limbs:
      if i < limbs:
        let next =
          when i == Limbs - 1:
            0'u64
          else:
            r.limb(i + 1)
        let limb = r.limb(i) shl 4 or next shr 60

        const pos = i * 8 + 1
        result.buf.storeBE(pos, limb)
  else:
    staticFor i, 0 ..< Limbs:
      if i < limbs:
        const
          pos = i * 8 + 1
          src = i * 8
        discard result.buf[pos + 7]
        c_memcpy(addr result.buf[pos], unsafeAddr r.bytes[src], 8)

  result.setLen(int((r.iend shr 1) + 1))

func fromHexPrefix*(
    T: type NibblesBuf, bytes: openArray[byte]
): tuple[isLeaf: bool, nibbles: NibblesBuf] {.noinit.} =
  if bytes.len > 0:
    result.isLeaf = (bytes[0] and 0x20) != 0
    let hasOddLen = (bytes[0] and 0x10) != 0

    if hasOddLen:
      let high = uint8(min(31, bytes.len - 1))
      result.nibbles =
        NibblesBuf.nibble(bytes[0] and 0x0f) &
        NibblesBuf.fromBytes(bytes.toOpenArray(1, int high))
    else:
      result.nibbles = NibblesBuf.fromBytes(bytes.toOpenArray(1, bytes.high()))
  else:
    result.isLeaf = false
    result.nibbles.iend = 0

func getBytes*(a: NibblesBuf): array[32, byte] =
  a.bytes
