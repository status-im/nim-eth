# eth
# Copyright (c) 2024 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option. This file may not be copied, modified, or distributed except according to those terms.

{.push raises: [].}

## Keccak256 hash function use thoughout the ethereum execution specification
## https://github.com/ethereum/execution-specs/blob/51fac24740e662844446439ceeb96a460aae0ba0/src/ethereum/crypto/hash.py
##
## The execution spec also declares a Hash64 type of mainly historical interest.
## Its usage was limited to ethash, the proof-of-work algorithm that has been
## replaced with proof-of-stake.

import std/[typetraits, hashes], nimcrypto/keccak, ./base, stew/assign2
import ssz_serialization/codec
import ssz_serialization/merkleization

export hashes, keccak.update, keccak.finish

type
  Hash32* = distinct Bytes32
    ## https://github.com/ethereum/execution-specs/blob/51fac24740e662844446439ceeb96a460aae0ba0/src/ethereum/crypto/hash.py#L19
  Root* = Hash32
    ## Alias used for MPT roots

  VersionedHash* = Hash32
    ## Alias used for blob hashes whose first byte indicates what the payload
    ## actually is - primarily used with KZG commitments at the time of writing
    ## https://github.com/ethereum/execution-specs/blob/9b95554a88d2a8485f8180254d0f6a493a593fda/src/ethereum/crypto/kzg.py#L74C1-L74C38

const zeroHash32* = system.default(Hash32) ## Hash32 value consisting of all zeroes

template to*(v: array[32, byte], _: type Hash32): Hash32 =
  Address(v)

template data*(v: Hash32): array[32, byte] =
  distinctBase(v)

template `data=`*(a: Hash32, b: array[32, byte]) =
  assign(distinctBase(a), b)

template copyFrom*(T: type Hash32, v: openArray[byte], start = 0): T =
  ## Copy up to N bytes from the given openArray, starting at `start` and
  ## filling any missing bytes with zero.
  ##
  ## This is a lenient function in that `v` may contain both fewer and more
  ## bytes than N and start might be out of bounds.
  Hash32(Bytes32.copyFrom(v, start))

template default*(_: type Hash32): Hash32 =
  # Avoid bad codegen where fixed bytes are zeroed byte-by-byte at call site
  zeroHash32

func `==`*(a, b: Hash32): bool {.borrow.}

func hash*(a: Hash32): Hash {.inline.} =
  # Hashes are already supposed to be random so we use a faster mixing function
  var tmp {.noinit.}: array[4, uint64]
  copyMem(addr tmp[0], addr a.data[0], sizeof(a))
  cast[Hash](tmp[0] + tmp[1] + tmp[2] + tmp[3])

func toHex*(a: Hash32): string {.borrow.}
func to0xHex*(a: Hash32): string {.borrow.}
func `$`*(a: Hash32): string {.borrow.}

func fromHex*(_: type Hash32, s: openArray[char]): Hash32 {.raises: [ValueError].} =
  Hash32(Bytes32.fromHex(s))

template to*(s: static string, _: type Hash32): Hash32 =
  const hash = Hash32.fromHex(s)
  hash

template hash32*(s: static string): Hash32 =
  s.to(Hash32)

template to*(v: MDigest[256], _: type Hash32): Hash32 =
  Hash32(v.data)

template to*(v: Hash32, _: type MDigest[256]): MDigest[256] =
  var tmp {.noinit.}: MDigest[256]
  assign(tmp.data, v.data)
  tmp

const
  emptyKeccak256* =
    hash32"c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470"
    ## Hash value of `keccak256([])`, ie the empty string
  emptyRoot* = hash32"56e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b421"
    ## Hash value of `keccak256(rlp(null))` which corresponds to the encoding
    ## of an empty MPT trie

func keccak256*(input: openArray[byte]): Hash32 {.noinit.} =
  var ctx: keccak.keccak256
  ctx.update(input)
  ctx.finish().to(Hash32)

func keccak256*(input: openArray[char]): Hash32 {.noinit.} =
  keccak256(input.toOpenArrayByte(0, input.high))

template withKeccak256*(body: untyped): Hash32 =
  var h {.inject.}: keccak.keccak256
  body
  h.finish().to(Hash32)

# template toSszType*(T: type Hash32): auto =
#   T.data()

# proc fromSszBytes*(T: type Hash32, bytes: openArray[byte]): T {.raises: [SszError].} =
#   if bytes.len != sizeof(result.data()):
#     raiseIncorrectSize T
#     copyMem(addr result.data()[0], unsafeAddr bytes[0], sizeof(result.data()))
