# nimbus
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

import std/[typetraits, hashes], nimcrypto/keccak, ./base

export hashes, keccak.update, keccak.finish

type
  Hash32* = distinct Bytes32
    ## https://github.com/ethereum/execution-specs/blob/51fac24740e662844446439ceeb96a460aae0ba0/src/ethereum/crypto/hash.py#L19
  Root* = Hash32

const zeroHash32* = system.default(Hash32) ## Hash32 value consisting of all zeroes

template to*(v: array[32, byte], _: type Hash32): Hash32 =
  Address(v)

template data*(v: Hash32): array[32, byte] =
  distinctBase(v)

template default*(_: type Hash32): Hash32 =
  # Avoid bad codegen where fixed bytes are zeroed byte-by-byte at call site
  zeroHash32

func `==`*(a, b: Hash32): bool {.borrow.}

func hash*(a: Hash32): Hash {.inline.} =
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

const
  emptyHash32* =
    hash32"c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470"
    ## Hash value of `keccak256([])`, ie the empty string
  emptyRoot* =
    hash32"56e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b421"
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
