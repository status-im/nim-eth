# eth
# Copyright (c) 2024-2025 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option. This file may not be copied, modified, or distributed except according to those terms.

{.push raises: [].}

## Base primitive types used in ethereum, as specified in the execution specs:
## https://github.com/ethereum/execution-specs/
##
## For all of `UInt` and `UIntXX`, we use native `uintXX` types and/or `stint`.
##
## In the specification `UInt` is often used to denote an unsigned
## arbitrary-precision integers - in actual code we opt for a bounded type
## instead depending on "reasonable bounds", ie bounds that are unlikely to be
## exceeded in the foreseeable future.

import
  std/[hashes, macros, typetraits],
  stint,
  results,
  stew/[assign2, byteutils, endians2, staticfor]

export stint, hashes, results

type
  FixedBytes*[N: static int] = distinct array[N, byte]
    ## Fixed-length byte sequence holding arbitrary data
    ## https://github.com/ethereum/execution-specs/blob/51fac24740e662844446439ceeb96a460aae0ba0/src/ethereum/base_types.py
    ##
    ## This type is specialized to `Bytes4`, `Bytes8` etc below.
    # A distinct array is used to avoid copying on trivial type conversions
    # to and from other array-based types

  ChainId* = UInt256
    ## Chain identifier used for transaction signing to guard against replay
    ## attacks between networks
    ##
    ## https://github.com/ethereum/EIPs/blob/master/EIPS/eip-155.md

  NetworkId* = UInt256
    ## Network identifier - similar to chain id but used for network
    ## communication to ensure connectivity with peers on the same network.
    ## Often has the same value as ChainId, but not always

  GasInt* = uint64
    ## Integer used to comput gas usage in individual blocks / transactions -
    ## here, a smaller type is convenient since gas computations are expensive.
    ##
    ## Care must be taken since the sum of gas usage across many blocks may
    ## exceed the uint64 range.
    ##
    ## See also:
    ## * https://github.com/status-im/nimbus-eth1/issues/35

template to*[N: static int](v: array[N, byte], T: type FixedBytes[N]): untyped =
  # using a typed return here runs into an assortment of generics bugs when the
  # compiler fails to instantiate N
  FixedBytes[sizeof(v)](v)

template data*[N: static int](v: FixedBytes[N]): array[N, byte] =
  distinctBase(v)

template `data=`*[N: static int](a: FixedBytes[N], b: array[N, byte]) =
  assign(distinctBase(a), b)

func copyFrom*[N: static int](T: type FixedBytes[N], v: openArray[byte], start = 0): T =
  ## Copy up to N bytes from the given openArray, starting at `start` and
  ## filling any missing bytes with zero.
  ##
  ## This is a lenient function in that `v` may contain both fewer and more
  ## bytes than N and start might be out of bounds.
  if v.len > start:
    let n = min(N, v.len - start)
    assign(result.data.toOpenArray(0, n - 1), v.toOpenArray(start, start + n - 1))

template default*[N](T: type FixedBytes[N]): T =
  # Avoid bad codegen where fixed bytes are zeroed byte-by-byte at call site
  const def = system.default(T)
  def

func `==`*(a, b: FixedBytes): bool {.inline.} =
  equalMem(addr a.data[0], addr b.data[0], a.N)

func hash*[N: static int](v: FixedBytes[N]): Hash {.inline.} =
  copyMem(addr result, addr v.data[0], min(N, sizeof(Hash)))

  when N > sizeof(Hash):
    var tmp: Hash
    staticFor i, 1 ..< N div sizeof(Hash):
      copyMem(addr tmp, addr v.data[i * sizeof(Hash)], sizeof(Hash))
      result = result !& tmp
    const last = N mod sizeof(Hash)
    when last > 0:
      copyMem(addr tmp, addr v.data[N - last], last)
      result !& tmp

func toHex*(v: FixedBytes): string =
  ## Convert to lowercase hex without 0x prefix
  toHex(v.data)

func to0xHex*(v: FixedBytes): string =
  ## Convert to lowercase hex with 0x prefix
  to0xHex(v.data)

func `$`*(v: FixedBytes): string =
  ## Convert the given value to a string representation suitable for presentation
  ## To convert to a specific string encoding, use `toHex`, `to0xHex` etc
  to0xHex(v)

func fromHex*(T: type FixedBytes, c: openArray[char]): T {.raises: [ValueError].} =
  ## Parse a string as hex after optionally stripping "0x", raising ValueError if:
  ## * the string is too long or to short
  ## * the string can't be parsed as hex
  T(hexToByteArrayStrict(c, T.N))

template makeFixedBytesN(N: static int) =
  # Create specific numbered instantiations along with helpers
  type `Bytes N`* = FixedBytes[N]

  const `zeroBytes N`* = system.default(`Bytes N`)
  template default*(T: type `Bytes N`): `Bytes N` =
    # reuse single constant for precomputed N
    `zeroBytes N`

  template `bytes N`*(s: static string): `Bytes N` =
    `Bytes N`.fromHex(s)

makeFixedBytesN(4)
makeFixedBytesN(8)
makeFixedBytesN(20)
makeFixedBytesN(32)
makeFixedBytesN(48)
makeFixedBytesN(64)
makeFixedBytesN(96)
makeFixedBytesN(256)

# Ethereum keeps integers as big-endian
template to*(v: uint32, T: type Bytes4): T =
  T v.toBytesBE()

template to*(v: Bytes4, T: type uint32): T =
  T.fromBytesBE(v)

template to*(v: uint64, T: type Bytes8): T =
  T v.toBytesBE()

template to*(v: Bytes8, T: type uint64): T =
  T.fromBytesBE(v)

template to*[M, N: static int](v: FixedBytes[M], T: type StUint[N]): T =
  static:
    assert N == M * 8
  T.fromBytesBE(v.data)

template to*[M, N: static int](v: StUint[M], T: type FixedBytes[N]): T =
  static:
    assert N * 8 == M
  T v.toBytesBE()

type
  # Aliases commonly found in the spec - reasons to use an alias instead of the
  # underlying type include:
  # * the spec says `UInt` and we use a bounded type instead (uint64 or UInt256)
  # * the spec consistently uses the alias and we're translating from there
  #   directly
  # * we have distinct behaviour attached to it that shouldn't "pollute" other
  #   usages of the same type - `$` is the canonical example
  # * the algorithm is specific to ethereum and not of "general interest"
  #
  # In most other cases, code is easier to read and more flexible when it
  # doesn't use these aliases.
  AccountNonce* = uint64
  BlockNumber* = uint64
  Bloom* = Bytes256
  Bytes* = seq[byte] # TODO distinct?
  KzgCommitment* = Bytes48
  KzgProof* = Bytes48

  ForkID* = tuple[crc: uint32, nextFork: uint64] ## EIP 2364/2124

func chainId*(x: SomeInteger): ChainId =
  x.u256
