# eth
# Copyright (c) 2024 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option. This file may not be copied, modified, or distributed except according to those terms.

{.push raises: [].}

# Minimal compatibility layer with earlier versions of this file, to be removed
# when users have upgraded

{.deprecated.}

import ./[addresses, hashes]

export hashes

from nimcrypto import MDigest

type
  Hash256* {.deprecated.} = Hash32
  KeccakHash* {.deprecated.} = Hash32

template keccakHash*(v: openArray[byte]): Hash32 {.deprecated.} =
  keccak256(v)

template keccakHash*(v: Address): Hash32 {.deprecated.} =
  keccak256(v.data)

from nimcrypto/hash import MDigest

# TODO https://github.com/nim-lang/Nim/issues/24241
when (NimMajor, NimMinor) >= (2, 12) or defined(ethDigestConverterWarning):
  {.pragma: convdeprecated, deprecated.}
else:
  {.pragma: convdeprecated.}

converter toMDigest*(v: Hash32): MDigest[256] {.convdeprecated.} =
  MDigest[256](data: v.data)
