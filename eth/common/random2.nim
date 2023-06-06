# nim-eth
# Copyright (c) 2020-2023 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option. This file may not be copied, modified, or distributed except according to those terms.
#

{.push raises: [].}

import bearssl/rand

type SecureRngContext* = HmacDrbgContext

proc newRng*(): ref SecureRngContext =
  # You should only create one instance of the RNG per application / library
  # Ref is used so that it can be shared between components
  SecureRngContext.new()

## Random helpers: similar as in stdlib, but with SecureRngContext rng
# TODO: Move these somewhere else?
const randMax = 18_446_744_073_709_551_615'u64

proc rand*(rng: var SecureRngContext, max: Natural): int =
  if max == 0: return 0

  var x: uint64
  while true:
    rng.generate(x)
    if x < randMax - (randMax mod (uint64(max) + 1'u64)): # against modulo bias
      return int(x mod (uint64(max) + 1'u64))

proc sample*[T](rng: var SecureRngContext, a: openArray[T]): T =
  a[rng.rand(a.high)]

proc shuffle*[T](rng: var SecureRngContext, a: var openArray[T]) =
  for i in countdown(a.high, 1):
    let j = rng.rand(i)
    swap(a[i], a[j])
