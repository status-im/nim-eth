# Copyright (c) 2022 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option. This file may not be copied, modified, or distributed except according to those terms.

when (NimMajor, NimMinor) < (1, 4):
  {.push raises: [Defect].}
else:
  {.push raises: [].}

## keccak256 is used across ethereum as the "default" hash function and this
## module provides a type and some helpers to produce such hashes

import
  nimcrypto/[keccak, hash]

export
  keccak.update, keccak.finish, hash

type
  KeccakHash* = MDigest[256]
    ## A hash value computed using keccak256
    ## note: this aliases Eth2Digest too, which uses a different hash!

template withKeccakHash*(body: untyped): KeccakHash =
  ## This little helper will init the hash function and return the sliced
  ## hash:
  ## let hashOfData = withHash: h.update(data)
  block:
    var h {.inject.}: keccak256
    # init(h) # not needed for new instance
    body
    finish(h)

func keccakHash*(input: openArray[byte]): KeccakHash =
  keccak256.digest(input)
func keccakHash*(input: openArray[char]): KeccakHash =
  keccak256.digest(input)

func keccakHash*(a, b: openArray[byte]): KeccakHash =
  withKeccakHash:
    h.update a
    h.update b
