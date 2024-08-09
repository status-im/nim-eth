# Copyright (c) 2022 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option. This file may not be copied, modified, or distributed except according to those terms.

import
  ./eth_hash,
  ../rlp

export eth_hash, rlp

proc read*(rlp: var Rlp, T: typedesc[MDigest]): T =
  result.data = rlp.read(type(result.data))

proc append*(rlpWriter: var RlpWriter, a: MDigest) =
  rlpWriter.append(a.data)
