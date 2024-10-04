# eth
# Copyright (c) 2024 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option. This file may not be copied, modified, or distributed except according to those terms.

{.push raises: [].}

import ./times, ../rlp

export times, rlp

proc read*(rlp: var Rlp, T: type EthTime): T {.raises: [RlpError].} =
  EthTime rlp.read(uint64)

proc append*(rlpWriter: var RlpWriter, t: EthTime) {.inline.} =
  rlpWriter.append(t.uint64)
