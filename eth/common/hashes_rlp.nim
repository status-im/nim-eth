# Copyright (c) 2022 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option. This file may not be copied, modified, or distributed except according to those terms.

import "."/hashes, ../rlp

export hashes, rlp

proc read*(rlp: var Rlp, T: type Hash32): Hash32 =
  Hash32(rlp.read(type(result.data)))

proc append*(rlpWriter: var RlpWriter, a: Hash32) =
  rlpWriter.append(a.data)
