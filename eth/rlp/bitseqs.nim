# eth
# Copyright (c) 2019-2024 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option. This file may not be copied, modified, or distributed except according to those terms.

import stew/bitseqs, ../rlp

type Bytes = seq[byte]

proc read*(rlp: var Rlp, T: type BitSeq): T {.inline.} =
  T read(rlp, Bytes)

proc append*(writer: var RlpWriter, value: BitSeq) =
  append(writer, Bytes(value))

export bitseqs, rlp
