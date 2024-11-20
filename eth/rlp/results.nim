# eth
# Copyright (c) 2024 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option. This file may not be copied, modified, or distributed except according to those terms.

import ../rlp
import writer
import pkg/results

export
  rlp, results

proc append*[T](w: var RlpWriter, val: Opt[T]) =
  mixin append

  if val.isSome:
    w.append(val.get())
  else:
    w.append("")

proc read*[T](rlp: var Rlp, val: var Opt[T]) {.raises: [RlpError].} =
  mixin read
  if rlp.blobLen != 0:
    val = Opt.some(rlp.read(T))
  else:
    rlp.skipElem

