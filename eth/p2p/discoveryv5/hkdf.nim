# nim-eth
# Copyright (c) 2020-2023 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option. This file may not be copied, modified, or distributed except according to those terms.
#

{.push raises: [].}

import
  nimcrypto/[hmac, hash]

export hmac, hash

proc hkdf*(
    HashType: typedesc, ikm, salt, info: openArray[byte],
    output: var openArray[byte]) =
  var ctx: HMAC[HashType]
  ctx.init(salt)
  ctx.update(ikm)
  let prk = ctx.finish().data
  const hashLen = HashType.bits div 8

  var t: MDigest[HashType.bits]

  var numIters = output.len div hashLen
  if output.len mod hashLen != 0:
    inc numIters

  for i in 0 ..< numIters:
    ctx.init(prk)
    if i != 0:
      ctx.update(t.data)
    ctx.update(info)
    ctx.update([uint8(i + 1)])
    t = ctx.finish()
    let iStart = i * hashLen
    var sz = hashLen
    if iStart + sz >= output.len:
      sz = output.len - iStart
    copyMem(addr output[iStart], addr t.data, sz)

  ctx.clear()
