# Copyright (c) 2022-2024 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option. This file may not be copied, modified, or distributed except according to those terms.

import
  "."/[
    accounts_rlp, addresses_rlp, base_rlp, eth_types, hashes_rlp,
    headers_rlp, receipts_rlp, times_rlp, transactions_rlp,
  ],
  ../rlp

export
  accounts_rlp, addresses_rlp, base_rlp, eth_types, hashes_rlp,
  headers_rlp, receipts_rlp, times_rlp, transactions_rlp, rlp

proc append*(rlpWriter: var RlpWriter, value: BlockHashOrNumber) =
  case value.isHash
  of true:
    rlpWriter.append(value.hash)
  else:
    rlpWriter.append(value.number)

proc read*(rlp: var Rlp, T: type BlockHashOrNumber): T =
  if rlp.blobLen == 32:
    BlockHashOrNumber(isHash: true, hash: rlp.read(Hash32))
  else:
    BlockHashOrNumber(isHash: false, number: rlp.read(BlockNumber))

proc rlpHash*[T](v: T): Hash32 =
  Hash32(rlp.encodeHash(v))

proc rlpHash*(tx: PooledTransaction): Hash32 =
  Hash32(rlp.encodeHash(tx.tx))

func blockHash*(h: Header): Hash32 {.inline.} =
  rlpHash(h)
