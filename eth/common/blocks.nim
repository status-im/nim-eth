# eth
# Copyright (c) 2024 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option. This file may not be copied, modified, or distributed except according to those terms.

{.push raises: [].}

import "."/[addresses, base, headers, transactions, block_access_lists]

export addresses, base, headers, transactions, block_access_lists

type
  Withdrawal* = object                     # EIP-4895
    index*         : uint64
    validatorIndex*: uint64
    address*       : Address
    amount*        : uint64

  BlockBody* = object
    transactions*:    seq[Transaction]
    uncles*:          seq[Header]
    withdrawals*:     Opt[seq[Withdrawal]] # EIP-4895
    blockAccessList*: Opt[BlockAccessList] # EIP-7928

  Block* = object
    header*     :     Header
    transactions*:    seq[Transaction]
    uncles*     :     seq[Header]
    withdrawals*:     Opt[seq[Withdrawal]] # EIP-4895
    blockAccessList*: Opt[BlockAccessList] # EIP-7928

const
  EMPTY_UNCLE_HASH* = hash32"1dcc4de8dec75d7aab85b567b6ccd41ad312451b948a7413f0a142fd40d49347"

# TODO https://github.com/nim-lang/Nim/issues/23354 - parameters should be sink
func init*(T: type Block, header: Header, body: BlockBody): T =
  T(
    header: header,
    transactions: body.transactions,
    uncles: body.uncles,
    withdrawals: body.withdrawals,
    blockAccessList: body.blockAccessList,
  )

template txs*(blk: Block): seq[Transaction] =
  # Legacy name emulation
  blk.transactions
