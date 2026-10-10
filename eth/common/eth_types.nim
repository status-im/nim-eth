# Copyright (c) 2022-2026 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option. This file may not be copied, modified, or distributed except according to those terms.

{.push raises: [].}

## Core ethereum types and small helpers - keep focused as it gets imported
## from many places

import
  stew/byteutils,
  std/strutils,
  ./[
    accounts, addresses, base, blocks, block_access_lists, hashes, headers, receipts,
    times, transactions,
  ]

export
  accounts, addresses, base, blocks, block_access_lists, hashes, headers, receipts,
  times, transactions

type
  BlockHashOrNumber* = object
    case isHash*: bool
    of true:
      hash*: Hash32
    else:
      number*: BlockNumber

  # Convenience names for types that exist in multiple specs and therefore
  # frequently conflict, name-wise.
  # These names are intended to be used in "boundary" code that translates
  # between types (consensus/json-rpc/rest/etc) while other code should use
  # native names within their domain
  EthAccount* = Account
  EthAddress* = Address
  EthBlock* = Block
  EthHash32* = Hash32
  EthHeader* = Header
  EthTransaction* = Transaction
  EthReceipt* = Receipt
  EthWithdrawal* = Withdrawal

func init*(T: type BlockHashOrNumber, str: string): T {.raises: [ValueError].} =
  if str.startsWith "0x":
    if str.len != sizeof(default(T).hash.data) * 2 + 2:
      raise newException(ValueError, "Block hash has incorrect length")

    var res = T(isHash: true)
    hexToByteArray(str, res.hash.data)
    res
  else:
    T(isHash: false, number: parseBiggestUInt str)

func `$`*(x: BlockHashOrNumber): string =
  if x.isHash:
    "0x" & x.hash.data.toHex
  else:
    $x.number
