# Copyright (c) 2022-2024 Status Research & Development GmbH
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
  "."/[
    accounts,
    addresses,
    base,
    block_access_lists,
    blocks,
    hashes,
    headers,
    receipts,
    times,
    transactions
  ]

export
  accounts,
  addresses,
  base,
  block_access_lists,
  blocks,
  hashes,
  headers,
  receipts,
  times,
  transactions

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

# Backwards-compatibility section - this will be removed in future versions of
# this file

type
  # Names that don't appear in the spec and have no particular purpose any more -
  # just use the underlying type directly
  Blob* {.deprecated: "seq[byte]".} = seq[byte]
  BlockHeader* {.deprecated: "Header".} = Header
  BlockNonce* {.deprecated: "Bytes8".} = Bytes8
  BloomFilter* {.deprecated: "Bloom".} = Bloom
  VersionedHashes* {.deprecated: "seq[VersionedHash]".} = seq[VersionedHash]

func toBlockNonce*(n: uint64): Bytes8 {.deprecated.} =
  n.to(Bytes8)

func newAccount*(
    nonce: AccountNonce = 0, balance: UInt256 = 0.u256
): Account {.deprecated: "Account.init".} =
  Account.init(nonce = nonce, balance = balance)
