# eth
# Copyright (c) 2025 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option. This file may not be copied, modified, or distributed except according to those terms.
#
# This implements the types required for EIP-7928: Block-Level Access Lists.
# Enforced block access lists with storage locations and post-transaction
# state diffs: https://eips.ethereum.org/EIPS/eip-7928
#

{.push raises: [], gcsafe.}

import "."/[addresses, base, hashes]

export addresses, base, hashes

const
  EMPTY_BLOCK_ACCESS_LIST_HASH* = hash32"1dcc4de8dec75d7aab85b567b6ccd41ad312451b948a7413f0a142fd40d49347"

type
  StorageKey* = Bytes32
  StorageValue* = Bytes32
  CodeData* = Bytes
  BlockAccessIndex* = uint16
  Balance* = UInt256
  Nonce* = AccountNonce

  StorageChange* = tuple[blockAccessIndex: BlockAccessIndex, newValue: StorageValue]
  BalanceChange* = tuple[blockAccessIndex: BlockAccessIndex, postBalance: Balance]
  NonceChange* = tuple[blockAccessIndex: BlockAccessIndex, newNonce: Nonce]
  CodeChange* = tuple[blockAccessIndex: BlockAccessIndex, newCode: CodeData]
  SlotChanges* = tuple[slot: StorageKey, changes: seq[StorageChange]]

  AccountChanges* = object
    address*: Address
    storageChanges*: seq[SlotChanges]
    storageReads*: seq[StorageKey]
    balanceChanges*: seq[BalanceChange]
    nonceChanges*: seq[NonceChange]
    codeChanges*: seq[CodeChange]

  BlockAccessList* = seq[AccountChanges]
