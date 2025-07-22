# eth
# Copyright (c) 2024-2025 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option. This file may not be copied, modified, or distributed except according to those terms.

{.push raises: [].}

import "."/[addresses, base, hashes]

export addresses, base, hashes

const EIP155_CHAIN_ID_OFFSET* = 35'u64

type
  AccessPair* = object
    address*    : Address
    storageKeys*: seq[Bytes32]

  AccessList* = seq[AccessPair]

  Authorization* = object
    chainId*: ChainId
    address*: Address
    nonce*: AccountNonce
    yParity*: uint8
    r*: UInt256
    s*: UInt256

  TxType* = enum
    TxLegacy    # 0
    TxEip2930   # 1
    TxEip1559   # 2
    TxEip4844   # 3
    TxEip7702   # 4

  Transaction* = object
    txType*        : TxType               # EIP-2718
    chainId*       : ChainId              # EIP-2930
    nonce*         : AccountNonce
    gasPrice*      : GasInt
    maxPriorityFeePerGas*: GasInt         # EIP-1559
    maxFeePerGas*  : GasInt               # EIP-1559
    gasLimit*      : GasInt
    to*            : Opt[Address]
    value*         : UInt256
    payload*       : seq[byte]
    accessList*    : AccessList           # EIP-2930
    maxFeePerBlobGas*: UInt256            # EIP-4844
    versionedHashes*: seq[VersionedHash]  # EIP-4844
    authorizationList*: seq[Authorization]# EIP-7702
    V*             : uint64
    R*, S*         : UInt256

func destination*(tx: Transaction): Address =
  # use getRecipient if you also want to get
  # the contract address
  tx.to.valueOr(default(Address))

func isEip155*(tx: Transaction): bool =
  tx.V >= EIP155_CHAIN_ID_OFFSET

func contractCreation*(tx: Transaction): bool =
  tx.to.isNone
