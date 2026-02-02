# eth
# Copyright (c) 2024-2026 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option. This file may not be copied, modified, or distributed except according to those terms.

{.push raises: [].}

import ./[addresses, base, hashes, times]

export addresses, base, hashes, times

type
  DifficultyInt* = UInt256

  Header* = object
    # https://github.com/ethereum/execution-specs/blob/51fac24740e662844446439ceeb96a460aae0ba0/src/ethereum/cancun/blocks.py
    parentHash*: Hash32
    ommersHash*: Hash32
    coinbase*: Address
    stateRoot*: Root
    transactionsRoot*: Root
    receiptsRoot*: Root
    logsBloom*: Bloom
    difficulty*: DifficultyInt
    number*: BlockNumber
    gasLimit*: GasInt
    gasUsed*: GasInt
    timestamp*: EthTime
    extraData*: seq[byte]
    mixHash*: Bytes32
      ## AKA mix_digest in some specs - Hash32 in the eth API but Bytes32 in
      ## the execution API and spec!
    nonce*: Bytes8
    baseFeePerGas*: Opt[UInt256] # EIP-1559
    withdrawalsRoot*: Opt[Hash32]  # EIP-4895
    blobGasUsed*: Opt[uint64]  # EIP-4844
    excessBlobGas*: Opt[uint64]  # EIP-4844
    parentBeaconBlockRoot*: Opt[Hash32]  # EIP-4788
    requestsHash*: Opt[Hash32]  # EIP-7685
    blockAccessListHash*: Opt[Hash32]  # EIP-7928
    slotNumber*: Opt[uint64] # EIP-7843

# starting from EIP-4399, `mixDigest` field is called `prevRandao`
template prevRandao*(h: Header): Bytes32 =
  h.mixHash

template `prevRandao=`*(h: Header, hash: Bytes32) =
  h.mixHash = hash

template txRoot*(h: Header): Root = h.transactionsRoot
