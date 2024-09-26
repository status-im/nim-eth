# eth
# Copyright (c) 2024 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option. This file may not be copied, modified, or distributed except according to those terms.

{.push raises: [].}

import "."/[addresses, base, hashes, times]

export addresses, base, hashes, times

type
  DifficultyInt* = UInt256

    # https://github.com/ethereum/execution-specs/blob/51fac24740e662844446439ceeb96a460aae0ba0/src/ethereum/paris/blocks.py#L22
  Header* = object
    parentHash*:      Hash32
    ommersHash*:      Hash32
    coinbase*:        Address
    stateRoot*:       Root
    transactionsRoot*: Root
    receiptsRoot*:    Root
    logsBloom*:       Bloom
    difficulty*:      DifficultyInt
    number*:          BlockNumber
    gasLimit*:        GasInt
    gasUsed*:         GasInt
    timestamp*:       EthTime
    extraData*:       seq[byte]
    mixHash*:         Hash32
    nonce*:           BlockNonce
    baseFeePerGas*:   Opt[UInt256]   # EIP-1559
    withdrawalsRoot*: Opt[Hash32]   # EIP-4895
    blobGasUsed*:     Opt[uint64]    # EIP-4844
    excessBlobGas*:   Opt[uint64]    # EIP-4844
    parentBeaconBlockRoot*: Opt[Hash32] # EIP-4788
    requestsRoot*:    Opt[Hash32]  # EIP-7685

  BlockHeader*{.deprecated: "Header".} = Header

# starting from EIP-4399, `mixHash`/`mixDigest` field will be called `prevRandao`
template prevRandao*(h: Header): Hash32 =
  h.mixHash

template `prevRandao=`*(h: Header, hash: Hash32) =
  h.mixHash = hash

template txRoot*(h: Header): Root = h.transactionsRoot