# Copyright (c) 2022 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option. This file may not be copied, modified, or distributed except according to those terms.

import
  chronicles,
  ./eth_types_rlp,
  ../rlp,
  ../trie/db

export eth_types_rlp, rlp, db

type
  AbstractChainDB* = ref object of RootRef

proc notImplemented(name: string) =
  debug "Method not implemented", meth = name

method genesisHash*(db: AbstractChainDB): KeccakHash
    {.base, gcsafe, raises: [Defect].} =
  notImplemented("genesisHash")

method getBlockHeader*(db: AbstractChainDB, b: HashOrNum,
    output: var BlockHeader): bool {.base, gcsafe, raises: [RlpError, Defect].} =
  notImplemented("getBlockHeader")

proc getBlockHeader*(db: AbstractChainDB, hash: KeccakHash): BlockHeaderRef {.gcsafe.} =
  new result
  if not db.getBlockHeader(HashOrNum(isHash: true, hash: hash), result[]):
    return nil

proc getBlockHeader*(db: AbstractChainDB, b: BlockNumber): BlockHeaderRef {.gcsafe.} =
  new result
  if not db.getBlockHeader(HashOrNum(isHash: false, number: b), result[]):
    return nil

# Need to add `RlpError` and sometimes `CatchableError` as the implementations
# of these methods in nimbus-eth1 will raise these. Using `CatchableError`
# because some can raise for errors not know to this repository such as
# `CanonicalHeadNotFound`. It would probably be better to use Result.
method getBestBlockHeader*(self: AbstractChainDB): BlockHeader
    {.base, gcsafe, raises: [RlpError, CatchableError, Defect].} =
  notImplemented("getBestBlockHeader")

method getSuccessorHeader*(db: AbstractChainDB, h: BlockHeader,
    output: var BlockHeader, skip = 0'u): bool
    {.base, gcsafe, raises: [RlpError, Defect].} =
  notImplemented("getSuccessorHeader")

method getAncestorHeader*(db: AbstractChainDB, h: BlockHeader,
    output: var BlockHeader, skip = 0'u): bool
    {.base, gcsafe, raises: [RlpError, Defect].} =
  notImplemented("getAncestorHeader")

method getBlockBody*(db: AbstractChainDB, blockHash: KeccakHash): BlockBodyRef
    {.base, gcsafe, raises: [RlpError, Defect].} =
  notImplemented("getBlockBody")

method getReceipt*(db: AbstractChainDB, hash: KeccakHash): ReceiptRef {.base, gcsafe.} =
  notImplemented("getReceipt")

method getTrieDB*(db: AbstractChainDB): TrieDatabaseRef
    {.base, gcsafe, raises: [Defect].} =
  notImplemented("getTrieDB")

method getCodeByHash*(db: AbstractChainDB, hash: KeccakHash): Blob {.base, gcsafe.} =
  notImplemented("getCodeByHash")

method getSetting*(db: AbstractChainDB, key: string): seq[byte] {.base, gcsafe.} =
  notImplemented("getSetting")

method setSetting*(db: AbstractChainDB, key: string, val: openArray[byte]) {.base, gcsafe.} =
  notImplemented("setSetting")

method getHeaderProof*(db: AbstractChainDB, req: ProofRequest): Blob {.base, gcsafe.} =
  notImplemented("getHeaderProof")

method getProof*(db: AbstractChainDB, req: ProofRequest): Blob {.base, gcsafe.} =
  notImplemented("getProof")

method getHelperTrieProof*(db: AbstractChainDB, req: HelperTrieProofRequest): Blob {.base, gcsafe.} =
  notImplemented("getHelperTrieProof")

method getTransactionStatus*(db: AbstractChainDB, txHash: KeccakHash): TransactionStatusMsg {.base, gcsafe.} =
  notImplemented("getTransactionStatus")

method addTransactions*(db: AbstractChainDB, transactions: openArray[Transaction]) {.base, gcsafe.} =
  notImplemented("addTransactions")

method persistBlocks*(db: AbstractChainDB, headers: openArray[BlockHeader], bodies: openArray[BlockBody]): ValidationResult {.base, gcsafe.} =
  notImplemented("persistBlocks")

method getForkId*(db: AbstractChainDB, n: BlockNumber): ForkID {.base, gcsafe.} =
  # EIP 2364/2124
  notImplemented("getForkId")

method getTotalDifficulty*(db: AbstractChainDB): DifficultyInt {.base, gcsafe, raises: [RlpError, Defect].} =
  notImplemented("getTotalDifficulty")
