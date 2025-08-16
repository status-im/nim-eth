import
  unittest2,
  stew/byteutils,
  stint,
  ../../eth/ssz/[transaction_ssz,transaction_builder,utils],     
  ../../eth/common/[addresses, base, hashes]

const
  recipient = address"095e7baea6a6c7c4c2dfeb977efac326af552d87"
  source    = address"0x0000000000000000000000000000000000000001"
  storageKey = default(Bytes32)
  abcdef    = hexToSeqByte("abcdef")

let accesses: seq[AccessTuple] = @[
  AccessTuple(address: source, storage_keys: @[storageKey])
]

proc dummySig(): Secp256k1ExecutionSignature =
  Secp256k1ExecutionSignature(secp256k1: secp256k1_pack(1.u256, 1.u256, 0'u8))

proc sszLegacyCall(i: int): Transaction =
  Transaction(
    txType = 0x00'u8,
    chain_id = ChainId(1.u256),
    nonce = i.uint64,
    gas = 21_000'u64,
    to = Opt.some(recipient),
    value = 0.u256,
    input = abcdef,
    max_fees_per_gas = BasicFeesPerGas(regular: 2.u256),
    signature = dummySig()
  )

proc sszLegacyCreate(i: int): Transaction =
  Transaction(
    txType = 0x00'u8,
    chain_id = ChainId(1.u256),
    nonce = i.uint64,
    gas = 50_000'u64,
    to = Opt.none(Address),                 # create
    value = 0.u256,
    input = abcdef,                         # initcode must be non-empty
    max_fees_per_gas = BasicFeesPerGas(regular: 2.u256),
    signature = dummySig()
  )

proc ssz2930Call(i: int): Transaction =
  Transaction(
    txType = 0x01'u8,
    chain_id = ChainId(1.u256),
    nonce = i.uint64,
    gas = 123_457'u64,
    to = Opt.some(recipient),
    value = 0.u256,
    input = abcdef,
    max_fees_per_gas = BasicFeesPerGas(regular: 10.u256),
    access_list = accesses,
    signature = dummySig()
  )

proc ssz2930Create(i: int): Transaction =
  Transaction(
    txType = 0x01'u8,
    chain_id = ChainId(1.u256),
    nonce = i.uint64,
    gas = 123_457'u64,
    to = Opt.none(Address),
    value = 0.u256,
    input = abcdef,
    max_fees_per_gas = BasicFeesPerGas(regular: 10.u256),
    access_list = @[],                      # empty access list is OK
    signature = dummySig()
  )

proc ssz1559Call(i: int): Transaction =
  Transaction(
    txType = 0x02'u8,
    chain_id = ChainId(1.u256),
    nonce = i.uint64,
    gas = 123_457'u64,
    to = Opt.some(recipient),
    value = 0.u256,
    input = abcdef,
    max_fees_per_gas = BasicFeesPerGas(regular: 10.u256),
    max_priority_fees_per_gas = BasicFeesPerGas(regular: 2.u256),
    access_list = accesses,
    signature = dummySig()
  )

proc ssz1559Create(i: int): Transaction =
  Transaction(
    txType = 0x02'u8,
    chain_id = ChainId(1.u256),
    nonce = i.uint64,
    gas = 123_457'u64,
    to = Opt.none(Address),
    value = 0.u256,
    input = abcdef,                         # initcode
    max_fees_per_gas = BasicFeesPerGas(regular: 10.u256),
    max_priority_fees_per_gas = BasicFeesPerGas(regular: 2.u256),
    access_list = @[],
    signature = dummySig()
  )

when compiles(BlobFeesPerGas):
  proc ssz4844BlobCallA(i: int): Transaction =
    const digestA = hash32"010657f37554c781402a22917dee2f75def7ab966d7b770905398eba3c444014"
    Transaction(
      txType = 0x03'u8,
      chain_id = ChainId(1.u256),
      nonce = i.uint64,
      gas = 123_457'u64,
      to = Opt.some(recipient),
      value = 0.u256,
      input = @[],
      max_fees_per_gas = BasicFeesPerGas(regular: 10.u256),
      max_priority_fees_per_gas = BasicFeesPerGas(regular: 1.u256),
      access_list = accesses,
      blob_versioned_hashes = @[digestA],
      blob_fee = 10.u256,
      signature = dummySig()
    )

  proc ssz4844BlobCallB(i: int): Transaction =
    const digestB = hash32"01624652859a6e98ffc1608e2af0147ca4e86e1ce27672d8d3f3c9d4ffd6ef7e"
    Transaction(
      txType = 0x03'u8,
      chain_id = ChainId(1.u256),
      nonce = i.uint64,
      gas = 123_457'u64,
      to = Opt.some(recipient),
      value = 0.u256,
      input = @[],
      max_fees_per_gas = BasicFeesPerGas(regular: 10.u256),
      max_priority_fees_per_gas = BasicFeesPerGas(regular: 1.u256),
      access_list = accesses,
      blob_versioned_hashes = @[digestB],
      blob_fee = 10.u256,
      signature = dummySig()
    )

# # --------------------------
# # Assertions
# # --------------------------
# suite "SSZ Transactions (constructor)":
#   test "Legacy Call":
#     let tx = sszLegacyCall(1)
#     check tx.kind == txRlp
#     check tx.rlp.kind == legacyBasic
#     check tx.rlp.legacyBasicTx.payload.to == recipient
#     check tx.rlp.legacyBasicTx.payload.max_fees_per_gas.regular == 2.u256

#   test "Legacy Create":
#     let tx = sszLegacyCreate(2)
#     check tx.kind == txRlp
#     check tx.rlp.kind == legacyCreate
#     # no `to` field in create payload; just sanity-check some values
#     check tx.rlp.legacyCreateTx.payload.gas == 50_000'u64
#     check tx.rlp.legacyCreateTx.payload.input.len == abcdef.len

#   test "2930 Call (non-empty access list)":
#     let tx = ssz2930Call(3)
#     check tx.kind == txRlp
#     check tx.rlp.kind == accessListBasic
#     check tx.rlp.accessListBasicTx.payload.access_list.len == 1

#   test "2930 Create (empty access list)":
#     let tx = ssz2930Create(4)
#     check tx.kind == txRlp
#     check tx.rlp.kind == accessListCreate
#     check tx.rlp.accessListCreateTx.payload.access_list.len == 0

#   test "1559 Call":
#     let tx = ssz1559Call(5)
#     check tx.kind == txRlp
#     check tx.rlp.kind == basic1559
#     check tx.rlp.basic1559Tx.payload.max_priority_fees_per_gas.regular == 2.u256

#   test "1559 Create":
#     let tx = ssz1559Create(6)
#     check tx.kind == txRlp
#     check tx.rlp.kind == create1559
#     check tx.rlp.create1559Tx.payload.input.len == abcdef.len

#   when compiles(BlobFeesPerGas):
#     test "4844 Blob Tx A":
#       let tx = ssz4844BlobCallA(7)
#       check tx.kind == txRlp
#       check tx.rlp.kind == blob4844
#       check tx.rlp.blobTx.payload.blob_versioned_hashes.len == 1

#     test "4844 Blob Tx B":
#       let tx = ssz4844BlobCallB(8)
#       check tx.kind == txRlp
#       check tx.rlp.kind == blob4844
#       check tx.rlp.blobTx.payload.to == recipient

#   # Optional: list construction sanity (no serialization here, just branch checks)
#   test "Tx list branch sanity":
#     var txs: seq[Transaction] = @[
#       sszLegacyCall(1), sszLegacyCreate(2), ssz2930Call(3),
#       ssz2930Create(4), ssz1559Call(5), ssz1559Create(6)
#     ]
#     when compiles(BlobFeesPerGas):
#       txs.add(ssz4844BlobCallA(7))
#       txs.add(ssz4844BlobCallB(8))

#     check:
#       txs[0].rlp.kind == legacyBasic
#       txs[1].rlp.kind == legacyCreate
#       txs[2].rlp.kind == accessListBasic
#       txs[3].rlp.kind == accessListCreate
#       txs[4].rlp.kind == basic1559
#       txs[5].rlp.kind == create1559
#     when compiles(BlobFeesPerGas):
#       check:
#         txs[6].rlp.kind == blob4844
#         txs[7].rlp.kind == blob4844
