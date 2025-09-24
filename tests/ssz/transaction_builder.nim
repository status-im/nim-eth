import
  unittest2,
  stew/byteutils,
  stint,
  ../../eth/ssz/[transaction_ssz, transaction_builder, signatures],
  ../../eth/common/[addresses, base, hashes]

const
  recipient = address"095e7baea6a6c7c4c2dfeb977efac326af552d87"
  source = address"0x0000000000000000000000000000000000000001"
  storageKey = default(Bytes32)
  abcdef = hexToSeqByte("abcdef")

let accesses: seq[AccessTuple] =
  @[AccessTuple(address: source, storage_keys: @[Hash32(storageKey)])]

proc dummySig(): Secp256k1ExecutionSignature =
  secp256k1Pack(1.u256, 1.u256, 0'u8)

suite "SSZ Transactions (constructor)":
  test "Legacy Call":
    let tx = Transaction(
      txType = 0x00'u8,
      chain_id = ChainId(1.u256),
      nonce = 1'u64,
      gas = 21_000'u64,
      to = Opt.some(recipient),
      value = 0.u256,
      input = abcdef,
      max_fees_per_gas = BasicFeesPerGas(regular: 2.u256),
      signature = dummySig(),
    )
    check tx.kind == RlpTransaction
    check tx.rlp.kind == txLegacyBasic
    check tx.rlp.legacyBasic.payload.to == recipient

  test "Legacy Create":
    let tx = Transaction(
      txType = 0x00'u8,
      chain_id = ChainId(1.u256),
      nonce = 2'u64,
      gas = 50_000'u64,
      to = Opt.none(Address), # create
      value = 0.u256,
      input = abcdef, # initcode must be non-empty
      max_fees_per_gas = BasicFeesPerGas(regular: 2.u256),
      signature = dummySig(),
    )
    check tx.kind == RlpTransaction
    check tx.rlp.kind == txLegacyCreate
    check tx.rlp.legacyCreate.payload.input.len == abcdef.len

  test "2930 Call (non-empty access list)":
    let tx = Transaction(
      txType = 0x01'u8,
      chain_id = ChainId(1.u256),
      nonce = 3'u64,
      gas = 123_457'u64,
      to = Opt.some(recipient),
      value = 0.u256,
      input = abcdef,
      max_fees_per_gas = BasicFeesPerGas(regular: 10.u256),
      access_list = accesses,
      signature = dummySig(),
    )
    check tx.kind == RlpTransaction
    check tx.rlp.kind == txAccessListBasic
    check tx.rlp.accessListBasic.payload.access_list.len == 1

  test "2930 Create (empty access list)":
    let tx = Transaction(
      txType = 0x01'u8,
      chain_id = ChainId(1.u256),
      nonce = 4'u64,
      gas = 123_457'u64,
      to = Opt.none(Address),
      value = 0.u256,
      input = abcdef,
      max_fees_per_gas = BasicFeesPerGas(regular: 10.u256),
      # access_list defaults to @[]
      signature = dummySig(),
    )
    check tx.kind == RlpTransaction
    check tx.rlp.kind == txAccessListCreate
    check tx.rlp.accessListCreate.payload.access_list.len == 0

  test "1559 Call":
    let tx = Transaction(
      txType = 0x02'u8,
      chain_id = ChainId(1.u256),
      nonce = 5'u64,
      gas = 123_457'u64,
      to = Opt.some(recipient),
      value = 0.u256,
      input = abcdef,
      max_fees_per_gas = BasicFeesPerGas(regular: 10.u256),
      max_priority_fees_per_gas = BasicFeesPerGas(regular: 2.u256),
      access_list = accesses,
      signature = dummySig(),
    )
    check tx.kind == RlpTransaction
    check tx.rlp.kind == txBasic
    check tx.rlp.basic.payload.max_priority_fees_per_gas.regular == 2.u256

  test "1559 Create":
    let tx = Transaction(
      txType = 0x02'u8,
      chain_id = ChainId(1.u256),
      nonce = 6'u64,
      gas = 123_457'u64,
      to = Opt.none(Address),
      value = 0.u256,
      input = abcdef,
      max_fees_per_gas = BasicFeesPerGas(regular: 10.u256),
      max_priority_fees_per_gas = BasicFeesPerGas(regular: 2.u256),
      signature = dummySig(),
    )
    check tx.kind == RlpTransaction
    check tx.rlp.kind == txCreate
    check tx.rlp.create.payload.input.len == abcdef.len

  when compiles(BlobFeesPerGas):
    test "4844 Blob Tx":
      const d = hash32"010657f37554c781402a22917dee2f75def7ab966d7b770905398eba3c444014"
      let tx = Transaction(
        txType = 0x03'u8,
        chain_id = ChainId(1.u256),
        nonce = 7'u64,
        gas = 123_457'u64,
        to = Opt.some(recipient),
        value = 0.u256,
        input = @[],
        max_fees_per_gas = BasicFeesPerGas(regular: 10.u256),
        max_priority_fees_per_gas = BasicFeesPerGas(regular: 1.u256),
        access_list = accesses,
        blob_versioned_hashes = @[VersionedHash(d)],
        blob_fee = 10.u256,
        signature = dummySig(),
      )
      check tx.kind == RlpTransaction
      check tx.rlp.kind == txBlob
      check tx.rlp.blob.payload.blob_versioned_hashes.len == 1

  test "7702 SetCode with replayable-basic auth":
    let auths = @[
      Authorization(
        kind: authReplayableBasic,
        replayable: RlpReplayableBasicAuthorizationPayload(
          magic: AuthMagic7702,
          address: recipient,
          nonce: 0'u64,
        )
      )
    ]
    let tx = Transaction(
      txType = 0x04'u8,
      chain_id = ChainId(1.u256),
      nonce = 8'u64,
      gas = 21000'u64,
      to = Opt.some(recipient),
      value = 0.u256,
      input = @[],
      max_fees_per_gas = BasicFeesPerGas(regular: 10.u256),
      max_priority_fees_per_gas = BasicFeesPerGas(regular: 1.u256),
      access_list = @[],
      authorization_list = auths,
      signature = dummySig(),
    )
    check tx.kind == RlpTransaction
    check tx.rlp.kind == txSetCode
    check tx.rlp.setCode.payload.authorization_list.len == 1
    check tx.rlp.setCode.payload.authorization_list[0].kind == authReplayableBasic

  test "7702 SetCode with basic auth":
    let auths = @[
      Authorization(
        kind: authBasic,
        basic: RlpBasicAuthorizationPayload(
          magic: AuthMagic7702,
          chain_id: ChainId(1.u256),
          address: recipient,
          nonce: 0'u64,
        )
      )
    ]
    let tx = Transaction(
      txType = 0x04'u8,
      chain_id = ChainId(1.u256),
      nonce = 9'u64,
      gas = 21001'u64,
      to = Opt.some(recipient),
      value = 0.u256,
      input = @[],
      max_fees_per_gas = BasicFeesPerGas(regular: 11.u256),
      max_priority_fees_per_gas = BasicFeesPerGas(regular: 1.u256),
      access_list = @[],
      authorization_list = auths,
      signature = dummySig(),
    )
    check tx.kind == RlpTransaction
    check tx.rlp.kind == txSetCode
    check tx.rlp.setCode.payload.authorization_list.len == 1
    check tx.rlp.setCode.payload.authorization_list[0].kind == authBasic

  test "7702 SetCode: fails when auth list empty":
    expect(TxBuildError):
      discard Transaction(
        txType = 0x04'u8,
        chain_id = ChainId(1.u256),
        nonce = 11'u64,
        gas = 21000'u64,
        to = Opt.some(recipient),
        value = 0.u256,
        input = @[],
        max_fees_per_gas = BasicFeesPerGas(regular: 10.u256),
        max_priority_fees_per_gas = BasicFeesPerGas(regular: 1.u256),
        authorization_list = @[],
        signature = dummySig(),
      )
