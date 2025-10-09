import
  unittest2,
  ssz_serialization,
  ssz_serialization/merkleization,
  ../../eth/common/[addresses, base, hashes],
  ../../eth/ssz/[ transaction_builder, signatures, adapter,sszcodec],
  ../../eth/ssz/transaction_ssz as ssz_tx,
  ../../eth/common/transactions as rlp_tx_mod



suite "SSZ: Hash32 distinct Bytes32 roundtrip":
  test "encode/decode parity":
    var h: Hash32
    for i in 0 ..< 32:
      distinctBase(h)[i] = byte(0xA0 + i)
    let enc = SSZ.encode(h)
    let dec = SSZ.decode(enc, Hash32)
    check distinctBase(h) == distinctBase(dec)

suite "SSZ: Hash32 merkleization":
  test "seq[Hash32] root stable and order-sensitive":
    var h1, h2: Hash32
    for i in 0 ..< 32:
      distinctBase(h1)[i] = byte(i)
      distinctBase(h2)[i] = byte(255 - i)
    let r1 = hash_tree_root(@[h1, h2])
    let r2 = hash_tree_root(@[h1, h2])
    let r3 = hash_tree_root(@[h2, h1])
    check r1 == r2
    check r1 != r3

  test "single vs pair has different root":
    var a, b: Hash32
    for i in 0 ..< 32:
      distinctBase(a)[i] = byte(i)
      distinctBase(b)[i] = byte(i xor 0xFF)
    let rs = hash_tree_root(@[a])
    let rp = hash_tree_root(@[a, b])
    check rs != rp

suite "SSZ: Address encode/decode + merkleization":
  test "Address encode/decode parity":
    var a: Address
    for i in 0 ..< 20:
      a.data[i] = byte(i + 1)
    let enc = SSZ.encode(a)
    let dec = SSZ.decode(enc, Address)
    check distinctBase(a) == distinctBase(dec)

  test "merkleization: seq[Address] root stable and order-sensitive":
    var a1, a2: Address
    for i in 0 ..< 20:
      a1.data[i] = byte(i)
      a2.data[i] = byte(19 - i)
    let r1 = hash_tree_root(a1)
    let r2 = hash_tree_root(a2)
    let r4 = hash_tree_root(@[a1, a2])

suite "Authorization List Conversion":
  test "Single replayable auth: RLP -> SSZ -> RLP":
    let rlpAuth = rlp_tx_mod.Authorization(
      chainId: ChainId(0.u256),
      address: address"0x1111111111111111111111111111111111111111",
      nonce: AccountNonce(5),
      yParity: 0,
      r: 123.u256,
      s: 456.u256
    )
    let sszAuths = toSszAuthList(@[rlpAuth])
    check sszAuths.len == 1
    check sszAuths[0].payload.kind == authReplayableBasic
    check sszAuths[0].payload.replayable.address == rlpAuth.address
    check sszAuths[0].payload.replayable.nonce == uint64(rlpAuth.nonce)

    let backRlp = toRlpAuthList(sszAuths)
    check backRlp.len == 1
    check backRlp[0].chainId == rlpAuth.chainId
    check backRlp[0].address == rlpAuth.address
    check backRlp[0].nonce == rlpAuth.nonce
    check backRlp[0].yParity == rlpAuth.yParity
    check backRlp[0].r == rlpAuth.r
    check backRlp[0].s == rlpAuth.s

  test "Single basic auth: RLP -> SSZ -> RLP":
    let rlpAuth = rlp_tx_mod.Authorization(
      chainId: ChainId(1.u256),
      address: address"0x2222222222222222222222222222222222222222",
      nonce: AccountNonce(10),
      yParity: 1,
      r: 789.u256,
      s: 101112.u256
    )
    let sszAuths = toSszAuthList(@[rlpAuth])
    check sszAuths.len == 1
    check sszAuths[0].payload.kind == authBasic
    check sszAuths[0].payload.basic.chain_id == ChainId(1.u256)

    let backRlp = toRlpAuthList(sszAuths)
    check backRlp[0] == rlpAuth

  test "Mixed auth list (2 replayable + 1 basic)":
    let auths = @[
      rlp_tx_mod.Authorization(
        chainId: ChainId(0.u256),
        address: address"0x1111111111111111111111111111111111111111",
        nonce: AccountNonce(1), yParity: 0, r: 1.u256, s: 2.u256
      ),
      rlp_tx_mod.Authorization(
        chainId: ChainId(0.u256),
        address: address"0x2222222222222222222222222222222222222222",
        nonce: AccountNonce(2), yParity: 1, r: 3.u256, s: 4.u256
      ),
      rlp_tx_mod.Authorization(
        chainId: ChainId(5.u256),
        address: address"0x3333333333333333333333333333333333333333",
        nonce: AccountNonce(3), yParity: 0, r: 5.u256, s: 6.u256
      )
    ]
    let sszAuths = toSszAuthList(auths)
    check sszAuths.len == 3
    check sszAuths[0].payload.kind == authReplayableBasic
    check sszAuths[1].payload.kind == authReplayableBasic
    check sszAuths[2].payload.kind == authBasic

    let backRlp = toRlpAuthList(sszAuths)
    check backRlp.len == 3
    for i in 0..2:
      check backRlp[i] == auths[i]

  test "Authorization with max values":
    let auth = rlp_tx_mod.Authorization(
      chainId: ChainId(u256(high(uint64))),
      address: address"0xffffffffffffffffffffffffffffffffffffffff",
      nonce: AccountNonce(high(uint64)),
      yParity: 1,
      r: u256(high(uint64)),
      s: u256(high(uint64))
    )
    let ssz = toSszSignedAuthList(@[auth])
    let back = toRlpAuthList(ssz)
    check back[0] == auth

  test "Empty authorization list":
    let empty: seq[rlp_tx_mod.Authorization] = @[]
    let ssz = toSszSignedAuthList(empty)
    check ssz.len == 0
    let back = toRlpAuthList(ssz)
    check back.len == 0
