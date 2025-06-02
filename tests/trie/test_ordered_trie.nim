import ../../eth/trie/[db, hexary, ordered_trie], ../../eth/rlp, ../../eth/common/transactions_rlp, unittest2

{.used.}

let tx = Transaction(
  txType: TxType.TxLegacy, 
  chainId: chainId(0), 
  nonce: 0, 
  gasPrice: 10.GasInt, 
  maxPriorityFeePerGas: 0.GasInt, 
  maxFeePerGas: 0.GasInt, 
  gasLimit: 42949672960.GasInt, 
  to: Opt.some address"0x0f572e5295c57f15886f9b263e2f6d2d6c7b5ec6", 
  value: u256"0", 
  V: uint64(27), 
  R: u256("86092867790932602674049739570226219391598990932787676600321317461460784211624"), 
  S: u256("32602745570769284550099276054202317025917639710803720420722152767517996779074")
)

let tx2 = Transaction(
  txType: TxType.TxEip1559,
  chainId: chainId(1),
  nonce: 0,
  gasPrice: 0.GasInt,
  maxPriorityFeePerGas: 0.GasInt,
  maxFeePerGas: 7.GasInt,
  gasLimit: 100000000.GasInt,
  to: Opt.some address"0x0000000000000000000000000000000000000100",
  payload: @[0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32, 33, 34, 35, 36, 37, 38, 39, 40, 41, 42, 43, 44, 45, 46, 47, 48, 49, 50, 51, 52, 53, 54, 55, 56, 57, 58, 59, 60, 61, 62, 63, 64, 65, 66, 67, 68, 69, 70, 71, 72, 73, 74, 75, 76, 77, 78, 79, 80, 81, 82, 83, 84, 85, 86, 87, 88, 89, 90, 91, 92, 93, 94, 95, 96, 97, 98, 99, 100, 101, 102, 103, 104, 105, 106, 107, 108, 109, 110, 111, 112, 113, 114, 115, 116, 117, 118, 119, 120, 121, 122, 123, 124, 125, 126, 127, 128, 129, 130, 131, 132, 133, 134, 135, 136, 137, 138, 139, 140, 141, 142, 143, 144, 145, 146, 147, 148, 149, 150, 151, 152, 153, 154, 155, 156, 157, 158, 159, 160, 161, 162, 163, 164, 165, 166, 167, 168, 169, 170, 171, 172, 173, 174, 175, 176, 177, 178, 179, 180, 181, 182, 183, 184, 185, 186, 187, 188, 189, 190, 191, 192, 193, 194, 195, 196, 197, 198, 199, 200, 201, 202, 203, 204, 205, 206, 207, 208, 209, 210, 211, 212, 213, 214, 215, 216, 217, 218, 219, 220, 221, 222, 223, 224, 225, 226, 227, 228, 229, 230, 231, 232, 233, 234, 235, 236, 237, 238, 239, 240, 241, 242, 243, 244, 245, 246, 247, 248, 249, 250, 251, 252, 253, 254, 255],
  V: uint64(0), 
  R: u256("56247832262823455468856823881508823668838282218082565762357790783193396561053"),
  S: u256("41264676679744500716811770511010812185591177620844949948278128119116121553882")
)

suite "OrderedTrie":
  for n in [0, 1, 2, 3, 126, 127, 128, 129, 130, 1000]:
    test "Ordered vs normal trie " & $n:
      let values = block:
        var tmp: seq[uint64]
        for i in 0 .. n:
          tmp.add i.uint64
        tmp

      let b1 = orderedTrieRoot(values)

      let b2 = block:
        var db2 = initHexaryTrie(newMemoryDB())
        for v in values:
          db2.put(rlp.encode(v), rlp.encode(v))

        db2.rootHash()
      check:
        b1 == b2

  test "Transaction Trie - interleaved lists and wrappings":
    let 
      txs = @[tx]
      root = Hash32.fromHex("0x3d2502c9090ceb3253140d96a5fa1b0f699a26c70aa798e7eb219c15571bef31")

    check orderedTrieRoot(txs) == root

  test "Transaction Trie - interleaved lists and wrappings with ignored item":
    let
      txs2 = @[tx2]
      root2 = Hash32.fromHex("0xa22e4570f1ca6c1dfd5f8651d19d91c9af0396b5426637a76c028f5c0e71610f")

    check orderedTrieRoot(txs2) == root2
