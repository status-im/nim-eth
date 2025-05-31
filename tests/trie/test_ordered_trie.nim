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
