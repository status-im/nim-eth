import
  ../trie/[trie_defs, db, hexary],
  ../rlp,
  ./chaindb

export chaindb

proc getAccount*(db: TrieDatabaseRef,
                 rootHash: KeccakHash,
                 account: EthAddress): Account =
  let trie = initSecureHexaryTrie(db, rootHash)
  let data = trie.get(account)
  if data.len > 0:
    result = rlp.decode(data, Account)
  else:
    result = newAccount()

proc getContractCode*(chain: AbstractChainDB, req: ContractCodeRequest): Blob {.gcsafe.} =
  let b = chain.getBlockHeader(req.blockHash)
  if b.hasData:
    let acc = getAccount(chain.getTrieDB, b.stateRoot, req.key)
    result = chain.getCodeByHash(acc.codeHash)

proc getStorageNode*(chain: AbstractChainDB, hash: KeccakHash): Blob
    {.raises: [CatchableError, Defect].} =
  let db = chain.getTrieDB
  return db.get(hash.data)
