import
  eth_trie/[defs, db, hexary], rlp,
  eth_types

proc getAccount*(db: TrieDatabaseRef,
                 rootHash: KeccakHash,
                 account: EthAddress): Account =
  let trie = initSecureHexaryTrie(db, rootHash)
  let data = trie.get(unnecessary_OpenArrayToRange account)
  if data.len > 0:
    result = rlp.decode(data, Account)
  else:
    result = newAccount()

proc getContractCode*(chain: AbstractChainDb, req: ContractCodeRequest): Blob {.gcsafe.} =
  let b = chain.getBlockHeader(req.blockHash)
  if b.hasData:
    let acc = getAccount(chain.getStateDb, b.stateRoot, req.key)
    result = chain.getCodeByHash(acc.codeHash)

proc getStorageNode*(chain: AbstractChainDb, hash: KeccakHash): Blob =
  let db = chain.getStateDb
  return db.get(hash.data)
  # let trie = initSecureHexaryTrie(db, emptyRlpHash) # TODO emptyRlpHash is not correct here
  # return trie.get(unnecessary_OpenArrayToRange hash.data)

