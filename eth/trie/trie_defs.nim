import
  ../common/eth_hash_rlp

export eth_hash_rlp

type
  TrieError* = object of CatchableError
    # A common base type of all Trie errors.

  PersistenceFailure* = object of TrieError
    # The backing database of the trie was not able to carry out
    # the storage or retrieval request.

  CorruptedTrieDatabase* = object of Defect
    # We consider this a Defect, because the software cannot safely
    # operate if its database has been tampered with. A swift crash
    # will be a more appropriate response.

const
  blankStringHash* = "c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470".toDigest
  emptyRlp* = @[128.byte]
  emptyRlpHash* = "56e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b421".toDigest
