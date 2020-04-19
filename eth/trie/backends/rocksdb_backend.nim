import os, rocksdb, eth/trie/[trie_defs, db_tracing]
import backend_defs

type
  RocksChainDB* = ref object of RootObj
    store: RocksDBInstance

  ChainDB* = RocksChainDB

# Maximum open files for rocksdb, set to 512 to be safe for usual 1024 Linux
# limit per application
const maxOpenFiles = 512

proc get*(db: ChainDB, key: openarray[byte]): seq[byte] =
  let s = db.store.getBytes(key)
  if s.isOk:
    result = s.value
    traceGet key, result
  elif s.error.len == 0:
    discard
  else:
    raiseKeyReadError(key)

proc put*(db: ChainDB, key, value: openarray[byte]) =
  tracePut key, value
  let s = db.store.put(key, value)
  if not s.isOk: raiseKeyWriteError(key)

proc contains*(db: ChainDB, key: openarray[byte]): bool =
  let s = db.store.contains(key)
  if not s.isOk: raiseKeySearchError(key)
  return s.value

proc del*(db: ChainDB, key: openarray[byte]) =
  traceDel key
  let s = db.store.del(key)
  if not s.isOk: raiseKeyDeletionError(key)

proc close*(db: ChainDB) =
  db.store.close

proc newChainDB*(basePath: string, readOnly = false): ChainDB =
  result.new()
  let
    dataDir = basePath / "data"
    backupsDir = basePath / "backups"

  createDir(dataDir)
  createDir(backupsDir)

  let s = result.store.init(dataDir, backupsDir, readOnly,
                            maxOpenFiles = maxOpenFiles)
  if not s.isOk: raiseStorageInitError()

  if not readOnly:
    put(result, emptyRlpHash.data, emptyRlp)
