{.push raises: [Defect].}

import os, rocksdb, ./kvstore, stew/results

export results

const maxOpenFiles = 512

type
  RocksStoreRef* = ref object of RootObj
    store: RocksDBInstance

proc get*(db: RocksStoreRef, key: openarray[byte], onData: kvstore.DataProc): KvResult[bool] =
  db.store.get(key, onData)

proc put*(db: RocksStoreRef, key, value: openarray[byte]): KvResult[void] =
  db.store.put(key, value)

proc contains*(db: RocksStoreRef, key: openarray[byte]): KvResult[bool] =
  db.store.contains(key)

proc del*(db: RocksStoreRef, key: openarray[byte]): KvResult[void] =
  db.store.del(key)

proc close*(db: RocksStoreRef) =
  db.store.close

proc init*(
    T: type RocksStoreRef, basePath: string, name: string,
    readOnly = false): KvResult[T] =
  let
    dataDir = basePath / name / "data"
    backupsDir = basePath / name / "backups"

  try:
    createDir(dataDir)
    createDir(backupsDir)
  except OSError, IOError:
    return err("rocksdb: cannot create database directory")

  var store: RocksDBInstance
  if (let v = store.init(
      dataDir, backupsDir, readOnly, maxOpenFiles = maxOpenFiles); v.isErr):
    return err(v.error)

  ok(T(store: store))
