# beacon_chain
# Copyright (c) 2018-2023 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option. This file may not be copied, modified, or distributed except according to those terms.

## Simple Key-Value store database interface that allows creating multiple
## tables within each store

{.push raises: [].}
{.pragma: callback, gcsafe, raises: [].}

import
  std/[tables, hashes, sets],
  stew/results

export results

type
  MemStoreRef* = ref object of RootObj
    records: Table[seq[byte], seq[byte]]
      # TODO interaction with this table would benefit from heterogeneous lookup
      #      (see `@key` below)
      #      https://github.com/nim-lang/Nim/issues/7457

  KvResult*[T] = Result[T, string]

  DataProc* = proc(val: openArray[byte]) {.callback.}
  KeyValueProc* = proc(key, val: openArray[byte]) {.callback.}

  PutProc = proc (db: RootRef, key, val: openArray[byte]): KvResult[void] {.nimcall, callback.}
  GetProc = proc (db: RootRef, key: openArray[byte], onData: DataProc): KvResult[bool] {.nimcall, callback.}
  FindProc = proc (db: RootRef, prefix: openArray[byte], onFind: KeyValueProc): KvResult[int] {.nimcall, callback.}
  DelProc = proc (db: RootRef, key: openArray[byte]): KvResult[bool] {.nimcall, callback.}
  ClearProc = proc (db: RootRef): KvResult[bool] {.nimcall, callback.}
  ContainsProc = proc (db: RootRef, key: openArray[byte]): KvResult[bool] {.nimcall, callback.}
  CloseProc = proc (db: RootRef): KvResult[void] {.nimcall, callback.}

  KvStoreRef* = ref object
    ## Key-Value store virtual interface
    obj: RootRef
    putProc: PutProc
    getProc: GetProc
    findProc: FindProc
    delProc: DelProc
    clearProc: ClearProc
    containsProc: ContainsProc
    closeProc: CloseProc

template put*(dbParam: KvStoreRef, key, val: openArray[byte]): KvResult[void] =
  ## Store ``value`` at ``key`` - overwrites existing value if already present
  let db = dbParam
  db.putProc(db.obj, key, val)

template get*(dbParam: KvStoreRef, key: openArray[byte], onData: untyped): KvResult[bool] =
  ## Retrieve value at ``key`` and call ``onData`` with the value. The data is
  ## valid for the duration of the callback.
  ## ``onData``: ``proc(data: openArray[byte])``
  ## returns true if found and false otherwise.
  let db = dbParam
  db.getProc(db.obj, key, onData)

template find*(
    dbParam: KvStoreRef, prefix: openArray[byte], onFind: untyped): KvResult[int] =
  ## Perform a prefix find, returning all data starting with the given prefix.
  ## An empty prefix returns all rows in the store.
  ## The data is valid for the duration of the callback.
  ## ``onFind``: ``proc(key, value: openArray[byte])``
  ## returns the number of rows found
  let db = dbParam
  db.findProc(db.obj, prefix, onFind)

template del*(dbParam: KvStoreRef, key: openArray[byte]): KvResult[bool] =
  ## Remove value at ``key`` from store - do nothing if the value is not present
  ## Returns true iff value was found and deleted
  let db = dbParam
  db.delProc(db.obj, key)

template clear*(dbParam: KvStoreRef): KvResult[bool] =
  ## Remove all values from store
  ## Returns true iff a value was found and deleted
  let db = dbParam
  db.clearProc(db.obj)

template contains*(dbParam: KvStoreRef, key: openArray[byte]): KvResult[bool] =
  ## Return true iff ``key`` has a value in store
  let db = dbParam
  db.containsProc(db.obj, key)

template close*(dbParam: KvStoreRef): KvResult[void] =
  ## Close database
  let db = dbParam
  db.closeProc(db.obj)

proc putImpl[T](db: RootRef, key, val: openArray[byte]): KvResult[void] {.gcsafe.} =
  mixin put
  put(T(db), key, val)

proc getImpl[T](db: RootRef, key: openArray[byte], onData: DataProc): KvResult[bool] {.gcsafe.} =
  mixin get
  get(T(db), key, onData)

proc findImpl[T](db: RootRef, key: openArray[byte], onFind: KeyValueProc): KvResult[int] {.gcsafe.} =
  mixin get
  find(T(db), key, onFind)

proc delImpl[T](db: RootRef, key: openArray[byte]): KvResult[bool] {.gcsafe.} =
  mixin del
  del(T(db), key)

proc clearImpl[T](db: RootRef): KvResult[bool] {.gcsafe.} =
  mixin clear
  clear(T(db))

proc containsImpl[T](db: RootRef, key: openArray[byte]): KvResult[bool] {.gcsafe.} =
  mixin contains
  contains(T(db), key)

proc closeImpl[T](db: RootRef): KvResult[void] {.gcsafe.} =
  mixin close
  close(T(db))

func kvStore*[T: RootRef](x: T): KvStoreRef =
  mixin del, clear, get, put, contains, close

  KvStoreRef(
    obj: x,
    putProc: putImpl[T],
    getProc: getImpl[T],
    findProc: findImpl[T],
    delProc: delImpl[T],
    clearProc: clearImpl[T],
    containsProc: containsImpl[T],
    closeProc: closeImpl[T]
  )

proc get*(db: MemStoreRef, key: openArray[byte], onData: DataProc): KvResult[bool] =
  db.records.withValue(@key, v):
    onData(v[])
    return ok(true)

  ok(false)

proc find*(
    db: MemStoreRef, prefix: openArray[byte],
    onFind: KeyValueProc): KvResult[int] =
  var total = 0
  # Should use lower/upper bounds instead
  for k, v in db.records:
    if k.len() >= prefix.len and k.toOpenArray(0, prefix.len() - 1) == prefix:
      onFind(k, v)
      total += 1

  ok(total)

proc del*(db: MemStoreRef, key: openArray[byte]): KvResult[bool] =
  if @key in db.records:
    db.records.del(@key)
    ok(true)
  else:
    ok(false)

proc clear*(db: MemStoreRef): KvResult[bool] =
  if db.records.len > 0:
    db.records.clear()
    ok(true)
  else:
    ok(false)

proc contains*(db: MemStoreRef, key: openArray[byte]): KvResult[bool] =
  ok(db.records.contains(@key))

proc put*(db: MemStoreRef, key, val: openArray[byte]): KvResult[void] =
  db.records[@key] = @val
  ok()

proc close*(db: MemStoreRef): KvResult[void] =
  db.records.clear()
  ok()

proc init*(T: type MemStoreRef): T =
  T(
    records: initTable[seq[byte], seq[byte]]()
  )
