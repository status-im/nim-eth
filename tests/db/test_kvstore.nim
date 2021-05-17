{.used.}

import
  std/unittest,
  ../../eth/db/kvstore

const
  key = [0'u8, 1, 2, 3]
  value = [3'u8, 2, 1, 0]
  value2 = [5'u8, 2, 1, 0]
  key2 = [255'u8, 255]

proc testKvStore*(db: KvStoreRef, supportsFind: bool) =
  check:
    db != nil

    not db.get(key, proc(data: openArray[byte]) = discard)[]
    not db.contains(key)[]

  db.del(key)[] # does nothing

  db.put(key, value)[]

  var k, v: seq[byte]
  proc grab(data: openArray[byte]) =
    v = @data
  proc grab2(key, value: openArray[byte]) =
    k = @key
    v = @value

  check:
    db.contains(key)[]
    db.get(key, grab)[]
    v == value

  db.put(key, value2)[] # overwrite old value
  check:
    db.contains(key)[]
    db.get(key, grab)[]
    v == value2

  db.del(key)[]
  check:
    not db.get(key, proc(data: openArray[byte]) = discard)[]
    not db.contains(key)[]

  db.del(key)[] # does nothing

  if supportsFind:
    check:
      db.find([], proc(key, value: openArray[byte]) = discard).get() == 0

    db.put(key, value)[]

    check:
      db.find([], grab2).get() == 1
      db.find(key, grab2).get() == 1
      k == key
      v == value

    db.put(key2, value2)[]
    check:
      db.find([], grab2).get() == 2
      db.find([byte 255], grab2).get() == 1
      db.find([byte 255, 255], grab2).get() == 1
      db.find([byte 255, 255, 0], grab2).get() == 0
      db.find([byte 255, 255, 255], grab2).get() == 0
      db.find([byte 255, 0], grab2).get() == 0

suite "MemoryStoreRef":
  test "KvStore interface":
    testKvStore(kvStore MemStoreRef.init(), true)
