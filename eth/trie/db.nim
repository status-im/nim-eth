import
  tables, hashes, sets,
  nimcrypto/[hash, keccak], eth/rlp,
  trie_defs, db_tracing

type
  MemDBRec = object
    refCount: int
    value: Bytes

  MemoryLayer* = ref object of RootObj
    records: Table[Bytes, MemDBRec]
    deleted: HashSet[Bytes]

  TrieDatabaseConcept* = concept DB
    mixin put, del, get

    put(var DB, KeccakHash, BytesRange)
    del(var DB, KeccakHash)
    get(DB, KeccakHash) is Bytes
    contains(DB, KeccakHash) is bool

  # XXX: poor's man vtref types
  PutProc = proc (db: RootRef, key, val: openarray[byte]) {.
    gcsafe, raises: [Defect, CatchableError] .}

  GetProc = proc (db: RootRef, key: openarray[byte]): Bytes {.
    gcsafe, raises: [Defect, CatchableError] .}
    ## The result will be empty seq if not found

  DelProc = proc (db: RootRef, key: openarray[byte]) {.
    gcsafe, raises: [Defect, CatchableError] .}

  ContainsProc = proc (db: RootRef, key: openarray[byte]): bool {.
    gcsafe, raises: [Defect, CatchableError] .}

  TrieDatabaseRef* = ref object
    obj: RootRef
    putProc: PutProc
    getProc: GetProc
    delProc: DelProc
    containsProc: ContainsProc
    mostInnerTransaction: DbTransaction

  TransactionState = enum
    Pending
    Committed
    RolledBack

  DbTransaction* = ref object
    db: TrieDatabaseRef
    parentTransaction: DbTransaction
    modifications: MemoryLayer
    state: TransactionState

  TransactionID* = distinct DbTransaction

proc put*(db: TrieDatabaseRef, key, val: openarray[byte]) {.gcsafe.}
proc get*(db: TrieDatabaseRef, key: openarray[byte]): Bytes {.gcsafe.}
proc del*(db: TrieDatabaseRef, key: openarray[byte]) {.gcsafe.}
proc beginTransaction*(db: TrieDatabaseRef): DbTransaction {.gcsafe.}

proc keccak*(r: BytesRange): KeccakHash =
  keccak256.digest r.toOpenArray

proc get*(db: MemoryLayer, key: openarray[byte]): Bytes =
  result = db.records.getOrDefault(@key).value
  traceGet key, result

proc del*(db: MemoryLayer, key: openarray[byte]) =
  traceDel key

  # The database should ensure that the empty key is always active:
  if key != emptyRlpHash.data:
    # TODO: This is quite inefficient and it won't be necessary once
    # https://github.com/nim-lang/Nim/issues/7457 is developed.
    let key = @key

    db.records.withValue(key, v):
      dec v.refCount
      if v.refCount <= 0:
        db.records.del(key)
        db.deleted.incl(key)

proc contains*(db: MemoryLayer, key: openarray[byte]): bool =
  db.records.hasKey(@key)

proc put*(db: MemoryLayer, key, val: openarray[byte]) =
  tracePut key, val

  # TODO: This is quite inefficient and it won't be necessary once
  # https://github.com/nim-lang/Nim/issues/7457 is developed.
  let key = @key

  db.deleted.excl(key)

  if key.len != 32:
    # This is not a Trie key, but a regular system mutable key
    # (e.g. the cannonical head hash). We don't need to ref count such keys.
    db.records[key] = MemDBRec(refCount: 1, value: @val)
  else:
    db.records.withValue(key, v) do:
      inc v.refCount
      if v.value != val: v.value = @val
    do:
      db.records[key] = MemDBRec(refCount: 1, value: @val)

proc newMemoryLayer: MemoryLayer =
  result.new
  result.records = initTable[Bytes, MemDBRec]()
  result.deleted = initHashSet[Bytes]()

proc commit(memDb: MemoryLayer, db: TrieDatabaseRef, applyDeletes: bool = true) =
  if applyDeletes:
    for k in memDb.deleted:
      db.del(k)

  for k, v in memDb.records:
    db.put(k, v.value)

proc init(db: var MemoryLayer) =
  db = newMemoryLayer()

proc newMemoryDB*: TrieDatabaseRef =
  new result
  discard result.beginTransaction
  put(result, emptyRlpHash.data, emptyRlp)

template isMemoryDB(db: TrieDatabaseRef): bool =
  # Make sure this is really a MemoryDB
  db.obj == nil and
    db.mostInnerTransaction != nil and
    db.mostInnerTransaction.parentTransaction == nil

proc totalRecordsInMemoryDB*(db: TrieDatabaseRef): int =
  doAssert isMemoryDB(db)
  return db.mostInnerTransaction.modifications.records.len

iterator pairsInMemoryDB*(db: TrieDatabaseRef): (Bytes, Bytes) =
  doAssert isMemoryDB(db)
  for k, v in db.mostInnerTransaction.modifications.records:
    yield (k, v.value)

proc beginTransaction*(db: TrieDatabaseRef): DbTransaction =
  new result
  result.db = db
  init result.modifications
  result.state = Pending
  result.parentTransaction = db.mostInnerTransaction
  db.mostInnerTransaction = result

proc rollback*(t: DbTransaction) =
  # Transactions should be handled in a strictly nested fashion.
  # Any child transaction must be committed or rolled-back before
  # its parent transactions:
  doAssert t.db.mostInnerTransaction == t and t.state == Pending
  t.db.mostInnerTransaction = t.parentTransaction
  t.state = RolledBack

proc commit*(t: DbTransaction, applyDeletes: bool = true) =
  # Transactions should be handled in a strictly nested fashion.
  # Any child transaction must be committed or rolled-back before
  # its parent transactions:
  doAssert t.db.mostInnerTransaction == t and t.state == Pending
  t.db.mostInnerTransaction = t.parentTransaction
  t.modifications.commit(t.db, applyDeletes)
  t.state = Committed

proc dispose*(t: DbTransaction) {.inline.} =
  if t.state == Pending:
    t.rollback()

proc safeDispose*(t: DbTransaction) {.inline.} =
  if (not isNil(t)) and (t.state == Pending):
    t.rollback()

proc putImpl[T](db: RootRef, key, val: openarray[byte]) =
  mixin put
  put(T(db), key, val)

proc getImpl[T](db: RootRef, key: openarray[byte]): Bytes =
  mixin get
  return get(T(db), key)

proc delImpl[T](db: RootRef, key: openarray[byte]) =
  mixin del
  del(T(db), key)

proc containsImpl[T](db: RootRef, key: openarray[byte]): bool =
  mixin contains
  return contains(T(db), key)

proc trieDB*[T: RootRef](x: T): TrieDatabaseRef =
  mixin del, get, put

  new result
  result.obj = x
  result.putProc = putImpl[T]
  result.getProc = getImpl[T]
  result.delProc = delImpl[T]
  result.containsProc = containsImpl[T]

proc put*(db: TrieDatabaseRef, key, val: openarray[byte]) =
  var t = db.mostInnerTransaction
  if t != nil:
    t.modifications.put(key, val)
  else:
    db.putProc(db.obj, key, val)

proc get*(db: TrieDatabaseRef, key: openarray[byte]): Bytes =
  # TODO: This is quite inefficient and it won't be necessary once
  # https://github.com/nim-lang/Nim/issues/7457 is developed.
  let key = @key

  var t = db.mostInnerTransaction
  while t != nil:
    result = t.modifications.records.getOrDefault(key).value
    if result.len > 0 or key in t.modifications.deleted:
      return
    t = t.parentTransaction

  if db.getProc != nil:
    result = db.getProc(db.obj, key)

proc del*(db: TrieDatabaseRef, key: openarray[byte]) =
  var t = db.mostInnerTransaction
  if t != nil:
    t.modifications.del(key)
  else:
    db.delProc(db.obj, key)

proc contains*(db: TrieDatabaseRef, key: openarray[byte]): bool =
  # TODO: This is quite inefficient and it won't be necessary once
  # https://github.com/nim-lang/Nim/issues/7457 is developed.
  let key = @key

  var t = db.mostInnerTransaction
  while t != nil:
    result = key in t.modifications.records
    if result or key in t.modifications.deleted:
      return
    t = t.parentTransaction

  if db.containsProc != nil:
    result = db.containsProc(db.obj, key)

# TransactionID imitate subset of JournalDB behaviour
# but there is no need to rollback or dispose
# TransactionID, because it will be handled elsewhere
# this is useful when we need to jump back to specific point
# in history where the database still in 'original' state
# and retrieve data from that point
proc getTransactionID*(db: TrieDatabaseRef): TransactionID =
  TransactionID(db.mostInnerTransaction)

proc setTransactionID*(db: TrieDatabaseRef, id: TransactionID) =
  db.mostInnerTransaction = DbTransaction(id)

template shortTimeReadOnly*(db: TrieDatabaseRef, id: TransactionID, body: untyped) =
  # hmm, how can we prevent unwanted database modification
  # inside this block?
  block:
    let tmpID = db.getTransactionID()
    db.setTransactionID(id)
    body
    db.setTransactionID(tmpID)
