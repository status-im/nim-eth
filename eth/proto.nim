import
  nimcrypto/keccak,
  results,
  ./common/transactions,
  ./rlp/vla

import
  ./rlp/priv/defs,
  ./rlp/utils

type
  PrefixTuple = object
    listLen: uint32
    prefixLen: uint32

  PrefixList = ptr object
    len: uint
    data: UncheckedArray[PrefixTuple]

  PrefixCounter = object
    index: uint
    list: PrefixList

  LenWriter = object
    pc: ptr PrefixCounter
    len: uint
    index: uint

  HashCounter = object
    list: PrefixList
    index: int
    keccak: keccak.keccak256

  HashWriter = object
    inner: ptr HashCounter

  PolyWriter = HashWriter | LenWriter

func countList[T](list: openArray[T]): uint =
  mixin countList
  result = 1
  for x in list:
    inc(result, countList(x))

func countList(x: AccessPair): uint =
  1'u + x.storageKeys.len.uint

func countList(x: Authorization): uint =
  1'u

func countList(tx: Transaction): uint =
  case tx.txType
  of TxLegacy:
    1'u
  of TxEip2930, TxEip1559:
    1'u + countList(tx.accessList)
  of TxEip4844:
    2'u + countList(tx.accessList) + tx.versionedHashes.len.uint
  of TxEip7702:
    1'u + countList(tx.accessList) + countList(tx.authorizationList)

template incLen(lc: var LenWriter, z: uint) =
  lc.len += z

func startList(pc: ptr PrefixCounter, listSize: uint): LenWriter =
  #doAssert(pc.index < pc.list.len)
  let index = pc.index
  inc pc.index
  LenWriter(
    index: index,
    pc: pc,
    len: (listSize == 0).uint
  )

template startList(lc: LenWriter, listSize: uint): LenWriter =
  lc.pc.startList(listSize)

func update(pc: ptr PrefixCounter, index: uint, listLen: uint, prefixLen: uint) =
  #doAssert(index < pc.list.len)
  pc.list.data[index] = PrefixTuple(
    listLen: listLen.uint32,
    prefixLen: prefixLen.uint32
  )

func update(lc: LenWriter, plc: var LenWriter) =
  # This replace PendingList
  let listLen = lc.len
  let prefixLen = if listLen < uint(THRESHOLD_LIST_LEN): 1'u
                  else: uint(uint64(listLen).bytesNeeded + 1)

  lc.pc.update(lc.index, lc.len, prefixLen)
  plc.len += lc.len + prefixLen

func lengthCount(count: int): int {.inline.} =
  if count < THRESHOLD_LIST_LEN: 1
  else: uint64(count).bytesNeeded + 1

func append(lc: var LenWriter, val: SomeUnsignedInt) =
  if val < typeof(val)(BLOB_START_MARKER):
    lc.incLen(1)
  else:
    let bn = val.bytesNeeded
    lc.incLen((lengthCount(bn) + bn).uint)

func append(lc: var LenWriter, data: openArray[byte]) =
  if data.len == 1 and byte(data[0]) < BLOB_START_MARKER:
    lc.incLen(1)
  else:
    lc.incLen((lengthCount(data.len) + data.len).uint)

template updateOuput(hw: var HashWriter, data: byte) =
  hw.inner.keccak.update([data])

template updateOuput(hw: var HashWriter, data: openArray[byte]) =
  hw.inner.keccak.update(data)

template updateBigEndian(hw: var HashWriter, i: SomeUnsignedInt,
                          length: uint) =
  var bigEndianBuf: array[8, byte]
  bigEndianBuf.writeBigEndian(i, length.int - 1, length.int)
  hw.updateOuput(bigEndianBuf.toOpenArray(0, length - 1))

func writeCount(hw: var HashWriter, count: uint, baseMarker: byte) =
  if count < THRESHOLD_LIST_LEN:
    hw.updateOuput(baseMarker + byte(count))
  else:
    let lenPrefixBytes = uint64(count).bytesNeeded.uint
    hw.updateOuput baseMarker + (THRESHOLD_LIST_LEN - 1) + byte(lenPrefixBytes)
    hw.updateBigEndian(count, lenPrefixBytes)

proc startList(hw: var HashWriter, listSize: uint): HashWriter =
  if listSize == 0:
    hw.updateOuput(LIST_START_MARKER.byte)
  else:
    let
      inner = hw.inner
      prefixLen = inner.list.data[inner.index].prefixLen
      listLen = inner.list.data[inner.index].listLen

    inner.index += 1

    if listLen < THRESHOLD_LIST_LEN:
      hw.updateOuput(LIST_START_MARKER + byte(listLen))
    else:
      let listLenBytes = prefixLen - 1
      hw.updateOuput(LEN_PREFIXED_LIST_MARKER + byte(listLenBytes))
      hw.updateBigEndian(listLen, listLenBytes)

  HashWriter(inner: hw.inner)

template update(hw: HashWriter, phw: var HashWriter) =
  discard

func append(hw: var HashWriter, val: SomeUnsignedInt) =
  if val == typeof(val)(0):
    hw.updateOuput BLOB_START_MARKER
  elif val < typeof(val)(BLOB_START_MARKER):
    hw.updateOuput byte(val)
  else:
    let bytesNeeded = val.bytesNeeded.uint
    hw.writeCount(bytesNeeded, BLOB_START_MARKER)
    hw.updateBigEndian(uint64(val), bytesNeeded)

proc append(hw: var HashWriter, bytes: openArray[byte]) =
  if bytes.len == 1 and byte(bytes[0]) < BLOB_START_MARKER:
    hw.updateOuput byte(bytes[0])
  else:
    hw.writeCount(bytes.len.uint, BLOB_START_MARKER)
    hw.updateOuput(bytes)

func significantBytesBE(val: openArray[byte]): int =
  ## Returns the number of significant trailing bytes in a big endian
  ## representation of a number.
  for i in 0 ..< val.len:
    if val[i] != 0:
      return val.len - i
  return 1

proc append(lc: var PolyWriter, value: StUint) =
  if value > 128:
    let bytes = value.toBytesBE
    let nonZeroBytes = significantBytesBE(bytes)
    lc.append bytes.toOpenArray(bytes.len - nonZeroBytes, bytes.len - 1)
  else:
    lc.append(value.truncate(uint))

func append[T](lc: var PolyWriter, val: Opt[T]) =
  mixin append
  if val.isSome: lc.append(val.get)
  else: lc.append("")

func append[T](plc: var PolyWriter, list: openArray[T]) =
  mixin append

  var lc = plc.startList(list.len.uint)
  for x in list:
    lc.append(x)
  lc.update(plc)

func append(lc: var PolyWriter, val: string) =
  lc.append(val.toOpenArrayByte(0, val.high))

func append(lc: var PolyWriter, val: Address) =
  lc.append(val.data)

func append(lc: var PolyWriter, val: Bytes32) =
  lc.append(val.data)

func append(lc: var PolyWriter, val: Hash32) =
  lc.append(val.data)

func append(lc: var PolyWriter, val: enum) =
  lc.append(val.uint)

proc appendTxLegacy(plc: var PolyWriter, tx: Transaction) =
  var lc = plc.startList(9)
  lc.append(tx.nonce)
  lc.append(tx.gasPrice)
  lc.append(tx.gasLimit)
  lc.append(tx.to)
  lc.append(tx.value)
  lc.append(tx.payload)
  lc.append(tx.V)
  lc.append(tx.R)
  lc.append(tx.S)
  lc.update(plc)

proc append(plc: var PolyWriter, x: AccessPair) =
  var lc = plc.startList(2)
  lc.append(x.address)
  lc.append(x.storageKeys)
  lc.update(plc)

proc appendTxEip2930(plc: var PolyWriter, tx: Transaction) =
  var lc = plc.startList(11)
  lc.append(tx.chainId.uint64)
  lc.append(tx.nonce)
  lc.append(tx.gasPrice)
  lc.append(tx.gasLimit)
  lc.append(tx.to)
  lc.append(tx.value)
  lc.append(tx.payload)
  lc.append(tx.accessList)
  lc.append(tx.V)
  lc.append(tx.R)
  lc.append(tx.S)
  lc.update(plc)

proc appendTxEip1559(plc: var PolyWriter, tx: Transaction) =
  var lc = plc.startList(12)
  lc.append(tx.chainId.uint64)
  lc.append(tx.nonce)
  lc.append(tx.maxPriorityFeePerGas)
  lc.append(tx.maxFeePerGas)
  lc.append(tx.gasLimit)
  lc.append(tx.to)
  lc.append(tx.value)
  lc.append(tx.payload)
  lc.append(tx.accessList)
  lc.append(tx.V)
  lc.append(tx.R)
  lc.append(tx.S)
  lc.update(plc)

proc appendTxEip4844(plc: var PolyWriter, tx: Transaction) =
  var lc = plc.startList(14)
  lc.append(tx.chainId.uint64)
  lc.append(tx.nonce)
  lc.append(tx.maxPriorityFeePerGas)
  lc.append(tx.maxFeePerGas)
  lc.append(tx.gasLimit)
  lc.append(tx.to)
  lc.append(tx.value)
  lc.append(tx.payload)
  lc.append(tx.accessList)
  lc.append(tx.maxFeePerBlobGas)
  lc.append(tx.versionedHashes)
  lc.append(tx.V)
  lc.append(tx.R)
  lc.append(tx.S)
  lc.update(plc)

proc append(plc: var PolyWriter, x: Authorization) =
  var lc = plc.startList(6)
  lc.append(x.chainId.uint64)
  lc.append(x.address)
  lc.append(x.nonce)
  lc.append(x.v)
  lc.append(x.r)
  lc.append(x.s)
  lc.update(plc)

proc appendTxEip7702(plc: var PolyWriter, tx: Transaction) =
  var lc = plc.startList(13)
  lc.append(tx.chainId.uint64)
  lc.append(tx.nonce)
  lc.append(tx.maxPriorityFeePerGas)
  lc.append(tx.maxFeePerGas)
  lc.append(tx.gasLimit)
  lc.append(tx.to)
  lc.append(tx.value)
  lc.append(tx.payload)
  lc.append(tx.accessList)
  lc.append(tx.authorizationList)
  lc.append(tx.V)
  lc.append(tx.R)
  lc.append(tx.S)
  lc.update(plc)

proc appendTxPayload(lc: var PolyWriter, tx: Transaction) =
  case tx.txType
  of TxLegacy:
    lc.appendTxLegacy(tx)
  of TxEip2930:
    lc.appendTxEip2930(tx)
  of TxEip1559:
    lc.appendTxEip1559(tx)
  of TxEip4844:
    lc.appendTxEip4844(tx)
  of TxEip7702:
    lc.appendTxEip7702(tx)

proc append(lc: var PolyWriter, tx: Transaction) =
  if tx.txType != TxLegacy:
    lc.append(tx.txType)
  lc.appendTxPayload(tx)


proc protoHash*(tx: Transaction): Hash32 =
  let numList = countList(tx)
  let vla = vlaAlloc(numList * sizeof(PrefixTuple).uint + sizeof(uint).uint)
  var pc = PrefixCounter(
    list: vla.to(PrefixList)
  )
  pc.list.len = numList

  var lc = LenWriter(pc: pc.addr)
  #debugEcho "PROTO LEN: ", pc.list.len
  lc.append(tx)
  #for i in 0..<pc.list.len:
    #let z = pc.list.data[i]
    #debugEcho "PROTO: ", z.listLen, " ", z.prefixLen

  var inner = HashCounter(list: pc.list)
  var hw = HashWriter(
    inner: inner.addr
  )

  hw.append(tx)
  vla.vlaFree

  inner.keccak.finish.to(Hash32)

