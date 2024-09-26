import ./base, ../rlp

export base, rlp

# TODO why is rlp serialization of `Opt` here and not in rlp?
proc append*[T](w: var RlpWriter, val: Opt[T]) =
  mixin append

  if val.isSome:
    w.append(val.get())
  else:
    w.append("")

template read*[T](rlp: var Rlp, val: var T) =
  mixin read
  val = rlp.read(type val)

proc read*[T](rlp: var Rlp, val: var Opt[T]) =
  mixin read
  if rlp.blobLen != 0:
    val = Opt.some(rlp.read(T))
  else:
    rlp.skipElem

proc read*(rlp: var Rlp, T: type StUint): T {.inline.} =
  if rlp.isBlob:
    let bytes = rlp.toBytes
    if bytes.len > 0:
      # be sure the amount of bytes matches the size of the stint
      if bytes.len <= sizeof(result):
        result.initFromBytesBE(bytes)
      else:
        raise newException(RlpTypeMismatch, "Unsigned integer expected, but the source RLP has the wrong length")
    else:
      result = 0.to(T)
  else:
    raise newException(RlpTypeMismatch, "Unsigned integer expected, but the source RLP is a list")

  rlp.skipElem

func significantBytesBE(val: openArray[byte]): int =
  ## Returns the number of significant trailing bytes in a big endian
  ## representation of a number.
  for i in 0 ..< val.len:
    if val[i] != 0:
      return val.len - i
  return 1

proc append*(w: var RlpWriter, value: StUint) =
  if value > 128:
    let bytes = value.toByteArrayBE
    let nonZeroBytes = significantBytesBE(bytes)
    w.append bytes.toOpenArray(bytes.len - nonZeroBytes,
                                       bytes.len - 1)
  else:
    w.append(value.truncate(uint))

proc read*(rlp: var Rlp, T: type StInt): T {.inline.} =
  # The Ethereum Yellow Paper defines the RLP serialization only
  # for unsigned integers:
  {.fatal: "RLP serialization of signed integers is not allowed".}
  discard

proc append*(w: var RlpWriter, value: StInt) =
  # The Ethereum Yellow Paper defines the RLP serialization only
  # for unsigned integers:
  {.fatal: "RLP serialization of signed integers is not allowed".}
  discard

proc append*(w: var RlpWriter, val: FixedBytes) =
  mixin append
  w.append(val.data())

proc read*[N: static int](rlp: var Rlp, T: type FixedBytes[N]): T =
  T(rlp.read(type(result.data)))

proc append*(w: var RlpWriter, id: ChainId) =
  w.append(id.uint64)

proc read*(rlp: var Rlp, T: type ChainId): T =
  T(rlp.read(uint64))

proc append*(w: var RlpWriter, id: NetworkId) =
  w.append(id.uint)

proc read*(rlp: var Rlp, T: type NetworkId): T =
  T(rlp.read(uint))
