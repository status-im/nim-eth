import
  eth/rlp, stew/ranges/typedranges, nimcrypto/hash

export
  typedranges, Bytes

type
  KeccakHash* = MDigest[256]
  BytesContainer* = ByteRange | Bytes | string

# can't be a const: https://github.com/status-im/nim-eth/issues/6
# we can't initialise it here, but since it's already zeroed memory, we don't need to
var zeroBytesRange* {.threadvar.}: ByteRange

const
  blankStringHash* = "c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470".toDigest
  emptyRlp* = @[128.byte]
  emptyRlpHash* = "56e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b421".toDigest

proc read*(rlp: var Rlp, T: typedesc[MDigest]): T {.inline.} =
  result.data = rlp.read(type(result.data))

proc append*(rlpWriter: var RlpWriter, a: MDigest) {.inline.} =
  rlpWriter.append(a.data)

proc unnecessary_OpenArrayToRange*(key: openarray[byte]): ByteRange =
  ## XXX: The name of this proc is intentionally long, because it
  ## performs a memory allocation and data copying that may be eliminated
  ## in the future. Avoid renaming it to something similar as `toRange`, so
  ## it can remain searchable in the code.
  toRange(@key)
