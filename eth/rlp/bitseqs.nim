import
  stew/bitseqs, ../rlp

type
  Bytes = seq[byte]

proc read*(rlp: var Rlp, T: type BitSeq): T {.inline.} =
  T read(rlp, Bytes)

proc append*(writer: var RlpWriter, value: BitSeq) =
  append(writer, Bytes(value))

export
  bitseqs, rlp
