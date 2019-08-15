import
  std/options, ../rlp

proc read*[T](rlp: var Rlp, O: type Option[T]): O {.inline.} =
  mixin read
  if not rlp.isEmpty:
    result = some read(rlp, T)

proc append*(writer: var RlpWriter, value: Option) =
  if value.isSome:
    writer.append value.get
  else:
    writer.append ""

export
  options, rlp

