import ../rlp
import results

proc append*[T](w: var RlpWriter, val: Opt[T]) =
  mixin append

  if val.isSome:
    w.append(val.get())
  else:
    w.append("")

proc read*[T](rlp: var Rlp, val: var Opt[T]) {.raises: [RlpError].} =
  mixin read
  if rlp.blobLen != 0:
    val = Opt.some(rlp.read(T))
  else:
    rlp.skipElem

export 
  rlp, results
