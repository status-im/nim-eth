import macros

template rlpIgnore* {.pragma.}
  ## Specifies that a certain field should be ignored for the purposes
  ## of RLP serialization

template rlpInline* {.pragma.}
  ## This can be specified on a record field in order to avoid the
  ## default behavior of wrapping the record in a RLP list.

template rlpCustomSerialization* {.pragma.}
  ## This pragma can be applied to a record field to enable the
  ## use of custom `read` and `append` overloads that also take
  ## a reference to the object holding the field.

template enumerateRlpFields*[T](x: T, op: untyped) =
  for f in fields(x):
    when not hasCustomPragma(f, rlpIgnore):
      op(f)

proc rlpFieldsCount*(T: type): int =
  mixin enumerateRlpFields

  proc helper: int =
    var dummy: T
    template countFields(x) = inc result
    enumerateRlpFields(dummy, countFields)

  const res = helper()
  return res

macro rlpFields*(T: typedesc, fields: varargs[untyped]): untyped =
  var body = newStmtList()
  let
    ins = genSym(nskParam, "instance")
    op = genSym(nskParam, "op")

  for field in fields:
    body.add quote do: `op`(`ins`.`field`)

  result = quote do:
    template enumerateRlpFields*(`ins`: `T`, `op`: untyped) {.inject.} =
      `body`

