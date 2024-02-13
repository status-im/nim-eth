import
  stew/shims/macros

template rlpIgnore* {.pragma.}
  ## Specifies that a certain field should be ignored for the purposes
  ## of RLP serialization

template rlpCustomSerialization* {.pragma.}
  ## This pragma can be applied to a record field to enable the
  ## use of custom `read` and `append` overloads that also take
  ## a reference to the object holding the field.

template enumerateRlpFields*[T](x: T, op: untyped) =
  type RecordType {.used.} = type x
  for fieldName, field in fieldPairs(x):
    when not hasCustomPragmaFixed(RecordType, fieldName, rlpIgnore):
      op(RecordType, fieldName, field)

proc rlpFieldsCount*(T: type): int =
  mixin enumerateRlpFields

  proc helper: int =
    var dummy: T
    template countFields(RT, n, x) {.used.} = inc result
    enumerateRlpFields(dummy, countFields)

  const res = helper()
  return res

macro rlpFields*(T: typedesc, fields: varargs[untyped]): untyped =
  var body = newStmtList()
  let
    ins = genSym(nskParam, "instance")
    op = genSym(nskParam, "op")

  for field in fields:
    let fieldName = $field
    body.add quote do: `op`(`T`, `fieldName`, `ins`.`field`)

  result = quote do:
    template enumerateRlpFields*(`ins`: `T`, `op`: untyped) {.inject.} =
      `body`

