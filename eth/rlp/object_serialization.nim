# eth
# Copyright (c) 2019-2024 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option. This file may not be copied, modified, or distributed except according to those terms.

import stew/shims/macros

template rlpIgnore*() {.pragma.}
  ## Specifies that a certain field should be ignored for the purposes
  ## of RLP serialization

template rlpCustomSerialization*() {.pragma.}
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

  proc helper(): int =
    var dummy: T
    template countFields(RT, n, x) {.used.} =
      inc result

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
    body.add quote do:
      `op`(`T`, `fieldName`, `ins`.`field`)

  result = quote:
    template enumerateRlpFields*(`ins`: `T`, `op`: untyped) {.inject.} =
      `body`
