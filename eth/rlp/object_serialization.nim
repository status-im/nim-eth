# eth
# Copyright (c) 2019-2026 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option. This file may not be copied, modified, or distributed except according to those terms.

{.push raises: [].}

import stew/shims/[iterators, macros]

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

template enumerateRlpFieldTypes*(T: type, op: untyped) =
  for fieldName, FieldType in fieldTypePairs(T):
    when not hasCustomPragmaFixed(T, fieldName, rlpIgnore):
      op(T, fieldName, FieldType)

func rlpFieldsCount*(T: type): int =
  mixin enumerateRlpFieldTypes

  func helper(): int =
    template countFields(RT, n, x) {.used.} =
      inc result

    enumerateRlpFieldTypes(T, countFields)

  const res = helper()
  return res
