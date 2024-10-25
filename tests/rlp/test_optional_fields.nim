{.used.}

import
  ../../eth/[rlp, common],
  unittest2

# Optionals in between mandatory fields for the convenience of
# implementation. According to the spec all optionals appear
# after mandatory fields. Moreover, an empty optional field
# cannot and will not appear before a non-empty optional field

type ObjectWithOptionals = object
  a* : uint64
  b* : uint64
  c* : Opt[uint64] # should not count this as optional
  d* : Opt[uint64] # should not count this as optional
  e* : uint64
  f* : uint64
  g* : uint64
  h* : Opt[uint64] # should not count this as optional
  i* : Opt[uint64] # should not count this as optional
  j* : Opt[uint64] # should not count this as optional
  k* : uint64
  l* : Opt[uint64] # should count this as an optional
  m* : Opt[uint64] # should count this as an optional
  n* : Opt[uint64] # should count this as an optional

var 
  objWithEmptyOptional: ObjectWithOptionals
  objWithNonEmptyOptional: ObjectWithOptionals
  objWithNonEmptyTrailingOptionals: ObjectWithOptionals
  objWithEmptyTrailingOptionals: ObjectWithOptionals

objWithNonEmptyOptional.c = Opt.some(0'u64)
objWithNonEmptyOptional.d = Opt.some(0'u64)
objWithNonEmptyOptional.h = Opt.some(0'u64)
objWithNonEmptyOptional.i = Opt.some(0'u64)
objWithNonEmptyOptional.j = Opt.some(0'u64)
objWithNonEmptyOptional.l = Opt.some(0'u64)
objWithNonEmptyOptional.m = Opt.some(0'u64)
objWithNonEmptyOptional.n = Opt.some(0'u64)

objWithNonEmptyTrailingOptionals.l = Opt.some(0'u64)
objWithNonEmptyTrailingOptionals.m = Opt.some(0'u64)
objWithNonEmptyTrailingOptionals.n = Opt.some(0'u64)

objWithEmptyTrailingOptionals.c = Opt.some(0'u64)
objWithEmptyTrailingOptionals.d = Opt.some(0'u64)
objWithEmptyTrailingOptionals.h = Opt.some(0'u64)
objWithEmptyTrailingOptionals.i = Opt.some(0'u64)
objWithEmptyTrailingOptionals.j = Opt.some(0'u64)

suite "test optional fields":
  test "all optionals are empty":
    let bytes = rlp.encode(objWithEmptyOptional)

  test "all optionals are non empty":
    let bytes = rlp.encode(objWithNonEmptyOptional)

  test "Only trailing optionals are non empty":
    let bytes = rlp.encode(objWithNonEmptyTrailingOptionals)

  test "Only trailing optionals are empty":
    let bytes = rlp.encode(objWithEmptyTrailingOptionals)

