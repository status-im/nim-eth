import
  testutils/fuzzing, chronicles,
  eth/rlp

type
  TestEnum = enum
    one = 1
    two = 2
  TestObject* = object
    test1: uint32
    test2: string

template testDecode(payload: openarray, T: type) =
  try:
    discard rlp.decode(payload, T)
  except RlpError as e:
    debug "Decode failed", err = e.msg

test:
  testDecode(payload, string)
  testDecode(payload, uint)
  testDecode(payload, uint8)
  testDecode(payload, uint16)
  testDecode(payload, uint32)
  testDecode(payload, uint64)
  testDecode(payload, int)
  testDecode(payload, bool)
  testDecode(payload, float64)
  testDecode(payload, seq[byte])
  testDecode(payload, (string, int32))
  testDecode(payload, TestEnum)
  testDecode(payload, TestObject)
