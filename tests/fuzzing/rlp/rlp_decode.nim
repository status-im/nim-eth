{.push raises: [].}

import
  testutils/fuzzing,
  ../../../eth/rlp,
  ../fuzzing_helpers

type
  TestEnum = enum
    one = 1
    two = 2
  TestObject* = object
    test1: uint32
    test2: string

test:
  checkRoundTrip(payload, string)
  checkRoundTrip(payload, uint)
  checkRoundTrip(payload, uint8)
  checkRoundTrip(payload, uint16)
  checkRoundTrip(payload, uint32)
  checkRoundTrip(payload, uint64)
  checkRoundTrip(payload, bool)
  checkRoundTrip(payload, seq[byte])
  checkRoundTrip(payload, (string, uint32))
  checkRoundTrip(payload, TestEnum)
  checkRoundTrip(payload, TestObject)
